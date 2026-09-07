import asyncio
import configparser
import io
import logging
import os
import re
import urllib.error
import urllib.request
from contextlib import suppress

import yaml

from ..controllers._data_load._helpers import _parse_github_repo_path
from ..github.client import GitHubAppClient
from ..net import real_ip
from ..github.http_utils import safe_urlopen
from ._pip_apt_map import resolve_apt_dependencies
from ._repo_requirements import (
    _apply_excludes,
    _parse_repo_addons,
    _repo_alias,
    create_pip_conflict_alert,
    detect_addon_conflicts,
    detect_pip_conflicts,
    fetch_repo_addons,
    fetch_requirements_txt_with_client,
    merge_pip_requirements,
    resolve_github_client,
)
from .abstract_executor import AbstractSSHExecutor, sql_escape_literal
from .docker_prune_executor import PROTECT_LABEL

_logger = logging.getLogger(__name__)

#: Where the instance's Odoo log lives. ``logs/`` sits next to the
#: compose files on the host and is bind-mounted into the container, so
#: the log outlives the container that wrote it — a rebuild recreates
#: the container by design and would otherwise take the only copy of
#: yesterday's log with it.
LOGS_DIRNAME = "logs"
ODOO_LOG_DIR = "/var/log/odoo"
ODOO_LOGFILE = f"{ODOO_LOG_DIR}/odoo.log"

#: The command each environment's compose file gives the ``odoo``
#: service, which the override *replaces* — so whatever the template
#: put there has to be repeated here or it is silently lost. Verified
#: against the pinned template (v9.6.1): ``prod.yaml`` sets none, so
#: the image's CMD applies; ``test.yaml`` pins the two worker options
#: below. Re-check both when bumping the template pin (RB-15).
ODOO_COMMAND_PROD = ("/usr/local/bin/odoo",)
ODOO_COMMAND_TEST = ("odoo", "--workers=3", "--max-cron-threads=1")

# Path to the incubacloud_connect module.  Navigate from __file__ via
# abspath (stays in auto/addons/) then realpath the result to resolve
# the doodba symlink into the actual directory with real files — sftp.put
# cannot copy symlinks.
_IC_CONNECT_MODULE = os.path.realpath(
    os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "incubacloud_connect",
        )
    )
)

# Prefix for all temp files uploaded to the remote host
_TMP_PREFIX = "/tmp/.incubacloud"

# Kill switch for the pre-build requirements re-sync. Absent ⇒ enabled:
# keeping dependencies in step with the code a rebuild ships is the
# desired steady state, and an operator who wants the old frozen
# behaviour sets the parameter to '0' explicitly.
_ICP_RESYNC = "incubacloud.requirements_resync_enabled"


_SSH_RE = re.compile(r"^git@github\.com:(.+?)(?:\.git)?$")

_ADDONS_CONFLICT_RE = re.compile(
    r"AddonsConfigError: Addon (\w+) defined in several repos \{([^}]+)\}"
)


def _github_authed_url(url, token):
    """Normalize a GitHub repo URL to HTTPS and inject a token if available.

    Converts SSH URLs (git@github.com:org/repo.git) to HTTPS so the remote
    server doesn't need an SSH key for GitHub.  Then injects the token for
    private repos when one is available.
    """
    if not url:
        return url
    url = url.strip()
    # Convert SSH → HTTPS
    m = _SSH_RE.match(url)
    if m:
        url = f"https://github.com/{m.group(1)}.git"
    # Ensure HTTPS scheme
    if not url.startswith(("https://", "http://")):
        url = f"https://{url}"
    # Inject token into HTTPS URLs
    if token and "github.com" in url:
        url = url.replace(
            "https://",
            f"https://x-access-token:{token}@",
            1,
        )
    return url


class DeployInstanceExecutor(AbstractSSHExecutor):
    """Deploy a doodba instance via copier copy."""

    _job_type = "deploy_instance"

    # ── Helpers ────────────────────────────────────────────────────────────

    def _get_github_tokens(self):
        """Return available tokens: (app_token, pat) — either may be None."""
        svc = self.env["cloud.github.credential.service"]
        app_token = None
        with suppress(Exception):
            creds = svc.get_credentials()
            app_token = GitHubAppClient(creds).get_installation_token()
        pat = None
        with suppress(Exception):
            pat = svc.get_pat()
        return app_token, pat

    def _get_token_for_repo(self, repo_url, app_token, pat, cache):
        """Check which token can access a repo.

        App first, PAT fallback. Caches results by owner to avoid
        repeated API calls for repos in the same org.
        Returns the working token or None.
        """
        url = (repo_url or "").strip()
        if not url:
            return None

        try:
            owner, repo = _parse_github_repo_path(url)
        except ValueError:
            return app_token or pat

        # Check cache by owner — repos in the same org use the same token
        if owner in cache:
            return cache[owner]

        api = f"https://api.github.com/repos/{owner}/{repo}"
        for token in (app_token, pat):
            if not token:
                continue
            req = urllib.request.Request(
                api,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            try:
                with safe_urlopen(req, timeout=5):  # nosec B310 — hardcoded https://api.github.com
                    cache[owner] = token
                    return token
            except Exception:
                continue

        fallback = app_token or pat
        cache[owner] = fallback
        return fallback

    def _inst(self):
        return self.job.instance_id

    def _tmp(self, suffix):
        """Return a /tmp path namespaced by instance name."""
        return f"{_TMP_PREFIX}-{self._inst().doodba_project_name}-{suffix}"

    def _backup_enabled(self):
        """Whether the backup container should be provisioned for this deploy.

        Thin delegator to :meth:`cloud.instance._backup_enabled` so that
        downstream modules (e.g. SaaS plan logic) only have to override
        the model side and every executor that needs the answer sees
        the same value.
        """
        return self._inst()._backup_enabled()

    def _backup_retention(self):
        """Effective retention string (e.g. '7D', '3M') for the backup job.

        Hook: inheriting executors can override to source the retention
        from their own logic (e.g. a per-instance policy) instead of
        the backend's default.
        """
        inst = self._inst()
        bb = inst.effective_backup_backend
        return (bb.backup_retention or "3M").strip() if bb else "3M"

    def _backup_env_content(self):
        """Generate .docker/backup.env content, or None if no backup backend."""
        if not self._backup_enabled():
            return None
        inst = self._inst()
        # sudo: executor is trusted; secret fields are restricted to managers.
        bb = inst.effective_backup_backend.sudo()
        lines = []
        if bb.s3_access_key_id:
            lines.append(f"AWS_ACCESS_KEY_ID={bb.s3_access_key_id}")
        if bb.s3_secret_access_key:
            lines.append(f"AWS_SECRET_ACCESS_KEY={bb.s3_secret_access_key}")
        if bb.s3_endpoint_url:
            lines.append(f"AWS_ENDPOINT_URL={bb.s3_endpoint_url}")
        lines.append(f"PASSPHRASE={bb.passphrase or ''}")
        # Override retention if different from copier default (3M)
        retention = self._backup_retention()
        if retention != "3M":
            lines.append(f"JOB_800_WHAT=dup --force remove-older-than {retention} $DST")
        return "\n".join(lines) + "\n"

    def _copier_template(self):
        """Return ``(template_url, vcs_ref)`` for the copier run.

        An empty ref keeps the historical behaviour — track the
        template's default branch — and ``deploy.sh`` logs whichever one
        is in effect, so the built tree is always traceable to a
        revision. Split out of ``get_commands`` so the command list can
        be built without a database, the way the executor's other
        environment reads already are.
        """
        settings = self.env["cloud.settings"].sudo()._get()
        return (
            settings.copier_template_url
            or "gh:Tecnativa/doodba-copier-template",
            settings.copier_template_ref or "",
        )

    def _build_answers(self):
        """Return a dict with all copier template answers.

        The render lives on ``cloud.instance._render_copier_answers``
        (single source of truth shared with the config-drift hash);
        this executor only dumps it into the remote answers file.
        """
        return self._inst()._render_copier_answers()

    def _repo_merge_ref(self, repo, branch):
        """Return the ref ``repos.yaml`` should merge for *repo*.

        A pinned row builds that exact commit; an unpinned one tracks
        its branch.

        A method rather than an inline expression so a subclass can
        answer from somewhere other than the row. That matters when the
        pin is written on a different transaction than the one
        rendering this file: Odoo runs its cursors REPEATABLE READ, so
        such a row is invisible here no matter how the cache is
        invalidated, and a subclass has to supply the value directly.

        Args:
            repo: The ``cloud.instance.repo`` row being rendered.
            branch: Its branch, already stripped and defaulted.

        Returns:
            str: A commit SHA or a branch name.
        """
        return repo.commit_sha or branch

    def _repos_yaml_content(self):
        """Build repos.yaml: odoo first, then the instance's git repos.

        For each repo, verifies which token (App or PAT) has access
        and injects the correct one into the URL.
        """
        inst = self._inst()
        data = {}
        app_token, pat = self._get_github_tokens()

        # odoo is always first — public, no token needed
        odoo_merge = inst.odoo_commit_sha or "$ODOO_VERSION"
        data["odoo"] = {
            "defaults": {"depth": "$DEPTH_DEFAULT"},
            "remotes": {"odoo": "https://github.com/odoo/odoo.git"},
            "target": "odoo $ODOO_VERSION",
            "merges": [f"odoo {odoo_merge}"],
        }

        token_cache = {}  # owner → token

        for repo in inst.repo_ids:
            raw_url = (repo.url or "").strip()
            alias = _repo_alias(raw_url)
            branch = (repo.branch or "main").strip()
            if not alias or not raw_url:
                continue
            token = self._get_token_for_repo(
                raw_url,
                app_token,
                pat,
                token_cache,
            )
            url = _github_authed_url(raw_url, token)
            merge_ref = self._repo_merge_ref(repo, branch)
            data[alias] = {
                "defaults": {"depth": "$DEPTH_DEFAULT"},
                "merges": [f"{alias} {merge_ref}"],
                "remotes": {alias: url},
                "target": f"{alias} {branch}",
            }

        return yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    async def _addons_yaml_content(self):
        """Build addons.yaml from the instance's repo addons config.

        When a repo has ``excludes`` set and ``addons`` is empty (*), we
        fetch the repo's full module list from GitHub (via
        ``asyncio.to_thread``) so we can generate an explicit include list
        that omits the excluded modules.  This avoids the
        ``AddonsConfigError: Addon X defined in several repos`` error that
        doodba raises when the same module name appears in two repos.
        """
        inst = self._inst()
        data = {}

        for repo in inst.repo_ids:
            alias = _repo_alias(repo.url)
            if not alias:
                continue

            addons_str = (repo.addons or "").strip()
            excludes_str = (repo.excludes or "").strip()

            if not excludes_str:
                # Fast path: no excludes — use the existing simple logic
                data[alias] = _parse_repo_addons(addons_str)
                continue

            if addons_str:
                # Explicit include list + excludes: just subtract
                incl = _parse_repo_addons(addons_str)
                data[alias] = _apply_excludes(incl, excludes_str)
            else:
                # addons = "*" with excludes: need the full module list
                modules = await asyncio.to_thread(
                    fetch_repo_addons,
                    self.job.env,
                    repo.url,
                    repo.branch or "main",
                )
                if modules is None:
                    _logger.warning(
                        "Could not fetch module list for %s — "
                        "excludes ignored, using all modules (*)",
                        repo.url,
                    )
                    data[alias] = ["*"]
                else:
                    data[alias] = _apply_excludes(modules, excludes_str)

        return (
            yaml.dump(
                data,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
            if data
            else ""
        )

    # Services present per environment. backup and smtp only exist in
    # production doodba deployments; including them in the override for
    # test/staging would cause a Docker Compose validation error.
    _TEST_SERVICES = ("odoo", "db")

    def _prod_services(self):
        """Return the services present in a production compose file.

        Thin delegator to :meth:`cloud.instance.expected_services` so
        that any extension that changes which services an instance
        actually runs (e.g. SaaS plans that disable ``backup``) is
        honoured uniformly across deploy, rebuild and the health
        probe.
        """
        return self._inst().expected_services()

    def _odoo_command(self):
        """Return the ``command`` the override gives the odoo service.

        The environment's own command plus ``--logfile``, so Odoo's log
        lands on the host instead of inside the container. Passing the
        flag here rather than in ``odoo.conf`` is deliberate: the panel
        runs one-shot containers (module installs, ``click-odoo-update``
        for the boot test) whose output has to keep reaching the job
        log, and ``docker compose run`` replaces the command — so those
        runs are untouched by construction, while a ``logfile`` in the
        conf would have swallowed them.

        :return: argv list for the compose ``command`` key
        """
        base = (
            ODOO_COMMAND_PROD
            if self._inst().environment == "production"
            else ODOO_COMMAND_TEST
        )
        return [*base, f"--logfile={ODOO_LOGFILE}"]

    def _log_archive_days(self):
        """Days of Odoo log the host keeps for this instance."""
        settings = self.env["cloud.settings"].sudo()._get()
        return settings.odoo_log_archive_days

    def _prepare_logs_step(self, d):
        """Return the get_commands step that readies ``logs/`` on the host.

        Must run before the stack starts: Docker creates a missing
        bind-mount source itself, as root, and Odoo (uid 1000) would
        then fail to write and fall back to stdout — the silent failure
        this whole feature exists to remove.

        :param str d: remote instance directory
        :return: a ``(label, command)`` tuple
        """
        return (
            "Prepare log directory",
            self.run_script("instance_logs.sh", [
                "install",
                d,
                self._inst().doodba_project_name,
                str(self._log_archive_days()),
            ]),
        )

    def _resource_override_content(self):
        """Generate docker-compose.override.yml: limits, label, logs.

        Only includes services that actually exist in the target
        environment's compose file to avoid Docker Compose errors.

        The ``odoo`` service additionally gets a ``command`` carrying
        ``--logfile`` and a bind mount of the instance's ``logs/``
        directory: Odoo's own log is archived per day on the host by
        logrotate, which is the copy that survives a rebuild. See
        :meth:`_odoo_command` for why the flag rides on the command.

        The ``smtp`` service gets ``ENABLE_UPDATE_CHECK=0``. It belongs
        in the override rather than in ``.docker/smtp.env`` or the
        compose files because ``copier update`` regenerates all three on
        every rebuild, which would drop it.

        Every service also carries a ``logging:`` block (``json-file``
        with the ``max-size``/``max-file`` from ``cloud.settings``).
        doodba's Odoo logs to stdout and the copier template sets no
        logging driver, so a container's log grows until the disk is
        full unless something limits it — and only hosts that ran
        ``host_hardening`` have a ``daemon.json`` doing so. Emitting the
        limit per service makes the rotation independent of how the
        host was set up; on hardened hosts it merely restates the
        daemon default. The values are read from settings at render
        time and are deliberately absent from the per-instance config
        snapshot: bumping the retention must not mark the fleet as
        drifted, it simply lands on each instance's next rebuild.

        Every service carries ``PROTECT_LABEL`` so the daily
        ``docker_prune`` (``docker system prune -af --filter
        "label!=…"``) never sweeps panel-managed resources. The
        invariant is "deployed by the panel, may legitimately sit
        stopped" (a warm pool spare, a Sablier-slept free instance, a
        manually stopped one): an unlabelled stopped container
        *matches* the ``label!=`` filter and is deleted. Anything the
        panel deploys is destroyed by ``delete_instance`` (``compose
        down``), never by the prune, so the label costs nothing.
        Because the labels are unconditional this method never returns
        ``None`` anymore — every consumer already tolerates both shapes.

        The project's ``default`` network is deliberately NOT labelled.
        Labelling it changes the network's definition, and ``docker
        compose`` answers that by recreating it: on an instance whose
        network predates the label that means tearing the live stack
        down mid-command, which failed outright ("has active endpoints"
        during a rebuild's boot test, "is not connected to the network"
        on a plain ``up``) and left tenants stopped.

        That used to be paired with the claim that protecting the
        containers already protects the network, because Docker keeps a
        network alive while any container — running or stopped — holds
        an endpoint on it. **That claim is false.** Stopping a container
        tears its sandbox down and releases the endpoint, so a stopped
        stack's network counts as unused and ``docker system prune``
        deletes it however well its containers are labelled. On
        2026-08-20 it deleted the networks of both ``ready`` warm
        spares: the containers survived, the post-prune check reported
        every stack intact, and neither stack could start again —
        a container that compose merely *starts* keeps the network id
        it was created with. The prune therefore no longer touches
        networks at all; see ``ansible/playbooks/host_maintenance.yml``.
        """
        inst = self._inst()
        allowed = (
            self._prod_services()
            if inst.environment == "production"
            else self._TEST_SERVICES
        )
        field_map = {
            "odoo": ("odoo_memory_limit", "odoo_cpus"),
            "db": ("db_memory_limit", "db_cpus"),
            "backup": ("backup_memory_limit", "backup_cpus"),
            "smtp": ("smtp_memory_limit", "smtp_cpus"),
        }
        services = {}
        for svc in allowed:
            mem_field, cpu_field = field_map[svc]
            mem = getattr(inst, mem_field, "") or ""
            cpus = getattr(inst, cpu_field, 0) or 0
            if mem or cpus:
                entry = {}
                if mem:
                    entry["mem_limit"] = mem
                if cpus:
                    entry["cpus"] = cpus
                services[svc] = entry
        key, value = PROTECT_LABEL.split("=", 1)
        settings = self.env["cloud.settings"].sudo()._get()
        for svc in allowed:
            entry = services.setdefault(svc, {})
            entry.setdefault("labels", {})[key] = value
            # A fresh mapping per service: PyYAML renders one dict
            # referenced from several places as an anchor plus aliases,
            # which compose reads fine but nobody wants to edit by hand.
            entry["logging"] = {
                "driver": "json-file",
                "options": {
                    "max-size": settings.container_log_max_size,
                    "max-file": str(settings.container_log_max_file),
                },
            }
        if "smtp" in allowed:
            # docker-mailserver runs an ``update-check`` service that asks
            # GitHub for the latest release and mails postmaster once per
            # container start. Which tag an instance runs is the panel's
            # call (``smtp_relay_version``), not the container's to
            # announce — and the announcement arrived at fleet scale:
            # copier renders the hostname as ``smtp.<relay domain>``, so
            # every instance relaying through the same domain reports
            # itself under one name, and a free tenant restarts on each
            # Sablier wake, turning "once per start" into dozens of
            # identical mails a day.
            services["smtp"]["environment"] = {"ENABLE_UPDATE_CHECK": "0"}
        if "odoo" in allowed:
            services["odoo"]["command"] = self._odoo_command()
            services["odoo"]["volumes"] = [
                f"./{LOGS_DIRNAME}:{ODOO_LOG_DIR}",
            ]
        data = {"services": services}
        return yaml.dump(
            data,
            default_flow_style=False,
            allow_unicode=True,
        )

    def _conf_content(self):
        """Return Odoo conf with the proxy settings the platform owns.

        Every instance we deploy is fronted by Traefik (the host's
        traefik service per ``data/traefik/``). Without proxy_mode,
        Odoo treats X-Forwarded-* headers naively, breaking URL
        building (web.base.url), OAuth callbacks, OIDC redirects, and
        per-IP rate-limit attribution. The platform enforces it here
        so a future copier-template change or a user-supplied
        ``odoo_conf`` value cannot silently disable it.
        """
        raw = self._inst().odoo_conf or (
            f"# Generated by IncubaCloud for instance {self._inst().name}\n[options]\n"
        )
        cp = configparser.ConfigParser()
        cp.read_string(raw)
        if not cp.has_section("options"):
            cp.add_section("options")
        cp.set("options", "proxy_mode", "True")
        # Which header states the visitor, and whose word to take for
        # it. Both or neither: a header believed from anywhere is one
        # any visitor can write. Cleared rather than left behind when
        # the host stops declaring one, so moving an instance to a host
        # reached directly does not leave it believing a header nobody
        # sets.
        host = self._inst().host_id
        header = host._effective_client_ip_header() if host else ""
        trusted = host._effective_trusted_proxy_ranges() if host else []
        if header and trusted:
            cp.set("options", real_ip.HEADER_OPTION, header)
            cp.set("options", real_ip.TRUSTED_OPTION, ", ".join(trusted))
        else:
            cp.remove_option("options", real_ip.HEADER_OPTION)
            cp.remove_option("options", real_ip.TRUSTED_OPTION)
        out = io.StringIO()
        cp.write(out)
        return out.getvalue()

    # ── AbstractSSHExecutor hooks ──────────────────────────────────────────

    async def _resync_repo_requirements(self):
        """Re-read each unpinned repo's ``requirements.txt`` before building.

        A repo line without a pinned commit is aggregated at the tip of
        its branch, so this job ships whatever code upstream published
        since the last build — including modules that need libraries the
        stored ``pip_dependencies`` never heard of. Reading the manifest
        here, in the same job that pulls the code, is what keeps the two
        in step; a line that ships a new dependency and a build that
        installs it become one event instead of two.

        Pinned repos are skipped: frozen code, frozen dependencies.

        Additive changes and upstream maintaining its own lines are
        applied and reported in the job log. A spec that contradicts the
        operator (or another repo) raises after filing the usual
        ``pip_conflict`` alert, which blocks the retry until a human
        picks a side. A failed fetch is non-fatal — the stored list is
        used, because a GitHub blip must not stop the fleet.
        """
        inst = self._inst()
        icp = self.env["ir.config_parameter"].sudo()
        if icp.get_param(_ICP_RESYNC, "1") != "1":
            return
        repos = [
            repo
            for repo in inst.repo_ids.sorted("sequence")
            if repo.url and repo.branch and not (repo.commit_sha or "").strip()
        ]
        if not repos:
            return

        self._sys("Re-syncing dependencies from repo requirements…")
        # Credentials are resolved here, on the main thread: the ORM is
        # not thread-safe and the fetches below run in worker threads.
        client = resolve_github_client(self.env)

        text = inst.pip_dependencies or ""
        sources = dict(inst.pip_dependency_sources or {})
        added, updated, conflicts = [], [], []
        for repo in repos:
            label = f"{_repo_alias(repo.url)}@{repo.branch}"
            content = await asyncio.to_thread(
                fetch_requirements_txt_with_client,
                client, repo.url, repo.branch,
            )
            if content is None:
                # No requirements.txt, or GitHub unreachable. Both are
                # indistinguishable from here and neither is worth
                # failing a deploy over.
                self._sys(
                    f"· {label}: no requirements.txt read — keeping the "
                    f"stored dependencies."
                )
                continue
            result = merge_pip_requirements(
                text, content,
                repo_url=repo.url, repo_branch=repo.branch,
                sources=sources,
            )
            text, sources = result["content"], result["sources"]
            added.extend(result["added"])
            updated.extend(result["updated"])
            conflicts.extend(result["conflicts"])
            if result["added"] or result["updated"] or result["adopted"]:
                self._sys(
                    f"· {label}: +{len(result['added'])} added, "
                    f"{len(result['updated'])} updated, "
                    f"{len(result['adopted'])} adopted."
                )
            for name in result["removed"]:
                self._sys(
                    f"· {label}: {name} is gone from upstream requirements "
                    f"— kept, dependencies are never auto-removed."
                )

        self._persist_resynced_requirements(inst, text, sources)
        for spec in added:
            self._sys(f"  + {spec}")
        for change in updated:
            self._sys(f"  ~ {change['name']}: {change['old']} → {change['new']}")

        if conflicts:
            names = ", ".join(c["name"] for c in conflicts[:5])
            if len(conflicts) > 5:
                names += f" (+{len(conflicts) - 5} more)"
            self._sys(
                f"✗ {len(conflicts)} dependency conflict(s) between the "
                f"repos and this instance's list: {names}"
            )
            self._sys(
                "Resolve them in Alerts (the stored spec wins unless you "
                "pick the repo's) and run this job again."
            )
            with self.job.env.registry.cursor() as cr:
                create_pip_conflict_alert(
                    self.job.env(cr=cr), conflicts, instance_id=inst.id,
                )
            raise RuntimeError(
                f"Pre-flight: {len(conflicts)} pip dependency conflict(s)"
            )
        if not (added or updated):
            self._sys("✓ Dependencies already in sync with the repos.")

    def _persist_resynced_requirements(self, inst, text, sources):
        """Store the merged dependency list on its own cursor.

        Committed independently of the job so the merged list (and any
        conflict markers) survive a later failure of this same job —
        otherwise the retry would re-derive them from scratch and the
        alert would point at a field that never changed.

        The job's own cache is invalidated afterwards so the upload step
        reads what was just written rather than the pre-merge value.

        :param inst: the instance being deployed
        :param text: merged ``pip_dependencies`` content
        :param sources: updated provenance map
        """
        vals = {}
        if text != (inst.pip_dependencies or ""):
            vals["pip_dependencies"] = text
            needed = resolve_apt_dependencies(text)
            missing = needed - set((inst.apt_dependencies or "").split())
            if missing:
                vals["apt_dependencies"] = (
                    (inst.apt_dependencies or "").rstrip()
                    + "\n" + "\n".join(sorted(missing))
                ).strip()
        if sources != (inst.pip_dependency_sources or {}):
            vals["pip_dependency_sources"] = sources
        if not vals:
            return
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            env["cloud.instance"].browse(inst.id).sudo().with_context(
                pip_provenance_managed=True,
            ).write(vals)
        inst.invalidate_recordset(
            ["pip_dependencies", "apt_dependencies", "pip_dependency_sources"],
        )

    async def _upload_copier_files(self, transport):
        """Upload all files needed by copier copy/update to the remote host."""
        await self._resync_repo_requirements()
        inst = self._inst()
        answers_yml = yaml.dump(
            self._build_answers(),
            default_flow_style=False,
            allow_unicode=True,
        )
        files = {
            self._tmp("answers.yml"): answers_yml,
            self._tmp("addons.yaml"): await self._addons_yaml_content(),
            self._tmp("repos.yaml"): self._repos_yaml_content(),
            self._tmp("odoo.conf"): self._conf_content(),
            self._tmp("pip.txt"): inst.pip_dependencies or "",
            self._tmp("apt.txt"): inst.apt_dependencies or "",
        }
        backup_env = self._backup_env_content()
        if backup_env is not None:
            files[self._tmp("backup.env")] = backup_env
        resource_override = self._resource_override_content()
        if resource_override is not None:
            files[self._tmp("override.yml")] = resource_override

        await transport.upload_text_files(files)

        # Stage incubacloud_connect in /tmp; get_commands moves it after copier.
        tmp_ic_parent = f"/tmp/.ic-modules-{inst.doodba_project_name}"
        # Clean up leftovers from previous failed attempts, then recreate.
        result = await transport.run(
            f"rm -rf {tmp_ic_parent} && mkdir -p {tmp_ic_parent}",
        )
        if result.exit_status != 0:
            raise RuntimeError(f"Failed to prepare staging directory: {result.stdout}")
        await transport.upload_dir(_IC_CONNECT_MODULE, tmp_ic_parent)

        self._sys("✓ Configuration files uploaded.")

    async def _preflight_addon_check(self):
        """Detect ALL addon conflicts before running gitaggregate."""
        inst = self._inst()
        if not inst or not inst.repo_ids:
            return
        self._sys("Checking for addon conflicts across repos…")
        conflicts = await detect_addon_conflicts(
            self.job.env,
            inst.repo_ids,
        )
        if not conflicts:
            self._sys("✓ No addon conflicts found.")
            return
        names = ", ".join(c["addon"] for c in conflicts[:5])
        if len(conflicts) > 5:
            names += f" (+{len(conflicts) - 5} more)"
        self._sys(f"✗ Found {len(conflicts)} addon conflict(s): {names}")
        self._sys("Resolve all conflicts before deploying.")
        self._create_preflight_addon_alert(conflicts)
        raise RuntimeError(f"Pre-flight: {len(conflicts)} addon conflict(s)")

    def _create_preflight_addon_alert(self, conflicts):
        """Create a single addon_conflict alert with ALL conflicts."""
        inst = self._inst()
        names = ", ".join(c["addon"] for c in conflicts[:3])
        if len(conflicts) > 3:
            names += f" (+{len(conflicts) - 3} more)"
        message = (
            f"Addon conflict: {names} defined in multiple"
            " repos — resolve all conflicts and redeploy"
        )
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            Alert = env["cloud.alert"]
            existing = Alert.search(
                [
                    ("instance_id", "=", inst.id),
                    ("code", "=", "addon_conflict"),
                    ("state", "=", "active"),
                ],
                limit=1,
            )
            vals = {
                "message": message,
                "conflict_data": conflicts,
                "job_id": self.job.id,
            }
            if existing:
                existing.write(vals)
            else:
                Alert.create(
                    {
                        "instance_id": inst.id,
                        "code": "addon_conflict",
                        "level": "critical",
                        **vals,
                    }
                )

    async def before_execute(self, transport):
        inst = self._inst()
        if not inst:
            raise ValueError("deploy_instance job has no instance_id")
        await self._preflight_addon_check()
        self._sys(f"Preparing deployment for '{inst.name}'...")
        await self._upload_copier_files(transport)

    def get_commands(self):
        inst = self._inst()
        name = inst.doodba_project_name
        d = self._inst_dir(inst)
        src = f"{d}/odoo/custom/src"
        confd = f"{d}/odoo/custom/conf.d"

        tmp_answers = self._tmp("answers.yml")
        tmp_addons = self._tmp("addons.yaml")
        tmp_repos = self._tmp("repos.yaml")
        tmp_conf = self._tmp("odoo.conf")
        tmp_pip = self._tmp("pip.txt")
        tmp_apt = self._tmp("apt.txt")

        # Copier creates docker-compose.yml as a symlink to devel.yaml.
        # Replace it with the correct target for the environment.
        compose_target = (
            "prod.yaml" if inst.environment == "production" else "test.yaml"
        )

        lang = (
            inst.odoo_initial_lang.code if inst.odoo_initial_lang else "en_US"
        ) or "en_US"

        has_smtp = bool(inst.smtp_relay_host)

        template_url, template_ref = self._copier_template()

        cmds = [
            # 0. Clean up any leftover directory from a previous failed deploy.
            (
                "Remove previous deploy if present",
                self.run_script("deploy.sh", ["teardown-previous", d]),
            ),
            # 1. Let copier create the full project structure first.
            (
                "Deploy with copier",
                self.run_script(
                    "deploy.sh",
                    [
                        "copier-deploy", d, tmp_answers,
                        template_url, template_ref,
                    ],
                ),
            ),
            # 2. Fix docker-compose.yml symlink: copier points to devel.yaml;
            #    use prod.yaml (production) or test.yaml (staging).
            #    Left inline: a trivial rm + ln, with the shell expanding ~.
            (
                "Fix docker-compose symlink",
                f"rm -f {d}/docker-compose.yml && "
                f"ln -s {compose_target} {d}/docker-compose.yml",
            ),
            # 2a. Set COMPOSE_PROJECT_NAME so container names are unique
            #     across projects on the same host.  Docker defaults to
            #     the dir basename which collides when multiple projects
            #     have an instance named "production".
            (
                "Set compose project name",
                f'echo "COMPOSE_PROJECT_NAME={name}" >> {d}/.env',
            ),
            # 2b. Ensure .docker/incubacloud.env exists with a Fernet key.
            (
                "Ensure incubacloud.env",
                self.run_script("deploy.sh", ["ensure-secret-key", d]),
            ),
            # 2c. Inject incubacloud.env into prod.yaml and test.yaml.
            (
                "Inject incubacloud.env in prod.yaml and test.yaml",
                self.run_script("deploy.sh", ["inject-secret-env", d]),
            ),
        ]

        # 2d. Strip the smtp service from prod.yaml when no SMTP relay is
        #     configured — copier renders an imageless block that breaks
        #     ``docker compose``.
        if not has_smtp and inst.environment == "production":
            cmds.append(
                (
                    "Strip smtp service (not configured)",
                    self.run_script(
                        "strip_compose_service.sh", [d, "smtp", "prod.yaml"],
                    ),
                )
            )

        # 2e. Strip the backup service when no backup backend is active
        #     (same imageless-block problem). copier emits it in prod.yaml;
        #     some templates also place shared defs in common.yaml.
        if not self._backup_enabled() and inst.environment == "production":
            cmds.append(
                (
                    "Strip backup service (not configured)",
                    self.run_script(
                        "strip_compose_service.sh",
                        [d, "backup", "prod.yaml", "common.yaml"],
                    ),
                )
            )

        # 2f. Cap the backup container hostname at 64 bytes.
        #     doodba renders "hostname: backup.<first_main_domain>" in
        #     common.yaml (inherited by prod.yaml via `extends`). A long
        #     production domain pushes it past the kernel limit
        #     (__NEW_UTS_LEN = 64) and the backup container dies on start
        #     with "sethostname: invalid argument".
        if self._backup_enabled() and inst.environment == "production":
            cmds.append(
                (
                    "Cap backup hostname",
                    self.run_script(
                        "deploy.sh", ["cap-backup-hostname", d, name],
                    ),
                )
            )

        cmds += [
            # 3. Overwrite backup.env with ours (adds AWS_ENDPOINT_URL if set;
            #    copier's version lacks it). No-op if no backup backend.
            (
                "Write backup.env",
                f"f={self._tmp('backup.env')};"
                f' [ -f "$f" ] &&'
                f' mv "$f" {d}/.docker/backup.env || true',
            ),
            # 3b. Write docker-compose.override.yml: resource limits,
            #     protect label and container log rotation.
            (
                "Write compose override",
                f"f={self._tmp('override.yml')};"
                f' [ -f "$f" ] &&'
                f' mv "$f" {d}/docker-compose.override.yml || true',
            ),
            # 4. Overwrite repos.yaml and addons.yaml in the copier tree
            (
                "Write addons.yaml",
                f"mv {tmp_addons} {src}/addons.yaml",
            ),
            (
                "Write repos.yaml",
                f"mv {tmp_repos} {src}/repos.yaml",
            ),
            # 5. Copy incubacloud_connect into the private src tree so Odoo
            #    can find and install it at init time.
            (
                "Install incubacloud_connect",
                f"mkdir -p {src}/private"
                f" && cp -r /tmp/.ic-modules-{name}/incubacloud_connect"
                f" {src}/private/"
                f" && rm -rf /tmp/.ic-modules-{name}",
            ),
            # 6. Create conf.d (copier may not) and drop the conf file
            (
                "Write Odoo conf",
                f"mkdir -p {confd} && mv {tmp_conf} {confd}/{name}.conf",
            ),
            # 7. Write pip.txt and apt.txt (extra dependencies)
            (
                "Write pip.txt",
                f"mkdir -p {d}/odoo/custom/dependencies && "
                f"mv {tmp_pip} {d}/odoo/custom/dependencies/pip.txt",
            ),
            (
                "Write apt.txt",
                f"mv {tmp_apt} {d}/odoo/custom/dependencies/apt.txt",
            ),
            # 8. Remove the answers file (others were moved above)
            (
                "Remove temp files",
                f"rm -f {tmp_answers}",
            ),
            # 9. Pull images first (may take a while; separated so the
            #    actual start step is always fast).
            #    Non-fatal: if a service uses a local build or the registry is
            #    unavailable, docker compose up will still use cached images.
            (
                "Pull images",
                f"cd {d} && docker compose pull --ignore-pull-failures || true",
            ),
            # 10. Start the database service first so it is ready for init.
            (
                "Start database",
                f"cd {d} && docker compose up -d db",
            ),
            # 11. Initialize the Odoo database.
            #     docker compose run --rm honours depends_on health checks,
            #     so it waits for the db to be healthy before running.
            (
                "Initialize database",
                f"cd {d} && docker compose run --rm odoo "
                f"odoo --stop-after-init -i base,incubacloud_connect --load-language {lang}",
                {"stop_on_failure": True},
            ),
            # 12. Store module checksums baseline so future rebuilds
            #     can detect which modules changed via click-odoo-update.
            (
                "Initialize module checksums",
                f"cd {d} && docker compose run --rm odoo"
                f" click-odoo-update --only-compute-hashes"
                f" --database {inst.postgres_dbname or 'prod'}",
            ),
            # 13. Set web.base.url and report.url before the stack starts so
            #     any post-init steps and Odoo itself see the correct public
            #     URL on first boot. ``base_url`` is sql-escaped as a
            #     defense-in-depth layer on top of the @api.constrains regex
            #     on cloud.instance.domain.hostname before it reaches the DO
            #     block inside the script.
            (
                "Set system parameters",
                self.run_script(
                    "deploy.sh",
                    [
                        "set-system-params", d,
                        inst.postgres_username or "odoo",
                        inst.postgres_dbname or "prod",
                        sql_escape_literal(self._base_url()),
                        "http://localhost:8069",
                    ],
                ),
            ),
            # 13. Capture service list for on_success.
            ("List services", f"cd {d} && docker compose config --services"),
            # 14. Ready ``logs/`` before anything starts: Docker would
            #     otherwise create the missing bind-mount source as root.
            self._prepare_logs_step(d),
            # 15. Bring the full stack up (odoo, proxy, …).
            (
                "Start instance",
                f"cd {d} && docker compose up -d",
            ),
        ]
        return cmds

    def parse_results(self, results):
        errors = []
        ignored = {"List services"}
        for label, data in results.items():
            exit_code = data.get("exit_status", 1)
            if exit_code != 0 and label not in ignored:
                errors.append(f"'{label}' exited with status {exit_code}")
        return errors

    def _detect_addon_conflicts(self):
        """Scan stderr chunks for AddonsConfigError and create/update an alert."""
        inst = self._inst()
        if not inst:
            return
        chunks = self.env["cloud.job.log.chunk"].search(
            [
                ("job_id", "=", self.job.id),
                ("source", "=", "stderr"),
                ("content", "ilike", "AddonsConfigError"),
            ]
        )
        conflicts = []
        for chunk in chunks:
            m = _ADDONS_CONFLICT_RE.search(chunk.content)
            if m:
                addon = m.group(1)
                repos = [r.strip().strip("'\"") for r in m.group(2).split(",")]
                conflicts.append({"addon": addon, "repos": repos})
        if not conflicts:
            return
        names = ", ".join(c["addon"] for c in conflicts[:3])
        if len(conflicts) > 3:
            names += f" (+{len(conflicts) - 3} more)"
        message = (
            f"Addon conflict: {names} defined in multiple repos"
            " — add excludes to the offending repo and redeploy"
        )
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            Alert = env["cloud.alert"]
            existing = Alert.search(
                [
                    ("instance_id", "=", inst.id),
                    ("code", "=", "addon_conflict"),
                    ("state", "=", "active"),
                ],
                limit=1,
            )
            if existing:
                existing.write(
                    {
                        "message": message,
                        "conflict_data": conflicts,
                        "job_id": self.job.id,
                    }
                )
            else:
                Alert.create(
                    {
                        "instance_id": inst.id,
                        "code": "addon_conflict",
                        "level": "critical",
                        "message": message,
                        "conflict_data": conflicts,
                        "job_id": self.job.id,
                    }
                )

    def _dismiss_addon_conflict_alerts(self):
        """Dismiss any active addon_conflict alerts for this instance."""
        inst = self._inst()
        if not inst:
            return
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            env["cloud.alert"].search(
                [
                    ("instance_id", "=", inst.id),
                    ("code", "=", "addon_conflict"),
                    ("state", "=", "active"),
                ]
            ).write({"state": "dismissed"})

    def _dismiss_pip_conflict_alerts(self):
        inst = self._inst()
        if not inst:
            return
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            env["cloud.alert"].search(
                [
                    ("instance_id", "=", inst.id),
                    ("code", "=", "pip_conflict"),
                    ("state", "=", "active"),
                ]
            ).write({"state": "dismissed"})

    async def on_success(self, results):
        self._sys("✓ Instance deployed successfully.")
        self._dismiss_pip_conflict_alerts()
        self._dismiss_addon_conflict_alerts()
        inst = self._inst()
        services_out = results.get("List services", {}).get("stdout") or ""
        services = [s.strip() for s in services_out.splitlines() if s.strip()]
        inst.write(
            {
                "status": "ok",
                "running": True,
                "compose_services": ",".join(services) if services else "odoo,db",
                "last_rebuild_fingerprint": inst.rebuild_fingerprint,
                # Config-drift anchor: this deploy just shipped exactly
                # the current snapshot, so the saved config is applied.
                **inst._applied_config_vals(),
            }
        )
        inst._transition("deployed")
        # The host's metric label map is a snapshot of its instance list;
        # without this the new instance's containers report unattributed.
        inst.host_id.refresh_observability_labels(reason="deploy")

    def _detect_pip_conflicts(self):
        """If pip_dependencies has conflict markers, create/update a pip_conflict alert."""
        inst = self._inst()
        if not inst:
            return
        conflicts = detect_pip_conflicts(inst.pip_dependencies)
        if not conflicts:
            return
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            create_pip_conflict_alert(env, conflicts, instance_id=inst.id)

    async def on_failure(self, results, errors):
        for err in errors:
            self._sys(f"✗ {err}")
        self._detect_pip_conflicts()
        self._detect_addon_conflicts()
        inst = self._inst()
        inst.write({"status": "error"})
        # Back to 'draft': nothing usable was left on the host, and
        # 'status' carries why. Re-running deploy() is then legal again.
        if inst.state == "deploying":
            inst._transition("draft")
