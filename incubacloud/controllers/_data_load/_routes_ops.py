"""Operational endpoints: deploy/rebuild, backups, delete project/instance,
browse/import host directory, container log streaming.

Mixed into ``CloudDataLoadController`` in ``data_load.py``.
"""

import logging
import re
import shlex
from contextlib import suppress
from operator import itemgetter

import asyncssh
import yaml

from odoo import _, http
from odoo.exceptions import UserError
from odoo.http import request

from .._rate_limit import Rule, rate_gate_json
from .._safe_error import safe_error_response
from ..async_utils import run_async
from ._helpers import (
    _is_safe_remote_path,
    _job_response,
    _quote_remote_path,
    is_safe_log_archive,
    log_archive_list_command,
    log_archive_search_command,
    odoo_log_live_command,
    odoo_log_read_command,
)

_logger = logging.getLogger(__name__)


class OpsMixin:
    """Deploy, rebuild, backups, delete, host import, container logs."""

    # ────────────────────────────────────────────────────────────────────────

    @http.route(["/cloud/deploy_instance"], type="jsonrpc", auth="user")
    def cloud_deploy_instance(self, instance_id):
        self._sec()._check_can_deploy()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        try:
            job_id = instance.deploy()
        except Exception as exc:
            return safe_error_response(exc, _("Failed to deploy instance"))
        return _job_response(request.env, job_id)

    @http.route(["/cloud/rebuild_instance"], type="jsonrpc", auth="user")
    def cloud_rebuild_instance(self, instance_id):
        self._sec()._check_can_deploy()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if not instance.host_id:
            return {"ok": False, "error": _("Instance has no host configured")}
        try:
            job_id = request.env["cloud.job"].enqueue(
                instance.host_id.id,
                instance_id,
                "rebuild_instance",
            )
        except Exception as exc:
            return safe_error_response(exc, _("Failed to rebuild instance"))
        return _job_response(request.env, job_id)

    # ── Backup management ──────────────────────────────────────────────────

    def _serialize_backups(self, instance_id, offset=0, limit=None):
        """Return a page of backup records for an instance as a dict.

        ``total`` is the unpaginated count so the SPA can drive a paginator.
        """
        Backup = request.env["cloud.instance.backup"].sudo()
        domain = [("instance_id", "=", instance_id)]
        total = Backup.search_count(domain)
        backups = Backup.search(
            domain,
            order="backup_time desc",
            offset=offset,
            limit=limit,
        )
        return {
            "total": total,
            "backups": [
                {
                    "id": b.id,
                    "type": b.backup_type,
                    "time": b.backup_time.isoformat() if b.backup_time else "",
                    "volumes": b.volumes,
                    "is_primary": b.is_primary,
                    "chain_start": (
                        b.chain_start.isoformat() if b.chain_start else None
                    ),
                    "attachment_id": b.attachment_id.id if b.attachment_id else None,
                    # ``size`` is now stored on the row uniformly:
                    # non-prod populates it from the attachment at create
                    # time, prod populates it from a boto3 listing in the
                    # ``backup_list`` job. Falls back to attachment.file_size
                    # for legacy rows whose attachment has not been pruned.
                    "size": (
                        b.size or (b.attachment_id.file_size if b.attachment_id else 0)
                    ),
                    "with_filestore": b.with_filestore,
                    "contents": self._backup_contents_label(b),
                }
                for b in backups
            ],
        }

    @staticmethod
    def _backup_contents_label(backup):
        """Human label of what's inside the ZIP/chain.

        Non-prod attachment + ``with_filestore`` → ``"DB + filestore"``
        Non-prod attachment + no filestore       → ``"DB only"``
        Prod (no attachment)                     → ``"S3 chain"``
        """
        if backup.attachment_id:
            return _("DB + filestore") if backup.with_filestore else _("DB only")
        return _("S3 chain")

    @http.route(["/cloud/list_backups"], type="jsonrpc", auth="user")
    def cloud_list_backups(self, instance_id, refresh=False, offset=0, limit=None):
        """List backups from cloud.instance.backup records.

        refresh=True enqueues a backup_list job (production: SSH scan,
        non-production: no-op that reports existing records).
        """
        self._sec()._check_can_manage_backups()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}

        if refresh:
            if not instance.host_id:
                return {"ok": False, "error": _("No host configured")}
            job_id = instance.list_backups()
            return {"ok": True, "job_id": job_id}

        return {
            "ok": True,
            "state": "done",
            "result": self._serialize_backups(instance_id, offset=offset, limit=limit),
        }

    @http.route(["/cloud/get_backup_result"], type="jsonrpc", auth="user")
    def cloud_get_backup_result(self, job_id, offset=0, limit=None):
        """Poll a backup_list job; return persisted records when done."""
        self._sec()._check_can_manage_backups()
        job = request.env["cloud.job"].browse(job_id)
        if not job.exists():
            return {"ok": False, "error": _("Job not found")}
        state = "blocked" if job.blocked_alert_id else job.state
        if state in ("pending", "enqueued", "started", "wait_dependencies"):
            return {"ok": True, "state": state, "result": None}
        if state == "done":
            inst_id = job.instance_id.id if job.instance_id else None
            return {
                "ok": True,
                "state": "done",
                "result": self._serialize_backups(inst_id, offset=offset, limit=limit)
                if inst_id
                else {},
            }
        return {
            "ok": False,
            "state": state,
            "error": job._get_last_system_message() or _("Job failed."),
        }

    @http.route(["/cloud/create_backup"], type="jsonrpc", auth="user")
    def cloud_create_backup(self, instance_id, with_filestore=True):
        """Enqueue a backup_create job.

        ``with_filestore`` (bool) is meaningful for non-production
        instances: it flips ``click-odoo-backupdb --filestore`` /
        ``--no-filestore``. Production ignores it (duplicity controls
        shape). Coerced to bool at the boundary so any truthy JSON-RPC
        input (including strings) collapses safely before reaching
        the executor.
        """
        self._sec()._check_can_manage_backups()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if not instance.host_id:
            return {"ok": False, "error": _("Instance has no host configured")}
        if not instance.deployed:
            return {"ok": False, "error": _("Instance is not deployed")}
        job_id = instance.create_backup(with_filestore=bool(with_filestore))
        return {"ok": True, "job_id": job_id}

    @http.route(["/cloud/clone_to_staging"], type="jsonrpc", auth="user")
    def cloud_clone_to_staging(self, instance_id, staging_name):
        self._sec()._check_can_clone_to_staging()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if instance.environment != "production":
            return {"ok": False, "error": _("Only production instances")}
        if not instance.deployed:
            return {"ok": False, "error": _("Instance not deployed")}
        if not staging_name or not staging_name.strip():
            return {"ok": False, "error": _("Name is required")}
        result = instance.clone_to_staging(staging_name.strip())
        return {"ok": True, **result}

    @http.route(["/cloud/refresh_from_production"], type="jsonrpc", auth="user")
    def cloud_refresh_from_production(
        self, instance_id, source_instance_id, source="backup",
        neutralize=True,
    ):
        """Replace a staging's data with a copy of its production's.

        Gated on the same capability as cloning: moving production data
        into a staging instance.
        """
        self._sec()._check_can_clone_to_staging()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        try:
            return instance.refresh_from_production(
                source_instance_id,
                source=source,
                neutralize=bool(neutralize),
            )
        except UserError as exc:
            return {"ok": False, "error": str(exc)}


    @http.route(["/cloud/instance/access_log"], type="jsonrpc", auth="user")
    def cloud_instance_access_log(self, instance_id, tail=None):
        """Return this instance's recent requests from the proxy log.

        The question this answers is "who is hitting this instance right
        now, with what, and how is it responding" — which the metrics
        cannot answer, because they carry neither client IP nor path.

        Read live over SSH and not stored: these lines contain the IP
        addresses of somebody else's end users, so the fewer copies exist
        the better. Gated on the same role as the metrics view.
        """
        self._sec()._check_can_view_metrics()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        try:
            host = instance._require_access_log_host()
            command = instance._access_log_command(tail=tail)
        except UserError as exc:
            return {"ok": False, "error": str(exc)}
        try:
            stdout, stderr = self._ssh_run(host, command)
        except Exception as exc:  # noqa: BLE001 — surfaced, not swallowed
            _logger.warning(
                "[access-log] could not read the proxy log on host %s: %s",
                host.name, exc,
            )
            return safe_error_response(exc, _("Could not read the proxy log"))
        rows = instance._parse_access_log(stdout or stderr or "")
        return {
            "ok": True,
            "entries": rows,
            "summary": instance._access_log_summary(rows),
        }

    @http.route(["/cloud/move_instance"], type="jsonrpc", auth="user")
    def cloud_move_instance(self, instance_id, target_host_id):
        """Move a deployed instance to another host (manager-only)."""
        self._sec()._check_can_manage_hosts()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        target = request.env["cloud.host"].browse(target_host_id)
        if not target.exists():
            return {"ok": False, "error": _("Target host not found")}
        try:
            return instance.move_to_host(target)
        except UserError as exc:
            return {"ok": False, "error": str(exc)}

    @http.route(["/cloud/rollback_move"], type="jsonrpc", auth="user")
    def cloud_rollback_move(self, instance_id):
        """Roll back a move that failed before cutover (manager-only)."""
        self._sec()._check_can_manage_hosts()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        try:
            return instance.rollback_move()
        except UserError as exc:
            return {"ok": False, "error": str(exc)}

    @http.route(["/cloud/download_backup"], type="jsonrpc", auth="user")
    def cloud_download_backup(self, instance_id, time, download_type="dump"):
        """Download a backup. Prod: enqueue job. Non-prod: return attachment URL."""
        self._sec()._check_can_manage_backups()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if not instance.host_id:
            return {"ok": False, "error": _("Instance has no host configured")}
        job_id = instance.download_backup(
            {
                "time": time,
                "download_type": download_type,
            }
        )
        return {"ok": True, "job_id": job_id}

    @http.route(
        ["/cloud/download_backup_neutralized"],
        type="jsonrpc",
        auth="user",
    )
    def cloud_download_backup_neutralized(
        self,
        instance_id,
        time="live",
        with_filestore=False,
    ):
        """Download a neutralized backup.

        Prod: ``time`` is a duplicity timestamp (or 'latest') — the S3
        backup is restored into a throwaway DB that is neutralized and
        re-dumped.

        Non-prod: ``time='live'`` — the current DB is dumped on the fly,
        neutralized into a throwaway DB and re-dumped.
        """
        self._sec()._check_can_manage_backups()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if not instance.host_id:
            return {"ok": False, "error": _("Instance has no host configured")}
        if not instance.deployed:
            return {"ok": False, "error": _("Instance is not deployed")}
        job_id = instance.download_backup_neutralized(
            {
                "time": time,
                "with_filestore": bool(with_filestore),
            }
        )
        return {"ok": True, "job_id": job_id}

    @http.route(["/cloud/restore_backup"], type="jsonrpc", auth="user")
    def cloud_restore_backup(self, instance_id, time):
        """Restore a production instance from a duplicity backup."""
        self._sec()._check_can_manage_backups()
        instance = request.env["cloud.instance"].browse(instance_id)
        if not instance.exists():
            return {"ok": False, "error": _("Instance not found")}
        if instance.environment != "production":
            return {
                "ok": False,
                "error": _("Backup restore only supported for production."),
            }
        if not instance.host_id:
            return {"ok": False, "error": _("Instance has no host configured")}
        job_id = instance.restore_backup({"time": time})
        return {"ok": True, "job_id": job_id}

    @http.route(["/cloud/delete_project"], type="jsonrpc", auth="user")
    def cloud_delete_project(self, project_id):
        self._sec()._check_can_delete_project()
        project = request.env["cloud.project"].browse(project_id)
        if not project.exists():
            return {"ok": False, "error": _("Project not found")}
        count = len(project.instance_ids)
        if count:
            return {
                "ok": False,
                "error": _(
                    "This project has %(count)s instance(s). "
                    "Delete all instances before deleting the project."
                )
                % {"count": count},
            }
        project.unlink()
        return {"ok": True}

    @http.route(["/cloud/delete_instance"], type="jsonrpc", auth="user")
    def cloud_delete_instance(self, instance_id):
        # The role floor is checked BEFORE ``exists()`` on purpose.
        # ``exists()`` runs raw SQL — no ACL, no record rule — so
        # answering "Instance not found" to a caller who may not delete
        # anything turns this route into an id -> exists oracle over
        # every instance on the platform, reachable by any authenticated
        # user including a portal customer. Every sibling delete route
        # gates first; this one did not.
        #
        # ``_check_can_delete_instance`` still runs below and is the one
        # that decides: it needs the record to tell production (manager)
        # from the rest (consultant), so only the floor of that decision
        # can be checked this early.
        self._sec()._check_cloud_group("group_cloud_consultant")
        inst = request.env["cloud.instance"].browse(instance_id)
        if not inst.exists():
            return {"ok": False, "error": _("Instance not found")}
        self._sec()._check_can_delete_instance(inst)
        running_job = request.env["cloud.job"].search(
            [
                ("instance_id", "=", inst.id),
                ("state", "in", ("started", "pending", "enqueued")),
            ],
            limit=1,
        )
        if running_job:
            return {
                "ok": False,
                "error": _(
                    "Cannot delete: a job is running (%s). "
                    "Wait for it to complete or cancel it first."
                )
                % running_job.name,
            }
        inst.unlink()
        return {"ok": True}

    # ── Host instance import (file browser + import) ─────────────────────────

    def _ssh_run(self, host, command):
        """Run a single SSH command on a host synchronously."""

        async def _run():
            async with asyncssh.connect(
                **host.ssh_connect_kwargs(),
            ) as conn:
                result = await conn.run(command, check=False)
                return result.stdout or "", result.stderr or ""

        return run_async(_run())

    def _ssh_run_multi(self, host, commands):
        """Run multiple SSH commands on a host in one connection."""

        async def _run():
            results = []
            async with asyncssh.connect(
                **host.ssh_connect_kwargs(),
            ) as conn:
                for cmd in commands:
                    result = await conn.run(cmd, check=False)
                    results.append(
                        (result.stdout or "", result.stderr or ""),
                    )
            return results

        return run_async(_run())

    @http.route(["/cloud/browse_host_dir"], type="jsonrpc", auth="user")
    def cloud_browse_host_dir(self, host_id, path="~"):
        """Browse directories on a remote host via SSH.

        Returns directory listing with doodba instance detection.
        """
        self._sec()._check_can_manage_hosts()
        host = request.env["cloud.host"].browse(host_id)
        if not host.exists():
            return {"ok": False, "error": _("Host not found")}

        # Reject any path that could break out of the intended 'cd <path>'
        # call. Defense-in-depth: we also shlex-quote below, but rejecting
        # bad input early makes the attack surface trivially auditable.
        if not _is_safe_remote_path(path):
            return {
                "ok": False,
                "error": _(
                    "Invalid path. Use letters, digits, dots, hyphens and "
                    "underscores in each segment. Shell metacharacters, "
                    "spaces and '..' are not allowed."
                ),
            }

        # Resolve ~ and get listing
        try:
            stdout, _stderr = self._ssh_run(
                host,
                (
                    f"cd {_quote_remote_path(path)} 2>/dev/null"
                    f' && pwd && echo "---" && ls -1pA 2>/dev/null'
                ),
            )
        except Exception:
            _logger.exception("SSH browse failed for host %s", host_id)
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }

        lines = stdout.strip().splitlines()
        if not lines or "---" not in lines:
            return {"ok": False, "error": _("Could not list directory")}

        sep_idx = lines.index("---")
        current_path = lines[0].strip()
        entries_raw = lines[sep_idx + 1 :]

        # Identify directories (ls -p appends / to dirs)
        dirs = []
        for entry in entries_raw:
            entry = entry.strip()
            if entry.endswith("/"):
                name = entry.rstrip("/")
                if name not in (".", ".."):
                    dirs.append(name)

        # Check which dirs are doodba instances
        # (must have BOTH .copier-answers.yml AND docker-compose.yml)
        # current_path comes from `pwd` output (already resolved, no ~)
        # and d comes from `ls -1pA` output. We still shlex-quote both as
        # defense-in-depth against exotic filenames on the remote host.
        if dirs:
            cp_q = shlex.quote(current_path)
            checks = " ".join(
                f"([ -f {cp_q}/{shlex.quote(d)}/.copier-answers.yml ] "
                f"&& [ -f {cp_q}/{shlex.quote(d)}/docker-compose.yml ] "
                f"&& echo DOODBA:{shlex.quote(d)}) || true"
                for d in dirs[:50]
            )
            try:
                check_stdout, _stderr = self._ssh_run(host, checks)
            except Exception:
                check_stdout = ""
            doodba_dirs = set()
            for line in check_stdout.splitlines():
                if line.startswith("DOODBA:"):
                    doodba_dirs.add(line[7:].strip())
        else:
            doodba_dirs = set()

        # Check if current directory is a doodba instance
        is_current_doodba = False
        copier_info = {}
        with suppress(Exception):
            cp_q = shlex.quote(current_path)
            stdout_check, _stderr = self._ssh_run(
                host,
                (
                    f"[ -f {cp_q}/.copier-answers.yml ] && "
                    f"[ -f {cp_q}/docker-compose.yml ] && "
                    f'cat {cp_q}/.copier-answers.yml || echo ""'
                ),
            )
            if stdout_check.strip() and "odoo_version" in stdout_check:
                is_current_doodba = True
                data = yaml.safe_load(stdout_check) or {}
                copier_info = {
                    "project_name": data.get("project_name", ""),
                    "odoo_version": str(data.get("odoo_version", "")),
                }

        # Check already imported instances
        imported_paths = set(
            request.env["cloud.instance"]
            .search(
                [
                    ("host_id", "=", host_id),
                    ("custom_remote_dir", "!=", False),
                ]
            )
            .mapped("custom_remote_dir")
        )

        parent_path = "/".join(current_path.rstrip("/").split("/")[:-1]) or "/"

        entries = []
        for d in sorted(dirs):
            full_path = f"{current_path}/{d}"
            entries.append(
                {
                    "name": d,
                    "is_dir": True,
                    "is_doodba": d in doodba_dirs,
                    "already_imported": full_path in imported_paths,
                }
            )

        return {
            "ok": True,
            "current_path": current_path,
            "parent_path": parent_path,
            "is_doodba": is_current_doodba,
            "copier_info": copier_info,
            "already_imported": current_path in imported_paths,
            "entries": entries,
        }

    @http.route(["/cloud/import_host_instance"], type="jsonrpc", auth="user")
    def cloud_import_host_instance(self, host_id, path):
        """Import a running doodba instance from a host directory.

        Reads all config files via SSH, creates project + instance.
        """
        # Manager-gated like browse_host_dir: importing reads the host's
        # ``.docker/*.env`` secrets over SSH and materialises them as
        # records, so it is a host-level operation, not a plain instance
        # create. (Today the developer-only field ACLs on the host
        # credentials already block a lower role, but the gate must match
        # the sensitivity in its own right.)
        self._sec()._check_can_manage_hosts()
        host = request.env["cloud.host"].browse(host_id)
        if not host.exists():
            return {"ok": False, "error": _("Host not found")}

        if not _is_safe_remote_path(path):
            return {
                "ok": False,
                "error": _(
                    "Invalid path. Use letters, digits, dots, hyphens and "
                    "underscores in each segment. Shell metacharacters, "
                    "spaces and '..' are not allowed."
                ),
            }

        # Check not already imported
        existing = request.env["cloud.instance"].search(
            [
                ("host_id", "=", host_id),
                ("custom_remote_dir", "=", path),
            ],
            limit=1,
        )
        if existing:
            return {
                "ok": False,
                "error": _("This instance is already imported."),
            }

        # All shell interpolations of `path` go through _quote_remote_path,
        # which shlex-quotes the value (and preserves ~/ home expansion).
        # Combined with the _is_safe_remote_path check above this is a
        # double defense against command injection.
        qp = _quote_remote_path(path)

        # Read all config files in one SSH connection
        files_to_read = [
            f"{qp}/.copier-answers.yml",
            f"{qp}/odoo/custom/src/repos.yaml",
            f"{qp}/odoo/custom/src/addons.yaml",
            f"{qp}/odoo/custom/dependencies/pip.txt",
            f"{qp}/odoo/custom/dependencies/apt.txt",
            f"{qp}/.docker/odoo.env",
            f"{qp}/.docker/db-access.env",
            f"{qp}/.docker/smtp.env",
            f"{qp}/.docker/backup.env",
            f"{qp}/docker-compose.override.yml",
        ]
        # Read all files + check symlink + docker compose ps
        commands = [f'cat {f} 2>/dev/null || echo ""' for f in files_to_read] + [
            # conf.d: concatenate all .conf files
            f'cat {qp}/odoo/custom/conf.d/*.conf 2>/dev/null || echo ""',
            # docker-compose.yml symlink target
            f'readlink -f {qp}/docker-compose.yml 2>/dev/null || echo ""',
            # Container status
            f"cd {qp} && docker compose ps --format "
            f"'{{{{.Service}}}}\\t{{{{.State}}}}' 2>/dev/null || echo ''",
        ]

        try:
            results = self._ssh_run_multi(host, commands)
        except Exception:
            _logger.exception(
                "SSH import failed for host %s path %s",
                host_id,
                path,
            )
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }

        # Unpack results
        (
            copier_raw,
            repos_raw,
            addons_raw,
            pip_raw,
            apt_raw,
            odoo_env_raw,
            db_env_raw,
            smtp_env_raw,
            backup_env_raw,
            override_raw,
        ) = [r[0] for r in results[:10]]
        conf_raw = results[10][0]
        compose_link = results[11][0].strip()
        compose_ps = results[12][0].strip()

        # Parse .copier-answers.yml
        copier = {}
        if copier_raw.strip():
            with suppress(Exception):
                data = yaml.safe_load(copier_raw) or {}
                domains = []
                for d in data.get("domains_prod", []) or []:
                    if isinstance(d, dict):
                        for h in d.get("hosts", []):
                            domains.append(
                                {
                                    "hostname": h,
                                    "redirect_to": d.get("redirect_to", ""),
                                }
                            )
                ov = data.get("odoo_version", "")
                copier = {
                    "odoo_version": f"{float(ov):.1f}" if ov else "",
                    "project_author": data.get("project_author", ""),
                    "project_license": data.get("project_license", ""),
                    "project_name": data.get("project_name", ""),
                    "postgres_version": str(
                        data.get("postgres_version", ""),
                    ),
                    "postgres_dbname": data.get("postgres_dbname", "prod"),
                    "postgres_username": data.get(
                        "postgres_username",
                        "odoo",
                    ),
                    "odoo_proxy": data.get("odoo_proxy", "traefik"),
                    "smtp_relay_host": data.get("smtp_relay_host", ""),
                    "smtp_relay_port": data.get("smtp_relay_port", 587),
                    "smtp_relay_user": data.get("smtp_relay_user", ""),
                    "domains": domains,
                    # Backup fields
                    "backup_dst": data.get("backup_dst", ""),
                    "backup_email_from": data.get(
                        "backup_email_from",
                        "",
                    ),
                    "backup_email_to": data.get("backup_email_to", ""),
                    "backup_image_version": data.get(
                        "backup_image_version",
                        "latest",
                    ),
                    "backup_tz": data.get("backup_tz", "UTC"),
                    "backup_deletion": data.get(
                        "backup_deletion",
                        False,
                    ),
                    "backup_smtp_report_success": data.get(
                        "backup_smtp_report_success",
                        True,
                    ),
                }

        # Parse .env files for secrets
        def _parse_env(content):
            env = {}
            for line in (content or "").splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
            return env

        odoo_env = _parse_env(odoo_env_raw)
        db_env = _parse_env(db_env_raw)
        smtp_env = _parse_env(smtp_env_raw)
        backup_env = _parse_env(backup_env_raw)

        # Parse repos.yaml + addons.yaml (reuse helpers from import_project)
        _SSH_RE = re.compile(r"^git@[^:]+:(.+?)(?:\.git)?$")

        def _ssh_to_https(u):
            u = (u or "").strip()
            m = _SSH_RE.match(u)
            if m:
                return f"https://github.com/{m.group(1)}.git"
            return u

        odoo_version = copier.get("odoo_version", "")
        repos_data = []
        if repos_raw.strip():
            try:
                repos_yaml = yaml.safe_load(repos_raw) or {}
                addons_yaml = yaml.safe_load(addons_raw) if addons_raw.strip() else {}
                addons_map = {}
                for alias, addons in (addons_yaml or {}).items():
                    if isinstance(addons, list):
                        addons_map[alias] = (
                            "" if "*" in addons else ",".join(str(a) for a in addons)
                        )
                    elif addons == "*":
                        addons_map[alias] = ""
                    else:
                        addons_map[alias] = str(addons) if addons else ""

                for alias, cfg in repos_yaml.items():
                    if alias in ("./odoo", "odoo"):
                        continue
                    if not isinstance(cfg, dict):
                        continue
                    remotes = cfg.get("remotes", {})
                    repo_url = next(iter(remotes.values()), "") if remotes else ""
                    repo_url = _ssh_to_https(repo_url)
                    target = cfg.get("target", "")
                    branch_val = ""
                    if target:
                        parts = target.split()
                        branch_val = parts[-1] if len(parts) >= 2 else parts[0]
                    if not branch_val:
                        merges = cfg.get("merges", [])
                        if merges and isinstance(merges[0], str):
                            parts = merges[0].split()
                            branch_val = parts[-1] if len(parts) >= 2 else parts[0]
                    if "$ODOO_VERSION" in branch_val and odoo_version:
                        branch_val = branch_val.replace(
                            "$ODOO_VERSION",
                            odoo_version,
                        )
                    repos_data.append(
                        {
                            "url": repo_url,
                            "branch": branch_val or "main",
                            "addons": addons_map.get(alias, ""),
                        }
                    )
            except Exception:
                _logger.exception("Failed to parse repos.yaml")

        # Parse docker-compose.override.yml for resource limits
        resource_limits = {}
        if override_raw.strip():
            with suppress(Exception):
                override = yaml.safe_load(override_raw) or {}
                services = override.get("services", {})
                for svc, key in (
                    ("odoo", "odoo"),
                    ("db", "db"),
                    ("backup", "backup"),
                    ("smtp", "smtp"),
                ):
                    svc_cfg = services.get(svc, {})
                    if svc_cfg.get("mem_limit"):
                        resource_limits[f"{key}_memory_limit"] = svc_cfg["mem_limit"]
                    if svc_cfg.get("cpus"):
                        resource_limits[f"{key}_cpus"] = float(
                            svc_cfg["cpus"],
                        )

        # Determine environment from symlink
        environment = "production"
        if compose_link and "test.yaml" in compose_link:
            environment = "staging"

        # Determine running status
        is_running = False
        if compose_ps:
            for line in compose_ps.splitlines():
                if "odoo" in line.lower() and "running" in line.lower():
                    is_running = True
                    break

        # ── Create project (or reuse existing) ────────────────────────
        project_name = copier.get("project_name") or path.rstrip("/").split("/")[-1]
        project = request.env["cloud.project"].search(
            [
                ("name", "=", project_name),
            ],
            limit=1,
        )
        if not project:
            proj_vals = {"name": project_name}
            if odoo_version:
                proj_vals["odoo_version"] = odoo_version
            if copier.get("project_author"):
                proj_vals["project_author"] = copier["project_author"]
            if copier.get("project_license"):
                proj_vals["project_license"] = copier["project_license"]
            if pip_raw.strip():
                proj_vals["pip_dependencies"] = pip_raw.strip()
            if apt_raw.strip():
                proj_vals["apt_dependencies"] = apt_raw.strip()
            project = request.env["cloud.project"].create(proj_vals)

            # Create project repos
            Repo = request.env["cloud.project.repo"].with_context(
                skip_apply_requirements=True,
            )
            for seq, r in enumerate(repos_data, start=10):
                if r.get("url"):
                    Repo.create(
                        {
                            "project_id": project.id,
                            "sequence": seq,
                            "url": r["url"],
                            "branch": r.get("branch", "main"),
                            "addons": r.get("addons", ""),
                        }
                    )

        # ── Create instance ───────────────────────────────────────────
        inst_vals = {
            "name": path.rstrip("/").split("/")[-1],
            "project_id": project.id,
            "host_id": host_id,
            "environment": environment,
            "custom_remote_dir": path,
            "custom_backup_dst": copier.get("backup_dst", ""),
            # Importing an instance that already runs on the host is the
            # one legal way into 'deployed' without a deploy job.
            "state": "deployed",
            "running": is_running,
            "status": "ok" if is_running else "error",
        }
        if odoo_version:
            inst_vals["odoo_version"] = odoo_version
        if conf_raw.strip():
            inst_vals["odoo_conf"] = conf_raw.strip()
        if pip_raw.strip():
            inst_vals["pip_dependencies"] = pip_raw.strip()
        if apt_raw.strip():
            inst_vals["apt_dependencies"] = apt_raw.strip()

        # Copier-derived fields
        if copier:
            for k in (
                "postgres_version",
                "postgres_dbname",
                "postgres_username",
                "odoo_proxy",
                "smtp_relay_host",
                "smtp_relay_user",
            ):
                if copier.get(k):
                    inst_vals[k] = copier[k]
            if copier.get("smtp_relay_port"):
                inst_vals["smtp_relay_port"] = int(copier["smtp_relay_port"])
            if copier.get("domains"):
                hostnames = [
                    (d.get("hostname") or "").strip()
                    for d in copier["domains"]
                    if (d.get("hostname") or "").strip()
                ]
                if hostnames:
                    taken = set(
                        request.env["cloud.instance.domain"]
                        .search([("hostname", "in", hostnames)])
                        .mapped("hostname")
                    )
                    conflicts = taken & set(hostnames)
                    if conflicts:
                        return {
                            "ok": False,
                            "error": _(
                                "The following domains are already "
                                "assigned to another instance: %s. "
                                "Remove them from the existing instance "
                                "first, then retry the import.",
                                ", ".join(sorted(conflicts)),
                            ),
                        }
                    inst_vals["domain_ids"] = [
                        (
                            0,
                            0,
                            {
                                "hostname": d["hostname"].strip(),
                                "redirect_to": d.get("redirect_to", ""),
                            },
                        )
                        for d in copier["domains"]
                        if (d.get("hostname") or "").strip()
                    ]

        # Secrets from .env files
        if odoo_env.get("ADMIN_PASSWORD"):
            inst_vals["odoo_admin_password"] = odoo_env["ADMIN_PASSWORD"]
        if db_env.get("PASSWORD"):
            inst_vals["postgres_password"] = db_env["PASSWORD"]
        if smtp_env.get("RELAY_PASSWORD"):
            inst_vals["smtp_relay_password"] = smtp_env["RELAY_PASSWORD"]

        # Resource limits
        inst_vals.update(resource_limits)

        try:
            instance = request.env["cloud.instance"].create(inst_vals)
        except Exception:
            _logger.exception("Failed to create instance during import")
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }

        # Handle backup backend from backup.env + copier backup fields
        if backup_env.get("AWS_ACCESS_KEY_ID"):
            try:
                # Parse backup_dst: "boto3+s3://bucket/path" → bucket, path
                s3_bucket = ""
                s3_path = ""
                backup_dst = copier.get("backup_dst", "")
                if "://" in backup_dst:
                    dst_path = backup_dst.split("://", 1)[1]
                    parts = dst_path.split("/", 1)
                    s3_bucket = parts[0]
                    s3_path = parts[1] if len(parts) > 1 else ""

                backend_name = f"S3 {copier.get('project_name') or 'import'}"
                backend = request.env["cloud.backup.backend"].search(
                    [
                        ("name", "=", backend_name),
                    ],
                    limit=1,
                )
                if not backend:
                    backend = request.env["cloud.backup.backend"].create(
                        {
                            "name": backend_name,
                            "s3_bucket": s3_bucket,
                            "s3_path": s3_path,
                            "s3_access_key_id": backup_env.get(
                                "AWS_ACCESS_KEY_ID",
                                "",
                            ),
                            "s3_secret_access_key": backup_env.get(
                                "AWS_SECRET_ACCESS_KEY",
                                "",
                            ),
                            "s3_endpoint_url": backup_env.get(
                                "AWS_ENDPOINT_URL",
                                "",
                            ),
                            "passphrase": backup_env.get("PASSPHRASE", ""),
                            "email_from": copier.get(
                                "backup_email_from",
                                "",
                            ),
                            "email_to": copier.get("backup_email_to", ""),
                            "backup_image_version": copier.get(
                                "backup_image_version",
                                "latest",
                            ),
                            "backup_tz": copier.get("backup_tz", "UTC"),
                            # An explicit backup_deletion=True in the copier
                            # answers is unambiguous (cron is on). False/absent
                            # is ambiguous — we don't know whether the bucket
                            # has a lifecycle policy — so it's left undeclared
                            # for the operator to confirm (see P15 #9a).
                            "retention_owner": (
                                "cron"
                                if copier.get("backup_deletion", False)
                                else "lifecycle"
                            ),
                            "retention_owner_declared": bool(
                                copier.get("backup_deletion", False),
                            ),
                            "smtp_report_success": copier.get(
                                "backup_smtp_report_success",
                                True,
                            ),
                        }
                    )
                instance.backup_backend_id = backend.id
            except Exception:
                _logger.exception(
                    "Could not create backup backend for import",
                )

        return {
            "ok": True,
            "project_id": project.id,
            "instance_id": instance.id,
            "project_name": project.name,
            "instance_name": instance.name,
            "is_running": is_running,
        }

    # ── Container log streaming ────────────────────────────────────────────────

    @http.route(["/cloud/fetch_container_logs"], type="jsonrpc", auth="user")
    def cloud_fetch_container_logs(self, instance_id, service, lines=200):
        """SSH into the instance host and return recent Docker Compose logs.

        Gated by ``can_view_logs`` (developer+) to match the HTML log
        viewer at /cloud/instance/<id>/logs. Internal users without
        cloud permissions must not be able to bypass the UI gate by
        calling this RPC directly.
        """
        self._sec()._check_can_view_logs()
        limited = rate_gate_json(self._log_read_rule("tail"))
        if limited:
            return limited

        # No `.sudo()`: developers already see every instance via
        # `rule_instance_all` (Project Manager+ domain `[(1,'=',1)]`,
        # implied by `group_cloud_developer`). Reading through the
        # caller's env keeps record-rule audit visible for this RPC.
        inst = request.env["cloud.instance"].browse(instance_id)
        if not inst.exists() or not inst.host_id:
            return {"ok": False, "error": _("Instance not found")}

        host = inst.host_id
        inst_dir = inst.get_remote_dir()
        yaml_file = "prod.yaml" if inst.environment == "production" else "test.yaml"
        tail = max(1, min(int(lines), 2000))
        # sanitize service name to prevent injection (alphanumeric, dash, underscore)
        if not re.match(r"^[a-zA-Z0-9_-]+$", service):
            return {"ok": False, "error": _("Invalid service name")}

        if service == "odoo":
            # Odoo's log lives on the host now; the container's output
            # is only the fallback for an instance not rebuilt yet.
            command = odoo_log_live_command(inst_dir, yaml_file, tail)
        else:
            command = (
                f"cd {inst_dir} && docker compose -f {yaml_file} "
                f"logs --no-color --tail={tail} {service} 2>&1"
            )

        async def _run():
            async with asyncssh.connect(**host.ssh_connect_kwargs()) as conn:
                result = await conn.run(command, check=False)
                return result.stdout or result.stderr or ""

        try:
            output = run_async(_run())
            return {"ok": True, "lines": [l for l in output.splitlines() if l]}
        except Exception:
            _logger.exception(
                "Error fetching container logs for instance %s", instance_id
            )
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }

    def _log_read_rule(self, kind):
        """Per-user, per-endpoint cap for a plain read of an instance's logs.

        One bucket per endpoint family rather than one shared bucket:
        the viewer opens by calling the listing and the tail at the
        same instant, and a single bucket makes those two upserts race
        for the same row on every open — Postgres answers that with a
        serialization failure, Odoo retries the request, and the user
        sees nothing but the server log fills with it. Same cap for
        all three, since they are the same kind of act.

        :param str kind: endpoint family (``tail``, ``list``, ``day``)
        """
        return Rule(
            f"logs_{kind}_user:{request.env.uid}",
            _("Too many log reads recently. Try again in a minute."),
            cap_key="rate_limit_logs_per_min",
            log_tag=f"logs {kind} user={request.env.uid}",
        )

    def _log_settings(self):
        """Settings that bound what a log read may cost the host."""
        return request.env["cloud.settings"].sudo()._get_system()

    @http.route(["/cloud/instance_log_archives"], type="jsonrpc", auth="user")
    def cloud_instance_log_archives(self, instance_id):
        """List the Odoo log files the host keeps for this instance.

        Newest first, the live file at the top. An instance that has
        not been rebuilt since file logging shipped simply has none —
        reported as an empty list plus ``archived=False`` so the viewer
        can say so instead of looking broken.
        """
        self._sec()._check_can_view_logs()
        limited = rate_gate_json(self._log_read_rule("list"))
        if limited:
            return limited
        inst = request.env["cloud.instance"].browse(instance_id)
        if not inst.exists() or not inst.host_id:
            return {"ok": False, "error": _("Instance not found")}
        try:
            stdout, _stderr = self._ssh_run(
                inst.host_id, log_archive_list_command(inst.get_remote_dir()),
            )
        except Exception:
            _logger.exception(
                "Error listing log archives for instance %s", instance_id,
            )
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }
        live, dated = None, []
        for line in stdout.splitlines():
            name, _sep, rest = line.strip().partition("|")
            size, _sep2, mtime = rest.partition("|")
            if not is_safe_log_archive(name):
                continue
            entry = {
                "name": name,
                "size": int(size) if size.isdigit() else 0,
                "mtime": int(mtime) if mtime.isdigit() else 0,
                "compressed": name.endswith(".gz"),
            }
            if name == "odoo.log":
                live = entry
            else:
                dated.append(entry)
        dated.sort(key=itemgetter("name"), reverse=True)
        return {
            "ok": True,
            "archived": bool(live or dated),
            "archives": ([live] if live else []) + dated,
        }

    @http.route(["/cloud/fetch_log_archive"], type="jsonrpc", auth="user")
    def cloud_fetch_log_archive(self, instance_id, name, lines=500, search=""):
        """Return the tail of one archived Odoo log, optionally filtered.

        The filter runs on the host: a day of logs is megabytes, and
        the answer to "what happened on Tuesday" is usually a handful
        of lines.
        """
        self._sec()._check_can_view_logs()
        limited = rate_gate_json(self._log_read_rule("day"))
        if limited:
            return limited
        inst = request.env["cloud.instance"].browse(instance_id)
        if not inst.exists() or not inst.host_id:
            return {"ok": False, "error": _("Instance not found")}
        if not is_safe_log_archive(name):
            return {"ok": False, "error": _("Unknown log file")}
        tail = max(1, min(int(lines or 500), 5000))
        try:
            stdout, _stderr = self._ssh_run(
                inst.host_id,
                odoo_log_read_command(
                    inst.get_remote_dir(), name, tail, (search or "").strip(),
                ),
            )
        except Exception:
            _logger.exception(
                "Error reading log archive %s for instance %s",
                name, instance_id,
            )
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }
        return {"ok": True, "lines": [ln for ln in stdout.splitlines() if ln]}

    @http.route(["/cloud/search_log_archives"], type="jsonrpc", auth="user")
    def cloud_search_log_archives(self, instance_id, term, max_files=60):
        """Return the archived days whose log mentions *term*.

        The day picker answers "show me the 17th"; this answers "which
        day was it", which is the question an operator actually has
        once the archive is two months deep.
        """
        self._sec()._check_can_view_logs()
        limited = rate_gate_json(Rule(
            f"log_search_user:{request.env.uid}",
            _("Too many log searches recently. Try again in a minute."),
            cap_key="rate_limit_log_search_per_min",
            log_tag=f"log_search user={request.env.uid}",
        ))
        if limited:
            return limited
        inst = request.env["cloud.instance"].browse(instance_id)
        if not inst.exists() or not inst.host_id:
            return {"ok": False, "error": _("Instance not found")}
        term = (term or "").strip()
        if len(term) < 2:
            # A one-character sweep matches every day and costs a full
            # decompression of the archive to say nothing useful.
            return {
                "ok": False,
                "error": _("Type at least two characters to search."),
            }
        settings = self._log_settings()
        # Audited before the sweep runs: the row is the record that the
        # search was asked for, and a search that dies on the host is
        # exactly the one worth having a trace of.
        request.env["cloud.audit.log"].sudo().create({
            "action": "Searched instance logs",
            "instance_id": inst.id,
            "details": f"term: {term[:120]}",
        })
        try:
            stdout, _stderr = self._ssh_run(
                inst.host_id,
                log_archive_search_command(
                    inst.get_remote_dir(), term,
                    max_files=max(1, min(
                        int(max_files or 0) or settings.log_search_max_files,
                        settings.log_search_max_files,
                    )),
                    timeout_s=settings.log_search_timeout_s,
                ),
            )
        except Exception:
            _logger.exception(
                "Error searching log archives for instance %s", instance_id,
            )
            return {
                "ok": False,
                "error": _("An internal error occurred. Check server logs."),
            }
        matches = []
        for line in stdout.splitlines():
            name, _sep, count = line.strip().partition("|")
            if not is_safe_log_archive(name):
                continue
            matches.append({
                "name": name,
                "count": int(count) if count.isdigit() else 0,
            })
        return {
            "ok": True,
            "matches": matches,
            # False when the sweep was cut short by its own timeout, so
            # the viewer can say "no match *so far*" instead of "none".
            "complete": "IC_DONE" in stdout,
        }

    # ── Monitoring (Fase 4 / A10) ─────────────────────────────────────────

    @http.route(["/cloud/monitoring/config"], type="jsonrpc", auth="user")
    def cloud_monitoring_config(self):
        """Return what the Monitoring tab needs to embed Grafana.

        Deliberately narrow: the master switch, the public Grafana URL,
        and the two picklists the embed has to fill in. The metrics
        backend URL and the remote-write token stay server-side — the
        browser has no business knowing either, and the token is a write
        credential for the whole fleet.

        The picklists are names, not records: they exist only to build
        ``var-host=``/``var-instance=`` for the iframe. Without them
        Grafana falls back to the first value its own variable query
        returns, so every host and instance but one was unreachable from
        this tab, with nothing on screen saying so.

        Instances follow the same rule the label map does — drafts are
        skipped, because nothing of theirs runs on a host yet and no
        series can carry their name.
        """
        self._sec()._check_can_view_metrics()
        settings = request.env["cloud.settings"].sudo()._get_system()
        hosts = request.env["cloud.host"].search([], order="name")
        instances = request.env["cloud.instance"].search(
            [("state", "!=", "draft"), ("host_id", "!=", False)],
            order="name",
        )
        return {
            "ok": True,
            "enabled": bool(settings.metrics_enabled),
            "grafana_base_url": settings.grafana_base_url or "",
            "hosts": [{"name": h.name} for h in hosts],
            "instances": [
                {"name": i.name, "host": i.host_id.name} for i in instances
            ],
        }
