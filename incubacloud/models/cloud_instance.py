import hashlib
import json
import logging
import re
from contextlib import suppress

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError

from ..github.client import GitHubAppClient
from ..net.outbound import OutboundError
from ..net.restore_source import (
    curl_resolve_argument,
    masked as masked_restore_url,
    split_credentials,
    validate as validate_restore_url,
)
from ..restore_staging import purge_stale
from ._odoo_versions import ODOO_VERSION_SELECTION
from . import _config_snapshot_diff as _snapshot_diff
from ._repo_requirements import _normalize_url
from .cloud_host import parse_memory_to_gb
from .encrypted_char import EncryptedChar
from .password_utils import generate_password

_logger = logging.getLogger(__name__)
_GLOBAL_BACKUP_PARAM = "incubacloud.backup_backend_id"


def _smtp_canonical_domain(inst):
    """Derive the SMTP canonical domain for SRS and the mailserver hostname.

    Priority:
      1. Domain part of smtp_relay_user email (user@example.com → example.com)
      2. Strip first label from smtp_relay_host (mail.example.com → example.com)
      3. Empty string (copier will skip SMTP service)

    Module-level (not a method) so unit tests can exercise it with a
    plain attribute namespace, no ORM record required.
    """
    user = inst.smtp_relay_user or ""
    if "@" in user:
        return user.split("@")[-1]
    host = inst.smtp_relay_host or ""
    parts = host.split(".")
    if len(parts) > 2:
        return ".".join(parts[1:])
    return host

# Docker compose project names / COMPOSE_PROJECT_NAME, DNS labels and the
# path segment used by executors must be lowercase alnum + [_-], 1-63 chars.
# Blocks every shell metachar (;|&$`"' space \) and path traversal (/ ..).
_INSTANCE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

# ~/..., /..., or relative path. Each segment is [A-Za-z0-9._-]+ and we
# explicitly reject '..' segments. No shell metacharacters.
_REMOTE_DIR_RE = re.compile(r"^(~/|/)?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/?$")

# PostgreSQL identifier (database / role name). Used in psql -U/-d
# arguments that flow through SSH shell to docker compose exec, so we
# must keep them free of any character bash or psql could misinterpret.
# 1-63 chars, lowercase letter or underscore start, then alnum + '_'.
_PG_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class CloudInstance(models.Model):
    _name = "cloud.instance"
    _inherit = [
        "cloud.security.mixin",
        "cloud.audit.tracked.mixin",
        "cloud.pip.provenance.mixin",
    ]
    _description = "Cloud Instance"

    _name_project_uniq = models.Constraint(
        "unique (project_id, name)",
        "Instance name must be unique within a project.",
    )
    _one_production_per_project = models.Constraint(
        "EXCLUDE (project_id WITH =) WHERE (environment = 'production' AND project_id IS NOT NULL)",
        "A project can only have one production instance.",
    )

    active = fields.Boolean(default=True)
    auto_rebuild = fields.Boolean(
        string="Auto-Rebuild on Push",
        default=True,
        help="Automatically trigger a rebuild when a push event is "
        "received on a matching (unfrozen) repo branch.",
    )
    last_auto_rebuild = fields.Datetime(
        string="Last Auto-Rebuild",
        readonly=True,
    )
    pending_push_ids = fields.One2many(
        "cloud.instance.pending.push",
        "instance_id",
        string="Pending Pushes",
        help="Pushes that arrived while a rebuild was running or within "
        "the auto-rebuild cooldown. They are merged into the next "
        "rebuild job triggered on completion of the current one.",
    )
    pending_push_count = fields.Integer(
        string="Pending Push Count",
        compute="_compute_pending_push_count",
    )
    auto_update = fields.Boolean(
        string="Auto-Update Modules on Rebuild",
        default=True,
        help="Run click-odoo-update during rebuild to apply module "
        "schema/data changes. Disable for instances that manage "
        "module state manually or cannot accept automatic updates "
        "(e.g. frozen production with a change-management policy). "
        "Disabling also skips the safe boot test that relies on "
        "click-odoo-update.",
    )

    # ── Smart rebuild fingerprint ─────────────────────────────────────────
    rebuild_fingerprint = fields.Char(
        string="Rebuild Fingerprint",
        compute="_compute_rebuild_fingerprint",
        store=True,
        help="Hash of fields that affect the Docker image. When this "
        "differs from last_rebuild_fingerprint, a full rebuild "
        "(--pull --no-cache) is triggered instead of a cached one.",
    )
    last_rebuild_fingerprint = fields.Char(
        string="Last Rebuild Fingerprint",
        readonly=True,
        help="Fingerprint saved after the last successful rebuild/deploy.",
    )

    name = fields.Char(
        required=True,
        translate=True,
    )
    doodba_project_name = fields.Char(
        compute="_compute_doodba_project_name",
        string="Doodba Project Name",
        help="Composite name used as copier project_name: "
        "{remote_folder}-{name}. Ensures unique Docker "
        "container names across projects on the same host.",
    )
    project_id = fields.Many2one(
        comodel_name="cloud.project",
        string="Project",
    )
    host_id = fields.Many2one(
        comodel_name="cloud.host",
        string="Host",
    )
    move_origin_host_id = fields.Many2one(
        comodel_name="cloud.host",
        string="Move Origin Host",
        copy=False,
        help="Set to the source host while a cross-host move is in "
        "flight; cleared once the destination is cut over. A "
        "non-empty value left after a failed move marks an instance "
        "an operator can roll back.",
    )
    move_target_host_id = fields.Many2one(
        comodel_name="cloud.host",
        string="Move Target Host",
        copy=False,
        help="Destination host while a cross-host move is in flight; "
        "cleared on cutover. Lets stuck-move recovery identify the "
        "half-built destination copy for cleanup.",
    )
    move_chain_job_ids = fields.Char(
        string="Move Chain Job IDs",
        copy=False,
        help="Comma-separated cloud.job IDs of the current move chain. "
        "Set by move_to_host(), cleared on cutover success or "
        "rollback completion. Lets rollback inspect each step's "
        "state to decide what to undo.",
    )
    move_rollback_in_progress = fields.Boolean(
        string="Move Rollback In Progress",
        copy=False,
        default=False,
        help="True while a rollback is running. Distinguishes "
        '"migrating" from "rolling back" in the UI and prevents '
        "duplicate rollbacks.",
    )
    status = fields.Selection(
        selection=[
            ("ok", "OK"),
            ("warning", "Warning"),
            ("error", "Error"),
        ],
        string="Status",
        required=True,
        default="ok",
        help="Health of the instance, independent of where it is in its "
        "lifecycle: 'ok' while it behaves, 'warning'/'error' when a "
        "health check or a job says otherwise. Lifecycle lives in "
        "``state``.",
    )
    state = fields.Selection(
        selection=[
            ("draft", "Draft"),
            ("deploying", "Deploying"),
            ("deployed", "Deployed"),
            ("deleting", "Deleting"),
        ],
        string="Lifecycle State",
        required=True,
        default="draft",
        copy=False,
        help="Where the instance is in its lifecycle. Written only by "
        "``_transition()``, which rejects illegal jumps. Rebuild, "
        "restore, move, start and stop all happen *inside* 'deployed' — "
        "they are operations, not states.",
    )
    deployed = fields.Boolean(
        string="Deployed",
        compute="_compute_deployed",
        store=True,
        help="True while the instance exists on a host — that is, in "
        "'deployed' and also in 'deleting', whose teardown has not "
        "finished yet. Stored because search domains, the SPA and "
        "cloud.tenant's related fields read it; derived from ``state`` "
        "so there is a single source of truth.",
    )
    running = fields.Boolean(string="Running", default=False)
    service_states = fields.Json(
        string="Service States",
        copy=False,
        readonly=True,
        help="What each container of the stack was doing when the health "
        "probe last looked, e.g. {'odoo': 'running', 'db': 'running'}. "
        "The probe has always known this and only ever raised alerts "
        "with it; the panel painted one dot per service from the single "
        "``running`` flag instead, so every service always showed the "
        "same state. Empty until the first probe lands.",
    )
    stop_is_expected = fields.Boolean(
        string="Stopped On Purpose",
        compute="_compute_stop_is_expected",
        help="True when this instance being down is normal rather than "
        "an incident. Always False here: base knows no reason for a "
        "deployed instance to be stopped. A layer above may — a plan "
        "that puts an idle instance to sleep — and answers by "
        "overriding ``_stop_is_expected``.",
    )
    custom_remote_dir = fields.Char(
        string="Custom Remote Directory",
        help="Override for the remote directory path. "
        "When set, used instead of the computed ~/project/instance path. "
        "Set automatically when importing existing instances.",
    )
    environment = fields.Selection(
        selection=[
            ("staging", "Staging"),
            ("production", "Production"),
        ],
        string="Environment",
        required=True,
        default="staging",
    )
    tag_ids = fields.Many2many(
        comodel_name="cloud.instance.tag",
        relation="cloud_instance_tag_rel",
        column1="instance_id",
        column2="tag_id",
        string="Tags",
    )

    # ── PR preview fields ────────────────────────────────────────────────────
    pr_number = fields.Integer(
        string="PR Number",
        index=True,
        help="GitHub PR number that created this instance. "
        "When set, this instance is a PR preview — auto-destroyed on PR close.",
    )
    pr_repo = fields.Char(
        string="PR Repository",
        help="Full repository name (owner/repo) of the PR.",
    )
    pr_head_branch = fields.Char(
        string="PR Branch",
        help="Head branch of the PR.",
    )
    pr_comment_id = fields.Integer(
        string="GitHub Comment ID",
        help="ID of the GitHub issue comment posted on the PR.",
    )

    # ── Copier template parameters ──────────────────────────────────────────

    odoo_version = fields.Selection(
        selection=ODOO_VERSION_SELECTION,
        string="Odoo Version",
        default="19.0",
    )
    odoo_commit_sha = fields.Char(
        string="Pinned Odoo Commit",
        help=(
            "When set, the Odoo core repository is frozen to this exact"
            " commit SHA instead of following the branch tip."
        ),
    )
    odoo_initial_lang = fields.Many2one(
        "res.lang",
        string="Initial Language",
        context={"active_test": False},
        help="Language installed via odoo -i base -l <code> on first deploy.",
    )
    odoo_admin_password = EncryptedChar(
        string="Admin Password",
        groups="incubacloud.group_cloud_developer",
    )
    odoo_admin_user_password = EncryptedChar(
        string="Admin User Password",
        groups="incubacloud.group_cloud_developer",
    )
    odoo_proxy = fields.Selection(
        [("traefik", "Traefik"), ("none", "None")],
        string="Proxy",
        default="traefik",
    )

    postgres_version = fields.Selection(
        [("14", "14"), ("15", "15"), ("16", "16"), ("17", "17"), ("18", "18")],
        string="PostgreSQL Version",
        default="17",
    )
    postgres_dbname = fields.Char(string="DB Name", default="prod")
    postgres_username = fields.Char(string="DB User", default="odoo")
    postgres_password = EncryptedChar(
        string="DB Password",
        groups="incubacloud.group_cloud_developer",
    )

    domain_ids = fields.One2many(
        "cloud.instance.domain",
        "instance_id",
        string="Domains",
    )
    domain = fields.Char(
        string="Primary Domain",
        compute="_compute_domain",
        store=True,
    )

    @api.depends("name", "project_id.remote_folder")
    def _compute_doodba_project_name(self):
        for inst in self:
            folder = inst.project_id.remote_folder if inst.project_id else ""
            if folder:
                inst.doodba_project_name = f"{folder}-{inst.name}"
            else:
                inst.doodba_project_name = inst.name

    def get_remote_dir(self):
        """Return the remote directory path for this instance.

        Uses ``custom_remote_dir`` if set (imported instances),
        otherwise computes ~/project_remote_folder/instance_name/.
        """
        self.ensure_one()
        if self.custom_remote_dir:
            return self.custom_remote_dir
        project_folder = (
            self.project_id.remote_folder if self.project_id else ""
        ) or "instances"
        return f"~/{project_folder}/{self.name}"

    @api.depends("pending_push_ids")
    def _compute_pending_push_count(self):
        """Count of pushes queued for the next coalesced rebuild."""
        for inst in self:
            inst.pending_push_count = len(inst.pending_push_ids)

    @api.depends("domain_ids.hostname", "domain_ids.sequence")
    def _compute_domain(self):
        # Sort explicitly by (sequence, id) instead of relying on
        # cloud.instance.domain._order. The value of ``inst.domain``
        # flows into _base_url() and from there into psql -c "..." in
        # deploy/rebuild executors (see H-MOD-2 fix). Sorting here
        # makes the resolution independent of any future change to
        # the related model's _order, so a refactor cannot silently
        # alter which hostname becomes the primary domain.
        for inst in self:
            domains = inst.domain_ids.sorted(
                key=lambda d: (d.sequence, d.id),
            )
            first = domains[:1]
            inst.domain = first.hostname if first else ""

    odoo_admin_email = fields.Char(string="Admin Email")

    smtp_relay_host = fields.Char(string="SMTP Host")
    smtp_relay_port = fields.Integer(string="SMTP Port", default=587)
    smtp_relay_security = fields.Selection(
        selection=[
            ("none", "None"),
            ("starttls", "STARTTLS"),
            ("ssl", "SSL/TLS"),
        ],
        string="SMTP Security",
        default="starttls",
    )
    smtp_relay_user = fields.Char(string="SMTP User")
    smtp_relay_password = EncryptedChar(
        string="SMTP Password",
        groups="incubacloud.group_cloud_developer",
    )

    # ── Resource limits (docker-compose.override.yml) ─────────────────
    odoo_memory_limit = fields.Char(
        string="Odoo Memory Limit",
        default="2g",
        help="Docker mem_limit for odoo service (e.g. 2g, 512m)",
    )
    odoo_cpus = fields.Float(string="Odoo CPUs", default=2.0)
    db_memory_limit = fields.Char(
        string="DB Memory Limit",
        default="1g",
    )
    db_cpus = fields.Float(string="DB CPUs", default=1.0)
    backup_memory_limit = fields.Char(
        string="Backup Memory Limit",
        default="512m",
    )
    backup_cpus = fields.Float(string="Backup CPUs", default=0.5)
    smtp_memory_limit = fields.Char(
        string="SMTP Memory Limit",
        default="256m",
    )
    smtp_cpus = fields.Float(string="SMTP CPUs", default=0.25)

    odoo_conf = fields.Text(
        string="Odoo Configuration",
        default=(
            "[options]\n"
            "workers = 2\n"
            "server_wide_modules = web\n"
            "limit_time_cpu = 600\n"
            "limit_time_real = 1200\n"
            "max_cron_threads = 1\n"
        ),
    )

    pip_dependencies = fields.Text(
        string="Python Dependencies",
        default=(
            "git+https://github.com/OCA/openupgradelib.git@master\n"
            "unicodecsv\n"
            "unidecode\n"
        ),
        help="Contents written to odoo/custom/dependencies/pip.txt on deploy.",
    )
    apt_dependencies = fields.Text(
        string="System (APT) Dependencies",
        help="Contents written to odoo/custom/dependencies/apt.txt on deploy.",
    )

    repo_ids = fields.One2many(
        comodel_name="cloud.instance.repo",
        inverse_name="instance_id",
        string="Repositories",
    )

    alert_ids = fields.One2many(
        comodel_name="cloud.alert",
        inverse_name="instance_id",
        string="Alerts",
    )

    last_health_check = fields.Datetime(
        string="Last Health Check",
        readonly=True,
    )
    cpu_over_threshold_streak = fields.Integer(
        default=0,
        readonly=True,
        help=(
            "Consecutive instance_health cycles with CPU above the "
            "warning threshold. Reset to 0 the moment we read a value "
            "below threshold. An alert is only raised once the streak "
            "reaches the configured hysteresis depth."
        ),
    )
    mem_over_threshold_streak = fields.Integer(
        default=0,
        readonly=True,
        help=(
            "Consecutive instance_health cycles with memory above the "
            "warning threshold. Hysteresis counterpart of "
            "cpu_over_threshold_streak."
        ),
    )
    http_fail_streak = fields.Integer(
        default=0,
        readonly=True,
        help=(
            "Consecutive instance_health cycles where the container was "
            "running but Odoo did not answer on 8069. The critical "
            "instance_unresponsive alert waits for the same hysteresis "
            "depth as CPU and memory: a container that is up but not "
            "listening yet is what every boot looks like from outside, "
            "so a single failed probe is not an incident."
        ),
    )

    compose_services = fields.Char(
        string="Compose Services",
        default="odoo,db",
        help=(
            "Comma-separated list of Docker Compose service names"
            " detected from the YAML."
        ),
    )

    backup_backend_id = fields.Many2one(
        comodel_name="cloud.backup.backend",
        string="Backup Destination",
        help="Backup backend for this instance. Overrides the project default.",  # noqa: E501
    )
    effective_backup_backend = fields.Many2one(
        comodel_name="cloud.backup.backend",
        string="Effective Backup Destination",
        compute="_compute_effective_backup_backend",
    )

    instance_backup_dst = fields.Char(
        string="Instance Backup Path",
        compute="_compute_instance_backup_dst",
        help="Per-instance duplicity DST: {backend_dst}/{project}/{instance}",
    )
    custom_backup_dst = fields.Char(
        string="Custom Backup Path",
        help="Override for the backup destination path. "
        "When set, used instead of the computed path. "
        "Set automatically when importing existing instances.",
    )

    @api.depends("backup_backend_id", "project_id.backup_backend_id")
    def _compute_effective_backup_backend(self):
        ICP = self.env["ir.config_parameter"].sudo()
        global_id = int(ICP.get_param(_GLOBAL_BACKUP_PARAM, 0) or 0)
        Backend = self.env["cloud.backup.backend"]
        global_backend = Backend.browse(global_id) if global_id else Backend
        for inst in self:
            inst.effective_backup_backend = (
                inst.backup_backend_id
                or inst.project_id.backup_backend_id
                or global_backend
            )

    @api.depends(
        "custom_backup_dst",
        "effective_backup_backend",
        "name",
        "project_id.remote_folder",
    )
    def _compute_instance_backup_dst(self):
        for inst in self:
            if inst.custom_backup_dst:
                inst.instance_backup_dst = inst.custom_backup_dst
                continue
            bb = inst.effective_backup_backend
            if bb and bb.backup_dst and inst.name:
                project_folder = (
                    inst.project_id.remote_folder if inst.project_id else ""
                ) or "default"
                inst.instance_backup_dst = (
                    f"{bb.backup_dst}/{project_folder}/{inst.name}"
                )
            else:
                inst.instance_backup_dst = ""

    @api.depends(
        "odoo_version",
        "odoo_commit_sha",
        "pip_dependencies",
        "apt_dependencies",
        "odoo_proxy",
        "repo_ids.url",
        "repo_ids.branch",
        "repo_ids.commit_sha",
        "repo_ids.addons",
        "repo_ids.excludes",
    )
    def _compute_rebuild_fingerprint(self):
        for inst in self:
            parts = [
                inst.odoo_version or "",
                inst.odoo_commit_sha or "",
                inst.pip_dependencies or "",
                inst.apt_dependencies or "",
                inst.odoo_proxy or "",
            ]
            for repo in inst.repo_ids.sorted("id"):
                parts.extend(
                    [
                        repo.url or "",
                        repo.branch or "",
                        repo.commit_sha or "",
                        repo.addons or "",
                        repo.excludes or "",
                    ]
                )
            raw = "|".join(parts)
            inst.rebuild_fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Config drift: saved config vs what the last deploy shipped ────────
    # The panel stores configuration; a deploy/rebuild applies it. Between
    # the two, the UI used to say nothing — an edited domain (or SMTP
    # relay, or backup backend, …) read as "saved" while the server kept
    # serving the previous state. The snapshot below is everything a
    # rebuild would ship, so ANY present or future field that feeds the
    # copier answers counts automatically; only the extras tuple needs
    # maintaining for inputs shipped outside the answers file.

    applied_config_hash = fields.Char(
        copy=False,
        readonly=True,
        help="Hash of the config snapshot the last successful deploy or "
             "rebuild shipped. Compared against the current snapshot to "
             "surface unapplied changes.",
    )
    applied_config_snapshot = fields.Json(
        copy=False,
        readonly=True,
        help="The snapshot behind applied_config_hash. Kept so the drift "
             "pill can say which keys moved instead of just that "
             "something did.",
    )
    config_dirty = fields.Boolean(
        compute="_compute_config_dirty",
        help="True when the saved configuration differs from what the "
             "last deploy shipped; a rebuild applies it.",
    )

    #: Deploy inputs shipped OUTSIDE the copier answers file (compose
    #: resource overrides, odoo.conf, dependency manifests, the pinned
    #: odoo commit used in repos.yaml). Inheriting modules may extend.
    _CONFIG_SNAPSHOT_EXTRA_FIELDS = (
        "odoo_conf",
        "odoo_memory_limit", "odoo_cpus",
        "db_memory_limit", "db_cpus",
        "backup_memory_limit", "backup_cpus",
        "smtp_memory_limit", "smtp_cpus",
        "pip_dependencies", "apt_dependencies",
        "odoo_commit_sha",
    )

    def _render_copier_answers(self):
        """Return the copier answers dict a deploy of this instance ships.

        Single source of truth shared by the deploy executor (which dumps
        it to the remote answers file) and the config-drift hash. Must
        stay deterministic: values come from stored state only — never
        tokens, timestamps or anything minted per run.
        """
        self.ensure_one()
        # sudo: executor path is trusted; secret fields carry group
        # restrictions that would otherwise hide them from the render.
        inst = self.sudo()

        entries = []
        for d in inst.domain_ids:
            hostname = (
                (d.hostname or "")
                .replace("https://", "")
                .replace("http://", "")
                .strip("/")
            )
            if not hostname:
                continue
            entry = {"hosts": [hostname]}
            if d.redirect_to:
                entry["redirect_to"] = d.redirect_to
                if d.redirect_permanent:
                    entry["redirect_permanent"] = True
            # Always emitted, never left to the template default: the
            # copier copy runs against a moving upstream ref, and a
            # default that changes between template releases would
            # silently change every tenant's TLS on the next rebuild.
            entry["cert_resolver"] = d._cert_resolver_answer()
            entries.append(entry)

        if inst.environment == "production":
            domains_prod = entries
            domains_test = []
        else:
            domains_prod = []
            domains_test = entries

        bb = inst.effective_backup_backend
        if bb:
            bb = bb.sudo()
        has_backup = inst._backup_enabled()

        answers = {
            "project_author": inst.project_id.project_author or "IncubaCloud",
            "project_license": inst.project_id.project_license or "BSL-1.0",
            "project_name": inst.doodba_project_name,
            "odoo_version": float(inst.odoo_version),
            "odoo_initial_lang": inst.odoo_initial_lang.code or "en_US",
            "odoo_admin_password": inst.odoo_admin_password or "",
            "odoo_proxy": inst.odoo_proxy or "traefik",
            "postgres_version": str(inst.postgres_version or "17"),
            "postgres_dbname": inst.postgres_dbname or "prod",
            "postgres_username": inst.postgres_username or "odoo",
            "postgres_password": inst.postgres_password or "",
            "domains_prod": domains_prod,
            "domains_test": domains_test,
            "smtp_relay_host": inst.smtp_relay_host or "",
            "smtp_relay_port": inst.smtp_relay_port or 587,
            "smtp_relay_version": "latest",
            "smtp_relay_user": inst.smtp_relay_user or "",
            "smtp_relay_password": inst.smtp_relay_password or "",
            "smtp_default_from": (
                inst.smtp_relay_user or inst.odoo_admin_email or ""
            ),
            # canonical_default = sending domain (from relay user email
            # if set, else strip first subdomain off relay host, e.g.
            # mail.x.com → x.com)
            "smtp_canonical_default": _smtp_canonical_domain(inst),
            "smtp_canonical_domains": [],
            # Backup defaults (always empty/disabled; overridden below
            # when a backup backend is configured and enabled).
            "backup_dst": "",
            "backup_image_version": "",
            "backup_email_from": "",
            "backup_email_to": "",
            "backup_smtp_report_success": False,
            "backup_deletion": False,
            "backup_tz": "UTC",
            "backup_aws_access_key_id": "",
            "backup_aws_secret_access_key": "",
            "backup_passphrase": "",
            # Answered explicitly even though we never use it. The
            # template added this question in v9.7.0 with a literal
            # placeholder as its default, and ``copier --defaults``
            # takes defaults for questions we leave out — which would
            # write ``BACKEND_PASSWORD=example-backup-backend-password``
            # into every backup.env. Empty keeps the line out of the
            # file entirely. Only password-capable duplicity backends
            # (SFTP) read it; ours are S3/R2, which authenticate with
            # the AWS keys above.
            "backup_backend_password": "",
        }
        if has_backup and bb:
            answers.update(
                {
                    "backup_dst": inst.instance_backup_dst or "",
                    "backup_image_version": bb.backup_image_version or "latest",
                    "backup_email_from": bb.email_from or "",
                    "backup_email_to": bb.email_to or "",
                    "backup_smtp_report_success": bb.smtp_report_success,
                    "backup_deletion": bb.retention_owner == "cron",
                    "backup_tz": bb.backup_tz or "UTC",
                    "backup_aws_access_key_id": bb.s3_access_key_id or "",
                    "backup_aws_secret_access_key": bb.s3_secret_access_key or "",
                    "backup_passphrase": bb.passphrase or "",
                }
            )
        return answers

    def _render_config_snapshot(self):
        """Return the full deterministic dict of what a rebuild ships.

        Copier answers + the token-free repos description + the extras
        tuple. Deliberately excluded: the GitHub tokens injected into
        repos.yaml (they rotate hourly) and the template url/ref pin
        (bumps are governed by their runbook, not per-instance drift).
        """
        self.ensure_one()
        inst = self.sudo()
        return {
            "answers": inst._render_copier_answers(),
            "repos": [
                {
                    "url": r.url or "",
                    "branch": r.branch or "",
                    "commit_sha": r.commit_sha or "",
                    "addons": r.addons or "",
                    "excludes": r.excludes or "",
                }
                for r in inst.repo_ids.sorted("id")
            ],
            "extras": {
                f: inst[f] or "" for f in self._CONFIG_SNAPSHOT_EXTRA_FIELDS
            },
        }

    def _config_snapshot_hash(self):
        """SHA-256 hex digest of the canonical-JSON config snapshot."""
        self.ensure_one()
        raw = json.dumps(
            self._render_config_snapshot(), sort_keys=True, default=str,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _applied_config_vals(self):
        """Write values that anchor this instance's config to right now.

        Every successful deploy / rebuild / warm build stamps through
        here so the hash and the snapshot behind it can never drift
        apart — a stamp that recorded only one of them would leave the
        pill unable to explain itself.
        """
        self.ensure_one()
        return {
            "applied_config_hash": self._config_snapshot_hash(),
            "applied_config_snapshot": _snapshot_diff.normalize(
                self._render_config_snapshot(),
            ),
        }

    def _config_drift_diff(self):
        """Return the snapshot keys that moved since the last deploy.

        Empty when nothing differs — and also when no snapshot was
        recorded, which is the case for every instance anchored before
        this field existed: the hash alone cannot name what changed.
        """
        self.ensure_one()
        stored = self.applied_config_snapshot
        if not stored:
            return []
        return _snapshot_diff.diff_keys(stored, self._render_config_snapshot())

    # Depends: only on the anchor. The snapshot side deliberately has NO
    # field dependency list (its whole point is covering every deploy
    # input automatically), so within one env cache the value can go
    # stale after an edit; every HTTP request gets a fresh cache, which
    # is the consumer that matters. Tests invalidate explicitly.
    @api.depends("applied_config_hash")
    def _compute_config_dirty(self):
        """Dirty = a hash was recorded by a deploy and it no longer
        matches. Records that never deployed (empty hash) are not dirty
        — their whole config is pending by definition and the UI already
        shows the deploy call-to-action."""
        for inst in self:
            applied = inst.applied_config_hash
            if not applied:
                inst.config_dirty = False
                continue
            try:
                inst.config_dirty = applied != inst._config_snapshot_hash()
            except Exception:
                # A snapshot that cannot render (undecryptable secret,
                # legacy row) must not break the detail page: treat the
                # record as untracked, not as dirty.
                _logger.warning(
                    "config_dirty: snapshot render failed for instance %s",
                    inst.id, exc_info=True,
                )
                inst.config_dirty = False

    # ── Lifecycle state machine ────────────────────────────────────────────

    # Legal moves between lifecycle states. Everything not listed here
    # is a bug in the caller, not a case to tolerate: an instance that
    # jumps straight from 'draft' to 'deleting' (or re-enters
    # 'deploying' while a deploy is in flight) means two flows are
    # fighting over the same record.
    #
    #   draft     → deploying   deploy() enqueues the job
    #   draft     → deployed    ONLY importing an already-running instance
    #   deploying → deployed    deploy/warm succeeded
    #   deploying → draft       deploy failed; status carries the error
    #   deployed  → deleting    teardown job enqueued
    #   deleting  → draft       torn down; config kept in the panel
    #   deleting  → deployed    teardown failed; it is still on the host
    #
    # Unlink is not a transition: a record can only be dropped from
    # 'draft' (see :meth:`unlink`).
    _STATE_TRANSITIONS = {
        "draft": ("deploying", "deployed"),
        "deploying": ("deployed", "draft"),
        "deployed": ("deleting",),
        "deleting": ("draft", "deployed"),
    }

    # States in which the instance still exists on its host. 'deleting'
    # belongs here: until the teardown job succeeds the stack is still
    # there, which is exactly what ``deployed`` meant before it became
    # derived — so search domains, crons and the SPA keep behaving the
    # same through a teardown.
    _ON_HOST_STATES = ("deployed", "deleting")

    @api.depends("state")
    def _compute_deployed(self):
        for inst in self:
            inst.deployed = inst.state in self._ON_HOST_STATES

    def _compute_stop_is_expected(self):
        """Expose :meth:`_stop_is_expected` to the panel and to views."""
        for inst in self:
            inst.stop_is_expected = inst._stop_is_expected()

    def _stop_is_expected(self):
        """Return whether this instance being down is normal, not broken.

        False here, always: base knows of no legitimate reason for a
        deployed instance to have stopped, so anything down is an
        incident and is reported as one. A layer that does know of one —
        a plan that sleeps an idle instance — overrides this.

        Asking the instance, rather than testing a field base does not
        have, is what keeps sleeping out of base entirely. Same shape as
        ``_metric_alerts_suppressed`` and the health probe's
        ``_odoo_stop_is_expected``, for the same reason.

        :rtype: bool
        """
        self.ensure_one()
        return False

    def _transition(self, to_state):
        """Move this instance to *to_state*.

        The only supported way to write ``state``: it validates the move
        against :attr:`_STATE_TRANSITIONS` and refuses anything else, so
        a wrong call fails where it happens instead of leaving a record
        in a state no flow can explain.

        :param str to_state: target lifecycle state
        :raises UserError: if the move is not in the transition map
        """
        self.ensure_one()
        if to_state not in self._STATE_TRANSITIONS.get(self.state, ()):
            raise UserError(
                _(
                    "Cannot move instance '%(name)s' from '%(current)s' to "
                    "'%(target)s'.",
                    name=self.name,
                    current=self.state,
                    target=to_state,
                )
            )
        return self.with_context(cloud_state_transition=True).write(
            {"state": to_state},
        )

    def write(self, vals):
        # The lifecycle is a state machine, so ``state`` is written by
        # _transition() alone. Refusing the direct write here is what
        # keeps the map from being quietly bypassed later.
        if "state" in vals and not self.env.context.get("cloud_state_transition"):
            raise UserError(
                _(
                    "The lifecycle state of an instance is set by "
                    "_transition(), not by writing 'state' directly."
                )
            )
        # ``deployed`` is derived from ``state``. Odoo accepts a write to
        # a stored computed field and then silently discards it on the
        # next recompute, which would turn a stale caller into an
        # invisible no-op; refuse it instead.
        if "deployed" in vals:
            raise UserError(
                _(
                    "'deployed' is derived from the lifecycle state. Use "
                    "_transition() instead of writing it."
                )
            )
        # Drop empty password values so existing stored passwords are preserved
        for field in self._PASSWORD_FIELDS:
            if field in vals and not vals[field]:
                del vals[field]
        changed, old_snap = self._audit_snapshot(vals)
        result = super().write(vals)
        # Auto-generate domain when a host is assigned to an instance
        # that doesn't have any domains yet (e.g. imported without host).
        if "host_id" in vals and vals["host_id"]:
            for inst in self:
                if inst.domain_ids:
                    continue
                host = inst.host_id
                if not host.wildcard_domain:
                    continue
                project = inst.project_id
                if project and project.remote_folder:
                    subdomain = f"{project.remote_folder}-{inst.name}"
                else:
                    subdomain = inst.name
                hostname = f"{subdomain}.{host._subdomain_suffix()}"
                self.env["cloud.instance.domain"].create(
                    {
                        "instance_id": inst.id,
                        "hostname": hostname,
                    }
                )
        self._audit_log_changes(changed, old_snap)
        return result

    def _audit_target_vals(self):
        """Point 'Config changed' audit rows at this instance and host."""
        self.ensure_one()
        return {
            "instance_id": self.id,
            "host_id": self.host_id.id if self.host_id else False,
        }

    def _check_backup_backend(self):
        """Raise if this production instance has no effective backup backend."""
        if self.environment == "production" and not self.effective_backup_backend:
            raise UserError(
                _(
                    "No backup backend configured for this instance. "
                    "Set one at instance level, project level, or globally "
                    "in Settings → General → Default Backup Backend."
                )
            )

    def _backup_enabled(self):
        """Whether this instance should run the doodba ``backup`` service.

        Default: any instance with a usable backup backend (one that
        resolves a ``backup_dst``) is backup-enabled. Modules layered
        on top (e.g. SaaS plan logic) may override to opt out.
        """
        self.ensure_one()
        bb = self.effective_backup_backend
        return bool(bb and bb.backup_dst)

    def expected_services(self):
        """Compose services this instance is supposed to render and run.

        Single source of truth consumed by deploy / rebuild (to emit
        the right ``docker-compose.override.yml``) and by the health
        probe (to know which containers must be ``running``). The
        shape matches what the copier template actually renders:

        * staging / dev → ``('odoo', 'db')`` only.
        * production    → ``odoo`` + ``db``, plus ``backup`` when
          :meth:`_backup_enabled` is true, plus ``smtp`` when a relay
          host is configured.
        """
        self.ensure_one()
        if self.environment != "production":
            return ("odoo", "db")
        svcs = ["odoo", "db"]
        if self._backup_enabled():
            svcs.append("backup")
        if self.smtp_relay_host:
            svcs.append("smtp")
        return tuple(svcs)

    def deploy(self):
        """Enqueue a deploy_instance job for this instance."""
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        if self.deployed:
            raise UserError(_("Instance is already deployed. Use Rebuild instead."))
        self._check_backup_backend()
        # Enter 'deploying' before enqueuing: the transition map is what
        # rejects a second deploy while the first is still in flight.
        self._transition("deploying")
        return self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "deploy_instance",
        )

    def list_backups(self):
        """Enqueue a backup_list job for this instance."""
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        if self.environment == "production":
            self._check_backup_backend()
        return self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "backup_list",
        )

    def create_backup(self, with_filestore=True):
        """Enqueue backup_create → backup_list chain.

        Returns the trailing backup_list job id so callers polling for
        completion only see ``done`` once the records have been synced
        from duplicity.

        ``with_filestore`` is forwarded as the ``backup_create``
        payload and used by the non-prod executor branch to flip
        ``click-odoo-backupdb --filestore`` / ``--no-filestore``.
        Production ignores it (duplicity controls shape).
        """
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        if not self.deployed:
            raise UserError(_("Instance is not deployed."))
        if self.environment == "production":
            self._check_backup_backend()
        step = {"host_id": self.host_id.id, "instance_id": self.id}
        # Bool coercion at the service-layer boundary so any truthy
        # input (a stray string from JSON-RPC, etc.) collapses to True
        # before reaching the shell command in the executor.
        create_step = {
            **step,
            "job_type_code": "backup_create",
            "payload": {"with_filestore": bool(with_filestore)},
        }
        ids = self.env["cloud.job"].enqueue_chain(
            [
                create_step,
                {**step, "job_type_code": "backup_list"},
            ]
        )
        return ids[-1]

    def download_backup(self, payload):
        """Enqueue a backup_download job for this instance.

        Prod: pulls the requested timestamp from S3 via duplicity.
        Non-prod: takes a live dump on demand (only ``time='latest'``
        is meaningful — no snapshot history exists).
        """
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        if self.environment != "production" and not self.deployed:
            # Non-prod takes a live dump from inside the running odoo
            # container; without a deployed stack there is no
            # docker-compose project to ``run --rm`` against.
            raise UserError(_("Instance is not deployed."))
        self._check_backup_backend()
        return self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "backup_download",
            payload=payload,
        )

    def download_backup_neutralized(self, payload):
        """Enqueue a backup_download_neutralized job for this instance.

        Unlike ``download_backup`` (prod-only, driven by duplicity), this
        works for both prod (``time`` = duplicity timestamp) and non-prod
        (``time`` = 'live', dumps the current DB on the fly).
        """
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        if not self.deployed:
            raise UserError(_("Instance is not deployed."))
        if self.environment == "production":
            self._check_backup_backend()
        return self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "backup_download_neutralized",
            payload=payload,
        )

    def revive(self, host_id=None):
        """Bring an archived instance back: redeploy, then restore.

        Both halves already exist — deploying an instance and restoring
        the latest snapshot into it — so this only chains them, which is
        exactly what the archived record was frozen to make possible.

        The host is a choice, not a given. The original may be gone, or
        full, or the whole reason for archiving may have been to move
        off it; defaulting to the stored one when nothing is passed
        keeps the common case one click.

        Restoring reads ``latest`` from the frozen destination rather
        than a timestamp: archiving pruned to a single chain, so
        ``latest`` *is* the archive copy, and asking for a date would
        mean storing one and keeping it true.

        The copy is re-checked live here. The cron's stamp is good
        enough to render a list, but this is the moment where being
        wrong costs something: a deploy that succeeds and a restore that
        finds nothing leaves an empty instance where the operator
        expected their data.

        :param host_id: host to redeploy on; defaults to the archived
            ``host_id``.
        :return: list of the enqueued job ids.
        :raises UserError: if the instance is not archived, has no
            frozen copy, or that copy is not there any more.
        """
        self.ensure_one()
        if self.active:
            raise UserError(_("This instance is not archived."))
        if not self.custom_backup_dst:
            raise UserError(
                _(
                    "%(name)s was archived without a backup destination, "
                    "so there is nothing to restore. Its data was "
                    "destroyed with the containers.",
                    name=self.name,
                )
            )
        state, _total = self._probe_archived_copy()
        if state != "present":
            raise UserError(
                _(
                    "The archived copy of %(name)s is not available at "
                    "%(path)s (%(state)s), so reviving would leave an "
                    "empty instance. Check the storage before retrying.",
                    name=self.name,
                    path=self.custom_backup_dst,
                    state=state,
                )
            )
        target_host = (
            self.env["cloud.host"].browse(host_id) if host_id else self.host_id
        )
        if not target_host.exists():
            raise UserError(_("Pick a host to revive this instance on."))
        # Un-archive before enqueuing: the jobs address the instance by
        # id and every downstream query filters on ``active``, so a
        # still-archived record would have its own deploy skip it.
        self.with_context(ic_archive_instance=True).write({
            "active": True,
            "host_id": target_host.id,
            # Cleared with the flag it belongs to: a stamp left behind
            # would make the next archiving look older than it is.
            "archived_at": False,
            # Same reasoning, sharper consequence. A deletion that was
            # decided, failed and then reverted by this revive must not
            # bound a *future* purge: the cutoff would predate the chain
            # written since, and that purge would delete nothing while
            # reporting success.
            "purge_cutoff_at": False,
        })
        return self.env["cloud.job"].enqueue_chain([
            {
                "host_id": target_host.id,
                "instance_id": self.id,
                "job_type_code": self._move_deploy_job_type(),
            },
            {
                "host_id": target_host.id,
                "instance_id": self.id,
                "job_type_code": "backup_restore",
                # No safety snapshot ahead of this one, unlike
                # ``restore_backup``: the instance was just built empty,
                # so there is nothing to protect and a snapshot of an
                # empty database would only add a chain to pay for.
                "payload": {"time": "latest"},
            },
        ])

    def restore_backup(self, payload):
        """Enqueue a backup_restore job for this instance.

        Always prepends a fresh ``backup_create`` — restoring an older
        duplicity snapshot is destructive, so a safety snapshot of the
        current state is taken first, unconditionally (no opt-out).
        Same rationale as ``move_to_host``.
        """
        self.ensure_one()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        self._check_backup_backend()
        job_ids = self.env["cloud.job"].enqueue_chain(
            [
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "backup_create",
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "backup_restore",
                    "payload": payload,
                },
            ]
        )
        return job_ids[0]

    def clone_to_staging(
        self, staging_name, pr_number=0, pr_repo="", pr_head_branch=""
    ):
        """Create a staging copy of this production instance with its data.

        When *pr_number* is provided the clone is a PR preview instance:
        the repo whose URL matches *pr_repo* has its branch set to
        *pr_head_branch* so the PR code is deployed instead of the
        default branch.
        """
        self.ensure_one()
        # Server-side backstop: the method is public and therefore
        # reachable over RPC (call_kw), where the controller's Developer
        # gate never runs. su callers — the GitHub webhook's sudo'd PR
        # previews — bypass inside _check_cloud_group.
        self.env["cloud.security.mixin"]._check_can_clone_to_staging()
        if self.environment != "production":
            raise UserError(_("Only production instances can be cloned."))
        if not self.deployed:
            raise UserError(_("Instance must be deployed first."))

        vals = {
            "name": staging_name,
            "project_id": self.project_id.id,
            "host_id": self.host_id.id,
            "environment": "staging",
            "odoo_version": self.odoo_version,
            "odoo_commit_sha": self.odoo_commit_sha,
            "odoo_initial_lang": (
                self.odoo_initial_lang.id if self.odoo_initial_lang else False
            ),
            "odoo_proxy": self.odoo_proxy,
            "postgres_version": self.postgres_version,
            "postgres_dbname": "prod",
            "postgres_username": self.postgres_username,
            "smtp_relay_host": self.smtp_relay_host,
            "smtp_relay_port": self.smtp_relay_port,
            "smtp_relay_security": self.smtp_relay_security,
            "smtp_relay_user": self.smtp_relay_user,
            "odoo_conf": self.odoo_conf,
            "pip_dependencies": self.pip_dependencies,
            "apt_dependencies": self.apt_dependencies,
        }
        if pr_number:
            vals |= {
                "pr_number": pr_number,
                "pr_repo": pr_repo,
                "pr_head_branch": pr_head_branch,
            }
        staging = self.with_context(
            skip_project_repos=True,
        ).create(vals)

        pr_repo_norm = _normalize_url(
            f"https://github.com/{pr_repo}" if pr_repo else ""
        )
        for repo in self.repo_ids:
            new_repo = repo.copy({"instance_id": staging.id})
            if pr_head_branch and pr_repo_norm:
                if _normalize_url(new_repo.url) == pr_repo_norm:
                    new_repo.write({"branch": pr_head_branch, "commit_sha": False})

        # The clone is deployed by the chain below rather than through
        # deploy(), so it enters 'deploying' here.
        staging._transition("deploying")

        job_ids = self.env["cloud.job"].enqueue_chain(
            [
                {
                    "host_id": self.host_id.id,
                    "instance_id": staging.id,
                    "job_type_code": "deploy_instance",
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,  # prod
                    "job_type_code": "backup_download",
                    "payload": {
                        # Without a backup backend there is no duplicity
                        # store to restore 'latest' from — an on-demand
                        # dump is the only workable source.
                        "time": (
                            "latest" if self.effective_backup_backend
                            else "live"
                        ),
                        "download_type": "all",
                        "handoff": "host",
                    },
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": staging.id,
                    "job_type_code": "restore_instance",
                    "payload": {
                        "mode": "from_host",
                        "source_job_id": "__chain_job_1__",
                        # A clone carries production's data, which means
                        # production's cron jobs and outgoing mail
                        # servers. Left live, a staging copy invoices,
                        # duns and emails real customers. PR previews
                        # included: the core posts the PR comment itself,
                        # it never goes through the instance's mail.
                        "neutralize": True,
                        "reset_base_url": True,
                    },
                },
            ]
        )
        return {"staging_id": staging.id, "job_id": job_ids[0]}

    def refresh_from_production(
        self, source_instance_id, source="backup", neutralize=True,
    ):
        """Overwrite this instance's data with a copy of a production's.

        The staging keeps its own code (repos and branches are untouched)
        and only its database and filestore are replaced — odoo.sh calls
        this a staging rebuild, a name already taken here by the real
        rebuild (``copier update`` + image rebuild).

        No new executor: this is the tail of the ``clone_to_staging``
        chain without the deploy step, so both jobs already tell their
        story in the timeline and both instances are already covered by
        ``enqueue_chain``'s per-instance advisory lock.

        :param int source_instance_id: production instance to copy from
        :param str source: ``'backup'`` (latest duplicity snapshot, the
            default) or ``'live'`` (on-demand dump). ``'backup'``
            degrades to ``'live'`` when the source has no backup backend
            rather than failing, and the resolved value is returned.
        :param bool neutralize: disable scheduled actions and outgoing
            mail in the restored copy and show the test banner
        :return: ``{'ok': True, 'job_ids': [...], 'source': <resolved>}``
        :raises UserError: on any validation failure
        :raises AccessError: below the Developer role (same gate as
            cloning — this method is reachable over RPC)
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_clone_to_staging()
        if source not in ("backup", "live"):
            raise UserError(_("Unknown data source: %s", source))
        if self.environment == "production":
            raise UserError(
                _("Production instances cannot be refreshed from production.")
            )
        if not self.deployed:
            raise UserError(_("Instance must be deployed first."))
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))

        prod = self.browse(int(source_instance_id)).exists()
        if not prod:
            raise UserError(_("Source instance not found."))
        if prod.environment != "production":
            raise UserError(_("The source must be a production instance."))
        if not prod.deployed:
            raise UserError(_("The source instance is not deployed."))
        if not prod.host_id:
            raise UserError(_("The source instance has no host assigned."))
        if prod.project_id != self.project_id:
            raise UserError(
                _("The source must belong to the same project.")
            )

        # No backup backend means no duplicity store to restore from; a
        # live dump is the only thing that can work, so degrade instead
        # of failing and let the caller tell the user what happened.
        if source == "backup" and not prod.effective_backup_backend:
            source = "live"

        # Hosts are per step: production and staging may live on
        # different machines. The archive travels through the control
        # plane as an ir.attachment, so cross-host is free.
        job_ids = self.env["cloud.job"].enqueue_chain(
            [
                {
                    "host_id": prod.host_id.id,
                    "instance_id": prod.id,
                    "job_type_code": "backup_download",
                    "payload": {
                        "time": "latest" if source == "backup" else "live",
                        "download_type": "all",
                        "handoff": "host",
                    },
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "restore_instance",
                    "payload": {
                        "mode": "from_host",
                        "source_job_id": "__chain_job_0__",
                        "neutralize": bool(neutralize),
                        "reset_base_url": True,
                    },
                },
            ]
        )
        return {"ok": True, "job_ids": job_ids, "source": source}

    # ── Cross-host move ────────────────────────────────────────────────────

    def _move_deploy_job_type(self):
        """Job type that (re)builds the stack on the destination host
        during a move.

        Core deploys the bare instance; SaaS overrides this to
        ``tenant_deploy_instance`` so the tenant module is staged on the
        new host (the restored DB references it).
        """
        return "deploy_instance"

    def _move_pre_steps(self, source_host):
        """Return extra chain steps to run BEFORE the move starts.

        Core: none. Inheriting layers (SaaS) prepend host-specific
        quiescing — e.g. removing the Sablier wake-gate so traffic
        cannot restart the source and produce writes that the dump
        (taken right after the source is stopped) would miss.
        """
        return []

    def _on_move_cutover(self, origin_host):
        """Hook fired on a successful host-move cutover, after ``host_id``
        has flipped to the destination.

        Core: no-op (DNS is the operator's concern on a bare core
        install). SaaS overrides this to re-point the managed DNS
        A-record at the new host IP and finalize the tenant.
        """

    def move_to_host(self, target_host):
        """Move this deployed instance to ``target_host``, preserving data.

        Reuses the existing executors in one ``enqueue_chain`` so the
        whole move is a single sequential pipeline. The source is only
        torn down after the destination is verified healthy and cut
        over, so a failure at any earlier step leaves the source
        recoverable (see ``rollback_move`` / ``cron_recover_stuck_moves``)::

            [pre-steps] → deploy(target) → stop(source, odoo only) →
            backup_create(source) → backup_download(source) →
            restore(target) → move_cutover(target) →
            move_cleanup_source(source)

        Only the ``odoo`` service is stopped on the source (not ``db`` or
        ``backup``) so the backup container stays alive for the following
        steps. ``backup_create`` freshes a snapshot to S3 (db up, odoo
        quiesced = consistent) so ``backup_download`` restores a current
        copy rather than a potentially stale scheduled backup.
        ``host_id`` flips to ``target_host`` only inside ``move_cutover``
        on success.
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_hosts()
        source = self.host_id
        if not source:
            raise UserError(_("Instance has no host assigned."))
        if not self.deployed:
            raise UserError(_("Instance must be deployed before it can move."))
        if not target_host or target_host == source:
            raise UserError(_("Pick a different target host."))
        if target_host.status != "compatible" or not target_host.traefik_deployed:
            raise UserError(
                _(
                    "Target host '%(name)s' is not ready (must be compatible "
                    "and have Traefik deployed).",
                    name=target_host.name or "?",
                )
            )
        if self.move_origin_host_id:
            raise UserError(_("A move is already in progress for this instance."))
        if not self.instance_backup_dst:
            raise UserError(
                _(
                    "This instance has no resolvable backup backend, so a "
                    "move cannot transfer its data. Configure a backup "
                    "backend (instance, project or global) first."
                )
            )

        self.move_origin_host_id = source.id
        self.move_target_host_id = target_host.id

        pre = self._move_pre_steps(source)
        # pre … deploy(+0) stop(+1) backup_create(+2) download(+3):
        # restore references the download job by its 0-indexed position.
        download_idx = len(pre) + 3
        steps = pre + [
            {
                "host_id": target_host.id,
                "instance_id": self.id,
                "job_type_code": self._move_deploy_job_type(),
            },
            {
                "host_id": source.id,
                "instance_id": self.id,
                "job_type_code": "stop_instance",
                "payload": {"services": ["odoo"]},
            },
            {
                "host_id": source.id,
                "instance_id": self.id,
                "job_type_code": "backup_create",
            },
            {
                "host_id": source.id,
                "instance_id": self.id,
                "job_type_code": "backup_download",
                "payload": {
                    "time": "latest",
                    "download_type": "all",
                    "handoff": "host",
                },
            },
            {
                "host_id": target_host.id,
                "instance_id": self.id,
                "job_type_code": "restore_instance",
                "payload": {
                    "mode": "from_host",
                    "source_job_id": f"__chain_job_{download_idx}__",
                },
            },
            {
                "host_id": target_host.id,
                "instance_id": self.id,
                "job_type_code": "move_cutover",
            },
            {
                "host_id": source.id,
                "instance_id": self.id,
                "job_type_code": "move_cleanup_source",
            },
        ]
        job_ids = self.env["cloud.job"].enqueue_chain(steps)
        self.move_chain_job_ids = ",".join(str(jid) for jid in job_ids)
        return {"ok": True, "job_id": job_ids[0]}

    def rollback_move(self):
        """Recover a move that failed before cutover (user entrypoint).

        Cancels all in-flight move-chain jobs, cleans up the
        half-built destination copy, and brings the source back up.
        The markers stay set until the cleanup executor succeeds so
        the UI reports "rolling back" rather than falsely claiming
        the instance has recovered.
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_hosts()
        if not self.move_origin_host_id:
            raise UserError(_("No move in progress to roll back."))
        if self.move_rollback_in_progress:
            raise UserError(_("A rollback is already in progress."))
        origin = self.move_origin_host_id
        if self.host_id != origin:
            raise UserError(
                _(
                    "Cannot roll back: the move already completed "
                    "(cutover succeeded). The instance is now live on "
                    "the target host. Use 'Move to host' to move it "
                    "back if needed."
                )
            )
        result = self._do_rollback_move()
        if result is False:
            return {"ok": False, "error": _("Nothing to roll back.")}
        return {"ok": True, "job_id": result}

    def _do_rollback_move(self):
        """Core stuck-move recovery, WITHOUT the ACL check.

        Cancels every active move-chain job (cooperatively for started
        ones, via queue_job for queued ones), then enqueues cleanup
        (target) and start (source) in parallel. Returns the
        ``move_rollback_cleanup`` job id (the head of the recovery),
        or ``False`` when there is nothing to recover.

        Shared by ``rollback_move`` (gated on ACL) and the unattended
        ``cron_recover_stuck_moves`` watchdog (runs via sudo).
        """
        self.ensure_one()
        origin = self.move_origin_host_id
        if not origin:
            return False
        if self.host_id != origin:
            return False
        self._cancel_move_chain()
        return self._enqueue_rollback_jobs()

    # ── Private helpers for rollback ───────────────────────────────────

    def _get_move_chain_jobs(self):
        """Return ``cloud.job`` records of the current move chain, ordered
        by step (same order as ``move_chain_job_ids``)."""
        self.ensure_one()
        if not self.move_chain_job_ids:
            return self.env["cloud.job"]
        ids = []
        for part in (self.move_chain_job_ids or "").split(","):
            part = part.strip()
            if part.isdigit():
                ids.append(int(part))
        if not ids:
            return self.env["cloud.job"]
        jobs = self.env["cloud.job"].browse(ids).exists()
        # Preserve original step order.
        id_to_pos = {jid: i for i, jid in enumerate(ids)}
        return jobs.sorted(key=lambda j: id_to_pos.get(j.id, 9999))

    def _cancel_move_chain(self):
        """Cancel every active job in the current move chain.

        Cancellation is best-effort and tolerant of missing records
        (a crashed worker may have left queue.job rows without a
        matching cloud.job, and that's fine — the chain stops when
        its head fails). Head-to-tail order ensures queue_job cascades
        ``button_cancelled`` to downstream children in
        ``wait_dependencies``, reducing the number of jobs that need
        individual cancellation.

        Active-state detection uses SQL because ``state`` is a stored
        related of ``queue_job_id.state`` and the ORM cache may serve
        the computed value instead of the raw DB column (relevant when
        tests force-persist a state without a queue.job).
        """
        chain_jobs = self._get_move_chain_jobs()
        if not chain_jobs:
            return
        active_states = tuple(self.env["cloud.job"]._active_states)
        self.env.cr.execute(
            "SELECT id FROM cloud_job WHERE id IN %s AND state IN %s",
            (tuple(chain_jobs.ids), active_states),
        )
        active_ids = {row[0] for row in self.env.cr.fetchall()}
        active = chain_jobs.filtered(lambda j: j.id in active_ids)
        for job in active:
            with suppress(UserError):
                job.cancel_job()

    def _enqueue_rollback_jobs(self):
        """Enqueue the two recovery jobs after a cancelled move.

        Runs cleanup on the TARGET host (idempotent: docker compose
        down -v + rm -rf) and start on the SOURCE host, both with
        ``bypass_running_check`` so the stale active chain does not
        block them. The cleanup executor clears the move markers on
        success; until then ``move_rollback_in_progress`` is True.

        Returns the ``move_rollback_cleanup`` job id.
        """
        target = self.move_target_host_id
        origin = self.move_origin_host_id
        self.move_rollback_in_progress = True
        # Start source in parallel — independent of cleanup.
        self.env["cloud.job"].enqueue(
            origin.id,
            self.id,
            "start_instance",
            bypass_running_check=True,
        )
        return self.env["cloud.job"].enqueue(
            target.id,
            self.id,
            "move_rollback_cleanup",
            bypass_running_check=True,
        )

    def _post_or_update_pr_comment(self, body):
        """Post or update the GitHub PR comment for this PR preview instance."""
        if not self.pr_number or not self.pr_repo:
            return
        owner, repo = self.pr_repo.split("/", 1)
        creds = self.env["cloud.github.credential.service"].get_credentials()
        if not creds:
            return
        client = GitHubAppClient(creds)
        try:
            if self.pr_comment_id:
                client.patch_issue_comment(owner, repo, self.pr_comment_id, body)
            else:
                result = client.post_issue_comment(owner, repo, self.pr_number, body)
                if result.get("id"):
                    self.write({"pr_comment_id": result["id"]})
        except Exception:
            _logger.exception("PR comment update failed for %s", self.name)

    def _delete_pr_comment(self):
        """Delete the GitHub PR comment for this PR preview instance."""
        if not self.pr_comment_id or not self.pr_repo:
            return
        owner, repo = self.pr_repo.split("/", 1)
        creds = self.env["cloud.github.credential.service"].get_credentials()
        if not creds:
            return
        client = GitHubAppClient(creds)
        try:
            client.delete_issue_comment(owner, repo, self.pr_comment_id)
            self.write({"pr_comment_id": 0})
        except Exception:
            _logger.exception("PR comment delete failed for %s", self.name)

    archived_at = fields.Datetime(
        copy=False,
        readonly=True,
        help="When this instance was archived. A field of its own and "
             "not ``write_date``, which the daily copy check rewrites "
             "on every archived record — the view would then report "
             "the last verification as the archiving date.",
    )
    archive_copy_state = fields.Selection(
        selection=[
            ("present", "Present"),
            ("missing", "Missing"),
            ("unreachable", "Unreachable"),
        ],
        copy=False,
        readonly=True,
        help="What the last verification pass found at the frozen "
             "backup path. Written by the archive-check cron, never "
             "measured while rendering a list.",
    )
    archive_copy_bytes = fields.Float(
        copy=False,
        readonly=True,
        help="Total size of the archived chain at the last check, so "
             "what an archived instance costs stays visible.",
    )
    archive_copy_checked_at = fields.Datetime(
        copy=False,
        readonly=True,
        help="When the archived copy was last verified. Shown alongside "
             "the state so a stale reading is visible as stale instead "
             "of passing for current.",
    )
    purge_cutoff_at = fields.Datetime(
        copy=False,
        readonly=True,
        help="The instant this instance's deletion was decided. The "
             "purge only removes objects older than it, so a retry — "
             "days or months later, by which time a new instance may "
             "hold the same name and therefore the same prefix — still "
             "deletes the old chain and nothing else. Stamped once and "
             "never refreshed: 'now' on a retry would defeat the point.",
    )

    @api.model
    def _cron_verify_archived_copies(self):
        """Check that every archived instance still has its copy.

        "The backend answers" is not the same as "the copy is there": a
        provider lifecycle rule or a manual delete empties the prefix
        while the credentials and the bucket stay perfectly healthy. The
        only honest check is to list the frozen prefix and see objects.

        Done on a schedule and stamped on the record, not on render: a
        list of archived instances would otherwise make one network call
        per row every time someone opened it. The view reads the stamp,
        and ``revive`` re-checks live — there the single call is worth
        it, because that is the moment being wrong actually costs
        something.

        An archived instance whose copy is gone is a record that lies.
        Finding out when the operator presses "revive" is too late, so
        this raises an alert as soon as it happens.
        """
        archived = self.with_context(active_test=False).search([
            ("active", "=", False),
            ("custom_backup_dst", "!=", False),
        ])
        Alert = self.env["cloud.alert"].sudo()
        for inst in archived:
            state, total = inst._probe_archived_copy()
            inst.sudo().write({
                "archive_copy_state": state,
                "archive_copy_bytes": total,
                "archive_copy_checked_at": fields.Datetime.now(),
            })
            if state == "present":
                Alert.resolve_alert("archive_copy_lost", instance=inst)
                continue
            if state == "missing":
                Alert.raise_alert(
                    "archive_copy_lost",
                    _(
                        "The archived copy of %(name)s is gone from "
                        "%(path)s. Nothing can be revived from it; the "
                        "record no longer has anything behind it.",
                        name=inst.name, path=inst.custom_backup_dst,
                    ),
                    level="critical",
                    instance=inst,
                )
        return len(archived)

    def _probe_archived_copy(self):
        """Return ``(state, bytes)`` for this instance's frozen prefix.

        ``unreachable`` is kept apart from ``missing`` on purpose. A
        provider outage and a deleted chain look the same from a
        distance and need opposite reactions: one is waited out, the
        other means the copy is gone for good. Reporting a temporary
        network failure as "missing" would raise a false alarm about
        data loss, so anything that is not a clear empty listing stays
        unreachable.
        """
        self.ensure_one()
        backend = self.effective_backup_backend
        if not backend:
            return "unreachable", 0.0
        try:
            total, count = backend._measure_prefix(self.custom_backup_dst)
        except Exception:
            _logger.warning(
                "archived copy check failed for %s at %s",
                self.name, self.custom_backup_dst, exc_info=True,
            )
            return "unreachable", 0.0
        return ("present" if count else "missing"), total

    def delete_archived(self, payload=None):
        """Delete an archived instance together with its backup chain.

        The record and the chain go together or not at all. An archived
        instance is the only thing that still knows where its objects
        are — the path is frozen on it precisely because the computed
        one stops being true — so unlinking it first would strand the
        chain permanently, with no instance, no project and no path left
        to find it by. That is the exact failure this whole feature was
        built to make impossible.

        The chain is emptied by a job (see
        ``PurgeArchivedBackupsExecutor``) and the record is unlinked
        there, on success only. Nothing is redeployed: the purge runs in
        a container created for that one command.

        Two shortcuts, both safe. An instance archived without a
        destination has no chain to delete, so it unlinks here. And an
        instance whose host is gone cannot run a container anywhere,
        which is a refusal rather than a licence to unlink: the objects
        would outlive it.

        The first call stamps ``purge_cutoff_at`` and every later one
        reuses it, so a retry deletes exactly what the original call
        would have. By then the name — and therefore the prefix — may
        belong to a new instance, and "everything under the prefix"
        would take its backups too.

        :param payload: extra job payload, for a caller that needs to
            chain something onto the purge's success.
        :return: list of enqueued job ids, empty when it unlinked here.
        :raises UserError: if the instance is not archived, or has a
            chain but no host left to purge it from.
        """
        self.ensure_one()
        if self.active:
            raise UserError(_("This instance is not archived."))
        if not self.custom_backup_dst:
            # Archived with nothing behind it — the teardown destroyed
            # its data and no copy was ever taken.
            self.sudo().unlink()
            return []
        if not self.host_id:
            raise UserError(
                _(
                    "%(name)s has an archived copy at %(path)s but no "
                    "host left to delete it from. Assign a host to the "
                    "instance and try again — deleting the record alone "
                    "would leave the copy behind with nothing pointing "
                    "at it.",
                    name=self.name, path=self.custom_backup_dst,
                )
            )
        if not self.purge_cutoff_at:
            self.sudo().write({"purge_cutoff_at": fields.Datetime.now()})
        # A list, so callers and the route see the same shape whether
        # this enqueued something or unlinked here.
        return [self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "purge_archived_backups",
            payload=payload or {},
        )]

    def _freeze_backup_dst(self):
        """Pin the archived copy's location into ``custom_backup_dst``.

        The computed path is derived from the project's remote folder and
        the instance name, so it is only true while those stay put. Once
        the instance is archived it stops being maintained and the
        derivation can quietly become false — a tenant deletion detaches
        the project and the computed path falls back to ``.../default/``,
        which is both wrong and shared with everything else that lost its
        project.

        Everything that touches the copy afterwards — pruning, expiry,
        restoring it back — reads the frozen value, never the computed
        one. Without this the record would eventually point somewhere
        that is not its own backups, which is worse than pointing
        nowhere.

        No-op when there is nothing to freeze (no destination resolves)
        or when an explicit override is already set: an imported instance
        carries its real location there and must not be overwritten.
        """
        self.ensure_one()
        if self.custom_backup_dst:
            return
        computed = self.instance_backup_dst
        if not computed:
            return
        self.write({"custom_backup_dst": computed})
        _logger.info(
            "instance %s archived: backup path frozen at %s",
            self.name, computed,
        )

    @api.model
    def _gc_restore_uploads(self):
        """Delete browser-uploaded restore archives nobody will consume.

        The executor removes the archive once it has sent it, but no
        ``finally`` covers the upload whose job never runs at all —
        cancelled before it started, or enqueued against an instance that
        was removed since. At up to 2 GiB each those would sit on the
        data volume until the container is recreated.

        :return: number of files removed.
        """
        return purge_stale()

    # ── Large restores: temporary upload key, and fetch-by-URL ────────────

    def grant_restore_upload(self):
        """Open a one-use SSH door for uploading a restore archive here.

        Returns the private half of a freshly generated key, which is
        never stored: the panel installs the public half on the host,
        restricted to one directory in write-only mode and with a
        deadline OpenSSH enforces by itself. Whoever called this is the
        only holder, and losing it costs another grant, not access.

        :return: dict with the key, where to send the archive, and the
            job installing it.
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_backups()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        grant, private_key = self.env["cloud.restore.upload.grant"]._open(self)
        job_id = self.env["cloud.job"].enqueue(
            self.host_id.id,
            self.id,
            "grant_restore_upload_key",
            payload={"grant_id": grant.id},
        )
        self.env["cloud.audit.log"].sudo().create({
            "action": "Granted a temporary restore upload key",
            "instance_id": self.id,
            "host_id": self.host_id.id,
            "job_id": job_id,
            "details": grant.fingerprint or "",
        })
        return {
            "grant_id": grant.id,
            "job_id": job_id,
            "private_key": private_key,
            "fingerprint": grant.fingerprint,
            "expires_at": grant.expires_at,
            "user": self.host_id.user or "root",
            "host": self.host_id.ip_address or "",
            "port": self.host_id.port or 22,
            "directory": grant._directory(),
        }

    def verify_restore_upload(self, grant_id):
        """Ask the host what actually arrived through a grant.

        The answer — name, size and SHA-256, all computed on the host —
        is what the operator confirms before anything is restored. It is
        also the only defence that matters if the key leaked inside its
        window: a file nobody recognises does not get restored.

        :param grant_id: the grant to inspect.
        :return: id of the job that reports back.
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_backups()
        grant = self.env["cloud.restore.upload.grant"].browse(
            int(grant_id)
        ).exists()
        if not grant or grant.instance_id != self:
            raise UserError(_("That upload grant does not exist."))
        return self.env["cloud.job"].enqueue(
            grant.host_id.id, self.id, "verify_restore_upload",
            payload={"grant_id": grant.id},
        )

    def revoke_restore_upload(self, grant_id):
        """Close a grant early, removing its key and directory."""
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_backups()
        grant = self.env["cloud.restore.upload.grant"].browse(
            int(grant_id)
        ).exists()
        if not grant or grant.instance_id != self:
            raise UserError(_("That upload grant does not exist."))
        return grant._revoke()

    def restore_from_url(self, url, backup_before_restore=False):
        """Have the host download an archive and restore from it.

        The URL is checked here rather than on the host: allowed scheme,
        a name that resolves to a public address, and no credentials
        left inside it. The address it resolved to is pinned into the
        download command, so the name cannot answer differently by the
        time the host dials it.

        :param url: ``https``, ``sftp`` or ``ftp`` source, which may
            carry ``user:password@``.
        :param backup_before_restore: take a safety backup first.
        :return: id of the restore job.
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_backups()
        clean, username, password = split_credentials(url)
        try:
            parts, address, port = validate_restore_url(clean)
        except OutboundError as exc:
            raise UserError(_("That link cannot be used: %s.", exc)) from exc
        job_id = self.restore_db({
            "mode": "from_url",
            "url": clean,
            "url_display": masked_restore_url(url),
            "resolve": curl_resolve_argument(parts, address, port),
            "backup_before_restore": bool(backup_before_restore),
        })
        if username:
            # Written after the job exists and outside the payload: the
            # payload is read back into the UI and notifications, and a
            # password has no business in either.
            self.env["cloud.job"].browse(job_id).sudo().secret_payload = (
                json.dumps({
                    "machine": parts.hostname,
                    "login": username,
                    "password": password,
                })
            )
        return job_id

    def restore_db(self, payload):
        """Enqueue a restore_instance job with the given payload.

        ``payload['mode']`` selects the source of the backup zip:

        * ``browser``  — operator uploaded a zip via /cloud/instance/<id>/restore;
                         the controller staged it under the data dir (the one
                         mount this container shares with the job runner) and
                         passes the resulting path as ``local_path``.
        * ``from_job`` — the zip is an ir.attachment of a previous cloud.job
                         (typically a backup_download); the executor pulls it
                         from the DB.
        * ``rsync``    — the zip is already on the remote host at the path
                         the executor expects (operator uploaded it manually).

        ``payload['backup_before_restore']`` requests a safety snapshot
        (backup_create + backup_download) chained before the restore.
        On production this is always forced regardless of the flag —
        same "no opt-out" rule as ``restore_backup``/``move_to_host``.
        On non-production it stays opt-in, default off.

        The method is exposed via JSON-RPC, so we gate it explicitly:
        only Developer+ can trigger a restore. The downstream executor
        also validates the ``local_path`` prefix as a defense-in-depth
        layer (see RestoreInstanceExecutor.before_execute).
        """
        self.ensure_one()
        self.env["cloud.security.mixin"]._check_can_manage_backups()
        if not self.host_id:
            raise UserError(_("Instance has no host assigned."))
        payload = payload or {}
        if payload.get("mode") not in (
            "browser", "from_job", "rsync", "ssh_upload", "from_url",
        ):
            raise UserError(_("Invalid restore mode."))
        if payload.get("mode") == "ssh_upload":
            grant = self.env["cloud.restore.upload.grant"].browse(
                int(payload.get("grant_id") or 0)
            ).exists()
            if not grant or grant.instance_id != self:
                raise UserError(_("That upload grant does not exist."))
            if not grant.received_filename:
                raise UserError(_(
                    "Nothing has been uploaded yet, or the upload has not "
                    "been checked. Check what arrived before restoring it."
                ))

        backup_first = self.environment == "production" or bool(
            payload.get("backup_before_restore")
        )
        if not backup_first:
            return self.env["cloud.job"].enqueue(
                self.host_id.id,
                self.id,
                "restore_instance",
                payload=payload,
            )

        if not self.instance_backup_dst:
            raise UserError(
                _(
                    "This instance has no resolvable backup backend, so a "
                    "pre-restore safety backup cannot be taken. Configure a "
                    "backup backend (instance, project or global) first."
                )
            )
        job_ids = self.env["cloud.job"].enqueue_chain(
            [
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "backup_create",
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "backup_download",
                    "payload": {"time": "latest", "download_type": "all"},
                },
                {
                    "host_id": self.host_id.id,
                    "instance_id": self.id,
                    "job_type_code": "restore_instance",
                    "payload": payload,
                },
            ]
        )
        return job_ids[0]

    @api.model
    def _periodic_maintenance_domain(self):
        """Extra filter every periodic maintenance cron must respect.

        The extension point for layers that deploy instances the daily
        crons have no business touching. Core deploys none, so it adds
        nothing; a SaaS layer with a pool of stopped spares excludes
        them here, once, instead of reimplementing each cron.

        That reimplementing is what this exists to stop. A layer that
        copies a cron body to add one filter owns a copy that stops
        receiving the guards added to the original — and the copy fails
        silently, because a cron that queues jobs nobody reads looks
        exactly like a cron doing its job.

        :return: a search domain, ANDed into each cron's own.
        """
        return []

    @api.model
    def cron_refresh_backup_list(self):
        """Queue a backup_list job for every production instance.

        Skips instances whose compose stack has no ``backup`` service
        (e.g. free-tier tenants): the executor shells into the backup
        container via ``docker compose exec -T backup``, which answers
        ``service "backup" is not running`` with status 1 for a service
        that is stopped *and* for one the compose file never declared.
        Either way it is a failed job and an alert, every day, forever —
        and one that never resolves, since a successful run is what
        clears it.

        Stopped stacks are skipped for the same reason. Warm spares are
        what forced that one: they ship stopped by design and hold no
        customer data at all.
        """
        instances = self.search(
            [
                ("deployed", "=", True),
                ("environment", "=", "production"),
                ("move_origin_host_id", "=", False),
                ("running", "=", True),
            ]
            + self._periodic_maintenance_domain()
        )
        for inst in instances:
            if not inst.host_id or not inst.instance_backup_dst:
                continue
            services = {
                s.strip() for s in (inst.compose_services or "").split(",") if s.strip()
            }
            if "backup" not in services:
                continue
            try:
                inst.list_backups()
            except Exception:
                _logger.warning(
                    "Could not enqueue backup_list for %s",
                    inst.name,
                    exc_info=True,
                )

    _NO_BACKUP_ALERT_CODE = "production_no_backup"

    @api.model
    def cron_check_production_backup(self):
        """Daily cron: warn on deployed production instances with no
        resolvable backup backend (instance/project/global all empty).

        Unlike the backend-scoped alerts in cloud.backup.backend, this
        one has a natural ``instance_id`` target so it's visible to
        every member of the instance's project, not just managers.
        """
        Alert = self.env["cloud.alert"].sudo()
        instances = self.search(
            [
                ("deployed", "=", True),
                ("environment", "=", "production"),
            ]
        )
        flagged = 0
        for inst in instances:
            existing = Alert.search(
                [
                    ("code", "=", self._NO_BACKUP_ALERT_CODE),
                    ("instance_id", "=", inst.id),
                    ("state", "=", "active"),
                ],
                limit=1,
            )
            if inst.effective_backup_backend:
                existing.write({"state": "dismissed"})
                continue
            flagged += 1
            vals = {
                "code": self._NO_BACKUP_ALERT_CODE,
                "level": "warning",
                "message": (
                    f"Production instance '{inst.name}' has no backup "
                    f"backend configured — it is not being backed up."
                ),
                "instance_id": inst.id,
            }
            if inst.project_id:
                vals["project_id"] = inst.project_id.id
            if inst.host_id:
                vals["host_id"] = inst.host_id.id
            if existing:
                existing.write(vals)
            else:
                Alert.create(vals)
        return {"flagged": flagged}

    @api.model
    def cron_instance_health(self):
        """Queue an instance_health job for every deployed instance."""
        instances = self.search(
            [("deployed", "=", True)] + self._periodic_maintenance_domain()
        )
        for inst in instances:
            if not inst.host_id:
                continue
            try:
                self.env["cloud.job"].enqueue(
                    inst.host_id.id,
                    inst.id,
                    "instance_health",
                )
            except Exception as e:
                _logger.warning(
                    "Could not enqueue instance_health for %s: %s",
                    inst.name,
                    e,
                )

    @api.model
    def cron_recover_stuck_moves(self):
        """Watchdog: recover instances stranded by a failed host move.

        A move stamps ``move_origin_host_id`` before enqueuing its job
        chain (atomically, same transaction) and clears it only on a
        successful cutover or a successful rollback cleanup. If the
        chain dies before cutover, the marker stays set and the source
        was left with ``odoo`` stopped — the instance is down with no
        automatic recovery.

        Two states are handled:

        * **Move failed, rollback not started** (``move_rollback_in_progress``
          False). The move chain is dead; cancel what remains and
          enqueue cleanup (target) + start (source). Raise a critical
          ``move_stuck`` alert.

        * **Rollback started but cleanup failed** (``move_rollback_in_progress``
          True, no active jobs left). The target could not be reached;
          the source should already be running. Clear the markers and
          raise a warning ``move_rollback_failed`` alert so an operator
          can manually reclaim the target later.

        Instances with active jobs are left alone (move or rollback in
        progress).
        """
        Job = self.env["cloud.job"]
        hidden = Job._get_hidden_job_types()
        active_states = Job._active_states
        Alert = self.env["cloud.alert"].sudo()
        stuck = self.search([("move_origin_host_id", "!=", False)])
        for inst in stuck:
            in_flight = Job.search_count(
                [
                    ("instance_id", "=", inst.id),
                    ("state", "in", active_states),
                    ("job_type_id.code", "not in", hidden),
                ]
            )
            if in_flight:
                continue
            origin = inst.move_origin_host_id
            if inst.move_rollback_in_progress:
                inst.write(
                    {
                        "move_origin_host_id": False,
                        "move_target_host_id": False,
                        "move_chain_job_ids": False,
                        "move_rollback_in_progress": False,
                    }
                )
                if not Alert.search_count(
                    [
                        ("instance_id", "=", inst.id),
                        ("code", "=", "move_rollback_failed"),
                        ("state", "=", "active"),
                    ]
                ):
                    Alert.create(
                        {
                            "code": "move_rollback_failed",
                            "level": "warning",
                            "message": _(
                                "Rollback cleanup of '%(name)s' failed on "
                                "target host '%(target)s'; source host "
                                "'%(origin)s' was restarted. Manual cleanup "
                                "of the target may be needed.",
                                name=inst.name,
                                origin=origin.name or "?",
                                target=inst.move_target_host_id.name or "?",
                            ),
                            "instance_id": inst.id,
                            "project_id": (
                                inst.project_id.id if inst.project_id else False
                            ),
                            "host_id": origin.id,
                        }
                    )
                continue
            try:
                inst._do_rollback_move()
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "Stuck-move recovery failed for instance %s",
                    inst.id,
                )
                continue
            if not Alert.search_count(
                [
                    ("instance_id", "=", inst.id),
                    ("code", "=", "move_stuck"),
                    ("state", "=", "active"),
                ]
            ):
                Alert.create(
                    {
                        "code": "move_stuck",
                        "level": "critical",
                        "message": _(
                            "Move of '%(name)s' failed before cutover; "
                            "source host '%(host)s' was restarted "
                            "automatically.",
                            name=inst.name,
                            host=origin.name or "?",
                        ),
                        "instance_id": inst.id,
                        "project_id": (
                            inst.project_id.id if inst.project_id else False
                        ),
                        "host_id": origin.id,
                    }
                )

    # ── Resource estimation for auto-assign ───────────────────────────────
    _RESOURCE_DEFAULTS = {
        "odoo_cpus": 2.0,
        "db_cpus": 1.0,
        "backup_cpus": 0.5,
        "smtp_cpus": 0.25,
        "odoo_memory_limit": "2g",
        "db_memory_limit": "1g",
        "backup_memory_limit": "512m",
        "smtp_memory_limit": "256m",
    }

    @staticmethod
    def _compute_instance_resources(vals):
        """Return (total_cpus, total_ram_gb) from creation vals with defaults."""
        d = CloudInstance._RESOURCE_DEFAULTS
        cpus = sum(
            float(vals.get(k, d[k]) or d[k])
            for k in ("odoo_cpus", "db_cpus", "backup_cpus", "smtp_cpus")
        )
        ram = sum(
            parse_memory_to_gb(vals.get(k, d[k]) or d[k])
            for k in (
                "odoo_memory_limit",
                "db_memory_limit",
                "backup_memory_limit",
                "smtp_memory_limit",
            )
        )
        return cpus, ram

    # Fields tracked in the audit log when changed (never passwords)
    _AUDIT_TRACKED_FIELDS = frozenset(
        {
            "name",
            "host_id",
            "project_id",
            "environment",
            "odoo_version",
            "smtp_relay_host",
            "smtp_relay_port",
            "smtp_relay_security",
            "odoo_proxy",
            "postgres_version",
            "postgres_dbname",
            "backup_backend_id",
            "active",
        }
    )

    # Password fields: auto-generated if empty on create, preserved on write
    _PASSWORD_FIELDS = (
        "odoo_admin_password",
        "odoo_admin_user_password",
        "postgres_password",
        "smtp_relay_password",
    )
    # Subset that must always have a value (auto-generated if not provided)
    _REQUIRED_PASSWORD_FIELDS = (
        "odoo_admin_password",
        "odoo_admin_user_password",
        "postgres_password",
    )

    # ── Validation: name + custom_remote_dir fluye a shell en executors ───
    # Un valor con shell metachars (; | & $ ` " ' space \ etc.) permite
    # command injection via SSH en el host remoto. El regex estricto es la
    # defensa principal; los executors pueden seguir usando f-strings.

    @api.constrains("name")
    def _check_name_shell_safe(self):
        for inst in self:
            if not _INSTANCE_NAME_RE.match(inst.name or ""):
                raise ValidationError(
                    _(
                        "Instance name '%(name)s' is invalid. It must start with "
                        "a lowercase letter or digit and contain only lowercase "
                        "letters, digits, hyphens and underscores (max 63 chars).",
                        name=inst.name,
                    )
                )

    @api.constrains("custom_remote_dir")
    def _check_custom_remote_dir_shell_safe(self):
        for inst in self:
            v = inst.custom_remote_dir
            if not v:
                continue
            if not _REMOTE_DIR_RE.match(v) or ".." in v.split("/"):
                raise ValidationError(
                    _(
                        "Custom remote directory '%(path)s' is invalid. Use only "
                        "letters, digits, dots, hyphens and underscores in each "
                        "path segment. No '..', spaces or shell metacharacters.",
                        path=v,
                    )
                )

    @api.constrains("postgres_dbname", "postgres_username")
    def _check_pg_identifiers_shell_safe(self):
        for inst in self:
            for fname, label in (
                ("postgres_dbname", "PostgreSQL database name"),
                ("postgres_username", "PostgreSQL user"),
            ):
                v = inst[fname]
                if v and not _PG_IDENT_RE.match(v):
                    raise ValidationError(
                        _(
                            "%(label)s '%(value)s' is invalid. Use a valid "
                            "PostgreSQL identifier (1-63 chars, start with a "
                            "lowercase letter or underscore, then letters, "
                            "digits and underscores).",
                            label=label,
                            value=v,
                        )
                    )

    @api.constrains("host_id", "project_id", "name", "custom_remote_dir")
    def _check_remote_dir_unique_per_host(self):
        """Two instances landing on the same directory of the same host
        would silently clobber each other's compose files, DB volume and
        filestore. ``remote_folder`` is only unique within its own
        project, so a collision is possible across different projects
        sharing a host — catch it here instead of on the remote disk.
        """
        for inst in self:
            if not inst.host_id:
                continue
            target = inst.get_remote_dir()
            siblings = inst.sudo().search(
                [
                    ("host_id", "=", inst.host_id.id),
                    ("id", "!=", inst.id),
                ]
            )
            for sibling in siblings:
                if sibling.get_remote_dir() == target:
                    raise ValidationError(
                        _(
                            "Instance '%(name)s' would use remote directory "
                            "'%(dir)s' on host '%(host)s', already used by "
                            "instance '%(other)s'.",
                            name=inst.name,
                            dir=target,
                            host=inst.host_id.name,
                            other=sibling.name,
                        )
                    )

    def unlink(self):
        for inst in self:
            self._check_can_delete_instance(inst)
            if inst.state == "deployed":
                raise UserError(
                    _(
                        "Instance '%(name)s' is still deployed. Remove it "
                        "from the host first (use Delete on the instance "
                        "page).",
                        name=inst.name,
                    )
                )
            if inst.state != "draft":
                # 'deploying' / 'deleting': a job owns the record right
                # now and will land it in a final state on its own.
                raise UserError(
                    _(
                        "Instance '%(name)s' has a job in flight "
                        "(state: %(state)s). Wait for it to finish before "
                        "deleting the record.",
                        name=inst.name,
                        state=inst.state,
                    )
                )
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": "Instance deleted",
                    "host_id": inst.host_id.id if inst.host_id else False,
                    "project_id": inst.project_id.id if inst.project_id else False,
                    "details": inst.name,
                }
            )
        return super().unlink()

    def _finalize_removal(self, keep_in_panel):
        """Apply the outcome of a successful ``delete_instance`` job.

        Called by the executor once the remote host has been torn
        down. Back to 'draft' either way: with ``keep_in_panel=True``
        the instance stays visible as a re-deployable draft, otherwise
        the record is unlinked now that it is a draft again and the
        :meth:`unlink` guard no longer applies.
        """
        self.ensure_one()
        self.write({"running": False})
        if keep_in_panel:
            self._freeze_backup_dst()
        if self.state == "deployed":
            # Normally the teardown job already marked 'deleting' in its
            # before_execute; step through it here so a caller that
            # finalises a still-'deployed' record (a rolled-back job
            # transaction, a direct call) walks the same legal path
            # instead of hitting the transition map.
            self._transition("deleting")
        if self.state != "draft":
            # Already-'draft' records reach here on a legitimate path: a
            # deploy that failed rolled the instance back to 'draft'
            # (deploy_instance_executor.on_failure), and the teardown job
            # that cleans it up skips its own 'deleting' step for the same
            # reason. ``draft → draft`` is not in the transition map, so
            # calling _transition unconditionally raised UserError inside
            # the hook's cursor: the rollback dropped the unlink() below
            # and the record was stranded, re-enqueued by the next cron
            # tick forever. Finalising an already-draft record is a no-op.
            self._transition("draft")
        if not keep_in_panel:
            self.unlink()
            return
        # Archived: out of the daily operation, into the archived view.
        # Done last so a failure above leaves the record where an
        # operator can still see it — hiding a half-finalised instance
        # would be the one outcome nobody could act on.
        #
        # ``ic_archive_instance`` says which of the two meanings of
        # ``active = False`` this is. In core it only ever meant "hidden
        # from the lists", but the SaaS layer reads it as "the tenant is
        # gone" and cleans up on it: it deletes the Cloudflare record and
        # unlinks the tenant and project. Archiving promises the exact
        # opposite — the copy is kept and the instance can come back —
        # so without this flag the new feature would quietly call the
        # destructive path. Marked here, on the one archive route, rather
        # than on each of the four removal callers: the fewer places have
        # to be right, and a forgotten one there would skip a cleanup
        # silently.
        self.with_context(ic_archive_instance=True).write({
            "active": False,
            "archived_at": fields.Datetime.now(),
        })

    @api.model
    def _check_name_not_held_by_an_archived(self, vals):
        """Refuse a name an archived instance of the same project holds.

        ``unique (project_id, name)`` already refuses it, and refusing is
        right: the archived instance's backup chain lives at a path
        derived from that pair, so a namesake would write into it. What
        the constraint cannot do is explain itself — it raises a generic
        integrity error naming a record that is invisible in every list,
        which reads as a bug in the panel rather than as a decision.

        Checked here rather than in a ``@api.constrains`` so the message
        arrives before the INSERT: once Postgres raises, the transaction
        is poisoned and the friendlier text would have to be recovered
        from the exception.
        """
        name = (vals.get("name") or "").strip()
        project_id = vals.get("project_id")
        if not name or not project_id:
            return
        clash = self.with_context(active_test=False).search(
            [
                ("project_id", "=", project_id),
                ("name", "=", name),
                ("active", "=", False),
            ],
            limit=1,
        )
        if clash:
            raise UserError(
                _(
                    "The name %(name)s is reserved by an archived instance "
                    "of this project. Its backups live at a path built from "
                    "that name, so reusing it would write into them. Revive "
                    "that instance, or delete it if you no longer need what "
                    "it holds.",
                    name=name,
                )
            )

    @api.model_create_multi
    def create(self, vals_list):
        self._check_can_create_instance()
        for vals in vals_list:
            # Seeding ``state`` on create is legal (that is how an
            # already-running instance is imported), but ``deployed`` is
            # derived: Odoo would accept it here and then quietly
            # overwrite it from ``state``, so say so instead.
            if "deployed" in vals:
                raise UserError(
                    _(
                        "'deployed' is derived from the lifecycle state. "
                        "Pass 'state' instead."
                    )
                )
            self._check_name_not_held_by_an_archived(vals)
            for field in self._REQUIRED_PASSWORD_FIELDS:
                if not vals.get(field):
                    vals[field] = generate_password()
            project_id = vals.get("project_id")
            if project_id:
                project = self.env["cloud.project"].browse(project_id)
                # Copy project dependencies to instance if not set
                if "pip_dependencies" not in vals and project.pip_dependencies:
                    vals["pip_dependencies"] = project.pip_dependencies
                    # Provenance travels with the text it describes:
                    # inheriting the lines without their authors would
                    # hand every upstream-owned package back to the
                    # operator and turn the next bump into a conflict.
                    if "pip_dependency_sources" not in vals:
                        vals["pip_dependency_sources"] = (
                            project.pip_dependency_sources or {}
                        )
                if "apt_dependencies" not in vals and project.apt_dependencies:
                    vals["apt_dependencies"] = project.apt_dependencies
                # Auto-generate domain from wildcard
                if (
                    not vals.get("domain_ids")
                    and vals.get("host_id")
                    and vals.get("name")
                ):
                    host = self.env["cloud.host"].browse(vals["host_id"])
                    if host.wildcard_domain:
                        project_folder = project.remote_folder or ""
                        subdomain = (
                            f"{project_folder}-{vals['name']}"
                            if project_folder
                            else vals["name"]
                        )
                        hostname = f"{subdomain}.{host._subdomain_suffix()}"
                        vals["domain_ids"] = [
                            (0, 0, {"hostname": hostname}),
                        ]
            elif (
                not vals.get("domain_ids") and vals.get("host_id") and vals.get("name")
            ):
                host = self.env["cloud.host"].browse(vals["host_id"])
                if host.wildcard_domain:
                    hostname = f"{vals['name']}.{host._subdomain_suffix()}"
                    vals["domain_ids"] = [
                        (0, 0, {"hostname": hostname}),
                    ]
        # sudo on create: encrypted password fields are restricted to
        # group_cloud_developer but consultants (lower in the hierarchy)
        # are allowed to create instances. We auto-generate those passwords
        # above; writing them requires sudo. We drop back to the caller's
        # env so the returned recordset respects their normal permissions.
        records = super(CloudInstance, self.sudo()).create(vals_list).with_env(self.env)
        for inst in records:
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": "Instance created",
                    "instance_id": inst.id,
                    "host_id": inst.host_id.id if inst.host_id else False,
                    "project_id": inst.project_id.id if inst.project_id else False,
                }
            )
        # skip_apply_requirements: requirements were already merged into the
        # project's pip_dependencies (and inherited by the instance above).
        # Re-fetching from GitHub here would just duplicate the work and block
        # the request with N synchronous HTTP calls.
        Repo = self.env["cloud.instance.repo"].with_context(
            skip_apply_requirements=True,
        )
        for inst in records:
            if self.env.context.get("skip_project_repos"):
                continue  # caller will create repos explicitly
            for repo in inst.project_id.repo_ids:
                Repo.create(
                    {
                        "instance_id": inst.id,
                        "sequence": repo.sequence,
                        "url": repo.url,
                        "branch": repo.branch or "main",
                        "addons": repo.addons or "",
                        "excludes": repo.excludes or "",
                        "commit_sha": repo.commit_sha or "",
                    }
                )
        return records
