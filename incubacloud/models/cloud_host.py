import asyncio
import base64
import hashlib
import json
import logging
from contextlib import asynccontextmanager

import asyncssh
import yaml

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError
from odoo.tools import file_open

from ..net.hostname import InvalidHostname, validate_wildcard_domain
from ..net import tls_names
from ..net.trusted_proxies import invalid_ranges, parse_ranges
from . import _config_snapshot_diff as _snapshot_diff
from .cloud_host_whitelist import DEFAULT_WHITELIST
from .encrypted_char import EncryptedChar, EncryptedText
from .password_utils import generate_password
from .transport import SSHTransport

_logger = logging.getLogger(__name__)


def parse_memory_to_gb(mem_str):
    """Convert Docker memory strings like '2g', '512m', '256m' to float GB."""
    if not mem_str:
        return 0.0
    s = str(mem_str).strip().lower()
    if not s:
        return 0.0
    suffix = s[-1]
    try:
        if suffix == "g":
            return float(s[:-1])
        if suffix == "m":
            return float(s[:-1]) / 1024.0
        if suffix == "k":
            return float(s[:-1]) / (1024.0**2)
        return float(s) / (1024.0**3)
    except ValueError:
        return 0.0


def _read_traefik_template(filename):
    """Read a Traefik template file bundled with the module."""
    try:
        with file_open(f"incubacloud/data/traefik/{filename}") as f:
            return f.read()
    except Exception as e:
        _logger.warning("Could not read Traefik template %s: %s", filename, e)
        return ""


class CloudHost(models.Model):
    _name = "cloud.host"
    _inherit = ["cloud.security.mixin", "cloud.audit.tracked.mixin"]
    _description = "Cloud Host"

    name = fields.Char(
        required=True,
        translate=True,
    )
    type = fields.Selection(
        selection=[
            ("self_hosted", "Self-hosted"),
        ],
        string="Host Type",
        default="self_hosted",
        help="Type of the cloud host. Other modules may extend this selection.",
    )
    # ``ip_address``/``port``/``user`` share the ``password``/``key_file``
    # gate (developer): whoever may read the SSH credential gains nothing
    # from the endpoint being hidden, and jobs run as the user who enqueued
    # them, so a stricter gate here would break every SSH job a Developer
    # triggers. Roles below Developer get neither the endpoint nor the
    # credential.
    ip_address = fields.Char(
        string="IP Address",
        required=True,
        groups="incubacloud.group_cloud_developer",
        help="The IP address of the cloud host.",
    )
    port = fields.Integer(
        string="Port",
        required=True,
        default=22,
        groups="incubacloud.group_cloud_developer",
        help="The port to connect to the cloud host.",
    )
    password = EncryptedChar(
        string="Password",
        required=True,
        groups="incubacloud.group_cloud_developer",
        help="Password for accessing the cloud host.",
    )
    key_file = EncryptedChar(
        string="SSH Key",
        groups="incubacloud.group_cloud_developer",
        help="SSH private key for accessing the cloud host.",
    )
    known_hosts_key = fields.Text(
        string="Known Hosts Key",
        help=(
            "Server host public key in known_hosts format, captured via "
            '"Trust SSH Key". All SSH connections verify against this key.'
        ),
    )
    known_hosts_fingerprint = fields.Char(
        string="Key Fingerprint",
        compute="_compute_known_hosts_fingerprint",
        help="SHA256 fingerprint of the trusted host key, in the same form "
             "'ssh-keygen -lf' prints, so it can be compared against what "
             "any other tool reports for this machine.",
    )
    revoked_key_fingerprint = fields.Char(
        string="Revoked Key Fingerprint",
        readonly=True,
        copy=False,
        help="Fingerprint of the key dropped by the last endpoint change. "
             "Kept so the next capture can be compared against it: an "
             "identical fingerprint proves the machine did not change, "
             "which is the one check that does not depend on an external "
             "channel. Cleared once that comparison has been made.",
    )
    user = fields.Char(
        string="User",
        required=True,
        groups="incubacloud.group_cloud_developer",
        help="Username for accessing the cloud host.",
    )
    login_type = fields.Selection(
        selection=[
            ("password", "Password"),
            ("ssh_key", "SSH Key"),
        ],
        string="Login Type",
        required=True,
        default="ssh_key",
        help="Method used to authenticate to the cloud host.",
    )
    description = fields.Text(
        string="Description",
        translate=True,
    )
    tag_ids = fields.Many2many(
        comodel_name="cloud.host.tag",
        relation="cloud_host_tag_rel",
        column1="host_id",
        column2="tag_id",
        string="Tags",
    )
    instance_ids = fields.One2many(
        comodel_name="cloud.instance",
        inverse_name="host_id",
        string="Instances",
    )
    whitelist_ids = fields.One2many(
        comodel_name="cloud.host.whitelist",
        inverse_name="host_id",
        string="Whitelist",
    )
    status = fields.Selection(
        selection=[
            ("compatible", "Compatible"),
            ("degraded", "Degraded"),
            ("unsupported", "Unsupported"),
            ("checking", "Checking"),
            ("unknown", "Unknown"),
        ],
        string="Status",
        default="unknown",
        help="Compatibility status of the cloud host.",
    )
    active = fields.Boolean(default=True)
    traefik_deployed = fields.Boolean(
        string="Traefik Deployed",
        default=False,
        help="Whether the Traefik reverse proxy has been deployed on this host.",
    )

    alert_ids = fields.One2many("cloud.alert", "host_id", string="Alerts")

    # ── Hardening (layer 1: in-host SSH/firewall recipe) ──────────────────
    # Applied by ``host_hardening_executor`` via the Ansible playbook
    # ``ansible/playbooks/host_hardening.yml`` (sshd drop-in, nftables,
    # fail2ban, sysctl, unattended-upgrades, docker daemon, journald,
    # auditd). When ``hardened`` is True the host is reached as the
    # non-root operator user on the randomized SSH port stored in ``port``.
    # The network-edge firewall (layer 2, e.g. Hetzner Cloud Firewall) is
    # NOT modelled here — it follows the provider and lives in the SaaS
    # layer (``incubacloud_saas_manager``).
    hardened = fields.Boolean(
        string="Hardened",
        default=False,
        readonly=True,
        copy=False,
        help="Set by host_hardening_executor on success. When True the host "
             "is reached as the non-root operator user on the randomized SSH "
             "port stored in ``port``.",
    )
    hardened_at = fields.Datetime(
        string="Hardened at",
        readonly=True,
        copy=False,
    )
    auto_security_updates = fields.Boolean(
        string="Auto Security Updates",
        default=True,
        help="Enable unattended-upgrades for OS security patches with an "
             "automatic reboot at 04:00 when a kernel update lands. Disable "
             "for hosts whose downtime windows must be controlled manually.",
    )
    allowed_ssh_ips = fields.Char(
        string="Allowed SSH IPs",
        groups="incubacloud.group_cloud_manager",
        help="Comma-separated IPs/CIDRs allowed to SSH in addition to the "
             "operator IP (prefilled from the request that triggers "
             "hardening). Edit and re-run hardening to push the change to "
             "the host (idempotent — updates the in-host nftables allowlist).",
    )

    http_conn_rate = fields.Integer(
        string="HTTP Connection-Rate Cap",
        default=0,
        help="Per-source new-connection cap (per second) on ports 80/443, "
             "enforced on the nftables forward hook by host hardening. 0 "
             "disables it (the default). Turn it on only after rehearsing the "
             "change on a throwaway VPS — an unrehearsed drop on that hook "
             "can break Docker's published ports (see runbook RB-18). Applies "
             "on the next hardening run.",
    )

    # ── Server specs + disk health (updated by cron every 5 min) ──────────
    cpu_cores = fields.Integer(string="CPU Cores", default=0)
    ram_total_gb = fields.Float(string="RAM Total (GB)", default=0, digits=(6, 1))
    disk_usage = fields.Float(string="Disk Usage %", default=0)
    disk_free_gb = fields.Float(string="Free Disk (GB)", default=0)
    last_probed = fields.Datetime(string="Last Specs Probe")

    # ── Observability enrolment ───────────────────────────────────────────
    # Two separate facts that used to be conflated into ``last_probed``,
    # with two bugs as a result. ``last_probed`` means "somebody read this
    # host's specs", and BOTH the SSH telemetry job and the metrics reader
    # write it — so it could never answer either of the questions below:
    #
    #   * are the agents installed here?  -> metrics_agents_state
    #   * are metrics actually arriving?  -> metrics_last_seen
    #
    # Inferring the first from ``last_probed`` made every host look
    # enrolled (the SSH job sets it on all of them). Inferring the second
    # from it made the SSH fallback disable itself on the strength of its
    # own writes.
    metrics_agents_state = fields.Selection(
        [
            ("never", "Never installed"),
            ("installed", "Installed"),
            ("failed", "Install failed"),
        ],
        string="Observability agents",
        default="never",
        copy=False,
        readonly=True,
        help="Whether the metrics agents are installed on this host. "
             "Maintained by the install job and the reconciliation cron; "
             "never inferred from readings, because a reading proves the "
             "agents worked at some point, not that they are there now.",
    )
    metrics_agents_since = fields.Datetime(
        string="Agents last changed",
        copy=False,
        readonly=True,
        help="When metrics_agents_state last changed. Drives the "
             "reconciliation back-off so a host that cannot be reached is "
             "retried at a decreasing rate instead of every tick.",
    )
    metrics_agents_attempts = fields.Integer(
        string="Failed install attempts",
        default=0,
        copy=False,
        readonly=True,
        help="Consecutive failed installs. Resets on success. Drives the "
             "back-off and the alert that fires once retrying stops being "
             "reasonable.",
    )
    metrics_last_seen = fields.Datetime(
        string="Metrics last seen",
        copy=False,
        readonly=True,
        help="Last time a sample for this host came back FROM the metrics "
             "backend. Written only by the metrics reader — never by the "
             "SSH fallback — so it is the one honest answer to 'are "
             "metrics flowing?'.",
    )

    # ── Auto-assign & resource tracking ─────────────────────────────────────
    exclude_from_autoassign = fields.Boolean(
        string="Exclude from auto-assign",
        default=False,
        help="If checked, this host will not be considered for automatic "
        "instance placement.",
    )
    allocated_cpus = fields.Float(
        string="Allocated CPUs",
        compute="_compute_resource_availability",
    )
    allocated_ram_gb = fields.Float(
        string="Allocated RAM (GB)",
        compute="_compute_resource_availability",
    )
    available_cpus = fields.Float(
        string="Available CPUs",
        compute="_compute_resource_availability",
    )
    available_ram_gb = fields.Float(
        string="Available RAM (GB)",
        compute="_compute_resource_availability",
    )

    usage_ratio = fields.Float(
        string="Usage Ratio",
        compute="_compute_usage_ratio",
        help="Fraction in [0, 1] of allocated/total on the most "
        "constrained dimension (CPU or RAM). Inheriting modules "
        "can read this metric to drive auto-provisioning decisions.",
    )

    @api.depends(
        "cpu_cores",
        "ram_total_gb",
        "instance_ids.odoo_cpus",
        "instance_ids.db_cpus",
        "instance_ids.backup_cpus",
        "instance_ids.smtp_cpus",
        "instance_ids.odoo_memory_limit",
        "instance_ids.db_memory_limit",
        "instance_ids.backup_memory_limit",
        "instance_ids.smtp_memory_limit",
    )
    def _compute_resource_availability(self):
        for host in self:
            total_cpus = 0.0
            total_ram = 0.0
            for inst in host.instance_ids:
                if not host._consumes_capacity(inst):
                    continue
                total_cpus += (
                    inst.odoo_cpus + inst.db_cpus + inst.backup_cpus + inst.smtp_cpus
                )
                total_ram += sum(
                    parse_memory_to_gb(m)
                    for m in (
                        inst.odoo_memory_limit,
                        inst.db_memory_limit,
                        inst.backup_memory_limit,
                        inst.smtp_memory_limit,
                    )
                )
            host.allocated_cpus = total_cpus
            host.allocated_ram_gb = total_ram
            host.available_cpus = host.cpu_cores - total_cpus
            host.available_ram_gb = host.ram_total_gb - total_ram

    def _consumes_capacity(self, inst):
        """Whether ``inst`` counts against this host's CPU/RAM.

        Hook for inheriting modules. The base implementation counts
        every instance attached to the host; subclasses can override
        to exclude instances whose containers are intentionally
        stopped and therefore do not reserve live capacity.
        """
        self.ensure_one()
        return True

    @api.depends("allocated_cpus", "cpu_cores", "allocated_ram_gb", "ram_total_gb")
    def _compute_usage_ratio(self):
        for host in self:
            cpu = host.allocated_cpus / host.cpu_cores if host.cpu_cores else 0
            ram = host.allocated_ram_gb / host.ram_total_gb if host.ram_total_gb else 0
            host.usage_ratio = max(cpu, ram)

    _MIN_DISK_FREE_GB = 10

    #: Active alert codes that mark a host as measurably unhealthy for
    #: placement. All are produced by the metrics pipeline from real
    #: readings; ``metrics_host_absent`` is included because a host that
    #: stopped reporting is an unknown, and silence is not health.
    _PLACEMENT_VETO_ALERT_CODES = (
        "metrics_disk_critical",
        "metrics_memory_high",
        "metrics_cpu_saturated",
        "metrics_host_absent",
    )

    def _placement_vetoed_hosts(self):
        """Return the subset of ``self`` with an active overload alert.

        Used by :meth:`select_best_host` to keep placement away from
        hosts the metrics pipeline has *measured* as overloaded or
        silent, complementing the declared-allocation scoring.
        """
        if not self:
            return self.browse()
        alerts = self.env["cloud.alert"].sudo().search(
            [
                ("code", "in", list(self._PLACEMENT_VETO_ALERT_CODES)),
                ("state", "=", "active"),
                ("host_id", "in", self.ids),
            ]
        )
        return alerts.mapped("host_id") & self

    @api.model
    def select_best_host(
        self, required_cpus=3.75, required_ram_gb=3.75, additional_domain=None
    ):
        """Return the best eligible host for a new instance.

        Prefers hosts that fit the requested ``required_cpus`` and
        ``required_ram_gb`` (scored by remaining balanced headroom).
        When no eligible host fits, falls back to the one with the
        most headroom in the most constrained dimension — callers can
        place instances while any inheriting auto-provisioning layer
        reacts to the saturation signal independently.
        Only returns empty when there is no compatible host at all.

        ``additional_domain`` is an optional extra search domain ANDed
        into the eligibility filter (and therefore the fallback too), so
        inheriting layers can constrain placement without forking this
        method — e.g. the SaaS layer passes ``[('pool_id', '=', ...)]``
        to keep free and paid tenants on separate hardware.
        """
        domain = [
            ("status", "=", "compatible"),
            ("traefik_deployed", "=", True),
            ("exclude_from_autoassign", "=", False),
            ("disk_free_gb", ">=", self._MIN_DISK_FREE_GB),
        ]
        if additional_domain:
            domain += additional_domain
        eligible = self.search(domain)
        if not eligible:
            return self.browse()

        # Real-signal veto: the scoring below works on *declared*
        # allocation (Docker limits), which says nothing about actual
        # load. When the metrics pipeline has raised a measured-overload
        # alert on a host, prefer the others; if every candidate is
        # vetoed, fall through with all of them so placement still works
        # and the saturation alerts remain the operator's signal. With
        # metrics disabled there are no such alerts and behavior is
        # unchanged (fail-safe).
        vetoed = eligible._placement_vetoed_hosts()
        if vetoed and eligible - vetoed:
            eligible -= vetoed

        best_fit, best_fit_score = None, -1.0
        best_fallback, best_fallback_headroom = None, float("-inf")
        for host in eligible:
            cpu_free = host.available_cpus
            ram_free = host.available_ram_gb
            cpu_r = cpu_free / host.cpu_cores if host.cpu_cores else 0
            ram_r = ram_free / host.ram_total_gb if host.ram_total_gb else 0
            headroom = min(cpu_r, ram_r)

            if cpu_free - required_cpus >= 0 and ram_free - required_ram_gb >= 0:
                avail_cpu = cpu_free - required_cpus
                avail_ram = ram_free - required_ram_gb
                acr = avail_cpu / host.cpu_cores if host.cpu_cores else 0
                arr = avail_ram / host.ram_total_gb if host.ram_total_gb else 0
                score = 2 * min(acr, arr) + acr + arr
                if score > best_fit_score:
                    best_fit, best_fit_score = host, score

            if headroom > best_fallback_headroom:
                best_fallback, best_fallback_headroom = host, headroom

        return best_fit or best_fallback or self.browse()

    # ── Traefik configuration ───────────────────────────────────────────────
    wildcard_domain = fields.Char(
        string="Wildcard Domain",
        required=True,
        help="Base domain for wildcard certificates (e.g. *.example.com).",
    )
    traefik_panel_password = EncryptedChar(
        string="Traefik Panel Password",
        required=True,
        groups="incubacloud.group_cloud_developer",
        help="Password for the Traefik dashboard.",
    )
    traefik_config_yml = fields.Text(
        string="config.yml",
        required=True,
        default=lambda self: _read_traefik_template("config.yml"),
        help="Content of the Traefik config.yml file.",
    )
    traefik_inverseproxy_yaml = fields.Text(
        string="inverseproxy.yaml",
        required=True,
        default=lambda self: _read_traefik_template("inverseproxy.yaml"),
        help="Content of the inverseproxy.yaml file.",
    )
    traefik_yml = fields.Text(
        string="traefik.yml",
        required=True,
        default=lambda self: _read_traefik_template("traefik.yml"),
        help="Content of the traefik.yml file.",
    )

    tls_default_cert = fields.Text(
        string="Default TLS Certificate",
        help="PEM certificate chain Traefik serves when nothing else "
             "matches. Behind a CDN this is what the CDN connects to, "
             "and it can be a long-lived origin certificate rather than "
             "one obtained per hostname — a challenge cannot reach a "
             "host whose visitors arrive through a proxy that terminates "
             "TLS. Leave empty to keep obtaining certificates on the "
             "host itself.",
    )
    tls_default_key = EncryptedText(
        string="Default TLS Private Key",
        help="Private key for the certificate above. Stored encrypted "
             "and written to the host with owner-only permissions.",
    )

    client_ip_header = fields.Char(
        string="Real Client IP Header",
        help="Header a proxy in front of this host states the visitor's "
             "address in, e.g. CF-Connecting-IP. Odoo reads the last "
             "entry of the forwarded chain, and a proxy appends its own "
             "peer to that chain — so behind a second proxy the address "
             "recorded against every session is the nearer proxy's, not "
             "the visitor's. Only honoured from the trusted ranges "
             "below. Empty leaves the chain alone.",
    )

    behind_cdn = fields.Boolean(
        string="Reached Through a CDN",
        default=False,
        help="This host answers its visitors through a CDN or reverse "
             "proxy rather than directly. It changes what is rendered "
             "for it: the rate limit keys on the forwarded chain instead "
             "of the connecting address, the real-client header is "
             "honoured, and certificates are expected to be supplied "
             "rather than obtained from the host itself. Leave off for a "
             "host the world reaches directly — turning it on there "
             "collapses every visitor into one rate-limit bucket, "
             "because a direct request carries no forwarded chain to "
             "read.",
    )
    frame_ancestors = fields.Char(
        string="Frame Ancestors",
        help="CSP ``frame-ancestors`` source list for every router on this "
             "host, e.g. \"'self' https://panel.example.com\". Sets who may "
             "put these pages inside an iframe; leave empty and no header "
             "is sent, which is the default because a tenant's own site "
             "may legitimately be embedded by its customers. Beware that "
             "this is an entrypoint-wide control: it reaches every router "
             "on the host, so anything else served here — a metrics "
             "dashboard the panel embeds, say — has to appear in the list "
             "or it stops rendering. ``X-Frame-Options`` is deliberately "
             "not sent alongside: it cannot express \"self and that other "
             "origin\", so pairing them would undo the exception.",
    )
    trusted_proxy_ranges = fields.Text(
        string="Trusted Proxy Ranges",
        help="CIDR ranges of the proxies in front of this host, one per "
             "line. Traefik believes X-Forwarded-For only on connections "
             "from these, and strips it from every other — which is what "
             "makes the header unspoofable and lets the per-client rate "
             "limit key on the real caller instead of a handful of edge "
             "addresses. Leave empty when the host answers its visitors "
             "directly; the connecting address is then used as-is.",
    )
    block_direct_access = fields.Boolean(
        string="Only Accept Traffic From Trusted Proxies",
        default=False,
        help="Refuse HTTPS requests that did not come through one of the "
             "trusted proxy ranges above, so the origin cannot be reached "
             "by its address to bypass the edge. Requires trusted proxy "
             "ranges to be set — with none, this would lock the host out "
             "of its own visitors, so it is ignored.",
    )

    # ── Config drift: saved host config vs what full_setup shipped ────────
    # Same mechanism as on cloud.instance: full_setup records the hash of
    # what it actually uploaded; the compute compares it against the
    # current snapshot so an edited traefik.yml (or wildcard, panel
    # password, whitelist) stops reading as "applied" when it is not.

    applied_config_hash = fields.Char(
        copy=False,
        readonly=True,
        help="Hash of the host config snapshot the last successful "
             "full setup shipped. Compared against the current snapshot "
             "to surface unapplied changes.",
    )
    applied_config_snapshot = fields.Json(
        copy=False,
        readonly=True,
        help="The snapshot behind applied_config_hash, kept so drift can "
             "name the keys that moved.",
    )
    config_dirty = fields.Boolean(
        compute="_compute_config_dirty",
        help="True when the saved host configuration differs from what "
             "the last full setup shipped; re-running full setup "
             "applies it.",
    )

    # ── Template drift: saved host config vs what the templates declare ──
    # A second, independent question from config_dirty, and deliberately
    # not folded into it. ``config_dirty`` answers "is what we saved what
    # we shipped"; a host can be perfectly clean by that measure and still
    # be running a template from before a feature existed — which is what
    # happened when the access log was added to the seed file and reached
    # no provisioned host for months, with nothing anywhere saying so.
    #
    # The remedies differ too, which is the real reason to keep them
    # apart: config_dirty is fixed by re-running full setup, while this is
    # fixed by amending the stored copy FIRST. Merging them would tell the
    # operator to re-ship the stale config and call it done.

    template_drift = fields.Boolean(
        compute="_compute_template_drift",
        help="True when a shipped Traefik template declares something the "
             "host's saved copy does not have at all.",
    )
    template_drift_details = fields.Text(
        compute="_compute_template_drift",
        help="The specific template settings the saved copy is missing.",
    )

    def _config_snapshot_fields(self):
        """Host fields full_setup renders and uploads.

        Override in modules whose full_setup variant renders more state
        (e.g. the SaaS catch-all flag changes the Traefik config) and
        extend the list via ``super()``.
        """
        return [
            "wildcard_domain",
            "traefik_yml",
            "traefik_inverseproxy_yaml",
            "traefik_panel_password",
            "trusted_proxy_ranges",
            "block_direct_access",
            "behind_cdn",
            "tls_default_cert",
        ]

    def _render_config_snapshot(self):
        """Deterministic dict of everything full_setup ships for this
        host: the declared fields plus the whitelist hostname set."""
        self.ensure_one()
        host = self.sudo()
        snap = {f: host[f] or "" for f in self._config_snapshot_fields()}
        snap["whitelist"] = sorted(host.whitelist_ids.mapped("hostname"))
        return snap

    def _config_snapshot_hash(self):
        """SHA-256 hex digest of the canonical-JSON host snapshot."""
        self.ensure_one()
        raw = json.dumps(
            self._render_config_snapshot(), sort_keys=True, default=str,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    # Same dependency stance as cloud.instance: anchor-only on purpose;
    # HTTP requests read through a fresh cache, tests invalidate.
    def _applied_config_vals(self):
        """Write values anchoring this host's config to right now."""
        self.ensure_one()
        return {
            "applied_config_hash": self._config_snapshot_hash(),
            "applied_config_snapshot": _snapshot_diff.normalize(
                self._render_config_snapshot(),
            ),
        }

    def _config_drift_diff(self):
        """Return the snapshot keys that moved since the last setup.

        Empty when nothing differs, and for hosts anchored before the
        snapshot was stored.
        """
        self.ensure_one()
        stored = self.applied_config_snapshot
        if not stored:
            return []
        return _snapshot_diff.diff_keys(stored, self._render_config_snapshot())

    @api.depends("applied_config_hash")
    def _compute_config_dirty(self):
        """Dirty only when a full_setup recorded a hash and it no longer
        matches; hosts that never completed a setup are not flagged."""
        for host in self:
            applied = host.applied_config_hash
            if not applied:
                host.config_dirty = False
                continue
            try:
                host.config_dirty = applied != host._config_snapshot_hash()
            except Exception:
                # Same stance as the instance compute: a snapshot that
                # cannot render must not break the detail page.
                _logger.warning(
                    "config_dirty: snapshot render failed for host %s",
                    host.id, exc_info=True,
                )
                host.config_dirty = False

    # A template setting is also satisfied by the sibling listed here.
    # Not an exception list: these are the SAME feature written the other
    # way, and Traefik accepts either. Its file provider reads one
    # ``filename`` or a whole ``directory``; a deployment layer that needs
    # to drop in extra dynamic files switches to the directory form, and
    # calling that "drift" would leave a warning nobody can ever clear —
    # which is how a drift signal stops being read at all.
    _TRAEFIK_TEMPLATE_EQUIVALENTS = {
        "traefik_yml": {"providers.file.filename": "providers.file.directory"},
    }

    @staticmethod
    def _missing_template_paths(template, current, prefix=""):
        """Dotted paths ``template`` declares that ``current`` lacks.

        Only absent keys are reported. A key present with a DIFFERENT
        value is a host's own setting — its domain, its ACME e-mail, its
        ports — and reporting those would drown the real signal.

        :param template: the parsed shipped template.
        :param current: the parsed copy stored on the host.
        :param prefix: dotted path of the node being compared.
        :return: list of dotted paths, in template order.
        """
        if not isinstance(template, dict):
            return []
        if not isinstance(current, dict):
            return [prefix] if prefix else []
        missing = []
        for key, value in template.items():
            path = f"{prefix}.{key}" if prefix else key
            if key not in current:
                missing.append(path)
            else:
                missing.extend(
                    CloudHost._missing_template_paths(
                        value, current[key], path,
                    )
                )
        return missing

    def _template_drift(self):
        """Return ``{field: [missing path, ...]}`` for this host.

        Compares each stored Traefik config against the template shipped
        in this version of the module. A field that does not parse is
        skipped rather than reported: it is an operator's editing mistake,
        a different problem with a different fix, and guessing about it
        here would be noise.
        """
        self.ensure_one()
        host = self.sudo()
        drift = {}
        for field, filename in self._TRAEFIK_TEMPLATE_FIELDS.items():
            try:
                template = yaml.safe_load(_read_traefik_template(filename))
                current = yaml.safe_load(host[field] or "") or {}
            except yaml.YAMLError:
                continue
            if not isinstance(template, dict):
                continue
            equivalents = self._TRAEFIK_TEMPLATE_EQUIVALENTS.get(field, {})
            missing = [
                path
                for path in self._missing_template_paths(template, current)
                if not self._path_present(current, equivalents.get(path))
            ]
            if missing:
                drift[field] = missing
        return drift

    @staticmethod
    def _path_present(data, path):
        """True when ``path`` (dotted) resolves to a key inside ``data``."""
        if not path:
            return False
        node = data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return True

    # Only the stored side can be depended on; the reference side lives on
    # disk and changes when the module is upgraded, not when a record is
    # written. That is precisely the drift this reports, so the compute is
    # correct on read and cannot be invalidated by a write that never
    # happened.
    @api.depends("traefik_yml", "traefik_config_yml", "traefik_inverseproxy_yaml")
    def _compute_template_drift(self):
        """Flag hosts whose saved Traefik config predates a template."""
        for host in self:
            try:
                drift = host._template_drift()
            except Exception:
                # A host detail page must never fail to render because a
                # template could not be read off disk.
                _logger.warning(
                    "template_drift: comparison failed for host %s",
                    host.id, exc_info=True,
                )
                host.template_drift = False
                host.template_drift_details = ""
                continue
            host.template_drift = bool(drift)
            host.template_drift_details = "\n".join(
                f"{self._TRAEFIK_TEMPLATE_FIELDS[field]}: {path}"
                for field, paths in drift.items()
                for path in paths
            )

    @api.constrains("wildcard_domain")
    def _check_wildcard_domain(self):
        """Refuse a wildcard domain that is not a DNS hostname.

        The field feeds generated configuration nobody reads back — the
        Traefik rule, the certificate request, every instance subdomain — so
        a malformed value does not surface as a bad value, it surfaces as a
        setup job dying on ``re.error`` or a router that matches the wrong
        thing. This is the floor under both BYOD doors: a value that reaches
        the ORM without passing either of them still cannot land here.

        Shape only. ``check_internal`` and the reserved list belong to the
        callers where the value means "a public DNS name a tenant chose";
        this table also holds hosts an operator named, and ``h.local`` on an
        internal network is a fair name for one.
        """
        for host in self:
            try:
                validate_wildcard_domain(host.wildcard_domain)
            except InvalidHostname as exc:
                raise ValidationError(
                    _(
                        "Invalid wildcard domain '%(domain)s' on host "
                        "'%(host)s': %(reason)s",
                        domain=host.wildcard_domain or "",
                        host=host.display_name,
                        reason=str(exc),
                    ),
                ) from exc

    def _subdomain_suffix(self):
        """Return the wildcard domain ready to suffix an instance subdomain.

        ``wildcard_domain`` is stored in wildcard form (e.g.
        ``*.example.com``); a concrete hostname is built as
        ``f"{subdomain}.{host._subdomain_suffix()}"``. Stripping the leading
        ``*.`` turns ``*.example.com`` into ``example.com`` so the result is a
        valid hostname (``sub.example.com``) instead of ``sub.*.example.com``.
        A plain domain without the wildcard label is returned unchanged.
        """
        self.ensure_one()
        return (self.wildcard_domain or "").removeprefix("*.")

    # ── SSH connection helpers ──────────────────────────────────────────────

    def _get_ssh_private_key_bytes(self):
        """Return ``key_file`` as raw PEM/OpenSSH bytes for asyncssh.

        ``key_file`` is stored base64-encoded — the SPA uploads it via
        ``btoa()`` ([host_detail.js]) and the auto-provisioner stamps
        new VPS keys the same way. ``asyncssh.connect``'s ``client_keys``
        accepts bytes containing raw key data, but a *string* gets
        treated as a filename and triggers ``open_file()``. So we always
        return bytes here and centralise the decode.
        """
        self.ensure_one()
        if not self.key_file:
            return b""
        return base64.b64decode(self.key_file)

    def _capture_known_host_key(self):
        """Connect once bypassing host-key verification (TOFU) and store
        the server public key in ``known_hosts_key``.

        Used both by the manual 'Trust SSH Key' UI action and by autoprov
        right after a freshly contracted VPS boots — the latter has no
        human in the loop, so the capture has to happen automatically.

        When the previous key was revoked by an endpoint change, its
        fingerprint is still on the record, and comparing the two answers
        the only question the operator actually has: an identical
        fingerprint means the machine did not change and the endpoint
        edit was administrative, while a different one means something
        else is answering there. The captured key is stored either way
        (the operator asked for a capture), but a change raises a
        critical alert instead of overwriting trust silently.

        Raises ``asyncssh.Error`` / ``OSError`` on connection failure.

        :returns: dict with ``entry`` (the stored known_hosts line),
            ``fingerprint``, ``previous_fingerprint`` (``''`` when there
            was nothing to compare against) and ``changed`` (True only
            when both exist and differ).
        """
        self.ensure_one()
        connect_kw = dict(
            host=self.ip_address,
            port=self.port,
            username=self.user,
            known_hosts=None,
            agent_path=None,
        )
        if self.login_type == "ssh_key" and self.key_file:
            connect_kw["client_keys"] = [self._get_ssh_private_key_bytes()]
        else:
            connect_kw["password"] = self.password
            connect_kw["client_keys"] = None

        async def _capture():
            async with asyncssh.connect(**connect_kw) as conn:
                server_key = conn.get_server_host_key()
                key_data = (
                    server_key.export_public_key(
                        "openssh",
                    )
                    .decode()
                    .strip()
                )
                prefix = self._known_hosts_prefix(self.ip_address, self.port)
                return f"{prefix} {key_data}"

        loop = asyncio.new_event_loop()
        try:
            entry = loop.run_until_complete(_capture())
        finally:
            loop.close()
        fingerprint = self._known_hosts_fingerprint(entry)
        previous = self.revoked_key_fingerprint or ""
        changed = bool(previous and fingerprint and fingerprint != previous)
        _logger.info(
            "[host %s] captured SSH host key %s%s",
            self.name,
            fingerprint or "(no decodable key in the captured entry)",
            f" (previously trusted: {previous})" if previous else "",
        )
        self.sudo().write({
            "known_hosts_key": entry,
            # The comparison has been made; keeping the old fingerprint
            # would make the next capture report a stale verdict.
            "revoked_key_fingerprint": False,
        })
        # The host is trusted again: clear the revocation alert (if any).
        self.env["cloud.alert"].sudo().resolve_alert(
            "host_key_revoked", host=self,
        )
        self._audit_key_capture(fingerprint, previous, changed)
        if changed:
            self.env["cloud.alert"].sudo().raise_alert(
                "host_key_changed",
                _(
                    "The machine at %(ip)s:%(port)s ('%(name)s') presents a "
                    "different SSH host key than the one trusted before: "
                    "%(new)s, was %(old)s. Expected after a rebuild or a "
                    "replaced server — otherwise something else is answering "
                    "at that address. The new key is now trusted; dismiss "
                    "this alert once you have confirmed the change.",
                    name=self.name,
                    ip=self.ip_address,
                    port=self.port,
                    new=fingerprint,
                    old=previous,
                ),
                level="critical",
                host=self,
            )
        # Deliberately not auto-resolved by a later matching capture, unlike
        # ``host_key_revoked``: that one tracks a live condition (the host is
        # unreachable), while this one records that the machine's identity
        # changed once. Clearing it on any routine re-trust would retire an
        # unread security event — and would let whoever caused the change
        # erase the warning by triggering one.
        return {
            "entry": entry,
            "fingerprint": fingerprint,
            "previous_fingerprint": previous,
            "changed": changed,
        }

    def _audit_key_capture(self, fingerprint, previous, changed):
        """Record the capture and its verdict in the audit log.

        The alert is the thing that gets noticed; this is the thing that
        is still readable months later when someone asks which key this
        host was trusted with, and when.
        """
        self.ensure_one()
        if changed:
            details = f"{fingerprint} (differs from revoked {previous})"
        elif previous:
            details = f"{fingerprint} (unchanged — same machine)"
        else:
            details = fingerprint or "unparsable key"
        self.env["cloud.audit.log"].sudo().create(
            {
                "action": "SSH host key trusted",
                "host_id": self.id,
                "details": details,
            }
        )

    @staticmethod
    def _known_hosts_fingerprint(entry):
        """Return the ``SHA256:…`` fingerprint of a ``known_hosts`` line.

        Same form ``ssh-keygen -lf`` prints, which is the point: the
        fingerprint is only useful if the operator can hold it next to
        what some other tool says about the same machine.

        A ``known_hosts`` line is ``<pattern> <keytype> <base64> [comment]``,
        so the key material is the *third* field — reading any other one
        yields a value that cannot be decoded, which is how this
        fingerprint silently never got logged before.

        :returns: the fingerprint, or ``''`` when no line carries a
            decodable key (a blank entry, a comment-only file, garbage).
        """
        for line in (entry or "").splitlines():
            parts = line.split()
            if len(parts) < 3 or line.lstrip().startswith("#"):
                continue
            try:
                digest = hashlib.sha256(base64.b64decode(parts[2])).digest()
            except Exception:
                continue
            fingerprint = base64.b64encode(digest).rstrip(b"=").decode("ascii")
            return f"SHA256:{fingerprint}"
        return ""

    @api.depends("known_hosts_key")
    def _compute_known_hosts_fingerprint(self):
        for host in self:
            host.known_hosts_fingerprint = self._known_hosts_fingerprint(
                host.known_hosts_key,
            )

    @staticmethod
    def _known_hosts_prefix(ip_address, port):
        """Return the ``known_hosts`` host pattern for an (ip, port) endpoint.

        OpenSSH files a non-default port under ``[host]:port``; the bare
        ``host`` form matches port 22 and nothing else. asyncssh is laxer
        and accepts the bare form on any port, which is precisely how a
        stale label stays invisible until an OpenSSH-based consumer (any
        Ansible-backed job) reaches the same host and reports it as
        unknown.
        """
        port = int(port or 22)
        return f"[{ip_address}]:{port}" if port != 22 else str(ip_address)

    def _relabel_known_hosts_entry(self):
        """Re-file the stored key under the current endpoint, key unchanged.

        For an endpoint change that provably does not change the machine
        — host hardening only rotates the SSH port — re-running TOFU
        would trade verified trust for a blind first-contact capture.
        Relabelling keeps the key material and fixes only the address it
        is filed under.

        Safe by construction: the key itself is never touched, so a
        relabelled entry cannot come to trust a machine it did not trust
        before. A genuinely different host answering at the new endpoint
        fails the key check instead of being silently accepted.
        """
        for host in self:
            prefix = self._known_hosts_prefix(host.ip_address, host.port)
            lines = []
            for line in (host.known_hosts_key or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                lines.append(f"{prefix} {parts[1]}")
            entry = "\n".join(lines)
            if entry and entry != (host.known_hosts_key or "").strip():
                host.sudo().write({"known_hosts_key": entry})

    def _alert_host_key_revoked(self):
        """Alert that these hosts just lost their trusted SSH host key.

        A revoked key is not a cosmetic state: ``ssh_connect_kwargs``
        refuses to build connection kwargs without one and
        ``_ssh_ready_domain`` drops the host from every cron, so all
        automation against it stops until someone re-runs "Trust SSH
        Key". The audit row this accompanies is passive — nobody reads
        it — so the revocation also goes out through the alert channels.

        The message names the revoked fingerprint and says what the panel
        will do with it, rather than asking for an out-of-band check the
        platform cannot actually support: our provider exposes no console
        output or metadata carrying host keys, so the comparison against
        the previously trusted key is the verification on offer.
        """
        for host in self:
            self.env["cloud.alert"].sudo().raise_alert(
                "host_key_revoked",
                _(
                    "SSH host key revoked for '%(name)s': its endpoint changed "
                    "to %(ip)s:%(port)s, so the key trusted for the old "
                    "address (%(fingerprint)s) no longer applies. Jobs on this "
                    "host fail until you run 'Trust SSH Key'; the panel then "
                    "reports whether the newly captured key matches that "
                    "fingerprint, which is what tells you it is still the same "
                    "machine.",
                    name=host.name,
                    ip=host.ip_address,
                    port=host.port,
                    fingerprint=(
                        host.revoked_key_fingerprint or _("not recorded")
                    ),
                ),
                level="critical",
                host=host,
            )

    def ssh_connect_kwargs(self):
        """Return kwargs dict for ``asyncssh.connect()``.

        Centralises auth logic so every caller (executors, controllers,
        terminal sessions) shares the same behaviour.  When *password*
        auth is selected, ``client_keys`` is set to an empty list to
        prevent asyncssh from probing ``~/.ssh`` for default keys.
        """
        self.ensure_one()
        if not self.known_hosts_key:
            raise UserError(
                _(
                    "Host '%(name)s' has no trusted SSH key. "
                    "Open the host page and click 'Trust SSH Key' first.",
                    name=self.name,
                )
            )
        kwargs = dict(
            host=self.ip_address,
            port=self.port,
            username=self.user,
            known_hosts=asyncssh.import_known_hosts(self.known_hosts_key),
        )
        if self.login_type == "ssh_key" and self.key_file:
            kwargs["client_keys"] = [self._get_ssh_private_key_bytes()]
        else:
            kwargs["password"] = self.password
            # None (not []) tells asyncssh to skip default key loading.
            # With [], asyncssh falls through to load_default_keypairs()
            # which reads ~/.ssh/id_* — breaks when those files are
            # empty/invalid inside the container.
            kwargs["client_keys"] = None
        # Disable SSH agent socket probing inside the container.
        kwargs["agent_path"] = None
        # Bound both phases so a dead/unreachable host fails fast instead
        # of hanging the job indefinitely.
        kwargs["connect_timeout"] = 30
        kwargs["login_timeout"] = 30
        return kwargs

    def build_port_forward_cmd(
        self, local_port, remote_host="127.0.0.1", remote_port=None,
    ):
        """Return an ``ssh -N -L`` local port-forward command for this host.

        Builds the string an operator runs on their workstation to tunnel
        ``local_port`` to ``remote_host:remote_port`` on this host — used
        for panels pinned to loopback (e.g. the Traefik dashboard). Odoo
        never runs it; it is a UX convenience, so this only assembles the
        string from the host's connection fields.

        :param int local_port: local port to bind on the operator's machine
        :param str remote_host: address to reach *on the host* (default
            loopback)
        :param remote_port: remote port; defaults to *local_port*
        :return: the ``ssh`` command string
        :raises UserError: if the host has no ip_address / SSH user
        """
        self.ensure_one()
        if not (self.ip_address and self.user):
            raise UserError(
                _("Host '%(name)s' is missing its IP address or SSH user.",
                  name=self.name)
            )
        remote_port = remote_port or local_port
        # -N keeps the tunnel open without running a remote command.
        parts = [
            "ssh", "-N",
            "-L", f"{local_port}:{remote_host}:{remote_port}",
        ]
        if self.port and self.port != 22:
            parts += ["-p", str(self.port)]
        parts.append(f"{self.user}@{self.ip_address}")
        return " ".join(parts)

    @asynccontextmanager
    async def get_transport(self):
        """Open a connection and yield a ``BaseTransport`` for this host.

        Usage::

            async with host.get_transport() as transport:
                result = await transport.run("uname -s")

        To support a new backend, add a ``backend_type`` field and branch
        here to return the appropriate transport class.
        """
        self.ensure_one()
        # Trusted reader: the job that opens this transport was authorized
        # at enqueue, and the credential fields are developer-gated for raw
        # reads. Elevate here — never inside ``ssh_connect_kwargs`` itself,
        # which is a public method that returns the password.
        connect_kw = self.sudo().ssh_connect_kwargs()
        connect_kw.update(keepalive_interval=30, keepalive_count_max=10)
        async with asyncssh.connect(**connect_kw) as conn:
            yield SSHTransport(conn)

    # ── Creation: seed default whitelist ───────────────────────────────────

    # Fields tracked in the audit log when changed (never passwords)
    _AUDIT_TRACKED_FIELDS = frozenset(
        {
            "name",
            "ip_address",
            "port",
            "user",
            "wildcard_domain",
            "active",
            "login_type",
            "traefik_deployed",
        }
    )

    # Password fields that are auto-generated when left empty
    _PASSWORD_FIELDS = ("password", "traefik_panel_password")
    # Traefik fields that should fall back to template defaults when empty
    _TRAEFIK_TEMPLATE_FIELDS = {
        "traefik_config_yml": "config.yml",
        "traefik_inverseproxy_yaml": "inverseproxy.yaml",
        "traefik_yml": "traefik.yml",
    }

    @api.model_create_multi
    def create(self, vals_list):
        self._check_can_manage_hosts()
        for vals in vals_list:
            for field in self._PASSWORD_FIELDS:
                if not vals.get(field):
                    vals[field] = generate_password()
            # Replace empty traefik fields with template defaults
            for field, filename in self._TRAEFIK_TEMPLATE_FIELDS.items():
                if field in vals and not vals[field]:
                    vals[field] = _read_traefik_template(filename)
        hosts = super().create(vals_list)
        for host in hosts:
            if not host.whitelist_ids:
                self.env["cloud.host.whitelist"].create(
                    [
                        {"host_id": host.id, "hostname": h, "sequence": i * 10}
                        for i, h in enumerate(DEFAULT_WHITELIST, 1)
                    ]
                )
            host._after_provision()
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": "Host created",
                    "host_id": host.id,
                }
            )
        return hosts

    def _after_provision(self):
        """Hook called after a host record is created.

        Override in dependent modules to run post-creation logic."""

    # ── Deletion guard ─────────────────────────────────────────────────────

    def _check_no_instances(self):
        for host in self:
            if host.instance_ids:
                raise UserError(
                    _(
                        "Cannot delete host '%s': it still has %d instance(s). "
                        "Delete all instances first."
                    )
                    % (host.name, len(host.instance_ids))
                )

    def _release_external_resources(self):
        """Lifecycle hook fired before a host is archived or unlinked.

        Override in derived modules to release any external resources
        attached to the host (cloud VMs, DNS records, remote API
        registrations, etc.). No-op by default."""

    def _dismiss_alerts_on_retirement(self):
        """Close every alert still open against a host leaving the fleet.

        Retiring a host does not retire what was said about it: its open
        alerts stayed active in the panel, and the metric-based ones
        would be re-raised on the next evaluation anyway while the
        backend still held its series. ``_resolve_host`` now skips
        archived hosts, which stops the re-raising; this closes what was
        already on screen, so a decommission leaves no residue.

        Uses ``resolve_alert`` rather than a bulk write so the external
        channels see the closure: whoever was paged when the alert
        opened must see it shut, or every incident looks permanently
        open from Telegram.
        """
        Alert = self.env["cloud.alert"].sudo()
        for host in self:
            codes = set(
                Alert.search(
                    [("host_id", "=", host.id), ("state", "=", "active")],
                ).mapped("code")
            )
            for code in codes:
                Alert.resolve_alert(code, host=host)

    def unlink(self):
        self._check_can_manage_hosts()
        self._check_no_instances()
        self._release_external_resources()
        for host in self:
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": "Host deleted",
                    "details": host.name,
                }
            )
        return super().unlink()

    def write(self, vals):
        self._check_can_manage_hosts()
        if vals.get("active") is False:
            self._check_no_instances()
            self.filtered("active")._release_external_resources()
            self.filtered("active")._dismiss_alerts_on_retirement()
        # Drop empty password values so existing stored passwords are preserved
        for field in self._PASSWORD_FIELDS:
            if field in vals and not vals[field]:
                del vals[field]
        # Endpoint change → forbid while jobs are running, then drop
        # the captured SSH host key so the next connection forces a
        # fresh TOFU. The previously captured key was bound to the
        # old (ip_address, port) pair and no longer corresponds to
        # the new endpoint.
        endpoint_changing = "ip_address" in vals or "port" in vals
        endpoint_invalidated = []
        # ``{host_id: fingerprint}`` for the hosts that actually lose a key
        # they had: a host still pending its first TOFU has nothing to
        # revoke, and a write carrying a replacement key leaves the host
        # trusted. Neither deserves the alert. The fingerprint is read
        # here, while the old key is still on the record, because it is
        # what lets the next capture prove the machine did not change.
        trust_revoked = {}
        # Executors that legitimately rotate the endpoint from inside
        # their own running job (e.g. host hardening rotates the SSH
        # port as part of its workflow) opt out of the guard with this
        # context flag. Without it the executor would self-block: its
        # own job is in ``started`` state, plus any chained job sits in
        # ``wait_dependencies``, so the active-jobs count is always ≥1.
        skip_guard = self.env.context.get("skip_endpoint_change_guard")
        if endpoint_changing and not skip_guard:
            for rec in self:
                new_ip = vals.get("ip_address", rec.ip_address)
                new_port = vals.get("port", rec.port)
                if new_ip == rec.ip_address and new_port == rec.port:
                    continue
                # Initial endpoint assignment (host without a real
                # prior IP) is not a security-relevant "change": no SSH
                # host key was captured yet, no running job targets a
                # previous endpoint, nothing to invalidate. Skip the
                # guard so provisioning executors (provision_vps,
                # manual setup) can persist the assigned IP from inside
                # their own running job without self-blocking.
                #
                # ``0.0.0.0`` is the placeholder used by on-demand host
                # creation (cloud.host.ip_address is required=True, so
                # _create_on_demand stores a sentinel until the
                # provisioning job writes the real IP).
                if not rec.ip_address or rec.ip_address == "0.0.0.0":
                    continue
                active = self.env["cloud.job"].search_count(
                    [
                        ("host_id", "=", rec.id),
                        ("state", "in", self.env["cloud.job"]._active_states),
                    ]
                )
                if active:
                    raise UserError(
                        _(
                            "Cannot change endpoint of host '%(name)s' while "
                            "%(count)d job(s) are running or pending against it. "
                            "Wait for them to finish (or cancel them) and try again.",
                        )
                        % {"name": rec.name, "count": active}
                    )
                endpoint_invalidated.append(rec.id)
                if rec.known_hosts_key:
                    trust_revoked[rec.id] = self._known_hosts_fingerprint(
                        rec.known_hosts_key,
                    )
            if endpoint_invalidated:
                # Don't override an explicit caller-supplied key (manager
                # may be importing a fresh known-good key on purpose).
                vals.setdefault("known_hosts_key", False)
                if vals.get("known_hosts_key"):
                    trust_revoked = {}
        changed, old_snap = self._audit_snapshot(vals)
        result = super().write(vals)
        for host_id in endpoint_invalidated:
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": "SSH host key invalidated due to endpoint change",
                    "host_id": host_id,
                    "details": trust_revoked.get(host_id) or "",
                }
            )
        for host_id, fingerprint in trust_revoked.items():
            host = self.browse(host_id)
            host.sudo().write({"revoked_key_fingerprint": fingerprint})
            # After super().write() and after stamping the fingerprint, so
            # the message carries the new endpoint and the revoked key.
            host._alert_host_key_revoked()
        self._audit_log_changes(changed, old_snap)
        return result

    def _audit_target_vals(self):
        """Point 'Config changed' audit rows at this host."""
        self.ensure_one()
        return {"host_id": self.id}

    # ── Metrics collection (cron) ───────────────────────────────────────────

    def _ssh_ready_domain(self):
        """Domain matching hosts whose SSH layer can actually connect.

        Filters out hosts pending trust (no captured server key) or
        missing credentials for their declared ``login_type``. Skipping
        them at the cron level avoids spawning jobs that would fail on
        ``ssh_connect_kwargs()`` for hosts the operator hasn't finished
        configuring yet.
        """
        return [
            ("ip_address", "!=", False),
            ("user", "!=", False),
            ("known_hosts_key", "!=", False),
            "|",
            "&",
            ("login_type", "=", "ssh_key"),
            ("key_file", "!=", False),
            "&",
            ("login_type", "=", "password"),
            ("password", "!=", False),
        ]

    @api.model
    def cron_collect_metrics(self):
        """Called by ir.cron — queue a host_metrics job for each reachable host."""
        hosts = self.search(self._ssh_ready_domain())
        for host in hosts:
            try:
                self.env["cloud.job"].enqueue(host.id, False, "host_metrics")
            except Exception as e:
                _logger.warning(
                    "Could not enqueue metrics job for host %s: %s",
                    host.name,
                    e,
                )

    @api.model
    def cron_docker_prune(self):
        """Called by ir.cron — queue a docker_prune job for each configured host."""
        hosts = self.search(self._ssh_ready_domain())
        for host in hosts:
            try:
                # docker_prune is a manager-gated job type; the cron bot is
                # not a cloud manager, so enqueue with sudo.
                self.env["cloud.job"].sudo().enqueue(
                    host.id,
                    False,
                    "docker_prune",
                )
            except Exception as e:
                _logger.warning(
                    "Could not enqueue docker_prune job for host %s: %s",
                    host.name,
                    e,
                )

    # ── Traefik template initialization ────────────────────────────────────

    # Image version migrations: old_tag → new_tag applied to stored templates
    _TRAEFIK_IMAGE_MIGRATIONS = [
        ("traefik:2.5", "traefik:v2.11"),
    ]

    # ── Traefik metrics retrofit ───────────────────────────────────────────
    # The Traefik templates are stored PER HOST, and ``init_traefik_templates``
    # only fills EMPTY fields — so editing the seed files in this repo reaches
    # new hosts only. Existing hosts need their stored copy amended in place.
    #
    # The amendment is a minimal merge, never a regeneration: an operator may
    # have hand-edited their template, and rewriting it wholesale would
    # silently discard that. Each helper below is a no-op when the block is
    # already there, so re-running is free.

    _TRAEFIK_METRICS_ENTRYPOINT = '  metrics:\n    address: ":8082"\n'
    _TRAEFIK_METRICS_BLOCK = (
        "\n# Auto-added by IncubaCloud: per-router HTTP metrics.\n"
        "metrics:\n"
        "  prometheus:\n"
        "    entryPoint: metrics\n"
        "    addEntryPointsLabels: true\n"
        "    addRoutersLabels: true\n"
        "    addServicesLabels: true\n"
    )
    _TRAEFIK_METRICS_PORT = '      - "127.0.0.1:8082:8082"\n'

    @staticmethod
    def _add_traefik_metrics(traefik_yml):
        """Return ``traefik.yml`` with the Prometheus wiring, if missing.

        Idempotent and conservative: returns the input untouched when a
        top-level ``metrics:`` key already exists, so a host whose template
        was customised keeps whatever it configured.
        """
        import re

        if not traefik_yml:
            return traefik_yml
        if re.search(r"^metrics:", traefik_yml, re.MULTILINE):
            return traefik_yml
        out = traefik_yml
        # Add the entryPoint the metrics block refers to, unless present.
        if re.search(r"^entryPoints:", out, re.MULTILINE) and not re.search(
            r"^\s+metrics:\s*$", out, re.MULTILINE,
        ):
            out = re.sub(
                r"^(entryPoints:[ \t]*\n)",
                lambda m: m.group(1) + CloudHost._TRAEFIK_METRICS_ENTRYPOINT,
                out,
                count=1,
                flags=re.MULTILINE,
            )
        return out.rstrip("\n") + "\n" + CloudHost._TRAEFIK_METRICS_BLOCK

    # Kept short on purpose: the seed template explains at length why the
    # log goes to stdout and why headers are dropped, and that prose is
    # already on every host provisioned from it. What a retrofitted host
    # needs is the block plus a note saying where it came from.
    _TRAEFIK_ACCESS_LOG_BLOCK = (
        "\n# Auto-added by IncubaCloud: per-request access log, in JSON, on\n"
        "# stdout. This is what attributes a request to an instance; the\n"
        "# metrics carry neither client IP nor path. Headers are dropped so\n"
        "# no cookie or Authorization value is ever written to the host.\n"
        "accessLog:\n"
        "  format: json\n"
        "  bufferingSize: 100\n"
        "  fields:\n"
        "    defaultMode: keep\n"
        "    headers:\n"
        "      defaultMode: drop\n"
    )

    # Response headers the ``secure`` middleware gained after the first
    # hosts were provisioned. Ordered as in the seed template.
    _TRAEFIK_SECURITY_HEADERS = (
        ("stsSeconds", "31536000"),
        ("stsIncludeSubdomains", '"true"'),
        ("stsPreload", '"true"'),
        ("frameDeny", '"true"'),
        ("contentTypeNosniff", '"true"'),
        ("browserXssFilter", '"true"'),
        ("referrerPolicy", '"strict-origin-when-cross-origin"'),
    )

    @staticmethod
    def _add_traefik_access_log(traefik_yml):
        """Return ``traefik.yml`` with the JSON access log, if missing.

        Idempotent and conservative, like the metrics retrofit: a host that
        already declares ``accessLog`` keeps whatever it configured, even
        if it configured something else entirely.
        """
        import re

        if not traefik_yml:
            return traefik_yml
        if re.search(r"^accessLog:", traefik_yml, re.MULTILINE):
            return traefik_yml
        return (
            traefik_yml.rstrip("\n")
            + "\n"
            + CloudHost._TRAEFIK_ACCESS_LOG_BLOCK
        )

    @staticmethod
    def _add_traefik_security_headers(config_yml):
        """Return ``config.yml`` with the ``secure`` middleware completed.

        The middleware predates the headers below, so hosts provisioned
        early carry a version that only forces HSTS and TLS. The missing
        keys are appended to the mapping that is already there — the block
        is never rewritten, so an operator's own values and the comments
        around them survive.

        Idempotent, and a no-op when the structure is not the one this
        knows how to extend: the same stance as the metrics port retrofit,
        because guessing where to insert into a hand-edited file is how a
        retrofit breaks a proxy.
        """
        import re

        if not config_yml:
            return config_yml
        # The ``headers`` mapping of the ``secure`` middleware, plus every
        # line indented under it. Anchored on ``secure:`` so a different
        # middleware that also sets headers is never the one extended.
        match = re.search(
            r"^[ \t]+secure:[ \t]*\n"
            r"(?P<hindent>[ \t]+)headers:[ \t]*\n"
            r"(?P<body>(?:(?P=hindent)[ \t]+\S.*\n)*)",
            config_yml,
            re.MULTILINE,
        )
        if not match:
            return config_yml
        body = match.group("body")
        if not body:
            return config_yml
        missing = [
            (key, value)
            for key, value in CloudHost._TRAEFIK_SECURITY_HEADERS
            if not re.search(rf"^[ \t]+{key}:", body, re.MULTILINE)
        ]
        if not missing:
            return config_yml
        child_indent = re.match(r"[ \t]*", body).group(0)
        addition = "".join(
            f"{child_indent}{key}: {value}\n" for key, value in missing
        )
        return (
            config_yml[: match.end("body")]
            + addition
            + config_yml[match.end("body"):]
        )

    # The HSTS middleware, kept apart from ``secure`` on purpose. See the
    # comment carried by the seed ``config.yml``: attaching ``secure``
    # wholesale would also set ``frameDeny`` and ``stsIncludeSubdomains``,
    # neither of which is safe to turn on fleet-wide today.
    # The HSTS middleware, kept apart from ``secure`` on purpose. See the
    # comment carried by the seed ``config.yml``: attaching ``secure``
    # wholesale would also set ``frameDeny`` and ``stsIncludeSubdomains``,
    # neither of which is safe to turn on fleet-wide today.
    #
    # ``{i}`` is the indent of the ``middlewares:`` key it is inserted
    # under, so a template written with a different indent still comes out
    # as valid YAML.
    _TRAEFIK_HSTS_MIDDLEWARE = (
        "{i}  # HSTS on its own, so it can be the default middleware of "
        "the https\n"
        "{i}  # entrypoint without dragging the rest of `secure` along. "
        "Auto-added\n"
        "{i}  # by IncubaCloud; the seed template explains the reasoning "
        "in full.\n"
        "{i}  hsts:\n"
        "{i}    headers:\n"
        '{i}      forceSTSHeader: "true"\n'
        "{i}      stsSeconds: 31536000\n"
    )

    @staticmethod
    def _add_traefik_hsts_middleware(config_yml):
        """Return ``config.yml`` with the standalone ``hsts`` middleware.

        Inserted into the ``middlewares`` mapping under ``http:`` rather
        than merged into ``secure``: ``secure`` is what an operator may
        have tuned, and this one has to stay minimal because it becomes
        the entrypoint default.

        Anchored on ``http:`` so a ``middlewares:`` belonging to a router
        further down the file is never the one extended, and indented from
        the key it found so a differently indented template still parses.

        Idempotent, and a no-op when the file does not have the mapping
        this knows how to extend — the same stance as every other Traefik
        retrofit here.
        """
        import re

        if not config_yml:
            return config_yml
        if re.search(r"^[ \t]+hsts:[ \t]*$", config_yml, re.MULTILINE):
            return config_yml
        match = re.search(
            r"^http:[ \t]*\n"
            r"(?:[ \t]*\n)*"
            r"(?P<indent>[ \t]+)middlewares:[ \t]*\n",
            config_yml,
            re.MULTILINE,
        )
        if not match:
            return config_yml
        block = CloudHost._TRAEFIK_HSTS_MIDDLEWARE.format(
            i=match.group("indent"),
        )
        return config_yml[: match.end()] + block + config_yml[match.end():]

    @staticmethod
    def _add_traefik_entrypoint_hsts(traefik_yml, config_yml):
        """Return ``traefik.yml`` with ``hsts@file`` on the https entrypoint.

        This is the only place a response header can be added once and
        reach every router on the host: the per-project routers come from
        copier and reference nothing but their own middlewares.

        Interlocked with the middleware on purpose. An entrypoint naming a
        middleware the file provider does not define is not a missing
        header — Traefik answers 500 on every router of that entrypoint,
        which is the whole host. So *config_yml* is checked first, and a
        file where the middleware retrofit did not apply gets no reference
        either. The pair fails closed.

        Only handles the shape the seed template ships — ``https:`` with an
        ``http:`` child. A host whose entrypoint was hand-edited into
        something else is left untouched, for the same reason.

        :param traefik_yml: the host's stored static configuration.
        :param config_yml: the host's stored dynamic configuration, the one
            that has to define ``hsts``.
        """
        import re

        if not traefik_yml:
            return traefik_yml
        if not config_yml or not re.search(
            r"^[ \t]+hsts:[ \t]*$", config_yml, re.MULTILINE,
        ):
            return traefik_yml
        match = re.search(
            r"^[ \t]+https:[ \t]*\n"
            r"(?P<hindent>[ \t]+)http:[ \t]*\n"
            r"(?P<body>(?:(?P=hindent)[ \t]+\S.*\n)*)",
            traefik_yml,
            re.MULTILINE,
        )
        if not match:
            return traefik_yml
        body = match.group("body")
        if not body or re.search(r"^[ \t]+middlewares:", body, re.MULTILINE):
            return traefik_yml
        child_indent = re.match(r"[ \t]*", body).group(0)
        addition = (
            f"{child_indent}# Auto-added by IncubaCloud: default middleware "
            f"for every router\n"
            f"{child_indent}# on this entrypoint. Without it no HSTS header "
            f"reaches the\n"
            f"{child_indent}# tenants, because their routers are generated "
            f"by copier.\n"
            f"{child_indent}middlewares:\n"
            f"{child_indent}  - hsts@file\n"
        )
        return (
            traefik_yml[: match.end("body")]
            + addition
            + traefik_yml[match.end("body"):]
        )

    # Per-source-IP rate limit, kept minimal because it becomes an
    # entrypoint default alongside ``hsts``. ``{i}`` is the indent of the
    # ``middlewares:`` key it is inserted under, so a template written with
    # a different indent still comes out as valid YAML.
    _TRAEFIK_RATELIMIT_MIDDLEWARE = (
        "{i}  # Per-source-IP rate limit. Auto-added by IncubaCloud as an "
        "https\n"
        "{i}  # entrypoint default so it reaches every copier-generated "
        "tenant\n"
        "{i}  # router, throttling by client IP before a request hits "
        "Odoo's\n"
        "{i}  # pbkdf2 login. Direct traffic only: a host behind a trusted "
        "CDN\n"
        "{i}  # must set sourceCriterion.ipStrategy. Tunable live — this "
        "file\n"
        "{i}  # is watched by Traefik.\n"
        "{i}  ratelimit:\n"
        "{i}    rateLimit:\n"
        "{i}      average: 300\n"
        "{i}      period: 1m\n"
        "{i}      burst: 100\n"
    )

    @staticmethod
    def _add_traefik_ratelimit_middleware(config_yml):
        """Return ``config.yml`` with the ``ratelimit`` middleware.

        Inserted into the ``middlewares`` mapping under ``http:``, exactly
        like the standalone ``hsts`` middleware, because it becomes the
        second entrypoint default. Anchored on ``http:`` so a
        ``middlewares:`` belonging to a router further down the file is
        never the one extended, and indented from the key it found so a
        differently indented template still parses.

        Idempotent, and a no-op when the file does not have the mapping
        this knows how to extend — the same stance as every other Traefik
        retrofit here.

        :param config_yml: the host's stored dynamic configuration.
        :return: the configuration with ``ratelimit`` defined, or the input
            untouched.
        """
        import re

        if not config_yml:
            return config_yml
        if re.search(r"^[ \t]+ratelimit:[ \t]*$", config_yml, re.MULTILINE):
            return config_yml
        match = re.search(
            r"^http:[ \t]*\n"
            r"(?:[ \t]*\n)*"
            r"(?P<indent>[ \t]+)middlewares:[ \t]*\n",
            config_yml,
            re.MULTILINE,
        )
        if not match:
            return config_yml
        block = CloudHost._TRAEFIK_RATELIMIT_MIDDLEWARE.format(
            i=match.group("indent"),
        )
        return config_yml[: match.end()] + block + config_yml[match.end():]

    @staticmethod
    def _add_traefik_entrypoint_ratelimit(traefik_yml, config_yml):
        """Return ``traefik.yml`` with ``ratelimit@file`` on https.

        The second default middleware of the https entrypoint, appended to
        the ``middlewares`` list the HSTS retrofit already put there. Same
        reach as HSTS: the per-project routers come from copier and
        reference nothing but their own middlewares, so an entrypoint
        default is the only place a control can be added once and apply to
        every instance on the host.

        Interlocked with the middleware, and fails closed: an entrypoint
        naming a middleware the file provider does not define makes Traefik
        answer 500 on every router of that entrypoint — the whole host. So
        *config_yml* is checked first, and a file where the middleware
        retrofit did not apply gets no reference either.

        Idempotent, and a no-op when the https entrypoint has no
        ``middlewares`` list to extend (HSTS runs first and creates it, so
        in practice it is always there) or the shape is not the seed's — an
        operator's own chain is never appended to blind, the same stance as
        the HSTS entrypoint retrofit.

        :param traefik_yml: the host's stored static configuration.
        :param config_yml: the host's stored dynamic configuration, the one
            that has to define ``ratelimit``.
        :return: the static configuration referencing ``ratelimit@file``, or
            the input untouched.
        """
        import re

        if not traefik_yml:
            return traefik_yml
        if not config_yml or not re.search(
            r"^[ \t]+ratelimit:[ \t]*$", config_yml, re.MULTILINE,
        ):
            return traefik_yml
        if re.search(
            r"^[ \t]+-[ \t]+ratelimit@file[ \t]*$", traefik_yml, re.MULTILINE,
        ):
            return traefik_yml
        match = re.search(
            r"^[ \t]+https:[ \t]*\n"
            r"(?P<hindent>[ \t]+)http:[ \t]*\n"
            r"(?P<body>(?:(?P=hindent)[ \t]+\S.*\n)*)",
            traefik_yml,
            re.MULTILINE,
        )
        if not match:
            return traefik_yml
        body = match.group("body")
        mw = re.search(
            r"^(?P<mindent>[ \t]+)middlewares:[ \t]*\n"
            r"(?P<items>(?:(?P=mindent)[ \t]+-[ \t]+\S.*\n)+)",
            body,
            re.MULTILINE,
        )
        if not mw:
            return traefik_yml
        if "hsts@file" not in mw.group("items"):
            # Not the IncubaCloud-managed chain but an operator's own list
            # (HSTS puts ``hsts@file`` on the one we manage). Appending to a
            # hand-written chain blind is how a retrofit breaks a proxy, so
            # it is left untouched — the same stance as the HSTS retrofit.
            return traefik_yml
        item_indent = re.match(r"[ \t]*", mw.group("items")).group(0)
        addition = f"{item_indent}- ratelimit@file\n"
        insert_at = match.start("body") + mw.end("items")
        return traefik_yml[:insert_at] + addition + traefik_yml[insert_at:]


    # Every block the frame-guard render writes carries this marker, so a
    # later render removes exactly what it wrote and nothing else. The
    # value is a policy that changes — a new origin starts embedding the
    # panel, or the feature is turned off — so this has to *set* the
    # middleware, not add it once.
    _FRAMEGUARD_MARK = "# incubacloud:frameguard"

    #: File-provider middleware naming who may frame this host's pages.
    _FRAMEGUARD_MIDDLEWARE = "frameguard"

    @staticmethod
    def _strip_frameguard_blocks(text):
        """Remove every block a previous frame-guard render wrote.

        A marked line takes the lines nested under it with it, so the whole
        ``headers`` mapping disappears together. A blank line ends a block:
        nothing written here contains one.

        :param text: a Traefik configuration document.
        :return: the document without any marked block.
        :rtype: str
        """
        if not text or CloudHost._FRAMEGUARD_MARK not in text:
            return text
        lines = text.splitlines(keepends=True)
        kept = []
        index = 0
        while index < len(lines):
            line = lines[index]
            if CloudHost._FRAMEGUARD_MARK not in line:
                kept.append(line)
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            index += 1
            while index < len(lines) and lines[index].strip():
                nested = len(lines[index]) - len(lines[index].lstrip())
                if nested <= indent:
                    break
                index += 1
        return "".join(kept)

    @staticmethod
    def _set_traefik_frameguard_middleware(config_yml, sources):
        """Return ``config.yml`` with the ``frameguard`` middleware set.

        Idempotent by replacement rather than by addition: *sources* is a
        policy that moves, and a stale allow-list is the failure this must
        not produce. An empty *sources* removes the middleware and returns
        the host to sending no frame header at all.

        Only ``Content-Security-Policy`` is written, never
        ``X-Frame-Options``. The latter has no syntax for "myself and that
        other origin" — ``ALLOW-FROM`` is gone from current browsers — so
        sending it alongside would block precisely the embed the source
        list was written to keep.

        Anchored on ``http:`` so a ``middlewares:`` belonging to a router
        further down is never the one extended, and indented from the key
        it found so a differently indented template still parses. A no-op
        when the file does not have the mapping this knows how to extend.

        :param config_yml: the host's stored dynamic configuration.
        :param sources: the ``frame-ancestors`` source list, or empty.
        :return: the patched configuration, or the input untouched.
        :rtype: str
        """
        import re

        if not config_yml:
            return config_yml
        text = CloudHost._strip_frameguard_blocks(config_yml)
        value = (sources or "").strip()
        if not value:
            return text
        match = re.search(
            r"^http:[ \t]*\n"
            r"(?:[ \t]*\n)*"
            r"(?P<indent>[ \t]+)middlewares:[ \t]*\n",
            text,
            re.MULTILINE,
        )
        if not match:
            return text
        i = match.group("indent")
        # Quoted so a value carrying ``:`` or ``#`` — every URL does —
        # stays one YAML scalar; single quotes are doubled, which is how
        # YAML escapes them inside a single-quoted scalar.
        escaped = value.replace("'", "''")
        # The marker rides on the key line, not above it: the strip takes
        # a marked line together with everything nested deeper, so a
        # marker on its own line would remove itself and leave the
        # mapping behind.
        block = (
            f"{i}  {CloudHost._FRAMEGUARD_MIDDLEWARE}:"
            f"  {CloudHost._FRAMEGUARD_MARK}\n"
            f"{i}    headers:\n"
            f"{i}      contentSecurityPolicy: 'frame-ancestors {escaped}'\n"
        )
        return text[: match.end()] + block + text[match.end():]

    @staticmethod
    def _set_traefik_entrypoint_frameguard(traefik_yml, config_yml):
        """Return ``traefik.yml`` referencing ``frameguard@file``, or not.

        The third default middleware of the https entrypoint, alongside
        HSTS and the rate limit, and it reaches the host the same way: the
        per-project routers come from copier and reference nothing but
        their own middlewares.

        Interlocked with the middleware and fails closed, like its two
        siblings — an entrypoint naming a middleware the file provider does
        not define makes Traefik answer 500 on every router of that
        entrypoint, the whole host. So *config_yml* decides: the reference
        is written only when the middleware is defined there, and taken
        back out when it is not, which is what turns the feature off.

        :param traefik_yml: the host's stored static configuration.
        :param config_yml: the host's stored dynamic configuration.
        :return: the patched configuration, or the input untouched.
        :rtype: str
        """
        import re

        if not traefik_yml:
            return traefik_yml
        wanted = bool(config_yml) and bool(
            re.search(
                rf"^[ \t]+{CloudHost._FRAMEGUARD_MIDDLEWARE}:[ \t]*(?:#.*)?$",
                config_yml,
                re.MULTILINE,
            )
        )
        present = bool(
            re.search(
                r"^[ \t]+-[ \t]+frameguard@file[ \t]*$",
                traefik_yml,
                re.MULTILINE,
            )
        )
        if wanted == present:
            return traefik_yml
        if not wanted:
            return "".join(
                line
                for line in traefik_yml.splitlines(keepends=True)
                if not re.match(r"^[ \t]+-[ \t]+frameguard@file[ \t]*$",
                                line.rstrip("\n"))
            )
        match = re.search(
            r"^[ \t]+https:[ \t]*\n"
            r"(?P<hindent>[ \t]+)http:[ \t]*\n"
            r"(?P<body>(?:(?P=hindent)[ \t]+\S.*\n)*)",
            traefik_yml,
            re.MULTILINE,
        )
        if not match:
            return traefik_yml
        body = match.group("body")
        mw = re.search(
            r"^(?P<mindent>[ \t]+)middlewares:[ \t]*\n"
            r"(?P<items>(?:(?P=mindent)[ \t]+-[ \t]+\S.*\n)+)",
            body,
            re.MULTILINE,
        )
        if not mw:
            return traefik_yml
        if "hsts@file" not in mw.group("items"):
            # An operator's own chain, not the one we manage. Appending to
            # it blind is how a retrofit breaks a proxy.
            return traefik_yml
        item_indent = re.match(r"[ \t]*", mw.group("items")).group(0)
        addition = f"{item_indent}- frameguard@file\n"
        insert_at = match.start("body") + mw.end("items")
        return traefik_yml[:insert_at] + addition + traefik_yml[insert_at:]

    # Every block written by the trusted-proxy retrofits carries this
    # marker, so re-rendering can remove exactly what it wrote before and
    # nothing else. These lists move — a CDN publishes new ranges — so the
    # retrofit has to *set* the value, not merely add it once, and it has
    # to be able to take it back out when the feature is turned off.
    _TRUSTED_PROXY_MARK = "# incubacloud:trusted-proxies"

    #: File-provider middleware that refuses connections which did not
    #: come through a trusted proxy. Referenced from the https entrypoint.
    _TRUSTED_PROXY_MIDDLEWARE = "trusted-proxies-only"

    @staticmethod
    def _strip_trusted_proxy_blocks(text):
        """Remove every block a previous trusted-proxy render wrote.

        A marked line takes the lines nested under it with it, so a
        multi-line ``forwardedHeaders`` mapping disappears whole. A blank
        line ends a block: nothing written here contains one, so an empty
        line that follows belonged to the document already.

        :param text: a Traefik configuration document
        :return: the document without any marked block
        :rtype: str
        """
        if not text or CloudHost._TRUSTED_PROXY_MARK not in text:
            return text
        lines = text.splitlines(keepends=True)
        kept = []
        index = 0
        while index < len(lines):
            line = lines[index]
            if CloudHost._TRUSTED_PROXY_MARK not in line:
                kept.append(line)
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            index += 1
            while index < len(lines) and lines[index].strip():
                nested = len(lines[index]) - len(lines[index].lstrip())
                if nested <= indent:
                    break
                index += 1
        return "".join(kept)

    @staticmethod
    def _patch_traefik_yml_trusted_proxies(
        traefik_yml, ranges, block_direct=False,
    ):
        """Return ``traefik.yml`` declaring which proxies may be believed.

        Traefik discards every inbound ``X-Forwarded-For`` unless the
        connection came from an address listed under
        ``entryPoints.<name>.forwardedHeaders.trustedIPs``. That one
        setting is what separates a header the client wrote from one our
        own edge appended, and therefore what every per-client control
        downstream rests on. Without it, an allowlist reading the
        forwarded chain matches nothing and rejects all traffic — so this
        is rendered before anything that reads that chain.

        This is static configuration: Traefik reads it at start-up only,
        so a change here needs the proxy restarted, unlike the dynamic
        documents it watches.

        Idempotent by replacement rather than by addition — the ranges
        move, and a stale list is exactly the failure this must not
        produce. An empty *ranges* removes the declaration and returns the
        host to believing nothing.

        :param traefik_yml: the host's stored static configuration
        :param ranges: CIDR strings of the proxies in front of this host
        :param bool block_direct: also refuse requests that did not come
            through one of those proxies. Ignored when *ranges* is empty,
            where it would reject every visitor the host has.
        :return: the patched configuration, or the input untouched when
            the entrypoints are not the shape this knows
        :rtype: str
        """
        import re

        if not traefik_yml:
            return traefik_yml
        text = CloudHost._strip_trusted_proxy_blocks(traefik_yml)
        entries = [
            str(item).strip() for item in (ranges or []) if str(item).strip()
        ]
        if not entries:
            return text
        mark = CloudHost._TRUSTED_PROXY_MARK

        # Anchored on the port, which appears once each and cannot be
        # confused with the nested ``http:`` key the https entrypoint
        # carries under it.
        def _declare(match):
            indent = match.group("indent")
            listed = "".join(
                indent + '    - "' + entry + '"\n' for entry in entries
            )
            return (
                match.group(0) + "\n"
                + indent + "forwardedHeaders:  " + mark + "\n"
                + indent + "  trustedIPs:\n"
                + listed.rstrip("\n")
            )

        patched, count = re.subn(
            r'^(?P<indent>[ \t]+)address:[ \t]*"(?::80|:443)"[ \t]*$',
            _declare,
            text,
            flags=re.MULTILINE,
        )
        if not count:
            return text
        if not block_direct:
            return patched
        return CloudHost._add_traefik_entrypoint_trusted_only(patched)

    @staticmethod
    def _add_traefik_entrypoint_trusted_only(traefik_yml):
        """Return ``traefik.yml`` refusing traffic that skipped the edge.

        Prepends the allowlist middleware to the https entrypoint chain so
        it runs before the rest: a request that did not come through a
        trusted proxy is refused without HSTS, rate-limit accounting or a
        backend lookup. It goes on the entrypoint because the per-project
        routers come from copier and reference only their own middlewares,
        so this is the one place a control reaches every instance.

        The http entrypoint is left alone on purpose — it only redirects
        to https, and a redirect leaks nothing.

        Same conservative stance as the other entrypoint retrofits: only
        the chain we manage (the one carrying ``hsts@file``) is touched.

        :param traefik_yml: static configuration, already carrying the
            trusted ranges
        :return: the patched configuration, or the input untouched
        :rtype: str
        """
        import re

        name = CloudHost._TRUSTED_PROXY_MIDDLEWARE
        if not traefik_yml or (name + "@file") in traefik_yml:
            return traefik_yml
        match = re.search(
            r"^[ \t]+https:[ \t]*\n"
            r"(?P<hindent>[ \t]+)http:[ \t]*\n"
            r"(?P<body>(?:(?P=hindent)[ \t]+\S.*\n)*)",
            traefik_yml,
            re.MULTILINE,
        )
        if not match:
            return traefik_yml
        mw = re.search(
            r"^(?P<mindent>[ \t]+)middlewares:[ \t]*\n"
            r"(?P<items>(?:(?P=mindent)[ \t]+-[ \t]+\S.*\n)+)",
            match.group("body"),
            re.MULTILINE,
        )
        if not mw or "hsts@file" not in mw.group("items"):
            return traefik_yml
        item_indent = re.match(r"[ \t]*", mw.group("items")).group(0)
        addition = (
            item_indent + "- " + name + "@file  "
            + CloudHost._TRUSTED_PROXY_MARK + "\n"
        )
        insert_at = match.start("body") + mw.start("items")
        return traefik_yml[:insert_at] + addition + traefik_yml[insert_at:]

    @staticmethod
    def _patch_config_yml_trusted_proxies(
        config_yml, ranges, block_direct=False, behind_cdn=False,
    ):
        """Return ``config.yml`` keyed on the client behind the proxy.

        Two independent edits:

        * with *behind_cdn*, the per-source rate limit starts keying on
          the forwarded client instead of the connecting address, so a
          whole CDN edge stops being one bucket shared by everyone
          behind it;
        * with *block_direct* and ranges, the allowlist middleware the
          entrypoint references is defined.

        The rate-limit edit turns on *behind_cdn* rather than on ranges
        being present, and that distinction is the whole point: a
        forwarded-chain strategy on a host that answers its visitors
        directly reads an absent header, and Traefik then keys every one
        of those visitors under the same empty value — one shared bucket
        for the whole internet, which is worse than the address-keyed
        limit it replaced. Declaring trusted ranges on such a host is
        still meaningful (it decides which forwarded headers are
        stripped); keying the limit on them is not.

        :param config_yml: the host's stored dynamic configuration
        :param ranges: CIDR strings of the proxies in front of this host
        :param bool block_direct: also define the allowlist middleware
        :param bool behind_cdn: the host is reached through those proxies,
            so every request carries a chain the limit can key on
        :return: the patched configuration
        :rtype: str
        """
        import re

        if not config_yml:
            return config_yml
        text = CloudHost._strip_trusted_proxy_blocks(config_yml)
        entries = [
            str(item).strip() for item in (ranges or []) if str(item).strip()
        ]
        if not entries:
            return text
        mark = CloudHost._TRUSTED_PROXY_MARK

        # Rate limit: key on the forwarded client.
        match = behind_cdn and re.search(
            r"^(?P<indent>[ \t]+)ratelimit:[ \t]*\n"
            r"(?P=indent)[ \t]+rateLimit:[ \t]*\n"
            r"(?P<body>(?:(?P=indent)[ \t]{2,}\S.*\n)+)",
            text,
            re.MULTILINE,
        )
        if match:
            # Indent taken from the block's own first line, not computed
            # from the key above it: a template written with a different
            # step still comes out as valid YAML.
            body_indent = re.match(r"[ \t]*", match.group("body")).group(0)
            addition = (
                body_indent + "sourceCriterion:  " + mark + "\n"
                + body_indent + "  ipStrategy:\n"
                # depth 1 reads the rightmost forwarded entry: the address
                # the trusted proxy saw and appended itself. Anything the
                # caller wrote sits to the left of it and is never read.
                + body_indent + "    depth: 1\n"
            )
            text = (
                text[: match.end("body")] + addition
                + text[match.end("body"):]
            )
        if not block_direct:
            return text

        # Allowlist middleware for the https entrypoint to reference.
        name = CloudHost._TRUSTED_PROXY_MIDDLEWARE
        mw_match = re.search(
            r"^http:[ \t]*\n"
            r"(?:[ \t]*\n)*"
            r"(?P<indent>[ \t]+)middlewares:[ \t]*\n",
            text,
            re.MULTILINE,
        )
        if not mw_match:
            return text
        indent = mw_match.group("indent")
        source_range = "".join(
            indent + '        - "' + entry + '"\n' for entry in entries
        )
        block = (
            indent + "  " + name + ":  " + mark + "\n"
            + indent + "    ipWhiteList:\n"
            # No ipStrategy on this one: it must read the address the
            # connection was actually opened from. Reading the forwarded
            # chain here would let a caller hand us the value being
            # checked, and every direct visitor would share one empty key.
            + indent + "      sourceRange:\n"
            + source_range
        )
        return text[: mw_match.end()] + block + text[mw_match.end():]

    def _shipped_traefik_yml(self):
        """Return the static configuration a setup run should upload.

        The stored template plus whatever this host's proxy posture adds.
        Executors render through here instead of reading the field, so a
        host whose trusted ranges moved ships the new ones on its next run
        without the stored copy ever being rewritten behind the operator.

        :rtype: str
        """
        self.ensure_one()
        ranges = self._effective_trusted_proxy_ranges()
        return self._patch_traefik_yml_trusted_proxies(
            self.traefik_yml or "", ranges, self.block_direct_access,
        )

    def _shipped_config_yml(self):
        """Return the dynamic configuration a setup run should upload.

        :rtype: str
        """
        self.ensure_one()
        ranges = self._effective_trusted_proxy_ranges()
        return self._patch_config_yml_trusted_proxies(
            self.traefik_config_yml or "", ranges, self.block_direct_access,
            self.behind_cdn,
        )

    def _effective_tls_default(self):
        """Return the certificate this host serves by default.

        The host's own pair wins. Modules that hold one certificate for
        a whole zone override this and hand it to every host they know
        sits behind their CDN, which is what keeps a self-hosted host
        from being given somebody else's.

        :return: ``(certificate, private key)``, both possibly empty.
        :rtype: tuple
        """
        self.ensure_one()
        return (self.tls_default_cert or "", self.tls_default_key or "")

    def _effective_client_ip_header(self):
        """Return the header this host states the visitor's address in.

        The host's own field wins. Modules that know a CDN answers for
        a host, and therefore which header that CDN writes, override
        this so nobody has to type it per host.

        :rtype: str
        """
        self.ensure_one()
        return (self.client_ip_header or "").strip()

    def _tls_default_covers(self, hostname):
        """Return whether this host's default certificate serves *name*.

        Asked of the certificate, not of the base domain, so the answer
        stays right when the certificate changes shape: a wildcard for
        one zone today, a purchased certificate covering two zones
        tomorrow, an internal CA on a self-hosted host.

        :param str hostname: the name a router on this host serves
        :rtype: bool
        """
        self.ensure_one()
        cert, key = self._effective_tls_default()
        if not (cert and key):
            return False
        return tls_names.covers(hostname, tls_names.certificate_names(cert))

    def _name_is_proxied(self, hostname):
        """Return whether requests for *name* reach this host via a CDN.

        The host-wide flag is the whole answer here: a host declared to
        be reached through a CDN is reached that way for everything it
        serves. Modules that decide name by name — because they own the
        zone and move it in batches — narrow this.

        :param str hostname: the name a router on this host serves
        :rtype: bool
        """
        self.ensure_one()
        return bool(self.behind_cdn)

    def _router_tls_mode(self, hostname):
        """Return how a router for *hostname* should obtain its cert.

        ``acme`` asks a certificate authority, which needs the authority
        to reach this host — so it is the answer whenever visitors still
        do. ``default`` serves the certificate the host already holds,
        and is the answer only once a CDN stands in front of the name
        *and* that certificate covers it.

        The pair matters. A proxied name whose certificate does not
        cover it gets ``acme`` even though ACME cannot succeed either:
        there is no third answer, and leaving the request in place keeps
        the failure where the logs already look for it rather than
        silently serving a certificate for somebody else's name.

        :param str hostname: the name the router serves
        :return: ``'default'`` or ``'acme'``
        :rtype: str
        """
        self.ensure_one()
        if self._name_is_proxied(hostname) and self._tls_default_covers(
            hostname
        ):
            return "default"
        return "acme"

    def _shipped_tls_default_yml(self):
        """Return the dynamic document naming the default certificate.

        Empty when there is nothing to serve, which is also the signal
        to remove the file: a store pointing at files that are not there
        makes Traefik answer every TLS handshake with its own throwaway
        certificate.

        :rtype: str
        """
        self.ensure_one()
        cert, key = self._effective_tls_default()
        if not (cert and key):
            return ""
        return (
            "# Auto-generated by IncubaCloud. Do not edit by hand.\n"
            "tls:\n"
            "  stores:\n"
            "    default:\n"
            "      defaultCertificate:\n"
            "        certFile: /etc/certs/default.crt\n"
            "        keyFile: /etc/certs/default.key\n"
        )

    @staticmethod
    def _acme_entry_names(entry):
        """Return the names one stored certificate presents itself for.

        :param entry: one element of a resolver's ``Certificates``
        :rtype: list
        """
        if not isinstance(entry, dict):
            return []
        domain = entry.get("domain")
        if not isinstance(domain, dict):
            return []
        names = [domain.get("main")] + list(domain.get("sans") or [])
        return [tls_names.normalise(name) for name in names if name]

    def _prune_acme_store(self, document):
        """Return this host's certificate store without what it no longer uses.

        Every certificate in the store is published under the default
        TLS store at start-up and chosen by server name before any
        router is consulted. So changing a router to serve the host's
        own certificate does not change what the visitor is handed: the
        stored one keeps winning until it is gone from the store. That
        is why a name moved behind a CDN goes on presenting a
        certificate it can no longer renew, with nothing in the logs to
        say so.

        An entry is retired only when *every* name on it is one this
        host now answers with its own certificate. One covering a
        mixture is left alone: retiring it would take down the names
        still reached directly, which have nothing else to be served
        with.

        A store that cannot be read is returned untouched. Rewriting one
        this version does not understand would cost every certificate on
        it, and the names that still need them cannot be re-obtained
        from behind a CDN.

        :param str document: contents of Traefik's ``acme.json``
        :return: ``(document, retired names)``, the document unchanged
            when nothing was retired
        :rtype: tuple
        """
        self.ensure_one()
        try:
            store = json.loads(document or "")
        except (TypeError, ValueError):
            return document, []
        if not isinstance(store, dict):
            return document, []
        retired = []
        for resolver in store.values():
            if not isinstance(resolver, dict):
                continue
            certificates = resolver.get("Certificates")
            if not isinstance(certificates, list):
                continue
            kept, dropped = [], []
            for entry in certificates:
                names = self._acme_entry_names(entry)
                if names and all(
                    self._router_tls_mode(name) == "default"
                    for name in names
                ):
                    dropped.extend(names)
                    continue
                kept.append(entry)
            if dropped:
                resolver["Certificates"] = kept
                retired.extend(dropped)
        if not retired:
            return document, []
        return json.dumps(store), retired

    @api.constrains("trusted_proxy_ranges")
    def _check_trusted_proxy_ranges(self):
        """Refuse a range list carrying an entry that is not a network.

        A typo here narrows who we believe without saying so, and the
        request path skips what it cannot read. That is the same silent
        failure the whole mechanism exists to prevent, so it is refused
        where somebody can still fix it.

        :raise ValidationError: naming the unusable entries
        """
        for host in self:
            bad = invalid_ranges(host.trusted_proxy_ranges)
            if bad:
                raise ValidationError(_(
                    "These are not address ranges: %(entries)s. Write one "
                    "CIDR range per line, for example 198.51.100.0/24 or "
                    "2001:db8::/32.",
                    entries=", ".join(bad),
                ))

    def _trusted_proxy_source(self):
        """Return where this host's effective proxy ranges come from.

        Shown next to the override field so an operator can see whether
        the list being applied is the one in front of them or one a
        policy supplies. Modules that supply ranges override this
        alongside :meth:`_effective_trusted_proxy_ranges`.

        :return: ``'host'`` when the host's own field is set, ``'none'``
            when nothing applies
        :rtype: str
        """
        self.ensure_one()
        return "host" if parse_ranges(self.trusted_proxy_ranges) else "none"

    def _effective_trusted_proxy_ranges(self):
        """Return the ranges whose ``X-Forwarded-For`` this host believes.

        The host's own field wins, so an operator can always pin a single
        host. Otherwise nothing: core imposes no proxy on anybody. Modules
        that know the platform's own hosts answer behind a CDN override
        this and supply that list, which is what keeps a self-hosted host
        from inheriting a policy written for ours.

        :rtype: list
        """
        self.ensure_one()
        return parse_ranges(self.trusted_proxy_ranges)

    @staticmethod
    def _add_traefik_metrics_port(inverseproxy_yaml):
        """Publish the metrics port on loopback, if not already published.

        Idempotent: keyed on the port mapping itself, so a template that
        already exposes 8082 (however it was written) is left alone.
        """
        import re

        if not inverseproxy_yaml or "8082:8082" in inverseproxy_yaml:
            return inverseproxy_yaml
        if not re.search(r'^\s+-\s+"443:443"\s*$', inverseproxy_yaml, re.MULTILINE):
            # Unrecognisable ports block — leave it rather than guess.
            return inverseproxy_yaml
        return re.sub(
            r'^(\s+-\s+"443:443"[ \t]*\n)',
            lambda m: m.group(1) + CloudHost._TRAEFIK_METRICS_PORT,
            inverseproxy_yaml,
            count=1,
            flags=re.MULTILINE,
        )

    @api.model
    def init_traefik_templates(self):
        """
        Populate Traefik config fields for all existing hosts.
        Called from a data XML <function> on module install/upgrade.
        Fills empty fields with the current template and migrates
        outdated Traefik image versions in stored templates.
        """
        config = _read_traefik_template("config.yml")
        inverseproxy = _read_traefik_template("inverseproxy.yaml")
        traefik = _read_traefik_template("traefik.yml")

        hosts = self.search([])
        for host in hosts:
            vals = {}
            if not host.traefik_config_yml:
                vals["traefik_config_yml"] = config
            if not host.traefik_inverseproxy_yaml:
                vals["traefik_inverseproxy_yaml"] = inverseproxy
            if not host.traefik_yml:
                vals["traefik_yml"] = traefik
            # Migrate outdated Traefik image versions in stored templates
            current = (
                vals.get("traefik_inverseproxy_yaml", host.traefik_inverseproxy_yaml)
                or ""
            )
            for old_tag, new_tag in self._TRAEFIK_IMAGE_MIGRATIONS:
                if old_tag in current:
                    current = current.replace(old_tag, new_tag)
                    vals["traefik_inverseproxy_yaml"] = current
                    _logger.info(
                        "Migrated Traefik image %s → %s for host: %s",
                        old_tag,
                        new_tag,
                        host.name,
                    )

            # Retrofit the Prometheus metrics wiring onto stored templates.
            # Per-instance HTTP metrics come from Traefik, and Traefik only
            # emits them when configured — editing the seed files alone
            # would leave every existing host silently unmonitored.
            with_metrics = self._add_traefik_metrics(
                vals.get("traefik_yml", host.traefik_yml),
            )
            if with_metrics != (vals.get("traefik_yml", host.traefik_yml)):
                vals["traefik_yml"] = with_metrics
                _logger.info(
                    "Added Traefik metrics config for host: %s", host.name,
                )
            # Same reasoning for the access log: the proxy only writes one
            # when told to, so a host still on the pre-accessLog template
            # produces nothing for "Recent requests" to read, forever, and
            # an empty list is indistinguishable from a quiet instance.
            with_log = self._add_traefik_access_log(
                vals.get("traefik_yml", host.traefik_yml),
            )
            if with_log != (vals.get("traefik_yml", host.traefik_yml)):
                vals["traefik_yml"] = with_log
                _logger.info(
                    "Added Traefik access log config for host: %s", host.name,
                )

            # The security headers the ``secure`` middleware gained later.
            with_headers = self._add_traefik_security_headers(
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_headers != (
                vals.get("traefik_config_yml", host.traefik_config_yml)
            ):
                vals["traefik_config_yml"] = with_headers
                _logger.info(
                    "Added Traefik security headers for host: %s", host.name,
                )

            # HSTS. Two edits that only work together: the middleware
            # goes in the dynamic config, and the reference to it in the
            # static one. A host that got only the first would keep
            # serving without the header and look fixed.
            with_hsts = self._add_traefik_hsts_middleware(
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_hsts != (
                vals.get("traefik_config_yml", host.traefik_config_yml)
            ):
                vals["traefik_config_yml"] = with_hsts
                _logger.info(
                    "Added Traefik hsts middleware for host: %s", host.name,
                )

            with_ep_hsts = self._add_traefik_entrypoint_hsts(
                vals.get("traefik_yml", host.traefik_yml),
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_ep_hsts != (vals.get("traefik_yml", host.traefik_yml)):
                vals["traefik_yml"] = with_ep_hsts
                _logger.info(
                    "Added Traefik https entrypoint HSTS for host: %s",
                    host.name,
                )

            # Rate limit. The same interlocked pair as HSTS: the
            # middleware in the dynamic config, the reference to it on the
            # https entrypoint. Throttles every instance on the host by
            # client IP before a login flood can reach Odoo's pbkdf2.
            with_rl = self._add_traefik_ratelimit_middleware(
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_rl != (
                vals.get("traefik_config_yml", host.traefik_config_yml)
            ):
                vals["traefik_config_yml"] = with_rl
                _logger.info(
                    "Added Traefik ratelimit middleware for host: %s",
                    host.name,
                )

            with_ep_rl = self._add_traefik_entrypoint_ratelimit(
                vals.get("traefik_yml", host.traefik_yml),
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_ep_rl != (vals.get("traefik_yml", host.traefik_yml)):
                vals["traefik_yml"] = with_ep_rl
                _logger.info(
                    "Added Traefik https entrypoint ratelimit for host: %s",
                    host.name,
                )

            # Frame guard. Off unless the host names who may embed it,
            # because a tenant's own site may legitimately be framed by
            # its customers and this control reaches every router here.
            # Same interlocked pair, and it *sets* rather than adds: the
            # source list moves, and clearing it has to take the header
            # back out.
            with_fg = self._set_traefik_frameguard_middleware(
                vals.get("traefik_config_yml", host.traefik_config_yml),
                host.frame_ancestors,
            )
            if with_fg != (
                vals.get("traefik_config_yml", host.traefik_config_yml)
            ):
                vals["traefik_config_yml"] = with_fg
                _logger.info(
                    "Set Traefik frameguard middleware for host: %s",
                    host.name,
                )

            with_ep_fg = self._set_traefik_entrypoint_frameguard(
                vals.get("traefik_yml", host.traefik_yml),
                vals.get("traefik_config_yml", host.traefik_config_yml),
            )
            if with_ep_fg != (vals.get("traefik_yml", host.traefik_yml)):
                vals["traefik_yml"] = with_ep_fg
                _logger.info(
                    "Set Traefik https entrypoint frameguard for host: %s",
                    host.name,
                )

            with_port = self._add_traefik_metrics_port(
                vals.get(
                    "traefik_inverseproxy_yaml",
                    host.traefik_inverseproxy_yaml,
                ),
            )
            if with_port != vals.get(
                "traefik_inverseproxy_yaml", host.traefik_inverseproxy_yaml,
            ):
                vals["traefik_inverseproxy_yaml"] = with_port

            if vals:
                host.write(vals)
                _logger.info("Initialized Traefik templates for host: %s", host.name)
