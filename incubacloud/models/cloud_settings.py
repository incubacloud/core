import logging
import os
import re
import uuid

from psycopg2 import sql

from odoo import _, api, fields, models, tools
from odoo.exceptions import UserError, ValidationError

from ..net.trusted_proxies import invalid_ranges, parse_ranges
from .encrypted_char import EncryptedChar, EncryptedFieldMixin
from .password_utils import (
    generate_password,
    is_on_primary_key,
    key_is_configured,
    rotate_value,
)

_logger = logging.getLogger(__name__)

#: Container log rotation shipped in every instance's compose override.
#: Same figures as the ``daemon.json`` written by ``host_hardening``, so
#: a stack rotates identically whether or not its host was hardened.
CONTAINER_LOG_MAX_SIZE_DEFAULT = "10m"
CONTAINER_LOG_MAX_FILE_DEFAULT = 3
#: Days of Odoo's own log kept on the host as a dated archive
#: (``logs/odoo.log.<date>.gz``), the window an operator can still open
#: after noticing something days later.
ODOO_LOG_ARCHIVE_DAYS_DEFAULT = 60
#: Cost bounds for reading the archive back through the panel. They
#: guard someone else's host, so the operator owns the numbers rather
#: than discovering them baked into a release.
LOG_DOWNLOAD_MAX_MB_DEFAULT = 64
LOG_SEARCH_MAX_FILES_DEFAULT = 60
LOG_SEARCH_TIMEOUT_S_DEFAULT = 30

# Image used by the ephemeral container that empties an archived
# instance's backup prefix. The same image the doodba template renders
# for the ``backup`` service, because it is what the credentials and the
# destination were written for; the purge itself only needs boto3.
ARCHIVED_PURGE_IMAGE_DEFAULT = (
    "ghcr.io/tecnativa/docker-duplicity-postgres-s3:latest"
)
#: Docker's ``max-size`` grammar, restricted to one canonical spelling
#: (lower-case unit) so the override reads the same on every host.
_CONTAINER_LOG_MAX_SIZE_RE = re.compile(r"^[1-9]\d*[kmg]$")


class CloudSettings(models.Model):
    """System-wide IncubaCloud settings — singleton.

    Stores sensitive credentials that must not live in
    ``ir.config_parameter`` (plain text in the database).
    Fields use ``EncryptedChar`` (Fernet) so the DB column
    always holds ``enc:<token>``.
    """

    _name = "cloud.settings"
    _inherit = ["cloud.security.mixin"]
    _description = "IncubaCloud Settings"

    # ── GitHub credentials ─────────────────────────────────────────────────

    github_pat = EncryptedChar(
        string="GitHub Personal Access Token",
        groups="incubacloud.group_cloud_manager",
        help=(
            "PAT used as fallback when no GitHub App is configured. "
            "Stored encrypted — never exposed in logs or API responses."
        ),
    )

    # ── Job log retention ──────────────────────────────────────────────────
    # cloud.job.log.chunk grows monotonically (every SSH command stream
    # writes hundreds of rows per job). The daily purge cron deletes
    # chunks older than this many days that belong to terminal jobs.
    # Active jobs always keep their full log regardless of age.

    job_log_retention_days = fields.Integer(
        string='Job log retention (days)',
        default=30,
        help='Number of days to keep job log chunks (cloud.job.log.chunk) '
             'for terminated jobs. Active jobs are never purged. Set to 0 '
             'to disable purging entirely (table will grow unbounded).',
    )

    # cloud.job rows themselves also grow monotonically (the fourth leak
    # of the retention family). They feed the instance timeline in the
    # UI, so the window is much longer than the chunk one: purging a job
    # trims visible history to this many days.
    job_retention_days = fields.Integer(
        string='Job retention (days)',
        default=180,
        help='Number of days to keep terminal cloud.job rows (done, '
             'failed, cancelled). Active jobs are never purged. Purging '
             'a job also removes its remaining log chunks and trims the '
             'instance timeline to this window. Set to 0 to disable '
             'purging entirely (table will grow unbounded).',
    )

    # ── GitHub event retention ────────────────────────────────────────────
    # cloud.github.event stores the raw webhook JSON. Push payloads for
    # large monorepos are 100 KB+. Keeping them forever bloats backups
    # and keeps commit metadata (authors, messages, diff refs) around
    # beyond any useful audit window. Two-stage retention:
    #   * After ``github_event_truncate_days``: payload is replaced by a
    #     compact stub (event_type, ref, sha, action, original_size).
    #     Event row is preserved for audit; only the blob is shed.
    #   * After ``github_event_retention_days``: the row itself is
    #     unlinked. Only rows with ``processed=True`` are touched —
    #     unprocessed/error events remain until an operator investigates.

    github_event_retention_days = fields.Integer(
        string='GitHub event retention (days)',
        default=90,
        help='Number of days to keep processed cloud.github.event rows. '
             'Unprocessed/error rows are never auto-deleted. Set to 0 to '
             'disable deletion entirely.',
    )
    github_webhook_silence_hours = fields.Integer(
        string='GitHub webhook silence alert (hours)',
        default=48,
        help='Raise an alert when no webhook delivery has been recorded '
             'for this many hours while a GitHub App is configured. An '
             'edge allowlist that has fallen behind GitHub\'s published '
             'ranges fails by dropping deliveries silently, so the only '
             'way to notice is to watch for the silence itself. Set to 0 '
             'to disable the check.',
    )
    github_webhook_allowlist = fields.Boolean(
        string='Restrict the GitHub webhook at the edge',
        default=False,
        help="Publish a Traefik router that only lets GitHub's own "
             "published address ranges reach /cloud/github/webhook, so a "
             "forged signature is refused before its body is read. Off by "
             "default because it is only correct for deliveries from "
             "github.com: an installation served by GitHub Enterprise "
             "delivers from its own addresses and would be locked out.",
    )
    #: Where this installation serves its own panel from. Empty by
    #: default: core cannot know its public name, and guessing it from
    #: ``web.base.url`` is unsafe — Odoo rewrites that on an admin login
    #: unless it has been frozen. An installation that wants its own
    #: webhook endpoint protected fills these in; a layer that already
    #: knows the answer supplies them instead.
    panel_host_id = fields.Many2one(
        comodel_name='cloud.host',
        string='Panel Host',
        ondelete='set null',
        help="The host whose Traefik serves this panel. Only that host "
             "publishes a router for the panel's own webhook endpoint.",
    )
    panel_hostname = fields.Char(
        string='Panel Hostname',
        help="Public hostname this panel answers on, e.g. "
             "panel.example.com. Used to route its own GitHub webhook "
             "endpoint through the source allowlist.",
    )
    panel_service_url = fields.Char(
        string='Panel Backend URL',
        help="Where the host's Traefik reaches this panel, e.g. "
             "http://odoo:8069. It is a container name on the host's own "
             "network, not a public address.",
    )
    panel_tls_domain = fields.Char(
        string='Panel Wildcard Certificate',
        help="Optional. Serve the panel's webhook router from an "
             "existing wildcard certificate, e.g. *.example.com, instead "
             "of asking for one issued for the hostname itself.",
    )

    trusted_proxy_ranges = fields.Text(
        string='Trusted proxy ranges',
        help="CIDR ranges of the proxies in front of this installation, "
             "one per line. Only when a request arrives from one of them "
             "is its X-Forwarded-For header believed, so this is what "
             "makes every per-client control here — rate limits, "
             "allowlists, audit lines — key on the real caller instead of "
             "the proxy. Leave empty when nothing fronts this "
             "installation: the connecting address is then used as-is, "
             "which is over-restrictive but never spoofable.",
    )

    github_event_truncate_days = fields.Integer(
        string='GitHub event payload truncation (days)',
        default=7,
        help='After this many days, the raw JSON payload of a processed '
             'cloud.github.event is replaced by a compact stub (event '
             'type, ref, sha, action). Set to 0 to disable truncation.',
    )

    # ── Doodba template used to scaffold instances ────────────────────────
    # Every deploy runs ``copier copy`` against this template. Left
    # unpinned, each deploy silently picks up whatever is on the
    # template's default branch at that moment, so two instances created
    # a week apart can be built from different upstream revisions and a
    # breaking change upstream lands on the next tenant deploy with no
    # signal here. Pinning a tag makes template upgrades a decision.

    copier_template_url = fields.Char(
        string='Doodba template',
        default='gh:Tecnativa/doodba-copier-template',
        help='Copier source for new instances. Change it to deploy from a '
             'fork of the doodba template.',
    )
    # Default pin: v9.6.1, validated 2026-07-30 by rendering the template
    # in a sandbox with the exact answers the deploy executor emits
    # (domains/redirects in Traefik labels, backup DST, secrets excluded
    # from the answers file by the template's own secret marking). Bump
    # via the runbook (RB-15): sandbox render first, then staging canary.
    copier_template_ref = fields.Char(
        string='Doodba template version',
        default='v9.6.1',
        help='Git tag/branch/commit to pin the template to (copier '
             "--vcs-ref), e.g. 'v9.6.1'. Empty means the template's "
             'default branch: deploys then track upstream automatically '
             'and an upstream change can alter the next deploy without '
             'warning. The effective ref is recorded in the job log.',
    )

    # ── Archived instances ─────────────────────────────────────────────────
    # An archived instance has no stack left to purge its chain from, so
    # the deletion runs one throwaway container on the host. The image is
    # a setting rather than a constant because the template can move to
    # another tag and this must be able to follow without a code deploy —
    # and because the day it is wrong, the symptom is a purge that cannot
    # start and a record that refuses to be deleted.

    archived_purge_image = fields.Char(
        string="Archived purge image",
        default=ARCHIVED_PURGE_IMAGE_DEFAULT,
        required=True,
        help="Container image run once to empty an archived instance's "
             "backup prefix. Must have boto3 available; the duplicity "
             "image the backup service uses already does.",
    )

    # ── Container log rotation ─────────────────────────────────────────────
    # Emitted per service in the docker-compose.override.yml every deploy
    # and rebuild writes (``_resource_override_content``). doodba logs
    # to stdout and the template sets no ``logging:``, so without this a
    # host that never ran host_hardening keeps json-file logs until the
    # disk is full. Global on purpose: read at render time, outside the
    # per-instance config snapshot, so changing it never marks the fleet
    # as drifted — it lands on each instance's next rebuild.

    container_log_max_size = fields.Char(
        string="Container log max size",
        default=CONTAINER_LOG_MAX_SIZE_DEFAULT,
        required=True,
        help="Size at which Docker rotates each container's log file, as "
             "a positive integer followed by k, m or g (e.g. 10m). Applies "
             "to every service of every instance from its next deploy or "
             "rebuild.",
    )
    container_log_max_file = fields.Integer(
        string="Container log files kept",
        default=CONTAINER_LOG_MAX_FILE_DEFAULT,
        required=True,
        help="Number of rotated log files Docker keeps per container "
             "(the current one included). Older files are deleted; the "
             "retained history is at most size x files per container.",
    )
    log_download_max_mb = fields.Integer(
        string="Log download cap (MB)",
        default=LOG_DOWNLOAD_MAX_MB_DEFAULT,
        required=True,
        help="Largest compressed log download the panel will serve. A "
             "day whose rotation stalled can be gigabytes, and the "
             "whole answer is held in memory while it is sent.",
    )
    log_search_max_files = fields.Integer(
        string="Log search: days swept",
        default=LOG_SEARCH_MAX_FILES_DEFAULT,
        required=True,
        help="How many archived days a cross-day log search reads, "
             "newest first. Each one is decompressed on the instance's "
             "host, so this is a bound on that host's CPU.",
    )
    log_search_timeout_s = fields.Integer(
        string="Log search timeout (s)",
        default=LOG_SEARCH_TIMEOUT_S_DEFAULT,
        required=True,
        help="Seconds a cross-day log search may run on the host "
             "before it is cut short. A search that is cut short says "
             "so instead of reporting no matches.",
    )
    odoo_log_archive_days = fields.Integer(
        string="Odoo log archive (days)",
        default=ODOO_LOG_ARCHIVE_DAYS_DEFAULT,
        required=True,
        help="Days of Odoo's own log kept per instance on its host, as "
             "one dated file per day (compressed from the day before "
             "yesterday). Applied by logrotate on the host; a change "
             "reaches an instance on its next deploy or rebuild.",
    )

    # ── Rate limiting caps ────────────────────────────────────────────────
    # Read by ``cloud.rate.limit._get_cap`` when throttling the two
    # abuse-prone public/auth'd endpoints. Values ending in ``per_min``
    # use minute windows; GitHub import values use hour windows. Setting
    # any of them to 0 falls back to the
    # documented default so a misconfigured 0 can't accidentally
    # lock every request out.

    rate_limit_webhook_per_min = fields.Integer(
        string='GitHub webhook (per IP, per minute)',
        default=300,
        help='Max requests/min the ``/cloud/github/webhook`` endpoint '
             'accepts from a single client IP. GitHub can burst heavily '
             'on a push to a monorepo with many workflow triggers, so '
             'the default is generous; lower it if you see abuse. Set '
             'to 0 to fall back to the documented default (300).',
    )
    rate_limit_terminal_per_min = fields.Integer(
        string='Terminal open (per instance, per minute)',
        default=30,
        help='Max ``/cloud/terminal/open`` calls/min targeting the same '
             'cloud.instance, across all users. Protects the remote '
             'host from a multi-operator debug storm.',
    )
    rate_limit_terminal_user_per_min = fields.Integer(
        string='Terminal open (per user, per minute)',
        default=10,
        help='Max ``/cloud/terminal/open`` calls/min from a single '
             'internal user. Caps both legitimate human operators and '
             'any compromised account running a script. Each opened '
             'session holds an SSH connection + PTY buffer until '
             'SESSION_TIMEOUT.',
    )
    rate_limit_connect_per_min = fields.Integer(
        string='Connect as user (per instance, per minute)',
        default=20,
        help='Max connect-as calls/min targeting the same cloud.instance, '
             'across all users. Each call opens an SSH connection and runs '
             'a script inside the tenant container.',
    )
    rate_limit_logs_per_min = fields.Integer(
        string="Log reads per minute (per user)",
        default=60,
        help="Cap on log reads per user: the live tail, the day "
             "listing and reading one archived day. The viewer polls "
             "the live tail every 4 seconds, so a cap below ~15 breaks "
             "a single open viewer. 0 falls back to the default.",
    )
    rate_limit_log_search_per_min = fields.Integer(
        string="Log searches per minute (per user)",
        default=6,
        help="Cap on cross-day log searches and log downloads per user. "
             "A search decompresses up to the configured number of days "
             "on the instance's host; a download ships a whole day "
             "through the panel. 0 falls back to the default.",
    )
    rate_limit_connect_user_per_min = fields.Integer(
        string='Connect as user (per user, per minute)',
        default=10,
        help='Max connect-as calls/min from a single panel user. Caps a '
             'compromised account from enumerating tenant users or minting '
             'impersonation tokens in bulk.',
    )
    rate_limit_github_previews_per_hour = fields.Integer(
        string='GitHub import previews (per user, per hour)',
        default=10,
        help='Max bounded GitHub preview operations per panel user and hour. '
             'A busy global import lock is rejected before consuming this '
             'quota. 0 falls back to the default (10).',
    )
    rate_limit_github_imports_per_hour = fields.Integer(
        string='GitHub project imports (per user, per hour)',
        default=5,
        help='Max bounded GitHub project imports per panel user and hour. '
             'An admitted attempt counts even if GitHub or parsing fails '
             'later. 0 falls back to the default (5).',
    )

    # ── Backup usage alert default ────────────────────────────────────────
    # Per-backend ``alert_threshold_pct`` can opt in (1–100), opt out
    # (-1 = disabled), or inherit (0 = use this default). This system-wide
    # default keeps the per-backend form short for the common case while
    # still letting an operator dial it per backend when needed.

    default_backup_alert_threshold_pct = fields.Integer(
        string='Default backup alert threshold (%)',
        default=80,
        help='Default percentage at which an email alert is sent when a '
             "backup backend's usage approaches its quota. Per-backend "
             "overrides win — set the backend's own threshold to 0 to "
             'inherit this value, -1 to disable, or 1–100 for an explicit '
             'value.',
    )

    # ── Observability ──────────────────────────────────────────────────────
    # Agents push metrics outbound to a central VictoriaMetrics; the panel
    # reads it back over PromQL to evaluate ``cloud.metric.rule``. All of
    # it is inert until ``metrics_enabled`` is set, so the feature can ship
    # and be deployed before anyone turns it on.

    metrics_enabled = fields.Boolean(
        string='Enable observability',
        default=False,
        help='Master switch. When off, no agent is installed, the metric '
             'rules are not evaluated and no metrics alert is raised.',
    )
    metrics_central_url = fields.Char(
        string='Metrics backend URL',
        help='Base URL the PANEL uses to query metrics (PromQL). It must '
             'resolve from inside the panel container — e.g. '
             'http://host.docker.internal:8428 for a co-located backend, '
             'or its public URL when it lives on another server.',
    )
    metrics_remote_write_url = fields.Char(
        string='Remote-write URL',
        help='Endpoint each host AGENT pushes to. It must resolve from '
             'inside the agent container on every host — so 127.0.0.1 is '
             'almost never right: that is the agent itself. Use '
             'http://host.docker.internal:8428/api/v1/write only for '
             'agents on the same server as the backend, and a public '
             'HTTPS URL for every other host. Outbound only: no inbound '
             'port is opened, which is what keeps BYOH and NAT hosts '
             'working.',
    )
    metrics_account = fields.Char(
        string='Metrics account',
        readonly=True,
        copy=False,
        help='Identity this panel authenticates as against the central, '
             'and the label the central FORCES on every series it writes '
             'for us. It is what keeps one panel from reading or poisoning '
             "another's data, so it is never accepted from the agent: the "
             'central derives it from the authenticated user. A '
             'self-hosted panel generates its own; in SaaS mode the '
             'manager assigns it.',
    )
    # Where the central runs, and who it currently lets in. Both are
    # written by the deployment from what it actually did, never from
    # intent: they exist precisely so that a later job can tell the state
    # of the gateway apart from the state of this database.
    metrics_central_host_id = fields.Many2one(
        'cloud.host',
        string='Metrics central host',
        readonly=True,
        copy=False,
        ondelete='set null',
        help='Host carrying the central stack, recorded when a '
             'deployment of it succeeds. The account sync targets it. '
             'Empty means no central was ever deployed from this panel, '
             'and accounts cannot be granted until one is.',
    )
    metrics_accounts_deployed = fields.Text(
        string='Accounts on the central',
        readonly=True,
        copy=False,
        help='Metrics accounts the last successful deployment or sync '
             "wrote into the gateway's access-control list, one per "
             'line. An account minted but absent from here cannot '
             'authenticate yet, so handing out its credential would '
             'produce a permanent 401 rather than observability.',
    )
    def _desired_metrics_accounts(self):
        """Return ``[(user, token), ...]`` that should exist on the central.

        The single source of the access-control list. Core knows exactly
        one account: this panel's own. The SaaS layer overrides this to
        append one entry per tenant, because only it knows tenants exist.

        Deliberately on the model rather than on the executor that writes
        the list: the reconciliation has to compare the same set without
        being an executor, and two places assembling "who should have
        access" is precisely how the gateway and the database drifted
        apart in the first place.
        """
        user, token = self._get_system()._metrics_auth()
        return [(user, token)] if (user and token) else []

    def _grafana_oidc(self, accounts):
        """Return the OIDC settings Grafana should authenticate with.

        Empty here: core ships to partners, who have no identity provider
        of ours, so the playbook wires ``auth.proxy`` instead and trusts
        a header set by the panel's own reverse proxy. The SaaS manager
        overrides this.

        On the model rather than on the executor for the same reason the
        account list is: both the deployment and the account sync need
        it, and a job that had to re-declare it would eventually be one
        that forgot to.

        :param accounts: ``[(user, token), ...]`` the run is built from,
            used to map each account to its own organisation.
        """
        return {}

    def _grafana_org_mapping(self, accounts):
        """Return Grafana's ``org_mapping`` string, one entry per account.

        Format is ``claim:org:role`` entries separated by spaces. No
        wildcard entry: a wildcard would send any authenticated user into
        an organisation it does not own. Everyone gets Viewer except this
        panel's own account, which the operator needs Editor on to manage
        dashboards and datasources.

        :param accounts: ``[(user, token), ...]`` to map.
        """
        system_account = self._get_system().metrics_account
        return " ".join(
            "%s:%s:%s" % (
                account, account,
                "Editor" if account == system_account else "Viewer",
            )
            for account, _token in accounts
        )

    metrics_remote_write_token = EncryptedChar(
        string='Metrics credential',
        help='Password half of this panel\'s metrics account (the user '
             'half is ``metrics_account``). Presented as HTTP basic auth '
             'both when the agents push and when the panel queries. '
             'Scoped: it can only write series labelled with this account '
             'and only read those same series, so a host that leaks it '
             'exposes nothing beyond what that panel could already see. '
             'Stored encrypted; written to each host as root-only 0600.',
    )
    grafana_admin_password = EncryptedChar(
        string='Grafana admin password',
        help='Grafana\'s own administrative credential. Never leaves the '
             'central: the gateway authenticates callers with the '
             'operator credential and swaps this one in before proxying, '
             'so rotating it is a redeploy rather than a change in every '
             'place that talks to Grafana.',
    )
    metrics_operator_token = EncryptedChar(
        string='Operator read credential',
        help='Second credential, for the UNFILTERED read used by the '
             "operator's own Grafana organisation. Only meaningful on the "
             'panel that owns the central, and deliberately never written '
             'to any host — that is the whole point of keeping it apart '
             'from the account credential above.',
    )
    metrics_retention_days = fields.Integer(
        string='Metrics retention (days)',
        default=90,
        help='How long the central keeps series. Passed to the central '
             'deployment playbook.',
    )
    grafana_base_url = fields.Char(
        string='Grafana base URL',
        help='Base URL of the Grafana embedded in the panel, e.g. '
             'https://grafana.example.com. Empty hides the Monitoring tab.',
    )

    # ── Metrics account helpers ────────────────────────────────────────────

    def _ensure_metrics_account(self):
        """Return this panel's metrics account, generating one if absent.

        The identifier must be unique across every panel that shares a
        central, so it is random rather than derived from anything local:
        two self-hosted panels would otherwise both call themselves
        ``acct_1``. Generated once and then stable — it is the label every
        historical series carries, and series cannot be relabelled after
        ingestion.

        :return: the account identifier, e.g. ``acct_9f2c1ab4d0e7``.
        """
        settings = self._get_system()
        if settings.metrics_account:
            return settings.metrics_account
        account = 'acct_%s' % uuid.uuid4().hex[:12]
        settings.sudo().write({'metrics_account': account})
        return account

    def _ensure_operator_credential(self):
        """Return the unfiltered read credential, generating it if absent.

        Deliberately separate from the account credential: this one grants
        a view across every account, so it must never be written to a
        host. Only the panel that owns the central holds it, and only its
        own Grafana organisation uses it.

        :return: the plaintext operator password.
        """
        settings = self._get_system()
        if settings.metrics_operator_token:
            return settings.metrics_operator_token
        token = generate_password(32)
        settings.sudo().write({'metrics_operator_token': token})
        return token

    def _ensure_grafana_admin_password(self):
        """Return Grafana's admin password, generating it once.

        :return: the plaintext password.
        """
        settings = self._get_system()
        if not settings.grafana_admin_password:
            settings.sudo().write({
                'grafana_admin_password': generate_password(32),
            })
        return settings.grafana_admin_password

    def _ensure_metrics_credential(self):
        """Return ``(account, password)``, generating both if absent.

        Called when observability is switched on so the operator never
        has to invent either half. A panel that already has them keeps
        them: the account is the label on all of its historical series,
        and series cannot be relabelled after ingestion.
        """
        settings = self._get_system()
        account = self._ensure_metrics_account()
        if not settings.metrics_remote_write_token:
            settings.sudo().write({
                'metrics_remote_write_token': generate_password(32),
            })
        return account, settings.metrics_remote_write_token

    def _observability_capabilities(self):
        """Return what this panel can do with observability, as three axes.

        The single definition of "observability is configured", because
        four screens each deciding it for themselves is how a panel ended
        up offering a Monitoring section whose only possible message was
        an instruction to visit a Settings tab that panel does not have.
        They are three independent facts and collapsing them into one
        boolean is what made the contradiction expressible:

        ``collect``
            The data layer is on: agents enrol, rules evaluate, the panel
            queries the backend. Everything else is inert without it.
        ``dashboards``
            There is something to *look at* — collection plus a Grafana
            to embed. Collecting without a Grafana URL is a perfectly
            valid state; offering dashboards in it is not.
        ``configure``
            This panel's own operator edits these settings. False where
            they are injected from above, which core never does itself:
            it publishes ``True`` and lets the layer that injects them
            say otherwise, exactly as it does for every other capability
            it cannot know about.

        Every UI surface consumes this and none re-derives it. A new
        surface that needs a different question answered adds an axis
        here rather than reading a field directly.

        :return: dict with the ``collect``, ``dashboards`` and
            ``configure`` booleans.
        """
        settings = self._get_system()
        collect = bool(settings.metrics_enabled)
        return {
            'collect': collect,
            'dashboards': collect and bool(
                (settings.grafana_base_url or '').strip()
            ),
            'configure': True,
        }

    def _metrics_auth(self, operator=False):
        """Return ``(user, password)`` for talking to the metrics central.

        Replaces the fixed ``incubacloud`` user that predated per-account
        credentials: the user half is now the account, because the central
        derives the forced label from whoever authenticated.

        :param operator: when True, return the unfiltered operator
            credential instead of this panel's own account. Only the panel
            that owns the central has one.
        :return: ``(user, password)``, or ``('', '')`` when unset — callers
            must treat that as "no credentials" and not as anonymous
            access being acceptable.
        """
        settings = self._get_system()
        if operator:
            token = settings.metrics_operator_token or ''
            return ('operator', token) if token else ('', '')
        token = settings.metrics_remote_write_token or ''
        account = settings.metrics_account or ''
        if not (token and account):
            return ('', '')
        return (account, token)

    # ── Container log rotation ─────────────────────────────────────────────

    @api.constrains(
        "container_log_max_size",
        "container_log_max_file",
        "odoo_log_archive_days",
        "log_download_max_mb",
        "log_search_max_files",
        "log_search_timeout_s",
    )
    def _check_container_log_rotation(self):
        """Refuse log-rotation values Docker would reject or ignore.

        A malformed ``max-size`` makes ``docker compose up`` fail on
        every instance at its next rebuild, and ``max-file`` below 1
        is not a valid json-file option — better to stop the write here
        than to discover it stack by stack.
        """
        for rec in self:
            size = rec.container_log_max_size or ""
            if not _CONTAINER_LOG_MAX_SIZE_RE.match(size):
                raise ValidationError(
                    _(
                        "Container log max size must be a positive integer "
                        "followed by k, m or g (for example 10m), got %s.",
                        size or "''",
                    )
                )
            if rec.container_log_max_file < 1:
                raise ValidationError(
                    _("Container log files kept must be at least 1.")
                )
            if rec.odoo_log_archive_days < 1:
                raise ValidationError(
                    _("The Odoo log archive must keep at least 1 day.")
                )
            if rec.log_download_max_mb < 1:
                raise ValidationError(
                    _("The log download cap must be at least 1 MB.")
                )
            if rec.log_search_max_files < 1:
                raise ValidationError(
                    _("A log search must sweep at least 1 day.")
                )
            if rec.log_search_timeout_s < 5:
                raise ValidationError(
                    _(
                        "The log search timeout must be at least 5 "
                        "seconds, or no search can finish."
                    )
                )

    # ── Singleton constraint ───────────────────────────────────────────────

    @api.constrains("github_pat")
    def _check_singleton(self):
        if self.env["cloud.settings"].search_count([]) > 1:
            raise UserError(
                _("Only one IncubaCloud settings record is allowed.")
            )

    # ── Helpers ────────────────────────────────────────────────────────────

    @api.model
    def _get(self):
        """Return the settings singleton — requires manager ACL.

        The model's ``ir.model.access`` is restricted to
        ``group_cloud_manager``. Use this accessor from controllers that
        are gated to manager (or higher) so the ACL acts as a
        defense-in-depth check on top of the role gate. For trusted
        non-manager flows (cron jobs, queue_job workers, providers,
        webhooks, public endpoints, or any inheriting module that
        legitimately needs settings access without a manager gate) use
        :meth:`_get_system` instead.
        """
        rec = self.search([], limit=1)
        if not rec:
            rec = self.create({})
        return rec

    @api.model
    def _get_system(self):
        """Return the settings singleton, bypassing ACL via sudo.

        Reserved for system contexts where the caller is *not* a manager
        but legitimately needs to read settings: cron jobs, queue
        workers, provider integrations, public webhooks, controllers
        exposed to portal users that read non-secret feature flags,
        and any inheriting module operating in a system context. Never
        use from an admin-write path — those must go through
        :meth:`_get` after a manager gate.
        """
        rec = self.sudo().search([], limit=1)
        if not rec:
            rec = self.sudo().create({})
        return rec

    @api.constrains('trusted_proxy_ranges')
    def _check_trusted_proxy_ranges(self):
        """Refuse a range list carrying an entry that is not a network.

        Same reasoning as the host-level check: a typo narrows who we
        believe without saying so, and the request path skips what it
        cannot read.

        :raise ValidationError: naming the unusable entries
        """
        for settings in self:
            bad = invalid_ranges(settings.trusted_proxy_ranges)
            if bad:
                raise ValidationError(_(
                    "These are not address ranges: %(entries)s. Write one "
                    "CIDR range per line, for example 198.51.100.0/24 or "
                    "2001:db8::/32.",
                    entries=", ".join(bad),
                ))

    @api.model
    def _trusted_proxy_source(self):
        """Return where the effective proxy ranges come from.

        :return: ``'settings'`` when the field here is set, ``'none'``
            when nothing applies
        :rtype: str
        """
        raw = self._get_system().trusted_proxy_ranges
        return 'settings' if parse_ranges(raw) else 'none'

    @api.model
    def _github_panel_route(self):
        """Return the webhook route for this panel's own endpoint.

        The panel is not a ``cloud.instance``, so nothing walking a
        host's instances can find it — yet it is the one thing that
        certainly serves the endpoint. It is described here instead, and
        a layer that already knows the answer fills these fields in
        rather than making an operator type them.

        :return: a route mapping, or ``{}`` when not configured
        :rtype: dict
        """
        settings = self._get_system()
        hostname = (settings.panel_hostname or '').strip()
        service_url = (settings.panel_service_url or '').strip()
        if not (hostname and service_url):
            return {}
        route = {'hostname': hostname, 'service_url': service_url}
        tls_domain = (settings.panel_tls_domain or '').strip()
        if tls_domain:
            route['tls_domain'] = tls_domain
        return route

    @api.model
    def _github_panel_host(self):
        """Return the host whose Traefik should publish the panel's route.

        Read through a method rather than the field so a layer that
        already knows which host serves the panel can answer without an
        operator having to name it.

        :rtype: recordset
        """
        return self._get_system().panel_host_id

    @api.model
    def _panel_route_source(self):
        """Return where the panel's own webhook route comes from.

        Reads the fields rather than calling
        :meth:`_github_panel_route`, which resolves to whichever layer
        answers last: asking it here would report a derived route as
        though an operator had typed it.

        :return: ``'settings'`` when described by the fields here,
            ``'none'`` when it is not described at all
        :rtype: str
        """
        settings = self._get_system()
        described = bool(
            (settings.panel_hostname or '').strip()
            and (settings.panel_service_url or '').strip()
        )
        return 'settings' if described else 'none'

    @api.model
    def _effective_trusted_proxy_ranges(self):
        """Return the CIDR ranges whose ``X-Forwarded-For`` is believed.

        Reads the operator-entered field. Modules that know the proxy in
        front of this installation — the SaaS manager knows the platform
        answers behind a CDN — override this and supply the ranges
        themselves, so operators never have to keep a moving list of
        somebody else's addresses up to date by hand.

        :return: CIDR strings; empty means "believe nothing", which is
            the pre-existing behaviour
        :rtype: list
        """
        return parse_ranges(self._get_system().trusted_proxy_ranges)

    # ── Startup check: INCUBACLOUD_SECRET_KEY ──────────────────────────────

    def _register_hook(self):
        """Warn loudly at registry load if the encryption key is missing.

        The actual fail-loud behaviour lives in ``password_utils``: any
        attempt to encrypt/decrypt raises. This hook only surfaces the
        misconfiguration at startup so operators don't discover it at the
        first write. Suppressed during tests (the key is patched per-test)
        and behind ``INCUBACLOUD_ALLOW_NO_KEY=1`` for ad-hoc dev scripts
        that deliberately avoid the key.
        """
        super()._register_hook()
        if tools.config.get('test_enable'):
            return
        if os.environ.get('INCUBACLOUD_ALLOW_NO_KEY'):
            _logger.warning(
                "INCUBACLOUD_ALLOW_NO_KEY=1 — any write to an encrypted "
                "field will still raise at runtime."
            )
            return
        if not key_is_configured():
            _logger.critical(
                "INCUBACLOUD_SECRET_KEY is missing or invalid. Any write to "
                "cloud.host.password, cloud.instance.*_password, "
                "cloud.backup.backend.passphrase, cloud.settings.github_pat "
                "and similar fields will raise. Configure the variable in "
                "the Odoo container environment before going to production."
            )

    # ── Secret rotation ────────────────────────────────────────────────────
    # Rotation workflow (operator-driven, not time-based):
    #   1. Generate a new key, set INCUBACLOUD_SECRET_KEY="<new>,<old>".
    #   2. Restart Odoo. New writes already use the new key; old rows
    #      still decrypt via the trailing old key in the MultiFernet.
    #   3. Activate ``cron_rotate_encrypted_secrets`` (or call
    #      ``_rotate_all_secrets`` manually) to re-encrypt existing rows.
    #   4. When every field reports zero rotated rows, remove the old
    #      key from the env var and restart.
    # The cron ships with active=False — turning it on is a deliberate
    # operator action, so it can't run mid-rotation on a half-configured
    # env var and corrupt ciphertext.

    @api.model
    def _rotate_all_secrets(self, batch_size=500):
        """Re-encrypt every encrypted value with the primary key.

        Reads ciphertext with raw SQL so plain text is never materialised
        in Python memory. Iterates every model in the registry, picks up
        every stored field built on ``EncryptedFieldMixin`` (so both
        ``EncryptedChar`` and ``EncryptedText``, and any shape added
        later), and rotates row-by-row.
        Invalidates the ORM cache per field so subsequent reads in the
        same transaction return the freshly rotated value.

        **Tolerance**: rotation of one row failing (typically because
        the ciphertext was encrypted with a key no longer present in
        the current MultiFernet chain) MUST NOT abort the whole run.
        We catch per-row exceptions, log them, and keep going so the
        remaining rotatable values still make it to the new key. Every
        stranded row is surfaced as a ``cloud.alert`` linked to the
        owning host / instance / project (or just logged when the model
        has no such relation, e.g. ``cloud.settings``).

        Returns ``{table.field: {'rotated': n, 'failed': [id, ...]}}``.
        """
        stats = {}
        for Model in self.env.registry.values():
            # Abstract mixins (e.g. cloud.terminal.route.mixin) can carry
            # an encrypted field but have no table of their own — the
            # concrete models that inherit them are rotated instead. Skip
            # them so we never query a non-existent relation.
            if Model._abstract or Model._transient:
                continue
            enc_fields = [
                name for name, f in Model._fields.items()
                if isinstance(f, EncryptedFieldMixin) and f.store
            ]
            if not enc_fields:
                continue
            table = Model._table
            for field_name in enc_fields:
                rotated, failed = self._rotate_encrypted_column(
                    table, field_name, batch_size,
                )
                if rotated or failed:
                    stats[f"{table}.{field_name}"] = {
                        'rotated': rotated, 'failed': failed,
                    }
                if rotated:
                    self.env[Model._name].invalidate_model([field_name])
                if failed:
                    self._raise_rotation_alerts(
                        Model._name, field_name, failed,
                    )
        if stats:
            _logger.info("Rotated encrypted secrets: %s", stats)
        else:
            _logger.info("Rotate pass complete: nothing to rotate.")
        pending = self.rotation_pending_count()
        _logger.info(
            "Rotation status: %d value(s) still not on the primary key. "
            "The old key may only be removed from %s once this is 0.",
            pending['total'], 'INCUBACLOUD_SECRET_KEY',
        )
        return stats

    def rotation_pending_count(self):
        """Return how many stored secrets are not on the primary key yet.

        This is the number RB-01 needs and the ``rotated`` tally cannot
        give: a rotation pass rewrites every row every time, because
        Fernet tokens carry a timestamp and a random IV, so "how many
        did I rewrite" never falls to zero no matter how many passes
        run. Asking which key opens each ciphertext does converge, and
        it is what says whether the old key can be retired safely.

        Reads ciphertext with raw SQL, so no plaintext is materialised
        and no ORM cache is disturbed. A value that cannot be read at
        all counts as pending, which is the safe direction: it keeps
        the old key in the chain rather than stranding the row.

        :return: ``{'total': n, 'by_column': {'table.field': n, ...}}``,
            with only the non-zero columns listed.
        :rtype: dict
        """
        by_column = {}
        total = 0
        for Model in self.env.registry.values():
            if Model._abstract or Model._transient:
                continue
            enc_fields = [
                name for name, f in Model._fields.items()
                if isinstance(f, EncryptedFieldMixin) and f.store
            ]
            if not enc_fields:
                continue
            for field_name in enc_fields:
                self.env.cr.execute(
                    sql.SQL(
                        "SELECT id, {f} FROM {t} WHERE {f} LIKE 'enc:%%'"
                    ).format(
                        t=sql.Identifier(Model._table),
                        f=sql.Identifier(field_name),
                    )
                )
                stale = 0
                for _rid, value in self.env.cr.fetchall():
                    try:
                        on_primary = is_on_primary_key(value, self.env)
                    except Exception:  # noqa: BLE001
                        on_primary = False
                    if not on_primary:
                        stale += 1
                if stale:
                    by_column[f"{Model._table}.{field_name}"] = stale
                    total += stale
        return {'total': total, 'by_column': by_column}

    def _rotate_encrypted_column(self, table, field_name, batch_size):
        """Rotate every ``enc:`` value in *table.field_name*.

        ``psycopg2.sql.Identifier`` keeps identifiers safe even though
        they come from model metadata (never user input) — belt-and-
        braces in case a model developer ever picks a weird column name.

        Returns ``(rotated_count, failed_ids)``. A row lands in
        ``failed_ids`` when ``rotate_value`` raises — typically because
        its ciphertext was encrypted with a key no longer in the
        ``INCUBACLOUD_SECRET_KEY`` chain. We swallow the exception,
        log it, and move on so one stranded value never blocks the
        rotation of the rest.
        """
        cr = self.env.cr
        cr.execute(
            sql.SQL(
                "SELECT id, {f} FROM {t} "
                "WHERE {f} LIKE 'enc:%%' ORDER BY id"
            ).format(
                t=sql.Identifier(table),
                f=sql.Identifier(field_name),
            )
        )
        rows = cr.fetchall()
        rotated = 0
        failed = []
        update_stmt = sql.SQL(
            "UPDATE {t} SET {f} = %s WHERE id = %s"
        ).format(
            t=sql.Identifier(table),
            f=sql.Identifier(field_name),
        )
        for start in range(0, len(rows), batch_size):
            for rid, old_value in rows[start:start + batch_size]:
                try:
                    new_value = rotate_value(old_value)
                except Exception as e:  # noqa: BLE001
                    failed.append(rid)
                    _logger.warning(
                        "[rotate] %s.%s id=%s could not rotate: %s "
                        "(likely encrypted with a retired key; "
                        "regenerate this value manually)",
                        table, field_name, rid, e,
                    )
                    continue
                if new_value != old_value:
                    cr.execute(update_stmt, (new_value, rid))
                    rotated += 1
        return rotated, failed

    # Models that ARE the alert target — an alert on a host points to
    # the host itself via ``host_id``.
    _ROTATION_SELF_ALERT = {
        'cloud.host': 'host_id',
        'cloud.instance': 'instance_id',
        'cloud.project': 'project_id',
    }

    def _rotation_alert_link(self, Model, record):
        """Return ``(link_field, link_id)`` pointing to the cloud.alert
        target for *record*, or ``(None, None)`` when the model has no
        host/instance/project relation and can't carry an alert.
        """
        self_target = self._ROTATION_SELF_ALERT.get(Model._name)
        if self_target:
            return self_target, record.id
        for candidate in ('host_id', 'instance_id', 'project_id'):
            if candidate in Model._fields:
                ref = record[candidate]
                if ref:
                    return candidate, ref.id
        return None, None

    def _raise_rotation_alerts(self, model_name, field_name, failed_ids):
        """Open a ``cloud.alert`` per stranded row so operators see the
        list in the dashboard without digging through logs.

        When the model is not linked to a host/instance/project (e.g.
        ``cloud.settings``, ``cloud.github.app``) we skip the alert —
        a targetless row would be invisible to the member-scoped record
        rule and impossible to trace back to a record. Those cases stay
        log-only, which is acceptable because the same warning was
        already emitted in ``_rotate_encrypted_column``.
        """
        Alert = self.env['cloud.alert'].sudo()
        Model = self.env[model_name]
        code = f"secret_rotation_stranded:{model_name}.{field_name}"
        log_only = []

        for rid in failed_ids:
            record = Model.sudo().browse(rid)
            if not record.exists():
                continue
            link_field, link_id = self._rotation_alert_link(Model, record)
            if not link_field:
                log_only.append(rid)
                continue
            # Dedup: one active alert per (code, target) at a time.
            if Alert.search_count([
                ('code', '=', code),
                ('state', '=', 'active'),
                (link_field, '=', link_id),
            ], limit=1):
                continue
            Alert.create({
                'code': code,
                'level': 'warning',
                link_field: link_id,
                'message': (
                    f"Could not rotate {model_name}.{field_name} "
                    f"(id={rid}) — ciphertext was encrypted with a key "
                    f"no longer in INCUBACLOUD_SECRET_KEY. Regenerate "
                    f"the value manually to resolve."
                ),
            })

        if log_only:
            _logger.warning(
                "[rotate] %s.%s has %d stranded row(s) with no "
                "host/instance/project to link an alert to: %s",
                model_name, field_name, len(log_only), log_only,
            )
