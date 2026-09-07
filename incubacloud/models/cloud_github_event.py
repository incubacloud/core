import json
import logging
from datetime import timedelta

from odoo import _, api, fields, models

from ._repo_requirements import _normalize_url, is_safe_git_ref
from .res_users_ext import as_platform

_logger = logging.getLogger(__name__)

_AUTO_REBUILD_COOLDOWN = timedelta(seconds=60)

# Alert raised when the GitHub App installation is removed or suspended.
# Module-level so the webhook handler and any future health check dedup
# on the same code.
GITHUB_APP_REVOKED_CODE = 'github_app_revoked'

# Alert raised when deliveries stop arriving while an App is configured.
# An edge allowlist that has fallen behind the provider's published
# source ranges fails by dropping requests before they reach us, so the
# absence of traffic is the only signal that reaches this process.
GITHUB_WEBHOOK_SILENT_CODE = 'github_webhook_silent'


class CloudGitHubEvent(models.Model):
    """Log of received GitHub App webhook events.

    Events are persisted by the webhook controller immediately after HMAC
    validation.  Push events are processed to trigger auto-rebuilds.
    """

    _name = "cloud.github.event"
    _description = "GitHub Webhook Event"
    _order = "create_date desc"

    event_type = fields.Char(
        string="Event Type",
        readonly=True,
        help="Value of the X-GitHub-Event header (e.g. push, pull_request).",
    )
    action = fields.Char(
        string="Action",
        readonly=True,
        help="The 'action' field from the webhook payload (e.g. opened, closed).",
    )
    delivery_id = fields.Char(
        string="Delivery ID",
        readonly=True,
        index=True,
        help="Value of the X-GitHub-Delivery header — unique per delivery.",
    )
    payload = fields.Text(
        string="Payload",
        readonly=True,
        help="Raw JSON payload received from GitHub.",
    )
    processed = fields.Boolean(
        string="Processed",
        default=False,
        help="Set to True once business logic has handled this event.",
    )
    error = fields.Text(
        string="Processing Error",
        readonly=True,
        help="Error message if processing failed.",
    )

    def init(self):
        """Enforce anti-replay via a partial unique index on delivery_id.

        GitHub guarantees the X-GitHub-Delivery UUID is unique per delivery,
        so a duplicate means the same request was received twice — either a
        GitHub retry after a transient 5xx or, more concerning, a captured
        request being replayed by an attacker who cannot forge the HMAC but
        can resend a valid one. Either way we want the second insert to fail
        at the DB layer so the controller can swallow it without re-firing
        the push / pull_request handlers.

        Partial ``WHERE delivery_id != ''`` is the escape hatch for any
        legacy rows persisted before this constraint was added (tests and
        ad-hoc rows in older DBs). The webhook controller now rejects
        empty delivery headers with 400, so no new empty rows can land.

        The DELETE step is a one-shot dedupe keeping the oldest row
        (smallest id). It's idempotent: on subsequent upgrades there are
        no duplicates left, so the DELETE is a no-op.
        """
        cr = self.env.cr
        cr.execute(
            """
            DELETE FROM cloud_github_event a
            USING cloud_github_event b
            WHERE a.delivery_id = b.delivery_id
              AND a.delivery_id IS NOT NULL
              AND a.delivery_id != ''
              AND a.id > b.id
            """
        )
        cr.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                cloud_github_event_delivery_id_uidx
            ON cloud_github_event (delivery_id)
            WHERE delivery_id IS NOT NULL AND delivery_id != ''
            """
        )

    @api.model
    @api.model
    def _cron_check_delivery_silence(self):
        """Alert when no webhook has arrived for longer than configured.

        Only meaningful once an App exists: without one the platform is
        not expecting deliveries, and the webhook secret lookup returns
        before hashing anything. The check therefore stays quiet on an
        install that never wired GitHub up.

        Silence is measured against the newest event of any kind rather
        than against processed ones, so a run of failures still counts as
        "traffic is arriving" — the failure has its own alert.

        :return: the raised alert, or an empty recordset when quiet
        """
        Alert = self.env['cloud.alert'].sudo()
        settings = self.env['cloud.settings'].sudo()._get()
        hours = settings.github_webhook_silence_hours
        configured = self.env['cloud.github.app'].sudo().search_count([])
        if hours <= 0 or not configured:
            Alert.resolve_alert(GITHUB_WEBHOOK_SILENT_CODE)
            return Alert.browse()
        cutoff = fields.Datetime.now() - timedelta(hours=hours)
        if self.sudo().search_count([('create_date', '>=', cutoff)]):
            Alert.resolve_alert(GITHUB_WEBHOOK_SILENT_CODE)
            return Alert.browse()
        latest = self.sudo().search([], order='create_date desc', limit=1)
        last_seen = (
            fields.Datetime.to_string(latest.create_date) if latest
            else _('never')
        )
        return Alert.raise_alert(
            GITHUB_WEBHOOK_SILENT_CODE,
            _("No GitHub webhook delivery has been recorded in the last "
              "%(hours)s hours (last seen: %(last_seen)s). Repository pushes "
              "are not reaching the platform, so automatic rebuilds have "
              "stopped. Check the App installation and any source-address "
              "allowlist in front of /cloud/github/webhook.",
              hours=hours, last_seen=last_seen),
            level='warning',
        )

    def _purge_old(self):
        """Two-stage retention run from the daily cron.

        Stage 1 (``github_event_truncate_days``): replace the raw
        payload of processed events older than N days with a compact
        JSON stub that keeps only the fields used by downstream audit
        — event type, ref, head sha, action, pusher login, and the
        original payload size. This keeps the audit trail but releases
        ~99% of the row size for big monorepo pushes.

        Stage 2 (``github_event_retention_days``): delete processed
        events older than N days outright. Unprocessed rows
        (``processed=False`` or ``error`` set) are never auto-deleted
        so an operator can still investigate failures after a month.

        ``0`` disables the stage — explicit opt-out rather than a
        silent "disabled by default".
        """
        settings = self.env['cloud.settings'].sudo()._get()
        trunc_days = settings.github_event_truncate_days or 0
        del_days = settings.github_event_retention_days or 0
        now = fields.Datetime.now()

        if trunc_days > 0:
            cutoff = now - timedelta(days=trunc_days)
            candidates = self.sudo().search([
                ('processed', '=', True),
                ('create_date', '<', cutoff),
                ('payload', '!=', False),
                ('payload', '!=', ''),
                # Skip already-truncated rows: their payload is the
                # compact stub and re-stubbing would be a no-op at best
                # and miscount a 'truncated' every run at worst.
                ('payload', 'not ilike', '"_truncated":true'),
            ])
            truncated = 0
            for ev in candidates:
                stub = ev._payload_stub()
                if stub is not None and stub != ev.payload:
                    ev.payload = stub
                    truncated += 1
            if truncated:
                _logger.info(
                    "cloud.github.event: truncated %d payload(s) "
                    "older than %d days", truncated, trunc_days,
                )

        if del_days > 0:
            cutoff = now - timedelta(days=del_days)
            old = self.sudo().search([
                ('processed', '=', True),
                ('create_date', '<', cutoff),
            ])
            count = len(old)
            if count:
                old.unlink()
                _logger.info(
                    "cloud.github.event: purged %d row(s) "
                    "older than %d days", count, del_days,
                )

    def _payload_stub(self):
        """Return a compact JSON replacement preserving audit info.

        The stub keeps: event_type, ref, head sha, action, pusher
        login, and the original payload byte size. A truncated flag
        marks the row so future re-processing attempts know the full
        payload is no longer available.
        """
        self.ensure_one()
        try:
            data = json.loads(self.payload or '{}')
        except (ValueError, TypeError):
            data = {}
        stub = {
            '_truncated': True,
            '_original_size': len(self.payload or ''),
            'event_type': self.event_type or '',
            'action': self.action or '',
            'ref': data.get('ref', ''),
            'after': data.get('after', '')[:40],
            'pusher': (data.get('pusher') or {}).get('name', ''),
            'repository': (
                (data.get('repository') or {}).get('full_name', '')
            ),
        }
        return json.dumps(stub, separators=(',', ':'))

    def _record_pending_push(self, instance, push_info, reason):
        """Queue a push that could not trigger an immediate rebuild.

        The resulting ``cloud.instance.pending.push`` rows are surfaced in
        the instance card and consumed by the next successful rebuild's
        ``on_success`` hook, which folds them into a coalesced follow-up
        job so that every push remains traceable end-to-end.
        """
        self.ensure_one()
        self.env['cloud.instance.pending.push'].sudo().create({
            'instance_id': instance.id,
            'event_id': self.id,
            'push_repo': push_info.get('push_repo') or '',
            'push_branch': push_info.get('push_branch') or '',
            'push_sha': push_info.get('push_sha') or '',
            'push_message': push_info.get('push_message') or '',
            'push_by': push_info.get('push_by') or '',
            'skip_reason': reason,
        })

    def _rebuild_job_type(self, inst):
        """Job code used by webhook-driven auto-rebuild.

        Default: the core ``rebuild_instance``. Modules layered on top
        (e.g. the SaaS manager) override this to route tenant-bearing
        instances to the tenant-aware executor, which carries plan and
        tenant-module sync that the core executor lacks.

        A subclass may return a falsy value to decline the auto-rebuild
        entirely; the webhook handler then skips the instance without
        enqueuing anything.
        """
        return 'rebuild_instance'

    def _rebuild_blocking_codes(self):
        """Job codes whose active presence defers a new auto-rebuild.

        Default covers the core deploy / rebuild jobs. Overridden by
        the SaaS manager to also include the tenant-flavoured variants
        so a push can never race a tenant-rebuild already in flight.
        """
        return ('deploy_instance', 'rebuild_instance')

    def _dispatch(self, payload):
        """Route a freshly-persisted webhook event to its handler.

        Every path must leave the event ``processed=True``. Both stages of
        ``_purge_old`` filter on that flag, so a row left False is exempt
        from a retention policy that reads as covering it — payload and
        all, forever. The individual handlers set the flag themselves; the
        fallthrough covers the event types the App manifest subscribes to
        but which we take no action on (``create``, ``delete``, …).

        :param dict payload: the decoded webhook body
        """
        self.ensure_one()
        # Belt and braces with the webhook controller, which already
        # elevates: dispatching is what enqueues the fleet rebuilds, so
        # any *other* caller — a replay tool, a shell reprocessing a
        # stuck event — must not end up as their author either.
        self = as_platform(self)
        if self.event_type == 'installation':
            self._process_installation_lifecycle(payload)
        elif self.event_type == 'push':
            self._process_push_event()
        elif self.event_type == 'pull_request':
            self._process_pull_request_event()
        else:
            self.write({'processed': True})

    def _process_installation_lifecycle(self, payload):
        """Handle an ``installation`` webhook and mark the event processed.

        ``created`` auto-detects the installation id (the original reason
        this event type was subscribed).

        ``deleted`` and ``suspend`` are the ones that used to pass
        unnoticed: from that moment every GitHub API call 401s, the client
        invalidates its token cache and returns empty-handed, and
        auto-rebuild plus PR previews simply stop happening with nothing
        anywhere in the panel to explain why. Raise a critical alert so the
        silence becomes visible. ``unsuspend`` clears it, as does a fresh
        ``created`` after a reinstall.

        :param dict payload: the decoded webhook body
        """
        self.ensure_one()
        action = self.action or payload.get('action', '')
        Alert = self.env['cloud.alert'].sudo()
        if action == 'created':
            self.env['cloud.github.app'].sudo()._process_installation_event(
                payload,
            )
            Alert.resolve_alert(GITHUB_APP_REVOKED_CODE)
        elif action in ('deleted', 'suspend'):
            Alert.raise_alert(
                GITHUB_APP_REVOKED_CODE,
                _(
                    "The GitHub App installation was %(action)s. Auto-rebuild "
                    "on push and PR preview environments are disabled until "
                    "it is reinstalled.",
                    action=action,
                ),
                level='critical',
            )
            _logger.warning(
                "GitHub App installation %s — auto-rebuild is now inert.",
                action,
            )
        elif action == 'unsuspend':
            Alert.resolve_alert(GITHUB_APP_REVOKED_CODE)
        self.write({'processed': True})

    def _process_push_event(self):
        """Process a push webhook — trigger auto-rebuild for matching instances."""
        self.ensure_one()
        payload = json.loads(self.payload or '{}')

        # Ignore branch deletions and tag pushes
        if payload.get('deleted'):
            self.write({'processed': True})
            return

        ref = payload.get('ref', '')
        branch = ref.removeprefix('refs/heads/')
        if not branch or branch == ref:
            # Not a branch push (e.g. tag)
            self.write({'processed': True})
            return
        # Defense in depth: refuse to enqueue auto-rebuilds for refs
        # whose name would not pass the @api.constrains on
        # cloud.instance.repo.branch. The constraint already blocks
        # writes downstream, but rejecting here avoids ValidationError
        # noise in logs and makes the rejection visible in the
        # processed=True branch.
        if not is_safe_git_ref(branch):
            _logger.warning(
                "GitHub push: rejected unsafe branch name %r", branch,
            )
            self.write({'processed': True})
            return

        repo_data = payload.get('repository', {})
        clone_url = repo_data.get('clone_url', '')
        repo_norm = _normalize_url(clone_url)
        if not repo_norm:
            self.write({'processed': True})
            return

        # Push context for job payload
        pusher = payload.get('pusher', {}).get('name', '')
        head_sha = payload.get('after', '')[:7]
        head_msg = payload.get('head_commit', {}).get('message', '').split('\n')[0][:80]
        repo_short = repo_data.get('full_name', repo_norm.split('github.com/')[-1])

        # Find instance repos matching repo+branch, not frozen
        matched = self.env['cloud.instance.repo'].search([
            ('branch', '=', branch),
            ('commit_sha', 'in', (False, '')),
        ]).filtered(
            lambda r: _normalize_url(r.url) == repo_norm
        )

        now = fields.Datetime.now()
        triggered = []

        push_info = {
            'push_repo': repo_short,
            'push_branch': branch,
            'push_sha': head_sha,
            'push_message': head_msg,
            'push_by': pusher,
        }

        for repo in matched:
            inst = repo.instance_id
            # Never auto-rebuild an archived instance or one whose host is
            # deactivated/deleted: the repo match can surface archived
            # instances (e.g. recycled warms) and ``host_id`` may point at
            # an archived host, both of which would just fail SSH.
            if not (inst.active and inst.auto_rebuild and inst.deployed
                    and inst.host_id and inst.host_id.active):
                continue
            # A subclass may decline to auto-rebuild a given instance by
            # returning a falsy job type (e.g. the SaaS manager skips a
            # warm-pool instance already condemned to recycling). Resolve
            # it before the cooldown/active-job bookkeeping so we never
            # record a pending push for an instance we will never rebuild.
            job_type = self._rebuild_job_type(inst)
            if not job_type:
                continue
            if (inst.last_auto_rebuild
                    and (now - inst.last_auto_rebuild) < _AUTO_REBUILD_COOLDOWN):
                self._record_pending_push(inst, push_info, 'cooldown')
                _logger.info(
                    "Auto-rebuild deferred for %s (cooldown) — push %s queued",
                    inst.name, head_sha,
                )
                continue
            # Skip if there's already a running/pending job for this instance
            active_job = self.env['cloud.job'].search([
                ('instance_id', '=', inst.id),
                ('job_type_id.code', 'in', self._rebuild_blocking_codes()),
                ('state', 'in', ('pending', 'started')),
            ], limit=1)
            if active_job:
                self._record_pending_push(inst, push_info, 'active_job')
                _logger.info(
                    "Auto-rebuild deferred for %s (job %d already %s) — push %s queued",
                    inst.name, active_job.id, active_job.state, head_sha,
                )
                continue
            try:
                self.env['cloud.job'].enqueue(
                    inst.host_id.id, inst.id, job_type,
                    payload={
                        'trigger': 'webhook',
                        **push_info,
                    },
                )
                inst.write({'last_auto_rebuild': now})
                triggered.append(inst.name)
            except Exception:
                _logger.exception(
                    "Failed to enqueue auto-rebuild for %s", inst.name,
                )

        self.write({'processed': True})
        if triggered:
            _logger.info(
                "Auto-rebuild triggered for: %s (push %s@%s)",
                ', '.join(triggered), repo_norm.split('/')[-1], branch,
            )

    def _process_pull_request_event(self):
        """Process a pull_request webhook — create/rebuild/destroy PR preview instances."""
        self.ensure_one()
        payload   = json.loads(self.payload or '{}')
        action    = payload.get('action')
        pr        = payload.get('pull_request', {})
        pr_number = pr.get('number')
        head_ref  = pr.get('head', {}).get('ref')
        clone_url = pr.get('head', {}).get('repo', {}).get('clone_url', '')
        repo_full = payload.get('repository', {}).get('full_name', '')
        repo_norm = _normalize_url(clone_url)

        if not pr_number or not head_ref or not repo_norm:
            self.write({'processed': True})
            return
        # Same defense-in-depth rejection as in _process_push_event:
        # the head_ref will flow into cloud.instance.repo.branch via
        # repo.write(), so a hostile ref name (e.g. ``main --upload-pack=evil``)
        # would later be rejected by the constraint. Bail out cleanly here.
        if not is_safe_git_ref(head_ref):
            _logger.warning(
                "GitHub PR: rejected unsafe head_ref %r (PR #%s)",
                head_ref, pr_number,
            )
            self.write({'processed': True})
            return

        if action in ('opened', 'reopened'):
            # Find production instances with this repo configured
            prod_repos = self.env['cloud.instance.repo'].search([
                ('commit_sha', 'in', (False, '')),
                ('instance_id.environment', '=', 'production'),
                ('instance_id.deployed', '=', True),
                ('instance_id.project_id.pr_reviews_enabled', '=', True),
            ]).filtered(lambda r: _normalize_url(r.url) == repo_norm)

            for prod in prod_repos.mapped('instance_id'):
                exists = self.env['cloud.instance'].search([
                    ('pr_number', '=', pr_number),
                    ('pr_repo', '=', repo_full),
                    ('project_id', '=', prod.project_id.id),
                ], limit=1)
                if exists:
                    continue
                try:
                    prod.clone_to_staging(
                        f'pr-{pr_number}',
                        pr_number=pr_number,
                        pr_repo=repo_full,
                        pr_head_branch=head_ref,
                    )
                    _logger.info(
                        "PR preview instance created for PR #%s (%s) → project %s",
                        pr_number, repo_full, prod.project_id.name,
                    )
                except Exception:
                    _logger.exception(
                        "Failed to create PR preview for PR #%s", pr_number,
                    )

        elif action == 'synchronize':
            # New commit pushed to the PR branch → rebuild existing preview instances
            instances = self.env['cloud.instance'].search([
                ('pr_number', '=', pr_number),
                ('pr_repo', '=', repo_full),
            ])
            for inst in instances:
                # Skip archived instances or those on a deactivated/deleted
                # host — rebuilding them would only fail against a dead
                # server.
                if not (inst.active and inst.deployed
                        and inst.host_id and inst.host_id.active):
                    continue
                job_type = self._rebuild_job_type(inst)
                if not job_type:
                    continue
                for repo in inst.repo_ids:
                    if _normalize_url(repo.url) == repo_norm and repo.branch != head_ref:
                        repo.write({'branch': head_ref, 'commit_sha': False})
                try:
                    self.env['cloud.job'].enqueue(
                        inst.host_id.id, inst.id, job_type,
                    )
                    _logger.info(
                        "PR preview rebuild triggered for %s (PR #%s)",
                        inst.name, pr_number,
                    )
                except Exception:
                    _logger.exception(
                        "Failed to enqueue PR rebuild for %s", inst.name,
                    )

        elif action == 'closed':
            # PR merged or closed → destroy preview instances
            instances = self.env['cloud.instance'].search([
                ('pr_number', '=', pr_number),
                ('pr_repo', '=', repo_full),
            ])
            for inst in instances:
                inst_name = inst.name
                if inst.pr_comment_id:
                    inst._delete_pr_comment()
                if inst.deployed and inst.host_id:
                    try:
                        self.env['cloud.job'].enqueue(
                            inst.host_id.id, inst.id, 'delete_instance'
                        )
                    except Exception:
                        _logger.exception(
                            "Failed to enqueue delete for PR instance %s", inst_name,
                        )
                else:
                    inst.unlink()
                _logger.info(
                    "PR preview instance %s queued for deletion (PR #%s closed)",
                    inst_name, pr_number,
                )

        self.write({'processed': True})
