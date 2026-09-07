import logging
from datetime import timedelta

from psycopg2 import sql as psql

from odoo import api, fields, models
from odoo.exceptions import AccessError

from .encrypted_char import EncryptedChar

_logger = logging.getLogger(__name__)

CRON_BOT_LOGIN = "__incubacloud_cron__"
CRON_BOT_XML_ID = "incubacloud.user_incubacloud_cron"


def as_platform(records):
    """Re-bind *records* so the platform, not the caller, is the author.

    Odoo's ``sudo()`` raises privileges but leaves ``env.uid`` alone, so
    work the platform does on its own account inside somebody's request
    — refilling the warm pool during a signup, rebuilding the fleet from
    a GitHub push, filing an alert — is stamped with whoever happened to
    trigger it. That author then outlives the request: it lands on the
    record, on ``queue_job.user_id`` (so the executor *runs* as them),
    and on every row that executor writes. Customers have shown up as
    the authors of machines they never saw, and the public user as the
    author of 348 fleet rebuilds.

    Elevate once at the entry point and the whole chain below inherits
    the bot; there is no need to wrap individual ``create`` calls.

    ``sudo()`` comes after ``with_user`` deliberately: ``with_user``
    resets ``su``, and every caller here already held it. This changes
    *identity*, never privilege.

    Degrades to the caller's own environment when the bot cannot be
    resolved — a missing bot should cost a slightly wrong ``create_uid``,
    not the operation.

    :param records: any recordset (its ``env`` is what gets rebound).
    :return: the same recordset bound to the platform bot.
    """
    bot = records.env['res.users']._get_cron_bot()
    if not bot:
        return records
    return records.with_user(bot).sudo()


class ResUsers(models.Model):
    _inherit = 'res.users'

    cloud_notification_level = fields.Selection(
        selection=[
            ('all', 'All events (success + failure)'),
            ('failures', 'Failures only'),
            ('none', 'None'),
        ],
        string='Cloud Job Notifications',
        default='failures',
    )

    cloud_email_enabled = fields.Boolean(
        string='Email Notifications Enabled',
        default=True,
        help='When unchecked, no cloud job emails are sent to this '
             'user regardless of their notification level. Other '
             'notification channels are not affected.',
    )

    cloud_notification_mode = fields.Selection(
        selection=[
            ('immediate', 'Immediate'),
            ('daily_digest', 'Daily digest'),
        ],
        string='Cloud Email Delivery',
        default='immediate',
        help=(
            'Immediate: one email per event. Daily digest: events are '
            'batched into one summary email per day — except severe '
            'failures (production deploys/rebuilds, critical alerts), '
            'which are always sent immediately.'
        ),
    )

    cloud_muted_project_ids = fields.Many2many(
        comodel_name='cloud.project',
        relation='cloud_user_muted_project_rel',
        column1='user_id',
        column2='project_id',
        string='Muted Cloud Projects',
        help=(
            'Projects that never interrupt this user: no emails, no '
            'digest entries, no live toasts. The alerts panel and '
            'badge still show everything.'
        ),
    )

    cloud_last_digest_at = fields.Datetime(
        string='Last Cloud Digest Sent',
        help=(
            'Watermark of the daily digest window. Advanced after each '
            'run — also when the window turned out empty.'
        ),
    )

    cloud_telegram_bot_token = EncryptedChar(
        string='Telegram Bot Token',
        help='Bot token from @BotFather. Stored encrypted.',
    )
    cloud_telegram_chat_id = fields.Char(
        string='Telegram Chat ID',
        help='Numeric chat or channel ID where the bot sends messages.',
    )
    cloud_webhook_url = fields.Char(
        string='External Webhook URL',
        help='HTTPS endpoint that receives POST notifications on job '
             'state changes. Payloads are signed with HMAC-SHA256 '
             'when a signing secret is configured.',
    )
    cloud_webhook_secret = EncryptedChar(
        string='Webhook Signing Secret',
        help='HMAC-SHA256 secret used to sign webhook payloads. '
             'Set to the same value the receiving endpoint expects '
             'in the X-IncubaCloud-Signature header.',
    )

    def _cloud_project_muted(self, project):
        """Return True when *project* is in this user's muted list.

        Falsy/empty projects are never muted — host-level events have
        no project to mute by.
        """
        self.ensure_one()
        return bool(project) and project in self.cloud_muted_project_ids

    @api.model
    def _cron_send_cloud_digest(self):
        """Send the daily cloud digest to every opted-in user.

        Each user runs in its own try/except so one broken mailbox
        cannot starve the rest; the per-user watermark only advances
        after a successful send (or a genuinely empty window).
        """
        now = fields.Datetime.now()
        users = self.search([
            ('share', '=', False),
            ('active', '=', True),
            ('cloud_notification_level', '!=', 'none'),
            ('cloud_notification_mode', '=', 'daily_digest'),
            ('cloud_email_enabled', '=', True),
        ])
        for user in users:
            try:
                self._send_cloud_digest_for(user, now)
            except Exception:
                _logger.exception(
                    'cloud digest failed for user %s', user.id,
                )

    @api.model
    def _send_cloud_digest_for(self, user, now):
        """Build and send one user's digest for ``(watermark, now]``.

        Content is searched *as the user* — the cloud.job/cloud.alert
        record rules stay the single source of truth — and muted
        projects are excluded; the surviving records are then re-read
        with sudo only to format display values (a member may read a
        job without having read access to its host's name).
        Returns True when a mail was actually sent.
        """
        since = user.cloud_last_digest_at or (now - timedelta(days=1))
        muted_ids = user.cloud_muted_project_ids.ids
        CloudJob = self.env['cloud.job']
        job_domain = [
            ('write_date', '>', since),
            ('write_date', '<=', now),
            ('job_type_id.code', 'not in', CloudJob._get_hidden_job_types()),
        ]
        # Only add the mute legs when something is actually muted:
        # a dotted ``not in []`` does NOT mean "match all" — it drops
        # every record (empty-subselect semantics). The explicit
        # ``instance_id = False`` branch keeps host-level jobs, whose
        # NULL instance must never be swallowed by the traversal.
        if muted_ids:
            job_domain += [
                '|',
                ('instance_id', '=', False),
                ('instance_id.project_id', 'not in', muted_ids),
            ]
        if user.cloud_notification_level == 'all':
            job_domain.append(('state', 'in', ('failed', 'done')))
        else:
            job_domain.append(('state', '=', 'failed'))
        alert_domain = [
            ('create_date', '>', since),
            ('create_date', '<=', now),
            # job_failed alerts are redundant here — the digest's job
            # section already lists every failed job with its log URL.
            ('code', '!=', 'job_failed'),
        ]
        if muted_ids:
            alert_domain += [
                '!', '|',
                ('project_id', 'in', muted_ids),
                ('instance_id.project_id', 'in', muted_ids),
            ]
        if user.cloud_notification_level == 'failures':
            alert_domain.append(('level', '=', 'critical'))
        try:
            jobs = CloudJob.with_user(user).search(
                job_domain, order='write_date desc', limit=100,
            )
            alerts = self.env['cloud.alert'].with_user(user).search(
                alert_domain, order='create_date desc', limit=100,
            )
        except AccessError:
            # No cloud ACLs at all — nothing this user could digest.
            jobs = CloudJob
            alerts = self.env['cloud.alert']
        if not jobs and not alerts:
            user.sudo().cloud_last_digest_at = now
            return False
        email = user.partner_id.email
        if not email:
            # No mailbox to deliver to; advancing avoids an unbounded
            # backlog the day the user finally sets an address.
            _logger.warning(
                'cloud digest skipped for user %s: no email set', user.id,
            )
            user.sudo().cloud_last_digest_at = now
            return False
        values = self._cloud_digest_values(
            user, jobs.sudo(), alerts.sudo(), since, now,
        )
        body = self.env['ir.qweb']._render(
            'incubacloud.mail_cloud_digest', values,
        )
        subject = (
            f"[IncubaCloud] Daily digest: {values['failed_count']} failed"
            f" job(s), {values['alert_count']} new alert(s)"
        )
        self.env['mail.mail'].sudo().create({
            'subject': subject,
            'body_html': body,
            'email_to': email,
            'auto_delete': True,
        }).send()
        user.sudo().cloud_last_digest_at = now
        return True

    @api.model
    def _cloud_digest_values(self, user, jobs, alerts, since, now):
        """Format sudo'd records into the plain dicts the digest QWeb
        template renders — the template never touches the ORM.
        """
        def _when(dt):
            return fields.Datetime.context_timestamp(
                user, dt,
            ).strftime('%Y-%m-%d %H:%M')

        def _job_target(job):
            if job.instance_id:
                project = job.instance_id.project_id.name
                name = job.instance_id.name
                return f'{project} / {name}' if project else name
            return job.host_id.name or ''

        def _alert_target(alert):
            if alert.host_id:
                return alert.host_id.name
            if alert.instance_id:
                project = alert.instance_id.project_id.name
                name = alert.instance_id.name
                return f'{project} / {name}' if project else name
            return alert.project_id.name or ''

        base_url = self.env['ir.config_parameter'].sudo().get_param(
            'web.base.url', '',
        )
        failed, done = [], []
        for job in jobs:
            row = {
                'name': job.name,
                'target': _job_target(job),
                'when': _when(job.write_date),
                'url': f'{base_url}/cloud/log/{job.id}',
            }
            (failed if job.state == 'failed' else done).append(row)
        alert_rows = [
            {
                'level': a.level,
                'message': a.message,
                'target': _alert_target(a),
                'when': _when(a.create_date),
            }
            for a in alerts
        ]
        return {
            'period_start': _when(since),
            'period_end': _when(now),
            'failed_jobs': failed,
            'done_jobs': done,
            'alerts': alert_rows,
            'failed_count': len(failed),
            'done_count': len(done),
            'alert_count': len(alert_rows),
            'console_url': f'{base_url}/cloud/ui',
        }

    @api.model
    def _get_cron_bot(self):
        """Return the platform's own user, or an empty recordset.

        This is the user the scheduled actions already run as. It is
        also the right actor for any unattended work the platform does
        on its own account outside a cron — building a warm spare while
        serving a customer's request, say — so ``create_uid`` keeps
        meaning "who wanted this" rather than "who happened to be
        logged in when the platform did its housekeeping".

        Resolved by XML-id with a login fallback, mirroring
        :meth:`_incubacloud_ensure_cron_bot`, and returns empty rather
        than raising: a caller that cannot find the bot should carry on
        with a slightly wrong ``create_uid``, not fail the operation.
        """
        bot = self.env.ref(CRON_BOT_XML_ID, raise_if_not_found=False)
        if bot:
            return bot
        return self.sudo().search([('login', '=', CRON_BOT_LOGIN)], limit=1)

    @api.model
    def _incubacloud_ensure_cron_bot(self):
        """Create (or re-home) the cron bot user referenced by every
        ``ir.cron`` in this module.

        Called from ``security/cloud_users.xml`` so the bot exists
        before the cron records that reference it via ``user_id``.

        Going through ``create()`` in Python rather than an XML
        ``<record>`` avoids a flaky interaction with the ``account``
        module: that module adds a ``required=True`` column
        (``autopost_bills``) to ``res.partner`` via ``_inherit``, and
        the XML record-creation path sometimes fails to cascade the
        default into the auto-created partner. ``create()`` in
        Python honours the field's ``default='ask'`` cleanly.

        Idempotent: on second install we find the existing user by
        XML-id (preferred) or by login (fallback for manually
        created users) and only align groups.
        """
        IMD = self.env['ir.model.data'].sudo()
        module, name = CRON_BOT_XML_ID.split('.', 1)
        mdata = IMD.search(
            [('module', '=', module),
             ('name', '=', name),
             ('model', '=', 'res.users')],
            limit=1,
        )
        if mdata:
            user = self.browse(mdata.res_id).exists()
        else:
            user = self.sudo().search([('login', '=', CRON_BOT_LOGIN)], limit=1)

        if not user:
            # Create the partner via raw SQL so we can fill columns
            # added by modules outside our dependency graph
            # (``account.autopost_bills`` is a required column whose
            # default cannot be applied by the ORM when ``account``
            # is not in our ``depends`` — Odoo loads its python
            # fields lazily and this migration runs before they are
            # on ``_fields``).
            # The table layout is introspected so only columns that
            # exist in THIS deployment are written. We ship known
            # defaults for the few required columns common modules
            # are known to contribute; everything else falls back
            # to ORM write after the row exists.
            known_defaults = {
                'autopost_bills': 'ask',   # account module
            }
            self.env.cr.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'res_partner'
                """,
            )
            partner_cols = {row[0] for row in self.env.cr.fetchall()}

            # Build the column / value lists as Python objects, then
            # use psycopg2.sql.Identifier to safely interpolate the
            # column names and %s placeholders for the values. This
            # is the canonical way to build dynamic-column INSERTs
            # in psycopg2 — it cleanly separates SQL identifiers
            # (quoted with double-quotes) from values (parameterised),
            # so future additions to ``known_defaults`` can never
            # introduce SQL injection even if the value comes from
            # a less-trusted source.
            now = fields.Datetime.now()
            cols = ['name', 'active', 'is_company', 'type',
                    'create_date', 'write_date',
                    'create_uid', 'write_uid']
            vals = ['IncubaCloud Cron Bot', True, False, 'contact',
                    now, now, 1, 1]
            for col, default in known_defaults.items():
                if col in partner_cols:
                    cols.append(col)
                    vals.append(default)

            query = psql.SQL(
                "INSERT INTO res_partner ({cols}) "
                "VALUES ({placeholders}) RETURNING id"
            ).format(
                cols=psql.SQL(', ').join(map(psql.Identifier, cols)),
                placeholders=psql.SQL(', ').join(
                    [psql.Placeholder()] * len(vals)
                ),
            )
            self.env.cr.execute(query, vals)
            partner_id = self.env.cr.fetchone()[0]
            self.env['res.partner'].invalidate_model()
            user = self.sudo().create({
                'login': CRON_BOT_LOGIN,
                'partner_id': partner_id,
                'active': True,
                'share': False,
                'notification_type': 'email',
            })
            _logger.info("created incubacloud cron bot user id=%s", user.id)

        # Ensure an ``ir.model.data`` row exists so cron XMLs can
        # reference the user by its fully-qualified XML-id regardless
        # of how it got created above (existing-login fallback or
        # fresh create).
        if not mdata:
            IMD.create({
                'module': module,
                'name': name,
                'model': 'res.users',
                'res_id': user.id,
                'noupdate': True,
            })

        # Align groups. Re-running is safe (``(4, id)`` is a no-op
        # when the membership already exists). We intentionally do
        # NOT remove groups an operator may have added — only add
        # the ones we need.
        required = [
            self.env.ref('incubacloud.group_cloud_manager').id,
            self.env.ref('base.group_user').id,
            self.env.ref('queue_job.group_queue_job_manager').id,
        ]
        user.sudo().write({'group_ids': [(4, gid) for gid in required]})

    @api.model
    def _incubacloud_assign_cron_user_id(self, module_name):
        """Point every ``ir.cron`` owned by *module_name* at the
        cron bot.

        Called from the post-init hook of every module that ships
        crons (this module and any module that inherits from it). We
        detect the crons by their ``ir.model.data`` rows so only rows
        the calling module actually owns are touched; any cron the
        operator created manually from the UI is left alone.

        We only overwrite ``user_id`` when it still points at uid=1
        (the OdooBot default). If an operator has re-routed a cron
        to a specific user, their choice wins.
        """
        IMD = self.env['ir.model.data'].sudo()
        bot = self.env.ref(CRON_BOT_XML_ID)
        cron_mdata = IMD.search([
            ('module', '=', module_name),
            ('model', '=', 'ir.cron'),
        ])
        if not cron_mdata:
            return
        module_crons = self.env['ir.cron'].sudo().browse(
            cron_mdata.mapped('res_id'),
        ).exists()
        stale = module_crons.filtered(lambda c: c.user_id.id == 1)
        if stale:
            stale.write({'user_id': bot.id})
            _logger.info(
                "reassigned %d %s crons to cron bot user",
                len(stale), module_name,
            )

        # Odoo 19 hardened ``ir.actions.server.run()``: when an action
        # carries no ``group_ids``, ``_can_execute_action_on_records``
        # requires the executing user to have *write* access on the
        # action's model. The cron bot is a cloud manager but deliberately
        # lacks write on append-only / abstract orchestration models
        # (audit log, rate-limit buckets, terminal routes, the warm-pool
        # and host-provisioner helper AbstractModels), so those crons
        # raised AccessError before their internal ``sudo()`` ever ran.
        # Scoping each bot-owned cron's server action to a group the bot
        # belongs to makes the check take the group-membership branch,
        # authorising the run without granting broad table write.
        bot_crons = module_crons.filtered(lambda c: c.user_id.id == bot.id)
        if bot_crons:
            manager_group = self.env.ref('incubacloud.group_cloud_manager')
            bot_crons.ir_actions_server_id.write({
                'group_ids': [(4, manager_group.id)],
            })
