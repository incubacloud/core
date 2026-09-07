"""Tier 2 — who the platform says it is when it acts on its own account.

``sudo()`` raises privileges but leaves ``env.uid`` alone, so work the
platform does inside somebody else's request is authored by them. That
author is not cosmetic: it lands on ``queue_job.user_id``, so the
executor *runs* as them, and on every row that executor writes.

These tests pin the elevation itself and its two core consumers — the
alert model and the GitHub webhook event. The SaaS side (warm pool, OIDC
client) is pinned in ``incubacloud_saas_manager``.
"""
from unittest.mock import patch

from odoo.tests.common import TransactionCase, new_test_user

from odoo.addons.incubacloud.models.res_users_ext import as_platform


class ActorBase(TransactionCase):
    """Shared fixture: the bot, and a portal user that can be created.

    Optional modules add NOT NULL columns to ``res_partner`` without
    defaults (``account.autopost_bills`` is the one that bites), and
    ``new_test_user`` creates a partner without them. Same SQL-default
    patch ``test_cloud_job`` uses, for the same reason — rolled back
    with the test transaction.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env.cr.execute("""
            SELECT column_name, data_type
              FROM information_schema.columns
             WHERE table_name = 'res_partner'
               AND is_nullable = 'NO'
               AND column_default IS NULL
               AND column_name NOT IN ('id', 'name', 'company_type',
                                       'type', 'lang', 'active',
                                       'create_uid', 'write_uid',
                                       'create_date', 'write_date')
        """)
        for col, dtype in cls.env.cr.fetchall():
            default = "''" if 'char' in dtype or 'text' in dtype else "'no'"
            cls.env.cr.execute(
                f'ALTER TABLE res_partner '
                f'ALTER COLUMN "{col}" SET DEFAULT {default}'
            )
        cls.bot = cls.env['res.users']._get_cron_bot()
        cls.public = cls.env.ref('base.public_user')


class TestAsPlatform(ActorBase):
    """The elevation helper itself."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.portal = new_test_user(
            cls.env, 'actor-portal', groups='base.group_portal',
        )

    def test_rebinds_the_author_to_the_bot(self):
        records = self.env['cloud.alert'].with_user(self.portal)
        self.assertEqual(as_platform(records).env.uid, self.bot.id)

    def test_keeps_platform_privileges(self):
        # ``with_user`` resets ``su``, and every caller already held it —
        # losing it here would turn an identity change into a privilege
        # drop and break the callers outright.
        records = self.env['cloud.alert'].with_user(self.portal)
        self.assertTrue(as_platform(records).env.su)

    def test_degrades_when_the_bot_is_missing(self):
        # A missing bot must cost a slightly wrong author, not the
        # operation: these call sites sit on the signup and webhook
        # paths, where raising would be far worse than mis-attributing.
        records = self.env['cloud.alert'].with_user(self.portal)
        with patch.object(
            type(self.env['res.users']), '_get_cron_bot',
            return_value=self.env['res.users'],
        ):
            self.assertEqual(as_platform(records).env.uid, self.portal.id)


class TestAlertActor(ActorBase):
    """An alert is the platform noticing, never a user acting."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.portal = new_test_user(
            cls.env, 'alert-portal', groups='base.group_portal',
        )
        cls.host = cls.env['cloud.host'].create({
            'name': 'Actor Host',
            'ip_address': '10.0.0.7',
            'user': 'ubuntu',
            'wildcard_domain': 'actor.example.com',
        })

    def _alerts_as(self, user):
        """Return ``cloud.alert`` the way a real producer holds it.

        Every producer — executors, crons, the webhook — reaches
        ``raise_alert`` with privileges already raised and ``env.uid``
        still the caller's. Both halves matter: without ``sudo()`` the
        test would fail on a plain ``AccessError`` from ``search`` and
        never reach the attribution it is meant to pin.
        """
        return self.env['cloud.alert'].with_user(user).sudo()

    def test_alert_raised_in_a_customer_request_belongs_to_the_platform(self):
        # Reproduces prod: a customer signing up appeared as the author
        # of ``metrics_acl_sync_failed`` on infrastructure they had
        # nothing to do with.
        alert = self._alerts_as(self.portal).raise_alert(
            'actor_test', 'raised during a customer request',
            host=self.host,
        )
        self.assertEqual(alert.create_uid, self.bot)

    def test_public_producer_does_not_author_the_alert(self):
        alert = self._alerts_as(self.public).raise_alert(
            'actor_test_public', 'raised from a public route',
            host=self.host,
        )
        self.assertEqual(alert.create_uid, self.bot)

    def test_automatic_dismissal_belongs_to_the_platform(self):
        self.env['cloud.alert'].raise_alert(
            'actor_test_resolve', 'to be resolved', host=self.host,
        )
        dismissed = self._alerts_as(self.portal).resolve_alert(
            'actor_test_resolve', host=self.host,
        )
        self.assertEqual(dismissed.state, 'dismissed')
        self.assertEqual(dismissed.write_uid, self.bot)


class TestGithubEventActor(ActorBase):
    """The webhook route is ``auth='public'``; the platform still acts.

    A push to core rebuilds the fleet. In prod that produced 348 jobs,
    357 ``queue_job`` rows and 192k log chunks all authored by the public
    user — and the SSH executors ran as it.
    """

    def _event(self, user):
        return self.env['cloud.github.event'].with_user(user).sudo().create({
            'event_type': 'create',
            'action': '',
            'delivery_id': f'actor-{user.id}',
            'payload': '{}',
        })

    def test_dispatch_elevates_whoever_calls_it(self):
        # The controller elevates too, but ``_dispatch`` is what sets off
        # the rebuilds — a replay tool or a shell reprocessing a stuck
        # event must not end up as their author either.
        event = self._event(self.public)
        event._dispatch({})
        self.assertTrue(event.processed)
        self.assertEqual(event.write_uid, self.bot)
