"""A scheduled action that is switched off has to be noticed.

Nothing else notices. No job fails and no queue grows, because the work
is never attempted — the cron simply stops happening, and so does
everything downstream of it, somewhere else, later. The deploy pipeline
switches these off for the length of its window; a run that was killed
rather than aborted never switched them back on, and twenty-three of the
manager's twenty-four scheduled actions stayed off for five days with
the nightly backup of the free pool's host among them.

What is pinned here is the rule that decides "suspicious", because it is
the part that could quietly stop matching: a cron that has run before and
is now off, for longer than a deploy window lasts.
"""
from datetime import timedelta

from odoo import fields
from odoo.tests.common import TransactionCase

from odoo.addons.incubacloud.models import ir_cron_watch


class CronWatchCase(TransactionCase):

    def setUp(self):
        super().setUp()
        self.Cron = self.env["ir.cron"].with_context(active_test=False)
        self.watch = self.env["ir.cron"]
        self.long_ago = fields.Datetime.now() - timedelta(
            hours=ir_cron_watch.STOPPED_GRACE_HOURS + 1,
        )
        # Every one of ours starts on, so a test switching one off is
        # the only thing the check can be reacting to. The fleet these
        # run against is whatever the module installed, which differs
        # between a fresh database and a clone of production.
        self._stopped().write({"active": True})
        # And no alert of ours exists when a test starts. This check
        # runs for real on the manager, so any database it has run on
        # carries its rows, and what they leave behind changes the
        # answer in opposite directions: an *active* one is reused
        # rather than added, so "it raised an alert" finds a row the
        # test never caused; a *dismissed* one is not reused, so a
        # second row appears and "exactly one" counts two. Between
        # them they cover every database this suite runs against —
        # which is why every test here has to start from none.
        #
        # Removed rather than filtered around: the reuse means a
        # leftover changes what the code under test *does*, not just
        # what the assertions can see. The transaction rolls back, so
        # the manager keeps its own rows.
        self.env["cloud.alert"].sudo().search(
            [("code", "=", ir_cron_watch.ALERT_CODE)],
        ).unlink()

    def _stopped(self):
        """Return whatever the check currently considers stopped."""
        return self.env["ir.cron"]._disabled_platform_crons()

    def _alerts(self, **extra):
        """Return the alerts of ours now on the database.

        :param extra: further field/value pairs to filter on
        :rtype: odoo.models.Model
        """
        domain = [("code", "=", ir_cron_watch.ALERT_CODE)]
        domain += [(field, "=", value) for field, value in extra.items()]
        return self.env["cloud.alert"].sudo().search(domain)

    def _one_of_ours(self):
        """Return one cron owned by us, whatever the install has."""
        data = self.env["ir.model.data"].search(
            [
                ("model", "=", "ir.cron"),
                ("module", "in", list(ir_cron_watch.OUR_MODULES)),
            ],
            limit=1,
        )
        self.assertTrue(data, "no cron of ours is installed")
        return self.Cron.browse(data.res_id)

    def _active_alert(self):
        return self._alerts(state="active")[:1]


class TestWhatCountsAsStopped(CronWatchCase):

    def test_a_healthy_fleet_reports_nothing(self):
        self.assertFalse(self._stopped())

    def test_one_of_ours_switched_off_long_ago_is_reported(self):
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": self.long_ago})
        self.assertIn(cron, self._stopped())

    def test_one_switched_off_just_now_is_not(self):
        """That is what a deploy in progress looks like from here, and
        alerting on our own maintenance is how an alert list stops
        being read."""
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": fields.Datetime.now()})
        self.assertNotIn(cron, self._stopped())

    def test_one_that_never_ran_is_not(self):
        """Off since it was installed is a deliberate choice — the
        secret rotation is opt-in — not something that stopped.

        This is why the rule is "used to run and does not any more"
        rather than reading the module's declaration: the declaration
        lives in an XML file no running database can consult, and an
        exception list would drift away from it.
        """
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": False})
        self.assertNotIn(cron, self._stopped())

    def test_an_active_one_is_not_reported_however_old(self):
        cron = self._one_of_ours()
        cron.write({"active": True, "lastcall": self.long_ago})
        self.assertNotIn(cron, self._stopped())

    def test_odoo_s_own_crons_are_left_alone(self):
        """Several ship disabled by design, and switching one off is a
        configuration choice nobody needs an alert about."""
        theirs = self.env.ref("base.autovacuum_job")
        theirs.write({"active": False, "lastcall": self.long_ago})
        self.assertNotIn(theirs, self._stopped())


class TestTheAlert(CronWatchCase):

    def test_nothing_stopped_raises_nothing(self):
        self.assertEqual(self.env["ir.cron"]._cron_check_disabled(), 0)
        self.assertFalse(self._active_alert())

    def test_one_alert_covers_every_stopped_cron(self):
        """They go off together — a deploy pauses them as a group — so
        one row each would be the same fact repeated twenty-three
        times."""
        data = self.env["ir.model.data"].search(
            [
                ("model", "=", "ir.cron"),
                ("module", "in", list(ir_cron_watch.OUR_MODULES)),
            ],
            limit=3,
        )
        crons = self.Cron.browse(data.mapped("res_id"))
        self.assertEqual(len(crons), 3, "need three crons of ours")
        crons.write({"active": False, "lastcall": self.long_ago})

        self.assertEqual(self.env["ir.cron"]._cron_check_disabled(), 3)
        self.assertEqual(len(self._alerts(state="active")), 1)

    def test_the_alert_names_them(self):
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": self.long_ago})
        self.env["ir.cron"]._cron_check_disabled()
        alert = self._active_alert()
        self.assertIn(cron.cron_name, alert.message)
        self.assertEqual(
            [row["id"] for row in alert.payload["crons"]], [cron.id],
        )

    def test_switching_them_back_on_dismisses_it(self):
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": self.long_ago})
        self.env["ir.cron"]._cron_check_disabled()
        self.assertTrue(self._active_alert())

        cron.write({"active": True})
        self.assertEqual(self.env["ir.cron"]._cron_check_disabled(), 0)
        self.assertFalse(
            self._active_alert(),
            "the alert outlived the condition that raised it",
        )

    def test_running_twice_does_not_pile_up_alerts(self):
        cron = self._one_of_ours()
        cron.write({"active": False, "lastcall": self.long_ago})
        self.env["ir.cron"]._cron_check_disabled()
        self.env["ir.cron"]._cron_check_disabled()
        self.assertEqual(len(self._alerts()), 1)


class TestTheWatchdogIsNotItsOwnBlindSpot(CronWatchCase):
    """The pipeline must not pause the cron that reports pausing.

    It is owned by one of our modules, so the enumeration that picks
    what to pause would take it too — and then a killed deploy would
    switch off both the crons and the thing that says so.
    """

    def test_the_watchdog_is_declared_under_the_name_the_pipeline_skips(self):
        record = self.env.ref("incubacloud.cron_check_disabled_crons")
        self.assertTrue(record.active)
        data = self.env["ir.model.data"].search([
            ("model", "=", "ir.cron"),
            ("res_id", "=", record.id),
        ], limit=1)
        # ``tasks_local._CRON_WATCH_XMLID`` excludes exactly this name.
        self.assertEqual(data.name, "cron_check_disabled_crons")
        self.assertEqual(data.module, "incubacloud")
