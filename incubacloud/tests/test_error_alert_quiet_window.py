"""An error alert must outlive the five-minute window that saw it.

Every other health alert describes a condition the probe can read right
now — a container that is down, memory that is high — so a clean cycle
really is the end of it. ``instance_error_logs`` is different: it
describes something that already happened, and the window is only the
few minutes since the last check. An error that fires every six hours
therefore raised an alert that the very next cycle dismissed, five
minutes later, notifying on-call twice for something nobody could act
on in between. The panel filters to active by default, so the row was
gone before anyone looked.

That is how the reconcile cron stayed broken across the whole tenant
fleet for a week. Now the alert stays up until a full day passes
without the error being seen again.
"""
import asyncio
from datetime import timedelta

from odoo import fields
from odoo.tests.common import TransactionCase

from odoo.addons.incubacloud.models.instance_health_executor import (
    _ERROR_QUIET_HOURS,
    InstanceHealthExecutor,
)


class TestErrorAlertQuietWindow(TransactionCase):

    def setUp(self):
        super().setUp()
        # The probe writes alerts on a cursor of its own; test mode is
        # what lets that cursor see the records created here.
        self.registry_enter_test_mode()
        self.project = self.env["cloud.project"].create({"name": "Quiet Proj"})
        self.host = self.env["cloud.host"].create({
            "name": "quiet-host",
            "ip_address": "192.0.2.65",
            "user": "ubuntu",
            "wildcard_domain": "quiet.example.com",
        })
        self.instance = self.env["cloud.instance"].create({
            "name": "quietinst",
            "project_id": self.project.id,
            "environment": "production",
            "host_id": self.host.id,
        })
        self.job_type = self.env["cloud.job.type"].search(
            [("code", "=", "instance_health")], limit=1,
        )

    def _clean_cycle(self):
        """Run one health cycle that finds no ERROR line at all."""
        job = self.env["cloud.job"].create({
            "name": "Health",
            "host_id": self.host.id,
            "instance_id": self.instance.id,
            "job_type_id": self.job_type.id,
        })
        executor = InstanceHealthExecutor(job, self.host)
        executor._skipped = False
        results = {
            "container_state": {"stdout": "\n".join(
                f"{svc}\trunning" for svc in self.instance.expected_services()
            )},
            "cpu_mem_snapshot": {"stdout": "0.0\t0.0"},
            "http_health": {"stdout": "exit:0"},
            "error_lines": {"stdout": ""},
        }
        executor.parse_results(results)
        asyncio.run(executor.on_success(results))

    def _set_last_seen(self, alert, when):
        """Backdate the sighting stamp *and make it reach the database*.

        The probe reads the alert on a cursor of its own, so a value
        left in the ORM cache of this test would be invisible to it and
        the assertion below would pass or fail for the wrong reason.
        """
        alert.write({"last_raised_at": when})
        self.env.flush_all()

    def _raise_error_alert(self, message="1 ERROR line(s)"):
        """Write the starting state, rather than hope a cycle left it."""
        return self.env["cloud.alert"].raise_alert(
            "instance_error_logs", message, instance=self.instance,
        )

    def test_a_clean_cycle_minutes_later_keeps_the_alert_up(self):
        alert = self._raise_error_alert()
        self._clean_cycle()
        alert.invalidate_recordset()
        self.assertEqual(
            alert.state, "active",
            "the error was seen minutes ago; one quiet cycle proves "
            "nothing about whether it is fixed",
        )

    def test_a_full_quiet_day_dismisses_it(self):
        alert = self._raise_error_alert()
        self._set_last_seen(
            alert,
            fields.Datetime.now() - timedelta(hours=_ERROR_QUIET_HOURS + 1),
        )
        self._clean_cycle()
        alert.invalidate_recordset()
        self.assertEqual(alert.state, "dismissed")

    def test_an_old_alert_without_a_stamp_falls_back_to_its_creation(self):
        """Rows written before the field existed must still close.

        ``last_raised_at`` is nullable and no migration backfills it, so
        the rule has to read ``create_date`` when it is missing —
        otherwise every alert already open at deploy time would stay
        open for ever.
        """
        alert = self._raise_error_alert()
        old = fields.Datetime.now() - timedelta(hours=_ERROR_QUIET_HOURS + 1)
        self._set_last_seen(alert, False)
        self.env.cr.execute(
            "UPDATE cloud_alert SET create_date = %s WHERE id = %s",
            (old, alert.id),
        )
        alert.invalidate_recordset()
        self._clean_cycle()
        alert.invalidate_recordset()
        self.assertEqual(alert.state, "dismissed")

    def test_raising_again_moves_the_last_seen_stamp(self):
        alert = self._raise_error_alert()
        stale = fields.Datetime.now() - timedelta(hours=3)
        self._set_last_seen(alert, stale)
        self._raise_error_alert(message="2 ERROR line(s)")
        alert.invalidate_recordset()
        self.assertGreater(
            alert.last_raised_at, stale,
            "the upsert refreshes the message; it must refresh the "
            "clock the quiet window is measured against too",
        )
