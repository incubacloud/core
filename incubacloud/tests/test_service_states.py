"""What the panel is told about each container, and about being down.

The instance card draws one dot per service. It drew all of them from
the single ``running`` flag, so ``db`` and ``odoo`` were never two
readings — they were one reading printed twice, and an instance whose
``odoo`` was asleep showed it as up. The probe has always known the
difference; it just threw the answer away after alerting on it.

The other half is that "down" and "down on purpose" are not the same
thing to show. Base knows of no legitimate reason to be down and says
so; the layer that schedules sleep answers otherwise, and the card says
"Asleep" instead of "Stopped" on the strength of it.
"""
import asyncio

from odoo.tests.common import TransactionCase

from odoo.addons.incubacloud.models.instance_health_executor import (
    InstanceHealthExecutor,
)


class _SleepAwareInstance(TransactionCase):
    """Shared fixture: one deployed instance on one host."""

    def setUp(self):
        super().setUp()
        # The probe writes alerts on a cursor of its own; without test
        # mode those writes cannot see the records created here.
        self.registry_enter_test_mode()
        self.project = self.env["cloud.project"].create({"name": "SvcProj"})
        self.host = self.env["cloud.host"].create({
            "name": "svc-host",
            "ip_address": "192.0.2.71",
            "user": "ubuntu",
            "wildcard_domain": "svc.example.com",
        })
        self.instance = self.env["cloud.instance"].create({
            "name": "svcinst",
            "project_id": self.project.id,
            "environment": "production",
            "host_id": self.host.id,
        })
        self.job_type = self.env["cloud.job.type"].search(
            [("code", "=", "instance_health")], limit=1,
        )

    def _listing(self, **overrides):
        """Render a ``docker compose ps -a`` payload for this instance.

        Built from ``expected_services()`` rather than hard-coded, so
        these assertions do not depend on which optional services the
        database under test happens to enable.
        """
        states = dict.fromkeys(self.instance.expected_services(), "running")
        for svc, state in overrides.items():
            if state is None:
                states.pop(svc, None)
            else:
                states[svc] = state
        return "\n".join(f"{svc}\t{state}" for svc, state in states.items())

    def _probe(self, container_state):
        """Run one health probe against *container_state* and return it."""
        job = self.env["cloud.job"].create({
            "name": "Health",
            "host_id": self.host.id,
            "instance_id": self.instance.id,
            "job_type_id": self.job_type.id,
        })
        executor = InstanceHealthExecutor(job, self.host)
        executor._skipped = False
        results = {
            "container_state": {"stdout": container_state},
            "cpu_mem_snapshot": {"stdout": "0.0\t0.0"},
            "http_health": {"stdout": "exit:1"},
            "error_lines": {"stdout": ""},
        }
        executor.parse_results(results)
        asyncio.run(executor.on_success(results))
        return executor


class TestTheProbeKeepsWhatItSaw(_SleepAwareInstance):

    def test_nothing_is_stored_before_the_first_probe(self):
        self.assertFalse(self.instance.service_states)

    def test_a_healthy_stack_is_recorded_service_by_service(self):
        self._probe(self._listing())
        stored = self.instance.service_states
        self.assertEqual(stored.get("odoo"), "running")
        self.assertEqual(stored.get("db"), "running")

    def test_one_service_down_is_visible_next_to_the_others(self):
        """The reading the card could not show: two services, two
        different states."""
        self._probe(self._listing(db="exited"))
        stored = self.instance.service_states
        self.assertEqual(stored.get("odoo"), "running")
        self.assertEqual(stored.get("db"), "exited")

    def test_it_is_recorded_even_when_odoo_is_down(self):
        """That branch returns early after alerting — the reading has
        to be stored before it, or the card goes blank exactly when it
        matters."""
        self._probe(self._listing(odoo="exited"))
        self.assertEqual(self.instance.service_states.get("odoo"), "exited")

    def test_a_missing_container_is_absent_rather_than_invented(self):
        """A pruned stack has no entry at all, which is not the same as
        one that is stopped."""
        self._probe(self._listing(odoo=None))
        self.assertNotIn("odoo", self.instance.service_states)

    def test_a_later_probe_replaces_the_earlier_reading(self):
        self._probe(self._listing(db="exited"))
        self._probe(self._listing())
        self.assertEqual(self.instance.service_states.get("db"), "running")


class TestWhetherBeingDownIsExpected(_SleepAwareInstance):

    def test_base_knows_of_no_reason_to_be_down(self):
        """Anything stopped here is an incident, and is reported as one.
        A layer that schedules sleep overrides this."""
        self.assertFalse(self.instance._stop_is_expected())

    def test_the_field_says_what_the_method_says(self):
        """The panel reads the field; the layers override the method.
        They have to agree or the card contradicts the alerting."""
        self.assertEqual(
            self.instance.stop_is_expected,
            self.instance._stop_is_expected(),
        )
