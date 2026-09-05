"""Tests for deriving ``running`` from metrics (Fase 4 / A8).

The fail-safes are the point of this file: an unreachable backend must
change nothing, and an instance the backend has never reported on must
not be declared stopped. They protect the same chain — ``running``
feeds ``sleeping`` feeds ``last_activity_at`` feeds the 14-day
auto-suspend, so a false "stopped" eventually has a billing consequence.

The other half is which container the flag is about, which the fail-safes
say nothing about: a false "running" is just as wrong and far quieter,
because everything downstream simply never fires. See
``TestWhichContainerDecides``.
"""
from unittest.mock import MagicMock, patch

import requests

from odoo.tests.common import TransactionCase

_MODULE = "odoo.addons.incubacloud.models.cloud_metric_rule"


def _samples(*pairs):
    """Build a PromQL payload of (instance_id, seconds-since-seen)."""
    return {
        "status": "success",
        "data": {
            "result": [
                {"metric": {"instance_id": str(iid)}, "value": [0, str(age)]}
                for iid, age in pairs
            ],
        },
    }


class InstanceLivenessCase(TransactionCase):

    def setUp(self):
        super().setUp()
        # The cron stamps on a cursor of its own so it can run at READ
        # COMMITTED (see ``models/_concurrency``). Without test mode
        # that cursor is a real one: its writes would commit for good
        # and leak into the next test.
        self.registry_enter_test_mode()
        self.settings = self.env["cloud.settings"].sudo()._get_system()
        self.settings.write({
            "metrics_enabled": True,
            "metrics_central_url": "http://vm.test:8428",
        })
        self.project = self.env["cloud.project"].create({"name": "P"})
        self.inst = self.env["cloud.instance"].create({
            "name": "i1", "project_id": self.project.id,
            "environment": "staging",
        })

    def _run(self, payload=None, exc=None, odoo_payload=None):
        # The cron stamps on a cursor of its own, so it reads what is in
        # the database rather than what is pending in this env's cache —
        # which is exactly what happens in production, where the cron
        # opens a clean transaction of its own. Flush first, or the cron
        # grades a row whose ``running`` the test only *intends* to set.
        self.env.flush_all()
        # Two queries now: who the backend covers, then how long since
        # each one's ``odoo`` container. Passing only ``payload`` answers
        # both the same way, which is the shape of a fleet where every
        # instance's odoo container is the freshest thing it reports —
        # what every test written before the split assumed.
        coverage = payload or _samples()
        bodies = [coverage, coverage if odoo_payload is None else odoo_payload]
        responses = []
        for body in bodies:
            resp = MagicMock(spec=requests.Response)
            resp.json.return_value = body
            resp.raise_for_status.return_value = None
            responses.append(resp)
        with patch(f"{_MODULE}.requests.get",
                   side_effect=exc or responses):
            self.env["cloud.instance"]._cron_refresh_running_from_metrics()


class TestLivenessSendsCredentials(InstanceLivenessCase):
    """The liveness query must authenticate as this panel's account.

    ``promql_query`` attaches credentials only when given BOTH halves —
    ``auth=(user, token) if (token and user) else None`` — so a caller
    that unpacks the pair and forwards just the token queries
    anonymously. The central answers 401, the cron logs a warning and
    returns, and liveness silently stops being refreshed: every
    instance keeps whatever ``running`` it last had, which then feeds
    ``sleeping`` and the auto-suspend clock.

    That is precisely what this call site did while the other two
    passed both halves, so the property is pinned on the wire rather
    than on the call.
    """

    def setUp(self):
        super().setUp()
        self.settings.write({
            "metrics_account": "acct_test",
            "metrics_remote_write_token": "s3cr3t",
        })

    def test_the_query_carries_both_halves_of_the_credential(self):
        resp = MagicMock(spec=requests.Response)
        resp.json.return_value = _samples()
        resp.raise_for_status.return_value = None
        with patch(f"{_MODULE}.requests.get", return_value=resp) as get:
            self.env["cloud.instance"]._cron_refresh_running_from_metrics()
        self.assertEqual(
            get.call_args.kwargs["auth"], ("acct_test", "s3cr3t"),
        )


class TestLiveness(InstanceLivenessCase):

    def test_a_recently_seen_container_marks_running(self):
        self.inst.write({"running": False})
        self._run(_samples((self.inst.id, 20)))
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)

    def test_a_stale_container_marks_not_running(self):
        self.inst.write({"running": True})
        self._run(_samples((self.inst.id, 9999)))
        self.inst.invalidate_recordset()
        self.assertFalse(self.inst.running)

    def test_the_window_is_forgiving_of_one_missed_scrape(self):
        """Just over the scrape interval must not flap the flag."""
        window = self.env["cloud.instance"]._metrics_liveness_window()
        self.assertGreaterEqual(window, 90)
        self.inst.write({"running": False})
        self._run(_samples((self.inst.id, 45)))
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)


class TestLivenessFailSafes(InstanceLivenessCase):

    def test_unreachable_backend_changes_nothing(self):
        self.inst.write({"running": True})
        self._run(exc=requests.ConnectionError("down"))
        self.inst.invalidate_recordset()
        self.assertTrue(
            self.inst.running,
            "an unreachable backend must not mark instances stopped",
        )

    def test_an_uncovered_instance_is_left_alone(self):
        """No metrics for this instance = unknown, not stopped."""
        other = self.env["cloud.instance"].create({
            "name": "i2", "project_id": self.project.id,
            "environment": "staging",
        })
        self.inst.write({"running": True})
        other.write({"running": True})
        # Only i1 is reported on, and it is stale.
        self._run(_samples((self.inst.id, 9999)))
        self.inst.invalidate_recordset()
        other.invalidate_recordset()
        self.assertFalse(self.inst.running)
        self.assertTrue(
            other.running,
            "an instance the backend never reported on was clobbered",
        )

    def test_disabled_master_switch_changes_nothing(self):
        self.settings.metrics_enabled = False
        self.inst.write({"running": True})
        self._run(_samples((self.inst.id, 9999)))
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)

    def test_empty_result_changes_nothing(self):
        """A backend with no data yet must not stop the whole fleet."""
        self.inst.write({"running": True})
        self._run(_samples())
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)


class TestWhichContainerDecides(InstanceLivenessCase):
    """``running`` is about the ``odoo`` container, not about the stack.

    An instance put to sleep keeps its database and backup containers
    up — only ``odoo`` is stopped. Asked about any container of the
    stack, the backend therefore answers "seen seconds ago" all night,
    the flag never falls, and everything hanging off it never happens:
    the tenant is never marked sleeping, its activity clock is refreshed
    as though somebody had visited, and the panel shows a sleeping
    tenant as running.

    Nothing fails while that is wrong, which is why it is pinned here
    rather than left to the fail-safes above.
    """

    def setUp(self):
        super().setUp()
        self.awake = self.env["cloud.instance"].create({
            "name": "i2", "project_id": self.project.id,
            "environment": "staging",
        })

    def _queries(self):
        """Return the PromQL of each query the cron sent, in order."""
        self.env.flush_all()
        responses = []
        for _ in range(2):
            resp = MagicMock(spec=requests.Response)
            resp.json.return_value = _samples((self.inst.id, 5))
            resp.raise_for_status.return_value = None
            responses.append(resp)
        with patch(f"{_MODULE}.requests.get", side_effect=responses) as get:
            self.env["cloud.instance"]._cron_refresh_running_from_metrics()
        return [
            call.kwargs["params"]["query"] for call in get.call_args_list
        ]

    def test_two_questions_are_asked_not_one(self):
        self.assertEqual(len(self._queries()), 2)

    def test_the_first_asks_who_reports_at_all(self):
        """Coverage, not liveness: it decides whose flag may be written,
        so narrowing it to ``odoo`` would make a sleeping instance
        indistinguishable from one with no agent installed."""
        self.assertNotIn("compose_service", self._queries()[0])

    def test_the_second_asks_about_the_odoo_container(self):
        """The label the agents are started with. Get it wrong and the
        query matches nothing — silently, and forever."""
        second = self._queries()[1]
        self.assertIn("container_label_com_docker_compose_service", second)
        self.assertIn('"odoo"', second)

    def test_a_stack_whose_odoo_is_gone_is_not_running(self):
        """The sleeping tenant, exactly: still reporting containers, but
        not that one."""
        self.inst.write({"running": True})
        self.awake.write({"running": True})
        self._run(
            _samples((self.inst.id, 5), (self.awake.id, 5)),
            odoo_payload=_samples((self.awake.id, 5)),
        )
        self.inst.invalidate_recordset()
        self.awake.invalidate_recordset()
        self.assertFalse(
            self.inst.running,
            "an instance whose odoo container is gone read as running",
        )
        self.assertTrue(self.awake.running)

    def test_a_stale_odoo_is_not_running_either(self):
        """Reported, but too long ago — the container went away between
        scrapes and the series has not expired yet."""
        self.inst.write({"running": True})
        self._run(
            _samples((self.inst.id, 5), (self.awake.id, 5)),
            odoo_payload=_samples((self.inst.id, 9999), (self.awake.id, 5)),
        )
        self.inst.invalidate_recordset()
        self.assertFalse(self.inst.running)


class TestWhenTheSecondQuestionCannotBeTrusted(InstanceLivenessCase):

    def test_a_fleet_with_no_odoo_container_at_all_changes_nothing(self):
        """A missing label or a broken query looks exactly like every
        instance stopping at once, and the two need opposite reactions.

        Believing it would mark the whole fleet stopped, which flips
        every sleep-eligible tenant to sleeping and hands a false answer
        to the clock behind the 14-day auto-suspend. Refusing to believe
        it costs, at worst, the flag staying where it already was.
        """
        self.inst.write({"running": True})
        self._run(_samples((self.inst.id, 5)), odoo_payload=_samples())
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)

    def test_a_second_query_that_fails_changes_nothing(self):
        """Coverage answered, liveness did not. Silence is not an
        answer, and the first query alone cannot decide this."""
        self.env.flush_all()
        self.inst.write({"running": True})
        self.env.flush_all()
        first = MagicMock(spec=requests.Response)
        first.json.return_value = _samples((self.inst.id, 5))
        first.raise_for_status.return_value = None
        with patch(
            f"{_MODULE}.requests.get",
            side_effect=[first, requests.ConnectionError("down")],
        ):
            self.env["cloud.instance"]._cron_refresh_running_from_metrics()
        self.inst.invalidate_recordset()
        self.assertTrue(self.inst.running)
