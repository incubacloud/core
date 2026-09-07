"""The ``instance_error_logs`` payload must survive the container.

An alert whose payload holds only the ERROR headline is undiagnosable
once the instance has been rebuilt and its logs are gone — which is
exactly what happened on 2026-08-16, when three
``Exception during request handling`` groups were left without a stack
by the next rebuild. The probe now carries the traceback lines that
follow each header, bounded so a log stuck in a loop cannot inflate the
serialized payload.
"""
import asyncio
import pathlib

from odoo.tests.common import BaseCase, TransactionCase

from odoo.addons.incubacloud.models.instance_health_executor import (
    _ERROR_CONTEXT_CHARS,
    _ERROR_CONTEXT_TAIL,
    InstanceHealthExecutor,
)

_HEADER = (
    "2026-08-16 17:50:03,123 7 ERROR prod odoo.http: "
    "Exception during request handling."
)
_SECOND_HEADER = (
    "2026-08-16 17:51:10,000 7 ERROR prod odoo.sql_db: "
    "bad query"
)
_TRACEBACK = [
    "Traceback (most recent call last):",
    '  File "/usr/lib/python3/dist-packages/odoo/http.py", line 1, in dispatch',
    "    return self._do_it()",
    "ValueError: boom",
]

#: A real Odoo cron traceback: ``ir_cron`` → ``ir_actions`` →
#: ``safe_eval`` → the addon → the ORM. Thirty-odd frames, and the one
#: line that says what broke is the last.
_LONG_TRACEBACK = [
    "Traceback (most recent call last):",
    *[
        f'  File "/opt/odoo/odoo/addons/base/models/frame{n}.py", '
        f'line {n}, in step{n}'
        for n in range(30)
    ],
    "    record._check_field_access(self, 'read')",
    "odoo.exceptions.AccessError: You do not have enough rights to "
    'access the field "core_saas_url" on IncubaCloud Settings.',
]

#: What ``grep -A`` prints once the traceback is over: the next log
#: records, at whatever level. Alert 3115 (7-sep-2026) kept thirteen of
#: these under its ERROR and the exception as line 1 of a 14-line tail.
_AFTERMATH = [
    f"2026-09-07 08:34:{n:02d},000 7 INFO prod werkzeug: "
    f'192.0.2.{n} - - [07/Sep/2026 08:34:{n:02d}] '
    '"POST /websocket HTTP/1.1" 200 -'
    for n in range(13)
]
_WARNING_LINE = (
    "2026-08-16 17:50:04,000 7 WARNING prod odoo.addons.base: "
    "something unrelated"
)

_TEMPLATE = (
    pathlib.Path(__file__).resolve().parent.parent
    / "static" / "src" / "components" / "alert_history" / "alert_history.xml"
)


class TestErrorLogContext(TransactionCase):

    def setUp(self):
        super().setUp()
        # The probe writes alerts on a cursor of its own; test mode is
        # what lets that cursor see the records created here.
        self.registry_enter_test_mode()
        self.project = self.env["cloud.project"].create({"name": "Ctx Proj"})
        self.host = self.env["cloud.host"].create({
            "name": "ctx-host",
            "ip_address": "192.0.2.64",
            "user": "ubuntu",
            "wildcard_domain": "ctx.example.com",
        })
        self.instance = self.env["cloud.instance"].create({
            "name": "ctxinst",
            "project_id": self.project.id,
            "environment": "production",
            "host_id": self.host.id,
        })
        self.job_type = self.env["cloud.job.type"].search(
            [("code", "=", "instance_health")], limit=1,
        )

    def _executor(self):
        job = self.env["cloud.job"].create({
            "name": "Health",
            "host_id": self.host.id,
            "instance_id": self.instance.id,
            "job_type_id": self.job_type.id,
        })
        executor = InstanceHealthExecutor(job, self.host)
        executor._skipped = False
        return executor

    def _groups(self, raw):
        return self._executor()._dedupe_error_lines(raw)

    def test_traceback_is_filed_under_its_header(self):
        groups = self._groups("\n".join([_HEADER, *_TRACEBACK]))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 1, "context is not an ERROR line")
        self.assertIn("ValueError: boom", "\n".join(groups[0]["context"]))

    def test_grep_separator_closes_the_block(self):
        """A ``--`` between blocks must not leak context across groups."""
        groups = self._groups("\n".join([
            _HEADER, *_TRACEBACK, "--", _SECOND_HEADER,
        ]))
        by_fp = {g["fingerprint"]: g for g in groups}
        self.assertEqual(len(by_fp), 2)
        empty = [g for g in groups if not g["context"]]
        self.assertEqual(len(empty), 1, "second group must start clean")

    def test_only_the_first_occurrence_carries_context(self):
        """Repeats share the stack — storing it again is dead weight."""
        groups = self._groups("\n".join([
            _HEADER, *_TRACEBACK, "--", _HEADER, *_TRACEBACK,
        ]))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["context"].count("ValueError: boom"), 1)

    def test_the_exception_outlives_the_frames_above_it(self):
        """Trimming a long traceback must eat the middle, not the end.

        The alert that hid BUG-008 for a week stored twenty-five lines
        and stopped one frame short of ``AccessError: … core_saas_url``.
        Everything it did keep — ``ir_cron``, ``ir_actions``,
        ``safe_eval`` — is identical in every cron failure there is.
        """
        groups = self._groups("\n".join([_HEADER, *_LONG_TRACEBACK]))
        context = groups[0]["context"]
        self.assertIn("AccessError", context[-1])
        self.assertIn("Traceback (most recent call last):", context[0])
        self.assertTrue(
            any("skipped" in line for line in context),
            "a trimmed traceback must say how many lines it dropped",
        )
        self.assertLessEqual(
            len(context), _ERROR_CONTEXT_TAIL + 10,
            "the compacted form must stay small enough to read",
        )

    def test_the_next_log_record_ends_the_traceback(self):
        """``grep -A`` counts lines, not frames.

        What follows a traceback is the next log record, and filing it
        under the ERROR spends the tail budget on werkzeug requests:
        alert 3115 kept the exception as line 1 of 14, one request away
        from losing it — the defect this module exists to prevent, back
        by another door.
        """
        groups = self._groups("\n".join([
            _HEADER, *_LONG_TRACEBACK, *_AFTERMATH,
        ]))
        self.assertEqual(len(groups), 1)
        context = groups[0]["context"]
        self.assertIn("AccessError", context[-1])
        self.assertFalse(
            [line for line in context if "werkzeug" in line],
            "log records after the traceback are not its context",
        )

    def test_a_record_at_any_level_closes_the_group(self):
        """A WARNING closes the group like ``--`` does, whatever comes
        after it belongs to that record, and a later ERROR still opens
        a group of its own with a clean context."""
        groups = self._groups("\n".join([
            _HEADER, *_TRACEBACK,
            _WARNING_LINE,
            "  continuation of the warning, no level field",
            _SECOND_HEADER,
            "Traceback (most recent call last):",
            "KeyError: 'x'",
        ]))
        self.assertEqual(len(groups), 2)
        first = next(
            g for g in groups if "ValueError: boom" in "\n".join(g["context"])
        )
        self.assertNotIn("continuation", "\n".join(first["context"]))
        second = next(
            g for g in groups if "KeyError" in "\n".join(g["context"])
        )
        self.assertEqual(second["count"], 1)
        self.assertEqual(second["context"][-1], "KeyError: 'x'")

    def test_runaway_context_is_capped(self):
        """A log loop must not inflate the serialized payload."""
        noise = ["x" * 500] * 40
        groups = self._groups("\n".join([_HEADER, *noise]))
        stored = sum(len(line) for line in groups[0]["context"])
        self.assertLessEqual(stored, _ERROR_CONTEXT_CHARS)

    def test_alert_payload_ships_the_context(self):
        executor = self._executor()
        results = {
            "container_state": {"stdout": "\n".join(
                f"{svc}\trunning" for svc in self.instance.expected_services()
            )},
            "cpu_mem_snapshot": {"stdout": "0.0\t0.0"},
            "http_health": {"stdout": "exit:0"},
            "error_lines": {"stdout": "\n".join([_HEADER, *_TRACEBACK])},
        }
        executor.parse_results(results)
        asyncio.run(executor.on_success(results))
        alert = self.env["cloud.alert"].search([
            ("instance_id", "=", self.instance.id),
            ("code", "=", "instance_error_logs"),
            ("state", "=", "active"),
        ])
        self.assertEqual(len(alert), 1)
        self.assertIn(
            "ValueError: boom", "\n".join(alert.payload[0]["context"]),
        )


class TestErrorContextIsVisible(BaseCase):
    """A traceback nobody can see is a traceback nobody reads."""

    def test_the_panel_renders_the_stored_context(self):
        """The alert card must show ``context``, not only ``samples``.

        The probe has shipped the traceback in the payload since core
        1.0.75, and the panel has never rendered it: the only way to
        read one was a psql query against production.
        """
        markup = _TEMPLATE.read_text()
        self.assertIn(
            "grp.context", markup,
            "the alert history template ignores the stored traceback",
        )

