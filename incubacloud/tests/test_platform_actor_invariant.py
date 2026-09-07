"""Structural guard: unauthenticated routes must act as the platform.

Odoo's ``sudo()`` raises privileges but leaves ``env.uid`` alone. A route
declared ``auth="public"`` or ``auth="none"`` therefore runs as the
*public* user, and everything it writes is authored by it — the record,
``queue_job.user_id`` (so the executor runs as the public user too), and
every row that executor goes on to write.

This has now been found three times in three different shapes: the warm
pool stamped the customer who was signing up onto the spare built for the
*next* one, the GitHub webhook stamped the public user onto 348 fleet
rebuilds and 192k log chunks, and the alerts raised along the way
inherited whichever of the two produced them.

A behavioural test would have to be written once per route, which is
exactly what did not happen. So this one is structural: it reads the
source of every controller and refuses any public route that enqueues a
job, dispatches a webhook event or files an alert without first passing
through ``as_platform()``.
"""
import ast
import pathlib
import tempfile

from odoo.tests.common import BaseCase

#: Auth levels that leave ``env.uid`` pointing at the public user.
_UNAUTHENTICATED = frozenset({"public", "none"})

#: Calls that write platform-owned rows, directly or through the chain
#: they set off. Each is an entry point whose author outlives the request.
_PLATFORM_WRITES = frozenset({"enqueue", "enqueue_chain", "_dispatch",
                              "raise_alert", "resolve_alert"})

#: The one call that makes the platform, not the caller, the author.
_ELEVATOR = "as_platform"

_CORE_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC_ROOT = _CORE_ROOT.parent.parent


def _controller_dirs():
    """Return every controllers directory shipped by the platform.

    Reaches across repos on purpose: the rule belongs to core but the
    routes that break it mostly live in saas. A repo that is not checked
    out simply contributes nothing, so the guard degrades to whatever is
    present rather than failing on layout.

    :return: list of existing ``controllers`` directories.
    """
    candidates = [
        _CORE_ROOT / "controllers",
        _SRC_ROOT / "saas" / "incubacloud_saas_manager" / "controllers",
        _SRC_ROOT / "saas" / "incubacloud_oidc_provider" / "controllers",
        _SRC_ROOT / "saas" / "incubacloud_website" / "controllers",
    ]
    return [path for path in candidates if path.is_dir()]


def _is_unauthenticated_route(node):
    """True if *node* is decorated with an ``auth``-less ``http.route``.

    :param node: a function definition node.
    :return: whether any decorator declares a public/none auth level.
    """
    for deco in node.decorator_list:
        if not isinstance(deco, ast.Call):
            continue
        for kw in deco.keywords:
            if kw.arg != "auth":
                continue
            if (
                isinstance(kw.value, ast.Constant)
                and kw.value.value in _UNAUTHENTICATED
            ):
                return True
    return False


def _offending_routes(path):
    """Find public routes that write platform rows without elevating.

    Scoped to the route body — a helper called from it is not followed,
    deliberately: the elevation is cheap and belongs where the identity
    is decided, so requiring it in plain sight is the point rather than
    a limitation.

    :param path: module to inspect.
    :return: list of ``(route, call, lineno)`` for each violation.
    """
    tree = ast.parse(path.read_text())
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_unauthenticated_route(node):
            continue
        calls = [
            call for call in ast.walk(node)
            if isinstance(call, ast.Call)
        ]
        elevates = any(
            isinstance(call.func, ast.Name) and call.func.id == _ELEVATOR
            for call in calls
        )
        if elevates:
            continue
        for call in calls:
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in _PLATFORM_WRITES
            ):
                bad.append((node.name, call.func.attr, call.lineno))
    return bad


class TestPlatformActorInvariant(BaseCase):

    def test_public_routes_elevate_before_writing_platform_rows(self):
        """No unauthenticated route may author platform work as itself."""
        violations = []
        for directory in _controller_dirs():
            for path in sorted(directory.glob("*.py")):
                for route, call, lineno in _offending_routes(path):
                    violations.append(
                        f"{path.name}:{lineno} — {route}() calls {call}()"
                    )
        self.assertFalse(
            violations,
            "these routes run as the public user, so the job, its "
            "queue_job row and every log chunk its executor writes are "
            "authored by 'Public user' instead of the platform bot. "
            "Wrap the recordset in as_platform() first:\n  "
            + "\n  ".join(violations),
        )

    def test_the_detector_actually_detects(self):
        """A canary: the scan must flag a violation it is shown.

        Without this, a broken walker would report 'no violations' and
        the guard above would pass while checking nothing.
        """
        source = (
            "class C:\n"
            "    @http.route('/x', type='http', auth='public')\n"
            "    def hook(self):\n"
            "        request.env['cloud.job'].sudo().enqueue(1, 2, 'x')\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            canary = pathlib.Path(tmpdir) / "canary.py"
            canary.write_text(source)
            found = _offending_routes(canary)
        self.assertEqual(found, [("hook", "enqueue", 4)])

    def test_elevated_route_is_accepted(self):
        """The canary's twin: elevating clears the violation."""
        source = (
            "class C:\n"
            "    @http.route('/x', type='http', auth='public')\n"
            "    def hook(self):\n"
            "        Job = as_platform(request.env['cloud.job'])\n"
            "        Job.enqueue(1, 2, 'x')\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            canary = pathlib.Path(tmpdir) / "canary.py"
            canary.write_text(source)
            self.assertEqual(_offending_routes(canary), [])

    def test_authenticated_routes_are_out_of_scope(self):
        """``auth='user'`` has a real user; authoring as them is right."""
        source = (
            "class C:\n"
            "    @http.route('/x', type='http', auth='user')\n"
            "    def act(self):\n"
            "        request.env['cloud.job'].enqueue(1, 2, 'x')\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            canary = pathlib.Path(tmpdir) / "canary.py"
            canary.write_text(source)
            self.assertEqual(_offending_routes(canary), [])

    def test_it_is_scanning_something(self):
        """Guard against the scan silently covering zero files."""
        self.assertTrue(_controller_dirs())
        scanned = sum(
            len(list(directory.glob("*.py")))
            for directory in _controller_dirs()
        )
        self.assertGreater(scanned, 5)
