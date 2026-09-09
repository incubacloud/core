"""The delete-instance route must gate the caller's role before it looks.

Found by the FINAL-001 pentest against devel on 2026-09-09. Every delete
route in the panel refuses a caller without the role, except this one:
``cloud_delete_instance`` called ``exists()`` first and returned
"Instance not found" for an id nobody holds, while an id that does exist
raised ``AccessError``. Two distinguishable answers is an oracle, and
``exists()`` is raw SQL — neither the model ACL nor a record rule
narrows it — so the oracle covered every instance on the platform and
was reachable by any authenticated user, a portal customer included.

The order is the whole fix, so the order is what these tests pin: a
caller below ``group_cloud_consultant`` must get the same refusal
whether or not the id exists.
"""
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from odoo.exceptions import AccessError
from odoo.http import Request
from odoo.tests.common import TransactionCase, tagged

from ..controllers.data_load import CloudDataLoadController

# Both modules did ``from odoo.http import request``, so each holds its
# own name bound to the proxy: the route body reads the one in
# ``_routes_ops`` and ``_sec()`` reads the one in ``data_load``. Patching
# only the first leaves the second reaching for a request that is not
# there, which fails as a test error rather than as a verdict.
_REQUEST_NAMES = (
    'odoo.addons.incubacloud.controllers._data_load._routes_ops.request',
    'odoo.addons.incubacloud.controllers.data_load.request',
)


@tagged('post_install', '-at_install')
class TestDeleteInstanceGateOrder(TransactionCase):
    """Call the controller method directly against real records.

    Going through the method rather than the HTTP route keeps this off
    the web stack while still running the code the route runs. The role
    check reads ``self.env.user``, so binding ``request.env`` to an
    environment for a given user is enough to exercise it.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.host = cls.env['cloud.host'].create({
            'name': 'gate-order-host',
            'ip_address': '203.0.113.7',
            'wildcard_domain': 'gate-order.invalid',
            'user': 'root',
            'port': 22,
            'login_type': 'password',
            'password': 'unused-by-this-test',
        })
        cls.project = cls.env['cloud.project'].create({
            'name': 'gate-order-project',
        })
        cls.instance = cls.env['cloud.instance'].create({
            'name': 'gate-order-inst',
            'project_id': cls.project.id,
            'host_id': cls.host.id,
            'environment': 'staging',
        })
        # An id no row holds. Read from the table rather than hardcoded,
        # so a database with more rows cannot collide with it.
        cls.env.cr.execute('SELECT COALESCE(MAX(id), 0) FROM cloud_instance')
        cls.ghost_id = cls.env.cr.fetchone()[0] + 10000

        cls.low_user = cls.env['res.users'].create({
            'name': 'gate-order-low',
            'login': 'gate-order-low',
            'group_ids': [(6, 0, [
                cls.env.ref('base.group_user').id,
                cls.env.ref('incubacloud.group_cloud_user').id,
            ])],
        })
        cls.portal_user = cls.env['res.users'].create({
            'name': 'gate-order-portal',
            'login': 'gate-order-portal',
            'group_ids': [(6, 0, [cls.env.ref('base.group_portal').id])],
        })

    def _delete_as(self, user, instance_id):
        """Run the route's method as *user*.

        :param user: ``res.users`` record the call runs as.
        :param instance_id: value handed to the route.
        :return: ``('raised', message)`` when the gate refused, or
            ``('passed-the-gate', …)`` when it did not.
        """
        # spec'd against the real class: an attribute the controller
        # reaches for that ``odoo.http.Request`` does not have must fail
        # the test rather than be answered by an obliging double.
        fake_request = MagicMock(spec=Request)
        fake_request.env = self.env(user=user)
        controller = CloudDataLoadController()
        with ExitStack() as stack:
            for name in _REQUEST_NAMES:
                stack.enter_context(patch(name, fake_request))
            try:
                payload = controller.cloud_delete_instance(instance_id)
            except AccessError as exc:
                return 'raised', str(exc)
            except Exception as exc:  # noqa: BLE001
                # Anything else means the call got PAST the role check and
                # died further in, on machinery this test does not stand
                # up (translation, for one). That is still the verdict
                # under test — the gate let it through — so report it as
                # such instead of as a broken test.
                return 'passed-the-gate', f'{type(exc).__name__}: {exc}'
        return 'passed-the-gate', payload

    def test_low_role_cannot_tell_a_real_id_from_a_ghost(self):
        """The oracle: both answers must be the same refusal."""
        ghost = self._delete_as(self.low_user, self.ghost_id)
        real = self._delete_as(self.low_user, self.instance.id)
        self.assertEqual(
            ghost[0], 'raised',
            f'The role gate let a cloud_user reach the lookup for an id '
            f'nobody holds, so the route can be asked whether an id '
            f'exists. Got: {ghost}',
        )
        self.assertEqual(
            real[0], 'raised',
            f'The role gate let a cloud_user reach a real record. '
            f'Got: {real}',
        )
        self.assertEqual(
            ghost[1], real[1],
            'A caller without the role gets two different answers, so the '
            'route still tells them whether the id exists.',
        )

    def test_portal_user_cannot_tell_either(self):
        """A portal customer is authenticated too, and must learn nothing."""
        ghost = self._delete_as(self.portal_user, self.ghost_id)
        real = self._delete_as(self.portal_user, self.instance.id)
        self.assertEqual(
            ghost[0], 'raised',
            f'A portal customer reached the instance lookup. Got: {ghost}',
        )
        self.assertEqual(
            real[0], 'raised',
            f'A portal customer reached a real instance. Got: {real}',
        )

    def test_the_instance_survived_every_refused_call(self):
        """A refusal must not have deleted anything on the way out."""
        self.assertTrue(
            self.instance.exists(),
            'The instance was removed by a call that should have been '
            'refused before it reached unlink().',
        )
