"""A key rotation has to be able to tell when it is finished.

Found by the FINAL-001 rotation drill on 2026-09-09. ``_rotate_all_secrets``
reports how many rows it rewrote, and RB-01 told the operator to wait for
that number to reach zero before dropping the old key from
``INCUBACLOUD_SECRET_KEY``. It never reaches zero: Fernet puts a timestamp
and a random IV in every token, so re-encrypting the same plaintext with
the same key produces a different string, the ``!=`` guard always passes,
and every pass rewrites every row for as long as the cron runs.

Measured on devel: seeding six secrets under the secondary key and running
the sweep rotated 12 values; running it again rotated the same 12.

An operator following the runbook either waits forever, or drops the old
key on a hunch — and any row that had not moved becomes permanently
unreadable. These are host passwords and SSH keys.

``rotation_pending_count`` answers the question the tally cannot, by
asking the ciphertext which key opens it. That is a property of the data,
so it converges.

Each test writes the state it asserts on. The database these run against
is neutralised, so inheriting "whatever secrets happen to exist" would
mean asserting on an empty set and passing for the wrong reason.
"""
import os

from odoo.tests.common import TransactionCase, tagged

from ..models.password_utils import is_on_primary_key


def _keys():
    """Return the configured Fernet keys, primary first."""
    raw = os.environ.get('INCUBACLOUD_SECRET_KEY', '')
    return [k.strip() for k in raw.split(',') if k.strip()]


@tagged('post_install', '-at_install')
class TestRotationPendingCount(TransactionCase):
    """Exercise the rotation signal against real ciphertext."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.settings = cls.env['cloud.settings'].sudo()._get_system()
        cls.host = cls.env['cloud.host'].create({
            'name': 'rotation-signal-host',
            'ip_address': '203.0.113.61',
            'wildcard_domain': 'rotation-signal.invalid',
            'user': 'root',
            'port': 22,
            'login_type': 'password',
            'password': 'written-by-this-test',
        })

    def _encrypt_with(self, key, plaintext):
        """Return an ``enc:`` token built with *key* specifically."""
        from cryptography.fernet import Fernet

        return 'enc:' + Fernet(key).encrypt(plaintext.encode()).decode()

    def _set_raw(self, value):
        """Put *value* in the host's password column, bypassing the ORM."""
        self.env.cr.execute(
            'UPDATE cloud_host SET password = %s WHERE id = %s',
            (value, self.host.id),
        )
        self.env['cloud.host'].invalidate_model(['password'])

    def test_a_value_on_the_primary_key_is_not_pending(self):
        """The ordinary case: written today, nothing to do."""
        self.host.write({'password': 'freshly-written'})
        stored = self.host.read(['password'])  # force the write through
        self.assertTrue(stored)
        self.env.cr.execute(
            'SELECT password FROM cloud_host WHERE id = %s', (self.host.id,)
        )
        raw = self.env.cr.fetchone()[0]
        self.assertTrue(
            is_on_primary_key(raw, self.env),
            'A value just written must already be on the primary key.',
        )

    def test_a_value_on_an_older_key_is_pending(self):
        """The case the whole signal exists for."""
        keys = _keys()
        if len(keys) < 2:
            self.skipTest(
                'needs a second key in INCUBACLOUD_SECRET_KEY: with one key '
                'there is no such thing as a value on an older key, so this '
                'assertion would pass without exercising anything'
            )
        self._set_raw(self._encrypt_with(keys[1], 'seeded-under-old-key'))
        before = self.settings.rotation_pending_count()
        self.assertGreaterEqual(
            before['total'], 1,
            'A value encrypted with the secondary key must count as pending.',
        )
        self.assertIn('cloud_host.password', before['by_column'])

        self.settings._rotate_all_secrets()

        after = self.settings.rotation_pending_count()
        self.assertNotIn(
            'cloud_host.password', after['by_column'],
            'After a rotation pass the seeded value must be on the primary '
            'key, so it must no longer be counted as pending.',
        )

    def test_the_count_converges_where_the_rotated_tally_does_not(self):
        """The defect, pinned: rewriting is not the same as pending."""
        keys = _keys()
        if len(keys) < 2:
            self.skipTest('needs a second key in INCUBACLOUD_SECRET_KEY')
        self._set_raw(self._encrypt_with(keys[1], 'seeded-under-old-key'))

        first = self.settings._rotate_all_secrets()
        second = self.settings._rotate_all_secrets()
        rewritten_again = sum(v['rotated'] for v in second.values())

        # This is the observed behaviour, not the desired one. It is
        # asserted so that if a future change ever makes the sweep skip
        # values already on the primary key, this test fails loudly and
        # whoever did it can delete the workaround rather than discover
        # the docs are now wrong in the other direction.
        self.assertGreater(
            sum(v['rotated'] for v in first.values()), 0,
            'The first pass must have rotated the seeded value.',
        )
        self.assertGreater(
            rewritten_again, 0,
            'Known behaviour: a second pass rewrites the same rows, because '
            'Fernet tokens differ every time. If this now reports 0 the '
            'sweep became idempotent — good — and rotation_pending_count '
            'plus this test can be simplified.',
        )
        self.assertEqual(
            self.settings.rotation_pending_count()['total'], 0,
            'Meanwhile the pending count must be 0: everything is on the '
            'primary key, whatever the rewrite tally says.',
        )

    def test_an_unreadable_value_counts_as_pending(self):
        """Safe direction: keep the old key rather than strand a row."""
        self._set_raw('enc:not-a-valid-fernet-token')
        self.assertFalse(
            is_on_primary_key('enc:not-a-valid-fernet-token', self.env),
            'A ciphertext nothing can open must count as pending, so the '
            'operator does not retire a key that might still be needed.',
        )
        self.assertGreaterEqual(
            self.settings.rotation_pending_count()['total'], 1,
        )

    def test_empty_and_plain_values_are_not_pending(self):
        """Nothing to move is not the same as something left to move."""
        self.assertTrue(is_on_primary_key('', self.env))
        self.assertTrue(is_on_primary_key(False, self.env))
        self.assertTrue(is_on_primary_key('plain-legacy-value', self.env))
