"""Tier 2 — the job history cut for instance records that get reused.

A ``cloud.instance`` normally owns its whole job history, so core draws
no line and every job shows. The hook exists for layers that hand an
existing instance to a new owner (the SaaS warm pool): there, the jobs
logged before the handover are still true of the machine but are not the
new owner's, and listing them unannounced makes a brand-new tenant look
months old.

These tests pin the core half of that contract: the default is "no cut",
a floor hides exactly what predates it, the toggle brings it back, and
the fleet-wide history is never touched by one instance's floor.
"""
from datetime import timedelta
from unittest.mock import patch

from odoo import fields
from odoo.tests.common import TransactionCase


class TestJobHistoryFloor(TransactionCase):
    """Exercise ``_pre_claim_cut`` through both of its callers."""

    def setUp(self):
        super().setUp()
        self.host = self.env['cloud.host'].create({
            'name': 'Floor Host',
            'ip_address': '10.0.0.9',
            'user': 'ubuntu',
            'wildcard_domain': 'floor.example.com',
        })
        self.project = self.env['cloud.project'].create({
            'name': 'floor-project',
        })
        self.instance = self.env['cloud.instance'].create({
            'name': 'floor-instance',
            'project_id': self.project.id,
            'environment': 'production',
            'host_id': self.host.id,
        })
        self.job_type = self.env['cloud.job.type'].search(
            [('code', '=', 'floor_test')], limit=1,
        )
        if not self.job_type:
            self.job_type = self.env['cloud.job.type'].create({
                'name': 'Floor Test',
                'code': 'floor_test',
                'apply_to': 'instance',
            })
        # The handover moment these tests draw their line at. Fixed
        # rather than "now" so the before/after split is explicit and
        # cannot drift with execution time.
        self.claim = fields.Datetime.now() - timedelta(days=1)
        # 3 jobs before the handover, 2 after. Written here rather than
        # inherited from anything: the whole point under test is which
        # side of ``self.claim`` each job falls on.
        self.old_jobs = self._jobs(3, self.claim - timedelta(hours=2))
        self.new_jobs = self._jobs(2, self.claim + timedelta(hours=2))

    def _jobs(self, count, created_at):
        """Create *count* finished jobs stamped at *created_at*.

        Both columns go in by hand, for different reasons:

        * ``create_date`` is written by the database on insert and the
          cut is defined entirely in terms of it, so the test has to
          backdate it afterwards.
        * ``state`` is a stored *related* of ``queue_job_id.state``, so
          passing it to ``create`` is discarded in silence. The pending
          compute is flushed first, otherwise the invalidation below
          flushes it and overwrites the raw value with NULL (these jobs
          have no ``queue.job``). Same pattern as ``_start`` in
          ``test_cloud_job``.

        :param count: how many jobs to create.
        :param created_at: the ``create_date`` all of them get.
        :return: the created ``cloud.job`` recordset.
        """
        jobs = self.env['cloud.job']
        for i in range(count):
            jobs |= self.env['cloud.job'].create({
                'host_id': self.host.id,
                'instance_id': self.instance.id,
                'job_type_id': self.job_type.id,
                'name': f'floor job {i}',
            })
        jobs.flush_recordset(['state'])
        self.env.cr.execute(
            "UPDATE cloud_job SET create_date = %s, state = 'done' "
            "WHERE id IN %s",
            (created_at, tuple(jobs.ids)),
        )
        self.env['cloud.job'].invalidate_model(['create_date', 'state'])
        return jobs

    def _with_floor(self, floor):
        """Patch the instance model so its history floor is *floor*."""
        return patch.object(
            type(self.instance), '_job_history_floor',
            autospec=True, return_value=floor,
        )

    # ── Core default: an instance owns its whole history ────────────────

    def test_core_instance_has_no_floor(self):
        self.assertFalse(self.instance._job_history_floor())

    def test_timeline_shows_everything_without_a_floor(self):
        data = self.env['cloud.job'].get_instance_jobs(
            self.instance.id, limit=20,
        )
        self.assertEqual(data['total'], 5)
        self.assertFalse(data['preClaim'])

    # ── With a floor: the cut applies and announces itself ──────────────

    def test_timeline_hides_jobs_older_than_the_floor(self):
        with self._with_floor(self.claim):
            data = self.env['cloud.job'].get_instance_jobs(
                self.instance.id, limit=20,
            )
        self.assertEqual(data['total'], 2)
        self.assertEqual(data['preClaim']['hidden'], 3)
        self.assertFalse(data['preClaim']['showing_all'])
        returned = {j['id'] for j in data['activeJobs'] + data['recentJobs']}
        self.assertEqual(returned, set(self.new_jobs.ids))

    def test_include_pre_claim_brings_the_old_jobs_back(self):
        with self._with_floor(self.claim):
            data = self.env['cloud.job'].get_instance_jobs(
                self.instance.id, limit=20, include_pre_claim=True,
            )
        self.assertEqual(data['total'], 5)
        # Still reported, so the UI can offer to hide them again.
        self.assertEqual(data['preClaim']['hidden'], 3)
        self.assertTrue(data['preClaim']['showing_all'])

    def test_no_notice_when_the_floor_hides_nothing(self):
        # A warm claimed the instant it was built has a floor but no
        # earlier history; announcing "0 hidden jobs" would be noise.
        with self._with_floor(self.claim - timedelta(days=30)):
            data = self.env['cloud.job'].get_instance_jobs(
                self.instance.id, limit=20,
            )
        self.assertEqual(data['total'], 5)
        self.assertFalse(data['preClaim'])

    # ── load_history: same cut, same numbers ────────────────────────────

    def test_history_page_applies_the_cut_when_scoped_to_the_instance(self):
        with self._with_floor(self.claim):
            result = self.env['cloud.job'].load_history({
                'instance_id': self.instance.id,
                'job_category': 'all',
            })
        self.assertEqual(
            {j['id'] for j in result['jobs']}, set(self.new_jobs.ids),
        )
        self.assertEqual(result['preClaim']['hidden'], 3)

    def test_history_page_toggle_restores_the_old_jobs(self):
        with self._with_floor(self.claim):
            result = self.env['cloud.job'].load_history({
                'instance_id': self.instance.id,
                'job_category': 'all',
                'include_pre_claim': True,
            })
        self.assertEqual(
            {j['id'] for j in result['jobs']},
            set(self.old_jobs.ids) | set(self.new_jobs.ids),
        )
        self.assertTrue(result['preClaim']['showing_all'])

    def test_fleet_history_is_not_cut_by_one_instance_floor(self):
        # No instance filter → no instance whose floor could apply. A
        # cut here would silently drop jobs from the global view.
        with self._with_floor(self.claim):
            result = self.env['cloud.job'].load_history({
                'job_category': 'all',
            })
        ids = {j['id'] for j in result['jobs']}
        self.assertTrue(set(self.old_jobs.ids) <= ids)
        self.assertFalse(result['preClaim'])
