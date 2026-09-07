import contextlib
import hashlib
import hmac
import json
import logging
import re
import urllib.request
from datetime import timedelta

from psycopg2 import OperationalError

from odoo import _, api, fields, models
from odoo.exceptions import AccessError, UserError
from odoo.service.model import PG_CONCURRENCY_ERRORS_TO_RETRY
from odoo.tools import config as odoo_config

from odoo.addons.queue_job.delay import chain as delay_chain
from odoo.addons.queue_job.exception import JobError, RetryableJobError

from ..github.http_utils import safe_urlopen
from ..net.outbound import post_json
from ._repo_requirements import create_pip_conflict_alert, detect_pip_conflicts
from .encrypted_char import EncryptedChar
from .abstract_executor import (
    CONNECTION_RETRY_MARKER,
    CONNECTION_RETRY_SECONDS,
    is_transient_connection_error,
)
from .registry import executor_registry

_logger = logging.getLogger(__name__)


# Namespace used for PostgreSQL transactional advisory locks on
# ``cloud.job.enqueue``. The pair ``(namespace, instance_id)`` serialises
# concurrent enqueue() calls targeting the same instance so two racing
# requests cannot create parallel jobs. The lock is released on COMMIT
# or ROLLBACK automatically — no cleanup possible if the process dies.
_JOB_LOCK_NAMESPACE = 0x0C10D10B
# Separate namespace for host-scoped jobs (no instance_id). A host.id and an
# instance.id can collide numerically, so host locks must live in their own
# namespace to avoid falsely serialising unrelated host/instance work.
_HOST_JOB_LOCK_NAMESPACE = 0x0C10D10C


def _webhook_fields(payload):
    """Extract webhook trigger fields for job serialization.

    Recognises both ``webhook`` (direct push) and ``coalesced`` (a
    follow-up rebuild folding in pushes that arrived while a previous
    rebuild was running). For coalesced jobs ``coalesced_pushes`` lists
    every queued push so the UI can render the full set, not just the
    HEAD shown by the primary push_* fields.
    """
    p = payload or {}
    trigger = p.get("trigger")
    if trigger not in ("webhook", "coalesced"):
        return {"trigger": ""}
    fields = {
        "trigger": trigger,
        "push_repo": p.get("push_repo", ""),
        "push_branch": p.get("push_branch", ""),
        "push_sha": p.get("push_sha", ""),
        "push_message": p.get("push_message", ""),
        "push_by": p.get("push_by", ""),
    }
    if trigger == "coalesced":
        fields["coalesced_pushes"] = p.get("coalesced_pushes") or []
    return fields


class CloudJob(models.Model):
    _name = "cloud.job"
    _inherit = ["bus.listener.mixin"]
    _description = "Job executed remotely on a host"

    name = fields.Char(string="Job Name")
    host_id = fields.Many2one("cloud.host", required=True, string="Cloud Host")
    job_type_id = fields.Many2one(
        "cloud.job.type",
        required=True,
    )
    state = fields.Selection(
        related="queue_job_id.state",
        store=True,
    )
    date_done = fields.Datetime(
        related="queue_job_id.date_done",
        store=True,
        # Stored so ``load_history`` does not need ``queue.job`` ACL —
        # non-Job-Queue-Manager users were tripping ``Access Error`` on
        # ``View all activity`` because reading ``queue_job_id.date_done``
        # required group ``queue_job.group_queue_job_manager``.
    )
    log_chunk_ids = fields.One2many(
        "cloud.job.log.chunk", "job_id", string="Log Chunks"
    )
    result = fields.Serialized()
    payload = fields.Serialized(string="Job Payload")
    # A credential the job needs while it runs, kept out of ``payload``
    # on purpose: the payload is read back into the UI, echoed in
    # notifications and dumped when a job is inspected, and none of those
    # should ever carry a password. Encrypted at rest like every other
    # secret this module holds.
    secret_payload = EncryptedChar(
        string="Job Secret",
        copy=False,
        help="Credential this job needs at run time. Never shown.",
    )
    queue_job_uuid = fields.Char(string="Queue Job UUID", copy=False, index=True)
    queue_job_id = fields.Many2one(
        "queue.job",
        string="Queue Job",
        compute="_compute_queue_job_id",
        store=True,
    )
    instance_id = fields.Many2one(
        "cloud.instance",
        string="Instance",
        ondelete="set null",
    )
    blocked_alert_id = fields.Many2one(
        "cloud.alert",
        string="Blocking Alert",
        ondelete="set null",
        index=True,
        help="When set, this job is blocked waiting for the alert to be resolved.",
    )
    retry_of_id = fields.Many2one(
        "cloud.job",
        string="Retry of",
        ondelete="set null",
        index=True,
        help="When set, this job is a retry of the referenced failed job.",
    )

    @api.depends("queue_job_uuid")
    def _compute_queue_job_id(self):
        for job in self:
            if job.queue_job_uuid:
                queue_job = self.env["queue.job"].search(
                    [("uuid", "=", job.queue_job_uuid)], limit=1
                )
                job.queue_job_id = queue_job or None
            else:
                job.queue_job_id = None

    @api.model
    def enqueue_chain(self, steps):
        """Enqueue a chain of jobs that run sequentially.

        Uses OCA queue_job's DelayableChain so each job waits for
        the previous one to finish before starting.

        steps: list of dicts {host_id, instance_id, job_type_code, payload}

        Payload values matching ``__chain_job_N__`` (0-indexed) are
        replaced with the cloud.job ID of step N, allowing later
        steps to reference earlier ones.

        Returns: list of cloud.job IDs (in execution order)
        """
        _REF_RE = re.compile(r"^__chain_job_(\d+)__$")

        # Advisory lock on every instance touched by the chain. Two
        # concurrent enqueue_chain()/enqueue() calls targeting the same
        # instance serialise here; once we hold the lock we verify there
        # is no active user job for that instance before creating new
        # ones. Locks are released on COMMIT/ROLLBACK automatically.
        seen_instance_ids = set()
        seen_host_ids = set()
        hidden = self._get_hidden_job_types()
        for step in steps:
            # Same server-side role gate as ``enqueue`` — an arbitrary
            # chain of steps must not let a low-privilege caller smuggle a
            # manager-only job type through ``call_kw``.
            self._check_job_type_allowed(
                step["job_type_code"], step.get("instance_id"),
            )
            inst_id = step.get("instance_id")
            if inst_id and inst_id not in seen_instance_ids:
                self.env.cr.execute(
                    "SELECT pg_advisory_xact_lock(%s, %s)",
                    (_JOB_LOCK_NAMESPACE, inst_id),
                )
                seen_instance_ids.add(inst_id)
                running = self.search(
                    [
                        ("instance_id", "=", inst_id),
                        ("state", "in", self._active_states),
                        ("job_type_id.code", "not in", hidden),
                    ],
                    limit=1,
                )
                if running:
                    raise UserError(
                        _(
                            "A job is already running for this instance: "
                            "%(name)s. Wait for it to complete or cancel "
                            "it first.",
                            name=running.name,
                        )
                    )
            elif not inst_id:
                # Host-only step (provisioning, hardening, full setup…):
                # serialise per host so two chains can't run concurrently
                # on the same machine.
                host_id = step.get("host_id")
                if host_id and host_id not in seen_host_ids:
                    self.env.cr.execute(
                        "SELECT pg_advisory_xact_lock(%s, %s)",
                        (_HOST_JOB_LOCK_NAMESPACE, host_id),
                    )
                    seen_host_ids.add(host_id)
                    running = self.search(
                        [
                            ("host_id", "=", host_id),
                            ("instance_id", "=", False),
                            ("state", "in", self._active_states),
                            ("job_type_id.code", "not in", hidden),
                        ],
                        limit=1,
                    )
                    if running:
                        raise UserError(
                            _(
                                "A job is already running for this host: "
                                "%(name)s. Wait for it to complete or cancel "
                                "it first.",
                                name=running.name,
                            )
                        )

        # 1. Create all cloud.job records (without payloads that need resolving)
        records = []
        for step in steps:
            job_type = self.env["cloud.job.type"].search(
                [
                    ("code", "=", step["job_type_code"]),
                ],
                limit=1,
            )
            if not job_type:
                raise UserError(
                    _("Job type '{code}' not found.").format(
                        code=step["job_type_code"],
                    )
                )
            job_record = self.create(
                {
                    "host_id": step["host_id"],
                    "job_type_id": job_type.id,
                    "name": _(job_type.name),
                    "instance_id": step.get("instance_id"),
                    "payload": step.get("payload"),
                }
            )
            records.append(job_record)

        # 2. Resolve __chain_job_N__ references in payloads
        job_ids = [r.id for r in records]
        for record in records:
            payload = record.payload
            if not payload:
                continue
            changed = False
            for key, val in payload.items():
                if isinstance(val, str):
                    m = _REF_RE.match(val)
                    if m:
                        idx = int(m.group(1))
                        payload[key] = job_ids[idx]
                        changed = True
            if changed:
                record.write({"payload": payload})

        # 2b. Create audit log entries for each step, skipping the
        # cron-driven background types for the same reason as ``enqueue``:
        # they are machine noise, not operator actions, and they dominate
        # the table. ``hidden`` is the predicate computed above.
        for record in records:
            if record.job_type_id.code in hidden:
                continue
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": record.job_type_id.name,
                    "instance_id": record.instance_id.id
                    if record.instance_id
                    else False,
                    "host_id": record.host_id.id,
                    "job_id": record.id,
                }
            )

        # 3. Build delayable chain
        nodes = []
        for record in records:
            node = record.delayable(max_retries=1).execute()
            nodes.append(node)

        delay_chain(*nodes).delay()

        # 4. Store the generated queue_job UUIDs
        for node, record in zip(nodes, records, strict=False):
            if node._generated_job:
                record.write(
                    {
                        "queue_job_uuid": node._generated_job.uuid,
                    }
                )

        return [r.id for r in records]

    # ── Queue routing (tier → queue_job channel + priority) ──────────────
    #
    # Tiers:
    #   HIGH   → root.user / 5   (prod instance jobs)
    #   NORMAL → root.user / 10  (staging instance + host-only jobs)
    #   LOW    → root.bg   / 10  (background: health checks, metrics, prune)
    #
    # The tier is declared per cloud.job.type record (priority_tier field)
    # and can be auto-promoted NORMAL → HIGH when the target instance is
    # production. Requires the Odoo conf channels setting:
    #
    #   [queue_job]
    #   channels = root:3,root.user:2,root.bg:1
    #
    # See README for details.

    _TIER_TO_ROUTING = {
        "high": ("root.user", 5),
        "normal": ("root.user", 10),
        "low": ("root.bg", 10),
    }

    def _resolve_channel_priority(self, job_type, instance_id):
        """Return ``(channel, priority)`` for a job, promoting ``normal``
        → ``high`` when the target instance is in production."""
        tier = job_type.priority_tier or "normal"
        if tier == "normal" and instance_id:
            inst = self.env["cloud.instance"].browse(instance_id)
            if inst.exists() and inst.environment == "production":
                tier = "high"
        return self._TIER_TO_ROUTING.get(tier, self._TIER_TO_ROUTING["normal"])

    def _guard_no_active_job(self, host_id, instance_id):
        """Serialise against other jobs for the same target; raise if busy.

        Takes an advisory lock *before* looking, so two concurrent callers
        cannot both find the target idle: the second blocks until the first
        commits, then sees the freshly-created job and raises. Postgres
        releases the lock on COMMIT or ROLLBACK of this transaction.

        Instance-scoped jobs serialise per instance, host-scoped jobs
        (falsy ``instance_id``) per host, in separate lock namespaces so a
        host id can never collide with an instance id. Hidden background
        types (metrics, health probes) never block anything.

        Every path that puts work on the queue must come through here.
        ``retry_job`` and ``unblock_and_enqueue`` used to dispatch straight
        to ``with_delay``, which let a retry race a deploy already running
        on the same instance — two SSH sessions mutating one host.

        :param int host_id: target host
        :param int instance_id: target instance, or falsy for host-scoped
        :raises UserError: when an active user job already holds the target
        """
        hidden = self._get_hidden_job_types()
        if instance_id:
            self.env.cr.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                (_JOB_LOCK_NAMESPACE, instance_id),
            )
            running = self.search(
                [
                    ("instance_id", "=", instance_id),
                    ("state", "in", self._active_states),
                    ("job_type_id.code", "not in", hidden),
                ],
                limit=1,
            )
            if running:
                raise UserError(
                    _(
                        "A job is already running for this instance: %(name)s. "
                        "Wait for it to complete or cancel it first.",
                        name=running.name,
                    )
                )
        elif host_id:
            self.env.cr.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                (_HOST_JOB_LOCK_NAMESPACE, host_id),
            )
            running = self.search(
                [
                    ("host_id", "=", host_id),
                    ("instance_id", "=", False),
                    ("state", "in", self._active_states),
                    ("job_type_id.code", "not in", hidden),
                ],
                limit=1,
            )
            if running:
                raise UserError(
                    _(
                        "A job is already running for this host: %(name)s. "
                        "Wait for it to complete or cancel it first.",
                        name=running.name,
                    )
                )

    @api.model
    def enqueue(
        self,
        host_id,
        instance_id,
        job_type_code,
        payload=None,
        bypass_running_check=False,
    ):
        """
        Queue a job of given type for the given host/instance
        and return the job record ID.

        ``bypass_running_check`` skips the active-job guard. The guard
        exists to stop users triggering competing operations on the
        same instance (deploy + rebuild). It must be bypassed when an
        executor's ``on_success`` chains a follow-up internally — at
        that moment the parent job is still ``started`` and would
        otherwise block its own descendant. Internal use only;
        anything user-driven goes through the guard unchanged.
        """
        # Server-side role gate: the public entrypoint is reachable via
        # call_kw with only create-ACL, so enforce the per-type manager
        # requirement here, not only in the HTTP controllers.
        self._check_job_type_allowed(job_type_code, instance_id)
        # Block if there is already an active *user* job for this target.
        # Hidden system jobs (health checks, metrics, probes…) don't block.
        # Instance-scoped jobs serialise per instance; host-scoped jobs
        # (instance_id falsy) serialise per host. The two scopes are
        # independent — an instance deploy does not block a host probe and
        # vice versa.
        if not bypass_running_check:
            self._guard_no_active_job(host_id, instance_id)
        job_type_id = self.env["cloud.job.type"].search(
            [
                ("code", "=", job_type_code),
            ],
            limit=1,
        )
        if not job_type_id:
            raise UserError(
                _("Job type with code {job_type_name} not found.").format(
                    job_type_name=job_type_code
                )
            )
        vals = {
            "host_id": host_id,
            "job_type_id": job_type_id.id,
            "name": _(job_type_id.name),
        }
        if instance_id:
            vals["instance_id"] = instance_id
        if payload:
            vals["payload"] = payload
        job_record = self.create(vals)
        # Check pip_dependencies for conflict markers before queuing.
        _pip_blocked_types = ("deploy_instance", "rebuild_instance")
        if instance_id and job_type_code in _pip_blocked_types:
            inst = self.env["cloud.instance"].browse(instance_id)
            conflicts = detect_pip_conflicts(inst.pip_dependencies)
            if conflicts:
                alert = create_pip_conflict_alert(
                    self.env,
                    conflicts,
                    instance_id=instance_id,
                )
                job_record.write({"blocked_alert_id": alert.id})
                return job_record.id
            # No conflicts — dismiss any stale active pip_conflict alerts
            self.env["cloud.alert"].search(
                [
                    ("instance_id", "=", instance_id),
                    ("code", "=", "pip_conflict"),
                    ("state", "=", "active"),
                ]
            ).write({"state": "dismissed"})
            # Block if there is an active addon_conflict alert
            addon_alert = self.env["cloud.alert"].search(
                [
                    ("instance_id", "=", instance_id),
                    ("code", "=", "addon_conflict"),
                    ("state", "=", "active"),
                ],
                limit=1,
            )
            if addon_alert:
                job_record.write({"blocked_alert_id": addon_alert.id})
                return job_record.id
        # Background job types (host_metrics, instance_health, docker_prune)
        # are enqueued by cron for every host and every instance on every
        # tick. Auditing them buries the handful of real operator actions
        # under machine noise and grows the table without bound. The same
        # predicate that keeps them out of the job drawer keeps them out of
        # the audit trail — they are cron-only (see cloud.host.cron_*), so
        # no user-initiated action is lost here.
        if job_type_code not in self._get_hidden_job_types():
            self.env["cloud.audit.log"].sudo().create(
                {
                    "action": job_type_id.name,
                    "instance_id": instance_id or False,
                    "host_id": host_id,
                    "job_id": job_record.id,
                }
            )
        # max_retries=1 by default: allow one automatic retry for transient
        # DB errors, then fail permanently. The execution guard prevents
        # double SSH runs. Executors that opt into connection retries
        # (``_retry_on_connection_loss``) get a higher cap so a momentarily
        # unreachable host is retried instead of failing on the first blip —
        # only transient connection errors consume those retries; any other
        # exception still fails permanently via JobError on the first try.
        executor_cls = executor_registry.get(job_type_id.code)
        max_retries = 1
        if executor_cls and getattr(
            executor_cls,
            "_retry_on_connection_loss",
            False,
        ):
            max_retries = executor_cls._connection_retry_attempts
        channel, priority = self._resolve_channel_priority(
            job_type_id,
            instance_id,
        )
        delayed = job_record.with_delay(
            max_retries=max_retries,
            channel=channel,
            priority=priority,
            description=job_type_id.name,
        ).execute()
        job_record.write({"queue_job_uuid": delayed.uuid})
        return job_record.id

    def execute(self):
        # queue_job will re-enqueue jobs that were in "started" state when Odoo
        # restarted; those will run from the beginning, which is the desired
        # behaviour (SSH operations are generally idempotent).
        #
        # JobError causes queue_job to mark the job as permanently failed,
        # regardless of max_retries.  We wrap everything so that any exception
        # from the executor (SSH failure, RuntimeError, etc.) results in a
        # clean permanent failure rather than a silent infinite-retry loop.
        #
        # IMPORTANT: after a long-running SSH job completes, the original
        # HTTP cursor (used by queue_job's _try_perform_job) may have gone
        # stale — causing flush_all/set_done to fail, which makes queue_job
        # treat the job as "dead" and re-enqueue it.  To prevent duplicate
        # runs, we verify the cursor is still usable before returning.
        executor = self._get_executor()
        ssh_executor = executor(
            job_record=self,
            host_record=self.host_id,
        )
        try:
            ssh_executor.pre_run_checks()
            ssh_executor._publish_bus()
            ssh_executor.run()
        except RetryableJobError:
            # Executors can raise RetryableJobError to ask queue_job to
            # reschedule the job (e.g. the warm rebuild executor uses it
            # to honour a per-host advisory lock). Let it propagate so
            # queue_job applies its retry semantics; wrapping it as
            # JobError would mark the job permanently failed instead.
            raise
        except OperationalError as e:
            # Serialisation failures belong to queue_job, which already
            # postpones and retries them (``_runjob`` matches the same
            # PG_CONCURRENCY_ERRORS_TO_RETRY list). Wrapping one in
            # JobError turned a routine lost race — this probe and the
            # metrics cron stamping the same ``cloud_instance`` row —
            # into a permanently failed job plus a queue_job traceback,
            # which the log scraper then reported straight back to us
            # as an ``instance_error_logs`` alert. Let it through.
            if e.pgcode in PG_CONCURRENCY_ERRORS_TO_RETRY:
                raise
            raise JobError(str(e)) from e
        except Exception as e:
            # Transient connection failures on opt-in executors (the host
            # monitoring probes) are retried instead of failing on the
            # first blip.
            #
            # Whether this attempt was the *last* one is queue_job's
            # call, not ours: ``Job.perform`` increments the counter and
            # turns the final RetryableJobError into a FailedJobError
            # by itself. We used to decide it here, and got it wrong —
            # the runner can hand a job one more attempt than the
            # budget, so the alert fired on a job that then connected
            # and finished ``done``. Every ``host_unreachable`` on
            # 2026-08-29 was one of those. The alert now hangs off the
            # terminal state instead (see ``queue_job_ext``).
            if getattr(
                ssh_executor, "_retry_on_connection_loss", False
            ) and is_transient_connection_error(e):
                qj = self.queue_job_id
                attempt = (qj.retry or 0) + 1
                max_retries = qj.max_retries or 0
                # The marker first, then the exception *type*: ``str()``
                # of a bare TimeoutError is empty, and this text is what
                # the terminal-state alert will show as the last error.
                raise RetryableJobError(
                    f"{CONNECTION_RETRY_MARKER} {attempt}"
                    f"{f'/{max_retries}' if max_retries else ''}: "
                    f"{type(e).__name__}: {e}",
                    seconds=CONNECTION_RETRY_SECONDS,
                ) from e
            raise JobError(str(e)) from e
        finally:
            # After a long-running SSH job, the ORM environment used
            # by queue_job's _try_perform_job may have stale cache
            # entries (from on_success/on_failure writing via fresh
            # cursors).  Clear the env so flush_all() + set_done()
            # don't trip over phantom dirty records.
            with contextlib.suppress(Exception):
                self.env.cr.execute("SELECT 1")
                self.env.clear()

    def _get_executor(self):
        executor_cls = executor_registry.get(self.job_type_id.code)

        if not executor_cls:
            raise ValueError(f"No executor registered for '{self.job_type_id.code}'")

        return executor_cls

    @api.model
    def load_jobs(self, job_id=False):
        if job_id:
            job = self.browse(job_id)
            return job._format()
        return {
            "active": self._get_active_jobs(),
            "recent": self._get_recent_jobs(limit=15),
        }

    @api.model
    def _get_instance_timeline(
        self, instance_id, max_visible=5, include_pre_claim=False,
    ):
        """Return instance jobs formatted for the vertical activity timeline.

        Active jobs (running/waiting chains) are returned in execution order
        (id asc = running first). Recent terminal jobs fill the remaining
        slots. The caller merges both sets and sorts by id descending so the
        newest job renders at the top and the running job keeps its natural
        position without jumping when it finishes.

        When active jobs exceed *max_visible* (overflow), the caller forces
        the running job to the bottom and shows only the next-in-queue jobs
        above it, with an overflow slot at the top.

        Jobs older than the instance's ``_job_history_floor()`` are left
        out unless *include_pre_claim* asks for them; ``preClaim`` says
        how many were hidden so the caller can offer to show them.

        Returns ``{active, recent, total, preClaim}`` where *active* and
        *recent* are lists of ``_format()`` dicts.
        """
        hidden = self._get_hidden_job_types()
        base = [
            ("instance_id", "=", instance_id),
            ("job_type_id.code", "not in", hidden),
        ]
        pre_claim = self._pre_claim_cut(
            instance_id, base, include_pre_claim=include_pre_claim,
        )
        base = base + pre_claim["domain"]
        active = self.search(
            base + [("state", "in", self._active_states)],
            order="id asc",
        )
        recent_limit = max(0, max_visible - min(len(active), max_visible))
        recent = self.env["cloud.job"]
        if recent_limit > 0:
            recent = self.search(
                base + [("state", "in", self._terminal_states)],
                order="id desc",
                limit=recent_limit,
            )
        total = self.search_count(base)
        return {
            "active": active._format(),
            "recent": recent._format(),
            "total": total,
            "preClaim": pre_claim["info"],
        }

    @api.model
    def _pre_claim_cut(self, instance_id, base_domain, include_pre_claim=False):
        """Resolve the job-history cutoff for one instance.

        Central so the instance timeline and the history page draw the
        same line: everything logged against the record before
        :meth:`cloud.instance._job_history_floor` belongs to a previous
        life of the same machine.

        The count of what gets hidden is only computed when a cutoff
        actually applies, so instances without one (every instance, in
        core) pay nothing for this.

        :param instance_id: id of the target ``cloud.instance``.
        :param base_domain: the caller's domain, used to count the
            hidden jobs under the same filters the visible ones use.
        :param include_pre_claim: when true, resolve the cutoff for
            display but do not filter by it.
        :return: ``{"domain": [...], "info": {...} | False}`` — the leaf
            to append (empty when nothing is cut) and what the UI needs
            to offer the "show everything" toggle.
        """
        instance = self.env["cloud.instance"].browse(int(instance_id)).exists()
        floor = instance._job_history_floor() if instance else False
        if not floor:
            return {"domain": [], "info": False}
        hidden_count = self.search_count(
            base_domain + [("create_date", "<", floor)],
        )
        if not hidden_count:
            return {"domain": [], "info": False}
        info = {
            "since": fields.Datetime.to_string(floor),
            "hidden": hidden_count,
            "showing_all": bool(include_pre_claim),
        }
        if include_pre_claim:
            return {"domain": [], "info": info}
        return {"domain": [("create_date", ">=", floor)], "info": info}

    @api.model
    def get_instance_jobs(
        self, instance_id, limit=20, offset=0, include_pre_claim=False,
    ):
        """Return jobs for a specific instance (for the instance overview)."""
        data = self._get_instance_timeline(
            instance_id,
            max_visible=limit,
            include_pre_claim=include_pre_claim,
        )
        return {
            "activeJobs": data["active"],
            "recentJobs": data["recent"],
            "total": data["total"],
            "preClaim": data["preClaim"],
        }

    @api.model
    def get_host_jobs(self, host_id, limit=5, offset=0):
        """Return jobs for a specific host (for the host overview)."""
        hidden = self._get_hidden_job_types()
        domain = [
            ("host_id", "=", host_id),
            ("job_type_id.apply_to", "=", "host"),
            ("job_type_id.code", "not in", hidden),
        ]
        total = self.search_count(domain)
        jobs = self.search(domain, order="id desc", limit=limit, offset=offset)
        return {"jobs": jobs._format(), "total": total}

    _active_states = ["pending", "enqueued", "wait_dependencies", "started"]
    _terminal_states = ["done", "failed", "cancelled"]
    # Job types hidden from the drawer (automated background tasks).
    # These are still visible in the history page under the "Admin" category.
    # Override _get_hidden_job_types() in submodules to extend this list.
    _hidden_job_types = ["host_metrics", "docker_prune", "instance_health"]

    # Job types whose failure should raise a critical alert — these
    # are user-initiated, long-running operations whose failure the
    # operator almost always wants to investigate immediately. Anything
    # not listed here escalates to a ``warning`` alert instead. Extend
    # by overriding ``_get_severe_job_types()`` in child modules.
    # Generic, self-hosted-only job types that warrant a critical alert
    # on failure.
    _severe_job_types = frozenset(
        {
            "deploy_instance",
            "rebuild_instance",
        }
    )

    # Minimum cloud role required to enqueue each job type. ``enqueue``
    # and ``enqueue_chain`` are public @api.model methods reachable via
    # the stock ``call_kw`` JSON-RPC endpoint by anyone with create-ACL on
    # cloud.job (consultant+) — and the SPA calls them directly for some
    # actions — so the capability gates that live only in the HTTP
    # controllers do not protect them. This map is the server-side
    # authority for "who may ask for this action".
    #
    # Fail-closed: a code missing here requires the manager role, and a
    # structural test forces every declared job type to be listed
    # explicitly so nothing falls through silently. Extend via
    # ``_get_job_type_min_group()``.
    _job_type_min_group = {
        # Lifecycle / deploy — what a consultant may do on their projects.
        "deploy_instance": "group_cloud_consultant",
        "rebuild_instance": "group_cloud_consultant",
        "start_instance": "group_cloud_consultant",
        "stop_instance": "group_cloud_consultant",
        "restart_instance": "group_cloud_consultant",
        # Non-production only at this level: production deletion is
        # escalated to manager in ``_check_job_type_allowed``, so the
        # remote teardown can never start for a caller who would not be
        # allowed to delete the record afterwards.
        "delete_instance": "group_cloud_consultant",
        # Backups, restores and exports move customer data around.
        "backup_list": "group_cloud_developer",
        "backup_create": "group_cloud_developer",
        "backup_download": "group_cloud_developer",
        "backup_download_neutralized": "group_cloud_developer",
        "backup_restore": "group_cloud_developer",
        "restore_instance": "group_cloud_developer",
        # The upload key writes into one directory on the host and
        # nothing else, and only a restore consumes what it delivers —
        # so it sits with the restore it serves, not with the host-level
        # operations. Revocation is deliberately no higher: making it
        # harder to close a door than to open one would be backwards.
        "grant_restore_upload_key": "group_cloud_developer",
        "verify_restore_upload": "group_cloud_developer",
        "revoke_restore_upload_key": "group_cloud_developer",
        "export_instance": "group_cloud_developer",
        # Host-level, destructive or administrative. Every one of these is
        # enqueued by a manager-gated page, a cron or a sudo chain, so the
        # gate costs no legitimate flow anything.
        "host_probe": "group_cloud_manager",
        "host_metrics": "group_cloud_manager",
        "host_hardening": "group_cloud_manager",
        "full_setup": "group_cloud_manager",
        # Both rewrite what the host's proxy does with every request that
        # reaches it, so they sit with the other host-level operations.
        "push_trusted_proxies": "group_cloud_manager",
        "push_github_webhook_edge": "group_cloud_manager",
        "setup_whitelist": "group_cloud_manager",
        "delete_host": "group_cloud_manager",
        "docker_prune": "group_cloud_manager",
        "instance_health": "group_cloud_manager",
        "sync_metrics_accounts": "group_cloud_manager",
        # Both deploy containers on the host — cAdvisor runs privileged
        # with the root filesystem mounted, and the central brings up a
        # whole metrics stack.
        "install_observability": "group_cloud_manager",
        "deploy_metrics_central": "group_cloud_manager",
        # The move chain rewrites host_id and wipes the source directory
        # with no further guard of its own; only ``move_to_host`` (manager)
        # legitimately produces these.
        "move_cutover": "group_cloud_manager",
        "move_cleanup_source": "group_cloud_manager",
        "move_rollback_cleanup": "group_cloud_manager",
        # Deletes a chain that nothing else can reach any more, and the
        # record with it. Manager-only for the same reason production
        # deletion is: there is no undo behind it.
        "purge_archived_backups": "group_cloud_manager",
        # Legacy: the executor is gone; the job type record is kept only
        # because historical jobs still reference it.
        "delete_project": "group_cloud_manager",
    }

    def _get_hidden_job_types(self):
        """Return job type codes that should not appear in the UI job drawer.

        Override in dependent modules and call super() to extend the list::

            def _get_hidden_job_types(self):
                return super()._get_hidden_job_types() + ['my_background_job']
        """
        return self._hidden_job_types.copy()

    #: Warn at 45 running minutes: the dedicated runner kills jobs at
    #: ``limit_time_real`` = 60, so the alert fires while there is still
    #: time to look before the hard kill (decision log P12.5).
    _LONG_RUNNING_MINUTES = 45
    _LONG_RUNNING_ALERT_CODE = "job_running_too_long"

    @api.model
    def _cron_watch_long_running(self):
        """Alert on jobs running past the duration ceiling; self-resolve.

        One warning per (host, instance) target while at least one of
        its jobs has been ``started`` for over ``_LONG_RUNNING_MINUTES``;
        the alert resolves on the pass where no long runner remains for
        that target. The point is to surface jobs about to hit the
        runner's ``limit_time_real`` **with real data**, so the limit is
        tuned from evidence instead of guessed.
        """
        cutoff = fields.Datetime.now() - timedelta(
            minutes=self._LONG_RUNNING_MINUTES,
        )
        alerts = self.env["cloud.alert"].sudo()

        def _started_at(job):
            return job.queue_job_id.date_started or job.create_date

        long_jobs = (
            self.sudo()
            .search([("state", "=", "started")])
            .filtered(lambda j: _started_at(j) and _started_at(j) < cutoff)
        )
        long_targets = set()
        for job in long_jobs:
            long_targets.add((job.host_id.id, job.instance_id.id or False))
            minutes = int(
                (fields.Datetime.now() - _started_at(job)).total_seconds()
                // 60
            )
            alerts.raise_alert(
                self._LONG_RUNNING_ALERT_CODE,
                _(
                    "Job %(name)s (#%(id)d) has been running for "
                    "%(minutes)d minutes; the job runner kills it at 60.",
                    name=job.display_name or job.job_type_id.code,
                    id=job.id,
                    minutes=minutes,
                ),
                level="warning",
                host=job.host_id or None,
                instance=job.instance_id or None,
                job=job,
            )
        for alert in alerts.search(
            [
                ("code", "=", self._LONG_RUNNING_ALERT_CODE),
                ("state", "=", "active"),
            ]
        ):
            key = (alert.host_id.id or False, alert.instance_id.id or False)
            if key not in long_targets:
                alerts.resolve_alert(
                    self._LONG_RUNNING_ALERT_CODE,
                    host=alert.host_id or None,
                    instance=alert.instance_id or None,
                )

    #: Terminal-job retention. Jobs feed the instance timeline, so the
    #: window is deliberately long (settings default: 180 days). The
    #: batched loop mirrors the chunk purge: a purge that cannot drain
    #: its backlog is indistinguishable from no retention at all.
    _PURGE_BATCH = 5000
    _PURGE_MAX_BATCHES = 40

    @api.model
    def _cron_purge_old(self):
        """Delete terminal jobs older than the configured retention.

        Only ``done``/``failed``/``cancelled`` jobs are purged — active
        jobs (pending/enqueued/started/waiting) are never touched
        regardless of age. Unlinking a job cascades its remaining log
        chunks and nulls the FKs on alerts and retries
        (``ondelete='set null'``), so nothing dangles. Deletes in
        batches until the backlog drains or ``_PURGE_MAX_BATCHES`` is
        reached; the leftover is picked up by the next daily run.

        Returns the number of rows deleted in this run.
        """
        days = self.env["cloud.settings"].sudo()._get().job_retention_days
        if not days or days <= 0:
            return 0
        cutoff = fields.Datetime.now() - timedelta(days=days)
        domain = [
            ("create_date", "<", cutoff),
            ("state", "in", ("done", "failed", "cancelled")),
        ]
        total = 0
        for _pass in range(self._PURGE_MAX_BATCHES):
            jobs = self.sudo().search(
                domain, order="id", limit=self._PURGE_BATCH,
            )
            if not jobs:
                return total
            total += len(jobs)
            jobs.unlink()
        # Ceiling reached with matching rows still on the table. Say so:
        # silence here would read exactly like "retention is keeping up"
        # while the backlog quietly outlives every run.
        _logger.warning(
            "cloud.job: purge stopped at the %d-batch ceiling after "
            "deleting %d row(s); terminal jobs older than %d day(s) "
            "remain and will be picked up by the next run.",
            self._PURGE_MAX_BATCHES, total, days,
        )
        return total

    @api.model
    def _get_severe_job_types(self):
        """Return job type codes whose failure should raise a critical
        alert. Override in child modules and call super() to extend.
        """
        return set(self._severe_job_types)

    @api.model
    def _get_job_type_min_group(self):
        """Return the job type -> minimum cloud group map for the enqueue gate.

        Override in child modules and call super() to extend, e.g. the
        SaaS manager adds its provisioning/tenant types::

            def _get_job_type_min_group(self):
                return super()._get_job_type_min_group() | {
                    'provision_vps': 'group_cloud_manager',
                }
        """
        return self._job_type_min_group.copy()

    @api.model
    def _check_job_type_allowed(self, job_type_code, instance_id=None):
        """Raise ``AccessError`` if the caller may not enqueue this type.

        Superuser/sudo internal callers (crons, executors chaining a
        follow-up) bypass the check; everyone else must hold at least the
        role mapped in ``_get_job_type_min_group()`` — manager when the
        code is unknown, so a new type is gated until someone maps it.
        ``delete_instance`` escalates to manager for production instances,
        matching ``_check_can_delete_instance``: the remote teardown runs
        before the record is unlinked, so gating only the unlink would let
        a consultant destroy a production deployment.

        This is the server-side backstop for the public ``enqueue`` and
        ``enqueue_chain`` entrypoints, which the SPA and any RPC client
        can call directly.

        :param job_type_code: code of the ``cloud.job.type`` to enqueue.
        :param instance_id: target instance id, when the job has one; used
            for the per-record escalation above.
        """
        if self.env.su:
            return
        sec = self.env["cloud.security.mixin"]
        min_group = self._get_job_type_min_group().get(
            job_type_code, "group_cloud_manager",
        )
        sec._check_cloud_group(min_group)
        if job_type_code == "delete_instance" and instance_id:
            instance = self.env["cloud.instance"].browse(int(instance_id))
            # Runs in the caller's env on purpose: an instance hidden by
            # ``rule_instance_member`` reads as non-existing here and the
            # escalation is skipped — which is safe ONLY because
            # ``rule_job_member`` scopes cloud.job *creation* by the very
            # same membership domain, so the job row cannot be created for
            # a target the caller cannot see. Those two rule domains must
            # stay aligned (pinned by
            # ``test_foreign_production_instance_cannot_be_deleted``).
            if instance.exists():
                sec._check_can_delete_instance(instance)

    # Alert codes that block (re-)enqueueing a job until the operator
    # resolves them (see the pre-check in ``enqueue`` and
    # ``blocked_alert_id``). Only these warrant an "Action required"
    # badge in the UI; any other alert linked to a job is informational
    # — a plain failure only needs a Retry.
    _actionable_alert_codes = frozenset({"pip_conflict", "addon_conflict"})

    @api.model
    def _get_actionable_alert_codes(self):
        """Return alert codes that require operator action before the
        job can run again. Override in child modules and call super()
        to extend.
        """
        return set(self._actionable_alert_codes)

    @api.model
    def _create_job_failed_alert(self, cjob, exc_message=None):
        """Persist a ``cloud.alert`` when a job transitions to failed.

        Unlike the bus notification (which vanishes with the toast)
        the alert shows up in the Alerts panel so an operator who
        returns to the SPA later still sees the failure.

        Filters:
          * Hidden job types (``host_metrics``, ``instance_health``,
            ``docker_prune`` …) are skipped — they self-heal on the
            next tick and would flood the panel with noise.
          * Jobs without any host/instance/project target are skipped;
            a targetless alert would be invisible to the member-scoped
            record rule (targetless rows are reserved for global
            platform events).
        """
        if cjob.job_type_id.code in self._get_hidden_job_types():
            return None
        # ``cloud.job.host_id`` is required by the schema, so every
        # row has at least one target. Defensive check kept for child
        # modules that might add more exotic job rows.
        if not (cjob.host_id or cjob.instance_id):
            _logger.warning(
                "job_failed alert skipped: cjob id=%s has no host/instance target",
                cjob.id,
            )
            return None

        level = (
            "critical"
            if cjob.job_type_id.code in self._get_severe_job_types()
            else "warning"
        )
        target_name = cjob.instance_id.name or cjob.host_id.name or ""
        # Include a snippet of the exception for at-a-glance triage.
        # Cap at 100 chars so the panel doesn't wrap into a wall of
        # text; the job log has the full traceback.
        msg = f"{cjob.name or 'Job'} on {target_name} failed"
        if exc_message:
            excerpt = exc_message.strip().split("\n", 1)[0][:100]
            if excerpt:
                msg = f"{msg}: {excerpt}"

        vals = {
            "code": "job_failed",
            "level": level,
            "message": msg,
            "job_id": cjob.id,
        }
        if cjob.instance_id:
            vals["instance_id"] = cjob.instance_id.id
            if cjob.instance_id.project_id:
                vals["project_id"] = cjob.instance_id.project_id.id
        if cjob.host_id:
            vals["host_id"] = cjob.host_id.id

        # One incident, not one row per attempt. A failing cron job
        # re-enqueues on its own schedule, and every attempt used to
        # stack another alert *and* another mail/Telegram/webhook: on
        # 2026-08-24 a broken metrics ACL sync produced fourteen of
        # them in six hours, all dismissed by the same later success.
        # Refresh the open one instead, so the panel shows the latest
        # failure of a problem that is still open and the count says
        # how long it has been going.
        Alert = self.env["cloud.alert"].sudo()
        existing = Alert.search(self._job_failed_domain(cjob), limit=1)
        if existing:
            count = existing.occurrences + 1
            since = fields.Datetime.to_string(existing.create_date)
            vals["occurrences"] = count
            vals["message"] = f"{msg} (×{count} since {since} UTC)"
            existing.write(vals)
            return existing
        return Alert.create(vals)

    @api.model
    def _create_host_unreachable_alert(self, cjob, qjob):
        """Raise ``host_unreachable`` when a probe used up its retries.

        Hangs off the *terminal state*, deliberately. ``execute`` used
        to decide "this was the last attempt" from the retry counter
        and alert on the spot, but the runner can hand a job one more
        attempt than the budget — so every alert raised that way was
        followed, seconds later, by the same job connecting and
        finishing ``done``. Fired that way on 2026-08-29 while the host
        was rebooting for security updates: three critical alerts, no
        incident. Here the job really has given up.

        Only opt-in executors qualify, and only when the failure is the
        one we ourselves marked as a connection retry — a probe that
        failed for any other reason is not evidence about the host.
        """
        executor_cls = executor_registry.get(cjob.job_type_id.code)
        if not getattr(executor_cls, "_retry_on_connection_loss", False):
            return None
        message = qjob.exc_message or ""
        if CONNECTION_RETRY_MARKER not in message:
            return None
        if not cjob.host_id:
            return None
        attempts = qjob.retry or qjob.max_retries or 0
        # queue_job wraps our text as "Max. retries (N) reached: <marker>
        # <attempt>/<budget>: <type>: <detail>". The operator wants the
        # part after the attempt counter — the exception itself.
        tail = message.partition(CONNECTION_RETRY_MARKER)[2]
        last_error = tail.partition(": ")[2].strip() or tail.strip()
        return (
            self.env["cloud.alert"]
            .sudo()
            .raise_alert(
                "host_unreachable",
                f"Host unreachable: {attempts} consecutive connection "
                f"attempts failed. Last error: {last_error}",
                level="critical",
                host=cjob.host_id,
                job=cjob,
            )
        )

    @api.model
    def _job_failed_domain(self, cjob):
        """Return the domain identifying *cjob*'s open ``job_failed`` alert.

        Identity is (job type, target) rather than the job id, because
        ``retry_job`` creates a fresh ``cloud.job`` for every retry:
        keyed by id, a retry would file a second alert for the same
        incident and the original would never be dismissed.

        Shared with ``_dismiss_job_failed_alerts`` on purpose — raising
        and clearing must agree on what "the same incident" means, and
        two copies of that rule is precisely how they stop agreeing.
        """
        domain = [
            ("code", "=", "job_failed"),
            ("state", "=", "active"),
            ("job_id.job_type_id", "=", cjob.job_type_id.id),
        ]
        if cjob.instance_id:
            domain.append(("instance_id", "=", cjob.instance_id.id))
        else:
            # Host-scoped job: never touch instance-scoped alerts that
            # happen to live on the same host.
            domain += [
                ("host_id", "=", cjob.host_id.id),
                ("instance_id", "=", False),
            ]
        return domain

    @api.model
    def _dismiss_job_failed_alerts(self, cjob):
        """Mark stale active ``job_failed`` alerts as dismissed when a
        job reaches ``done``.

        ``retry_job`` always creates a *fresh* cloud.job (linked via
        ``retry_of_id``), so matching only ``job_id == cjob.id`` would
        leave the original failure's alert active forever. Instead we
        dismiss every active ``job_failed`` alert whose originating job
        has the same type and target: if a rebuild now succeeds on this
        instance, earlier rebuild failures are resolved history. Keeps
        the Alerts panel tidy — nobody wants to see fixed failures
        stacked.
        """
        stale = self.env["cloud.alert"].sudo().search(
            self._job_failed_domain(cjob),
        )
        if stale:
            stale.write({"state": "dismissed"})
        return stale

    def _get_active_jobs(self):
        domain = [
            ("job_type_id.code", "not in", self._get_hidden_job_types()),
            "|",
            ("blocked_alert_id", "!=", False),
            ("state", "in", self._active_states),
        ]
        return self.search(domain, order="id desc")._format()

    def _get_recent_jobs(self, limit=10):
        return self.search(
            [
                ("state", "in", self._terminal_states),
                ("job_type_id.code", "not in", self._get_hidden_job_types()),
            ],
            order="id desc",
            limit=limit,
        )._format()

    def _format(self):
        # Build a map of job_id → attachment_id for jobs that have a
        # downloadable file (e.g. export_instance).  Uses a single query
        # instead of per-job lookups.
        attachments = self.env["ir.attachment"].search(
            [
                ("res_model", "=", "cloud.job"),
                ("res_id", "in", self.ids),
            ],
            order="id desc",
        )
        att_map = {}
        for att in attachments:
            att_map.setdefault(att.res_id, att.id)

        # Jobs whose active alert actually demands operator action
        # (conflicts that block re-running). Informational alerts
        # (``job_failed``, …) don't count — a failed job only needs a
        # Retry, so flagging it "Action required" would be misleading.
        actionable_codes = list(self._get_actionable_alert_codes())
        action_job_ids = (
            set(
                self.env["cloud.alert"]
                .search(
                    [
                        ("job_id", "in", self.ids),
                        ("state", "=", "active"),
                        ("code", "in", actionable_codes),
                    ]
                )
                .mapped("job_id.id")
            )
            if self.ids
            else set()
        )

        return [
            {
                "id": job.id,
                "name": job.name,
                "host": job.host_id.name,
                "host_id": job.host_id.id if job.host_id else None,
                "job_type": job.job_type_id.name,
                "job_type_code": job.job_type_id.code,
                "instance_id": job.instance_id.id if job.instance_id else None,
                "state": "blocked" if job.blocked_alert_id else job.state,
                "requires_action": (
                    bool(job.blocked_alert_id) or job.id in action_job_ids
                ),
                "create_date": job.create_date,
                "last_system_message": job._get_last_system_message(),
                "download_url": (
                    f"/web/content/{att_map[job.id]}?download=true"
                    if job.id in att_map
                    else None
                ),
                "retry_of_id": job.retry_of_id.id if job.retry_of_id else None,
                "user_id": job.create_uid.id,
                "user_name": job.create_uid.name or "",
                **_webhook_fields(job.payload),
            }
            for job in self
        ]

    def _restore_url_credential(self):
        """Return the credential a from-URL restore must authenticate with.

        Stored encrypted and apart from the payload, so the password
        never reaches the job list, a notification or the log. Returns
        the three values the host needs to write a netrc line.

        :return: ``(machine, login, password)``, or ``None``.
        """
        self.ensure_one()
        raw = self.secret_payload
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return None
        machine = data.get("machine")
        login = data.get("login")
        password = data.get("password")
        if not (machine and login):
            return None
        return machine, login, password or ""

    def _get_last_system_message(self):
        system_chunks = self.log_chunk_ids.filtered(lambda c: c.source == "system")
        return system_chunks[-1].content if system_chunks else ""

    @api.model
    def load_chunks(self, job_id, after_id=0):
        """Return log chunks for the terminal view.

        Source-based and project-based scoping is enforced by record
        rules on ``cloud.job.log.chunk`` (``rule_job_log_chunk_member``
        filters stakeholders/consultants to ``source='system'`` and
        project membership). The search below honours those rules
        automatically.
        """
        chunks = self.env["cloud.job.log.chunk"].search(
            [
                ("job_id", "=", job_id),
                ("id", ">", after_id),
            ]
        )
        job = self.browse(job_id)
        return {
            "chunks": chunks._format(),
            "state": job.state,
        }

    @api.model
    def load_history(self, filters=None):
        """Return jobs for the history page, optionally filtered.

        filters.job_category:
          - ``"operational"`` (default) — excludes admin background jobs
          - ``"admin"`` — only admin background jobs (host_metrics, docker_prune, …)
          - ``"all"`` — no category restriction

        When scoped to a single instance, jobs older than that
        instance's ``_job_history_floor()`` are hidden and summarised in
        ``preClaim``; ``filters.include_pre_claim`` brings them back.
        """
        domain = []
        pre_claim = False
        job_id = (filters or {}).get("job_id")
        if job_id:
            # Direct job lookup — bypass all other filters
            domain.append(("id", "=", int(job_id)))
        else:
            if filters:
                if filters.get("states"):
                    domain.append(("state", "in", filters["states"]))
                if filters.get("host_id"):
                    domain.append(("host_id", "=", int(filters["host_id"])))
                if filters.get("date_from"):
                    domain.append(("create_date", ">=", filters["date_from"]))
                if filters.get("date_to"):
                    domain.append(("create_date", "<=", filters["date_to"]))
                if filters.get("instance_id"):
                    domain.append(("instance_id", "=", int(filters["instance_id"])))
                if filters.get("user_id"):
                    domain.append(("create_uid", "=", int(filters["user_id"])))
                if filters.get("apply_to"):
                    domain.append(("job_type_id.apply_to", "=", filters["apply_to"]))

            category = (filters or {}).get("job_category", "operational")
            admin_types = self._get_hidden_job_types()
            if category == "operational":
                domain.append(("job_type_id.code", "not in", admin_types))
            elif category == "admin":
                domain.append(("job_type_id.code", "in", admin_types))
            # "all" → no category filter

            # Scoped to one instance: hide what predates the handover,
            # under the same category/state filters the visible jobs
            # use, so the count in the notice matches what the toggle
            # would actually reveal.
            if filters and filters.get("instance_id"):
                cut = self._pre_claim_cut(
                    filters["instance_id"],
                    domain,
                    include_pre_claim=bool(filters.get("include_pre_claim")),
                )
                domain = domain + cut["domain"]
                pre_claim = cut["info"]

        jobs = self.search(domain, order="id desc", limit=200)
        hosts = self.env["cloud.host"].search([], order="name asc")
        instances = self.env["cloud.instance"].search(
            [],
            order="project_id, name asc",
        )
        user_ids = jobs.mapped("create_uid").sorted("name")
        return {
            "jobs": jobs._format_history(),
            "hosts": [{"id": h.id, "name": h.name} for h in hosts],
            "instances": [
                {
                    "id": i.id,
                    "name": f"{i.project_id.name}/{i.name}" if i.project_id else i.name,
                }
                for i in instances
            ],
            "users": [{"id": u.id, "name": u.name} for u in user_ids],
            "preClaim": pre_claim,
        }

    def _format_history(self):
        now = fields.Datetime.now()
        result = []
        for job in self:
            start = job.create_date
            # ``date_done`` is a related-stored mirror of
            # ``queue_job_id.date_done`` so this read does not require
            # ``queue.job`` ACL.  Fall back to ``write_date`` for
            # terminal jobs that were finalised without queue_job
            # writing date_done (cancel paths, legacy rows), and to
            # ``now`` for jobs still running.
            terminal = job.state in self._terminal_states
            end = job.date_done or job.write_date if terminal else now
            duration_s = int((end - start).total_seconds()) if start and end else 0
            result.append(
                {
                    "id": job.id,
                    "name": job.name,
                    "host": job.host_id.name,
                    "host_id": job.host_id.id,
                    "instance_name": (
                        f"{job.instance_id.project_id.name}/{job.instance_id.name}"
                        if job.instance_id
                        else ""
                    ),
                    "instance_id": (job.instance_id.id if job.instance_id else None),
                    "job_type": job.job_type_id.name,
                    "state": job.state,
                    "create_date": job.create_date,
                    "write_date": job.write_date,
                    "duration_s": max(0, duration_s),
                    "log_lines": len(job.log_chunk_ids),
                    "last_system_message": job._get_last_system_message(),
                    "user_id": job.create_uid.id,
                    "user_name": job.create_uid.name or "",
                    **_webhook_fields(job.payload),
                }
            )
        return result

    def cancel_job(self):
        """Cancel an active job.

        ``state`` is a stored related on ``queue_job_id.state`` with no
        inverse, so writing it directly never reaches the queue.job — the
        runner would pick a queued job up and clobber the cancellation.
        A job that has not started yet is therefore cancelled through the
        queue.job so the runner skips it entirely (``button_cancelled``)
        and the terminal state syncs back cleanly as ``cancelled``. A
        started job cannot be force-cancelled by queue_job (its runner is
        mid-flight), so we set ``state`` cancelled as a cooperative stop
        flag the executor polls on a separate cursor (``_check_cancel``).
        """
        self.ensure_one()
        if self.blocked_alert_id:
            raise UserError(
                _(
                    "Blocked jobs cannot be cancelled. "
                    "Resolve the pip dependency conflict first, then cancel if needed."
                )
            )
        if self.state not in self._active_states:
            raise UserError(_("Only active jobs can be cancelled."))
        if self.state == "started" or not self.queue_job_id:
            self.write({"state": "cancelled"})
        else:
            self.queue_job_id.button_cancelled()

    def retry_job(self):
        self.ensure_one()
        if self.blocked_alert_id:
            raise UserError(
                _(
                    "Blocked jobs cannot be retried. "
                    "Resolve the pip dependency conflict first."
                )
            )
        if self.state != "failed":
            raise UserError(_("Only failed jobs can be retried."))
        # Same role gate as ``enqueue``: the retry runs under the
        # *retrying* user's env, so without this a consultant who can read
        # a failed higher-role job of their project (e.g. a move step)
        # could relaunch it as themselves.
        self._check_job_type_allowed(
            self.job_type_id.code,
            self.instance_id.id if self.instance_id else None,
        )
        # Same guard as ``enqueue``: a retry is a user-initiated job like
        # any other, and firing one while a deploy is already running on
        # the target means two SSH sessions mutating the same host. This
        # job is ``failed``, so it never blocks its own retry.
        self._guard_no_active_job(
            self.host_id.id,
            self.instance_id.id if self.instance_id else False,
        )
        # Create a fresh job as a retry — keeps the original's logs intact.
        new_job = self.create(
            {
                "name": self.name,
                "host_id": self.host_id.id,
                "job_type_id": self.job_type_id.id,
                "instance_id": self.instance_id.id if self.instance_id else False,
                "payload": self.payload,
                "retry_of_id": self.id,
            }
        )
        channel, priority = self._resolve_channel_priority(
            new_job.job_type_id,
            new_job.instance_id.id if new_job.instance_id else False,
        )
        delayed = new_job.with_delay(
            max_retries=1,
            channel=channel,
            priority=priority,
            description=new_job.job_type_id.name,
        ).execute()
        new_job.write({"queue_job_uuid": delayed.uuid})
        return new_job.id

    @api.model
    def cron_cleanup_backup_attachments(self):
        """Delete expired backup artefacts (>2h old).

        Two passes:

        * **A — `cloud.instance.backup` rows with attachments**:
          rows older than the cutoff are unlinked together with
          their attachment.  Without this pass the row would survive
          (`attachment_id ondelete='set null'`) and the SPA would
          show a download button that no longer resolves.

        * **B — orphan job attachments**: attachments produced by
          one-shot download jobs (`BackupDownloadExecutor`,
          `BackupDownloadNeutralizedExecutor`) live on `cloud.job`
          and never got linked to a `cloud.instance.backup` row, so
          pass A never sees them.  Match them by name pattern.

        Both passes are bounded to `res_model='cloud.job'` for
        attachments — no risk of touching unrelated attachments.
        """
        cutoff = fields.Datetime.now() - timedelta(hours=2)

        # Pass A — rows + their attachments.
        Backup = self.env["cloud.instance.backup"].sudo()
        expired_rows = Backup.search(
            [
                ("attachment_id", "!=", False),
                ("backup_time", "<", cutoff),
            ]
        )
        if expired_rows:
            attachments = expired_rows.mapped("attachment_id")
            _logger.info(
                "Cleaning up %d expired backup row(s) + attachment(s)",
                len(expired_rows),
            )
            expired_rows.unlink()
            # Some attachments may already be gone (manual cleanup);
            # ``exists`` filters those out without raising.
            attachments.exists().unlink()

        # Pass B — orphan attachments from one-shot download jobs.
        orphan = self.env["ir.attachment"].search(
            [
                ("res_model", "=", "cloud.job"),
                ("create_date", "<", cutoff),
                "|",
                ("name", "like", "%-backup-%"),
                ("name", "like", "%-neutralized-%"),
            ]
        )
        # ``cloud.instance.backup.attachment_id`` is the only legit
        # consumer of ``-backup-`` named attachments on cloud.job;
        # exclude any that are still referenced so pass B never
        # races pass A on an in-flight backup.
        if orphan:
            referenced = Backup.search(
                [
                    ("attachment_id", "in", orphan.ids),
                ]
            ).mapped("attachment_id.id")
            orphan = orphan.filtered(lambda a: a.id not in referenced)
        if orphan:
            _logger.info(
                "Cleaning up %d orphan backup/neutralized attachment(s)",
                len(orphan),
            )
            orphan.unlink()

    def unblock_and_enqueue(self):
        """Called by the resolve endpoint after a pip conflict is resolved.

        Guarded like ``enqueue``: the job has been sitting blocked, possibly
        for a long time, and the operator may well have started something
        else on the same target meanwhile. This job was never dispatched —
        it has no ``queue_job_id`` and therefore no active state — so it
        cannot block itself.
        """
        self.ensure_one()
        # Same role gate as ``enqueue``: dispatching runs under the
        # unblocking user's env. Blocked jobs are only pip-conflicted
        # deploys/rebuilds today (consultant-level), so this is symmetry
        # and RPC safety, not a behaviour change.
        self._check_job_type_allowed(
            self.job_type_id.code,
            self.instance_id.id if self.instance_id else None,
        )
        self._guard_no_active_job(
            self.host_id.id,
            self.instance_id.id if self.instance_id else False,
        )
        self.blocked_alert_id = False
        channel, priority = self._resolve_channel_priority(
            self.job_type_id,
            self.instance_id.id if self.instance_id else False,
        )
        delayed = self.with_delay(
            max_retries=1,
            channel=channel,
            priority=priority,
            description=self.job_type_id.name,
        ).execute()
        self.write({"queue_job_uuid": delayed.uuid})

    # ── Multi-user notifications ───────────────────────────────────────────

    @api.model_create_multi
    def create(self, vals_list):
        """Broadcast newly-created jobs so the UI updates immediately.

        Runs on the caller's cursor (HTTP / cron / orm.call) — the
        ``pg_notify`` emitted by ``_bus_send`` fires at that cursor's
        commit. We deliberately do NOT hook ``write`` / ``_write``: the
        ``state`` field is a stored related on ``queue_job_id.state`` and
        its updates arrive via ``_write`` from whatever cursor queue_job
        is using (sometimes a fresh cursor in failure paths, sometimes
        the SSH executor's cursor), which is exactly the scenario the
        memory note warns about. State transitions are already
        broadcast explicitly from ``queue_job_ext.write`` (terminal) and
        ``abstract_executor._publish_bus`` (while running).
        """
        records = super().create(vals_list)
        for record in records:
            self._broadcast_job_update(record.id)
        return records

    @api.model
    def _bus_audience(self, job):
        """Return the internal users allowed to read *job*.

        The bus does not apply record rules, so the audience is the
        gate: we resolve who may read the job through ``_job_visible_to``
        (the same helper the email and external notifiers use, so the
        ``cloud.job`` ir.rule stays the single source of truth) and send
        only to them. Two things follow from that. A stakeholder stops
        receiving events for the six projects they are not a member of,
        and the payload can safely name the job's target — every
        recipient has already passed the ACL for it.

        Resolving this costs one ``check_access`` per candidate user, so
        callers on a repeating path (the executor tick) should compute
        it once and pass the ids back in. See
        ``AbstractExecutor._publish_bus``.

        :param job: a single ``cloud.job`` record.
        :returns: ``res.users`` recordset.
        """
        return (
            self.env["res.users"]
            .search([("share", "=", False), ("active", "=", True)])
            .filtered(lambda u: self._job_visible_to(job, u))
        )

    @api.model
    def _broadcast_job_update(self, job_id, state=None, audience_ids=None):
        """Send bus notification for a job state change to its audience.

        Hidden job types (host_metrics, instance_health, docker_prune,
        …) are system/cron jobs the SPA never shows in the drawer.
        Broadcasting them is pure noise — tens of thousands of bus
        events per day × N internal users for zero UI benefit — so we
        skip them here. The frontend already filters these types out
        of the job list; skipping the bus hop saves a lot of work on
        the server, network and client.

        :param audience_ids: precomputed ``res.users`` ids from
            ``_bus_audience``. Pass it from repeating callers to avoid
            re-running the per-user ACL check on every event; omit it
            for one-shot broadcasts (create, terminal transition).
        """
        job = self.browse(job_id)
        if not job.exists():
            return
        if job.job_type_id.code in self._get_hidden_job_types():
            return
        users = (
            self.env["res.users"].browse(audience_ids)
            if audience_ids is not None
            else self._bus_audience(job)
        )
        if not users:
            return
        # ``state`` lets the client toast terminal transitions without
        # polling: it is only present when the caller knows it
        # (queue_job_ext passes the terminal state it just wrote);
        # create/chunk-flush broadcasts omit it and the client ignores
        # them. Passing it explicitly instead of reading ``job.state``
        # here matters twice: no ORM read on the hot chunk-flush path,
        # and no premature materialisation of the stored related state
        # at create() time (the queue.job may not exist yet).
        #
        # ``host_id`` / ``instance_id`` / ``project_id`` name the job's
        # target so a watcher can drop an event that does not concern it
        # without a round-trip — instance_detail used to spend one
        # ``load_jobs`` call per event purely to learn this. Shipping
        # them is safe precisely because the audience above is
        # ACL-filtered; do not widen the payload without keeping that
        # gate.
        #
        # ``project_id`` is a traversal, not a field: host-level jobs
        # have no instance and therefore no project, and they report
        # ``None``. Watchers must read that as "unknown, refresh
        # anyway" rather than "not mine" — a host job still changes the
        # host rows a project view renders.
        payload = {
            "id": job_id,
            "host_id": job.host_id.id or None,
            "instance_id": job.instance_id.id or None,
            "project_id": job.instance_id.project_id.id or None,
        }
        if state:
            payload["state"] = state
        for user in users:
            user._bus_send("cloud_jobs", payload)

    @api.model
    def _notify_by_email(self, job, state):
        """Email active internal users according to their notification prefs.

        Skips:
          * ``cancelled`` — a user-initiated non-event; the preference
            labels only promise success + failure.
          * Hidden job types (``host_metrics``, …) — they run on cron
            every few minutes, so a persistent failure (e.g. host down)
            would email every subscriber per tick. The bus and alert
            channels already filter them for the same reason.
        """
        if state == "cancelled":
            return
        if job.job_type_id.code in self._get_hidden_job_types():
            return
        # Start from every subscribed internal user, then narrow to
        # what each may actually read (the cloud.job record rules —
        # single source of truth, not a duplicated membership domain)
        # and hasn't muted. A user who cannot see the job in the UI
        # must not learn about it by email.
        users = (
            self.env["res.users"]
            .search(
                [
                    ("share", "=", False),
                    ("active", "=", True),
                    ("cloud_notification_level", "!=", "none"),
                    ("cloud_email_enabled", "=", True),
                ]
            )
            .filtered(
                lambda u: self._job_visible_to(job, u)
                and not self._job_muted_for(job, u)
            )
        )
        # Digest users only get instant mail for severe failures
        # (production deploys/rebuilds); everything else reaches them
        # in the daily digest instead.
        severe = (
            state == "failed" and job.job_type_id.code in self._get_severe_job_types()
        )
        if not severe:
            users = users.filtered(
                lambda u: u.cloud_notification_mode != "daily_digest",
            )
        for user in users:
            if user.cloud_notification_level == "failures" and state != "failed":
                continue
            email = user.partner_id.email
            if not email:
                continue
            state_label = "completed" if state == "done" else state
            subject = f"[IncubaCloud] Job '{job.name}' {state_label}"
            body = self._build_email_body(job, state)
            self.env["mail.mail"].sudo().create(
                {
                    "subject": subject,
                    "body_html": body,
                    "email_to": email,
                    "auto_delete": True,
                }
            ).send()

    @api.model
    def _job_visible_to(self, job, user):
        """Return True when *user* passes ACL + record rules to read
        *job* — used to scope job emails to what the UI would show.
        """
        try:
            job.with_user(user).check_access("read")
        except AccessError:
            return False
        return True

    @api.model
    def _job_muted_for(self, job, user):
        """Return True when the job's project is muted by *user* —
        shared by email, digest and the live-toast brief endpoint so
        every personal channel honours the same mute list.
        """
        project = job.instance_id.project_id if job.instance_id else None
        return user._cloud_project_muted(project)

    @api.model
    def _build_email_body(self, job, state):
        instance_line = (
            f"<tr><td><b>Instance</b></td><td>{job.instance_id.name}</td></tr>"
            if job.instance_id
            else ""
        )
        log_url = f"/cloud/log/{job.id}"
        state_label = "completed" if state == "done" else state
        return (
            f"<table>"
            f"<tr><td><b>Job</b></td><td>{job.name}</td></tr>"
            f"<tr><td><b>Host</b></td><td>{job.host_id.name}</td></tr>"
            f"{instance_line}"
            f"<tr><td><b>Status</b></td><td>{state_label}</td></tr>"
            f"</table>"
            f"<p><a href='{log_url}'>View logs</a></p>"
        )

    @api.model
    def _notify_external(self, job, state):
        """Push job notifications to Telegram and/or external webhooks.

        Runs the same user filter as ``_notify_by_email``: only active
        internal users who are subscribed, can see the job via record
        rules, and haven't muted its project. Digest-mode users only
        receive severe failures immediately — everything else waits for
        the daily digest, matching the email delivera-bility promise.

        Telegram and webhook sends each run inside a try/except so one
        broken endpoint can never starve another user's notification.

        In test mode the pipeline is disabled by default — real
        HTTP calls would spill credentials to external APIs.  Tests
        that intentionally exercise the pipeline pass
        ``with_context(test_external_notify=True)`` on the recordset.
        """
        if odoo_config.get("test_enable") and not self.env.context.get(
            "test_external_notify"
        ):
            return
        if state == "cancelled":
            return
        if job.job_type_id.code in self._get_hidden_job_types():
            return
        users = (
            self.env["res.users"]
            .search(
                [
                    ("share", "=", False),
                    ("active", "=", True),
                    ("cloud_notification_level", "!=", "none"),
                ]
            )
            .filtered(
                lambda u: self._job_visible_to(job, u)
                and not self._job_muted_for(job, u)
            )
        )
        severe = (
            state == "failed" and job.job_type_id.code in self._get_severe_job_types()
        )
        if not severe:
            users = users.filtered(
                lambda u: u.cloud_notification_mode != "daily_digest",
            )
        for user in users:
            if user.cloud_notification_level == "failures" and state != "failed":
                continue
            if user.cloud_telegram_bot_token and user.cloud_telegram_chat_id:
                try:
                    self._send_telegram(user, job, state, severe)
                except Exception:
                    _logger.warning(
                        "telegram send failed for user %s",
                        user.id,
                    )
            if user.cloud_webhook_url:
                try:
                    self._send_webhook(user, job, state, severe)
                except Exception:
                    _logger.warning(
                        "webhook send failed for user %s",
                        user.id,
                    )

    @api.model
    def _send_telegram(self, user, job, state, severe):
        """POST a job state notification to the user's Telegram chat.

        Uses the Bot API ``sendMessage`` endpoint. Failure is logged
        but never propagated — a bad token or connectivity blip must
        not abort the notification pipeline for other users.
        """
        base_url = (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param(
                "web.base.url",
                "",
            )
        )
        emoji = "\U0001f534" if state == "failed" else "\U0001f7e2"
        severity_tag = " \u26a0\ufe0f SEVERE" if severe else ""
        lines = [
            f"{emoji} *{job.name}* {state}{severity_tag}",
            f"Host: {job.host_id.name}",
        ]
        if job.instance_id:
            lines.append(f"Instance: {job.instance_id.name}")
        lines.append(f"Logs: {base_url}/cloud/log/{job.id}")
        text = "\n".join(lines)
        url = f"https://api.telegram.org/bot{user.cloud_telegram_bot_token}/sendMessage"
        payload = json.dumps(
            {
                "chat_id": user.cloud_telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }
        ).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        safe_urlopen(req, timeout=10)  # nosec B310 — Telegram API, no redirects

    @api.model
    def _send_webhook(self, user, job, state, severe):
        """POST a signed JSON notification to the user's webhook URL.

        The ``X-IncubaCloud-Signature`` header carries the HMAC-SHA256
        hex digest so the receiver can verify authenticity and integrity.
        When *user* has no signing secret the header is omitted — basic
        HTTPS alone serves as the authenticity channel.
        """
        base_url = (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param(
                "web.base.url",
                "",
            )
        )
        payload = json.dumps(
            {
                "event": "job_state_change",
                "job_id": job.id,
                "job_name": job.name,
                "state": state,
                "severe": severe,
                "host": job.host_id.name,
                "instance": job.instance_id.name if job.instance_id else None,
                "log_url": f"{base_url}/cloud/log/{job.id}",
                "timestamp": fields.Datetime.to_string(fields.Datetime.now()),
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        secret = user.cloud_webhook_secret or ""
        if secret:
            sig = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()
            headers["X-IncubaCloud-Signature"] = "sha256=" + sig
        # The destination is the only one in this codebase a user picks,
        # and this process can reach the metadata service, its own
        # loopback and the internal database. ``post_json`` re-resolves
        # and pins the address; see :mod:`..net.outbound` for why the
        # https check at save time was never enough on its own.
        post_json(user.cloud_webhook_url, payload, headers=headers)

    # ── Audit trail ───────────────────────────────────────────────────────

    @api.model
    def get_audit_log(
        self,
        instance_id=None,
        host_id=None,
        limit=100,
        offset=0,
        q=None,
        action_filter=None,
        date_from=None,
        date_to=None,
    ):
        """Return a page of audit log entries for an instance or host.

        Returns ``{'entries', 'total', 'actions'}``: ``total`` drives the
        paginator and ``actions`` is the full set of distinct action names
        for the target (ignoring the current filters) so the filter
        dropdown stays complete across pages.
        """
        empty = {"entries": [], "total": 0, "actions": []}
        if not self.env.user.has_group("incubacloud.group_cloud_manager"):
            return empty
        if instance_id:
            base = [("instance_id", "=", int(instance_id))]
        elif host_id:
            base = [("host_id", "=", int(host_id))]
        else:
            return empty
        domain = list(base)
        if q:
            domain += [
                "|",
                ("user_id.name", "ilike", q),
                ("action", "ilike", q),
            ]
        if action_filter:
            domain.append(("action", "=", action_filter))
        if date_from:
            domain.append(("create_date", ">=", date_from))
        if date_to:
            domain.append(("create_date", "<=", date_to))
        Log = self.env["cloud.audit.log"]
        total = Log.search_count(domain)
        entries = Log.search(
            domain,
            order="id desc",
            limit=limit,
            offset=offset,
        )._format()
        actions = [a for (a,) in Log._read_group(base, groupby=["action"]) if a]
        return {"entries": entries, "total": total, "actions": actions}
