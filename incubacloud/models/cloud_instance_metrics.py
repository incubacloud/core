"""Derive ``cloud.instance.running`` from metrics (Fase 4 / A8).

Today ``running`` is written by ``instance_health_executor`` — one SSH job
per instance every few minutes, the telemetry that does not scale past
~100 targets. This is its replacement: the same fact read from cAdvisor,
which the agents already report.

**Why cAdvisor and not Traefik.** ``running`` means *the instance's
``odoo`` container is up*, which is the same thing the SSH probe
measures. "Is anyone using it" is a different fact, already modelled by
``sleeping`` (decided by Sablier from real traffic) and by
``last_activity_at``. If ``running`` were sourced from request traffic, a
healthy but idle instance would read as not-running, and the 14-day
auto-suspend that hangs off that chain would eventually act on legitimate
idleness — a billing consequence, not just a cosmetic one.

**Nothing is retired here.** The SSH telemetry keeps running until this
signal has been verified against real data; flipping the source and
deleting the old one in the same step is how you find out too late that
the new one had a blind spot.
"""
import logging

from odoo import api, fields, models

from ._concurrency import read_committed_cursor
from .cloud_metric_rule import promql_query

_logger = logging.getLogger(__name__)

# A container is considered up when cAdvisor saw it within this window.
# Comfortably above the 30 s scrape interval so one missed scrape does
# not flap the flag.
_SEEN_WINDOW_SECONDS = 180

#: How long a metrics reading keeps the SSH health probe from writing
#: ``running``. Comfortably above the liveness cron's own period so one
#: skipped tick does not hand the flag back and forth.
_LIVENESS_HANDOVER_SECONDS = 900

#: The compose service whose container decides whether an instance is up.
#: Every other container of the stack can be running while this one is
#: not — that is exactly what a sleeping tenant looks like.
_ODOO_SERVICE = "odoo"

#: Which instances the backend reports on at all, by any container of
#: theirs. Not a liveness answer: it says whose telemetry reaches us,
#: and therefore whose ``running`` may be written at all.
_COVERAGE_EXPRESSION = (
    "max by (instance_id) (time() - container_last_seen{"
    'instance_id!=""})'
)

#: How long since each instance's ``odoo`` container was reported. The
#: service label is there because the agents are started with
#: ``com.docker.compose.service`` whitelisted (see host_observability).
_ODOO_EXPRESSION = (
    "max by (instance_id) (time() - container_last_seen{"
    'instance_id!="", '
    f'container_label_com_docker_compose_service="{_ODOO_SERVICE}"'
    "})"
)


class CloudInstance(models.Model):
    _inherit = "cloud.instance"

    metrics_last_seen = fields.Datetime(
        string="Metrics last seen",
        copy=False,
        readonly=True,
        help="Last time the metrics backend reported on this instance. "
             "Written only by the cron below, and read by the SSH health "
             "probe to decide who owns ``running``: two writers with no "
             "arbitration would fight over the flag every few minutes.",
    )

    def _metric_alerts_suppressed(self):
        """Return True when metric alerts about this instance are noise.

        Core always answers False: it knows of no legitimate reason for a
        deployed instance to stop reporting. A layer above may — a plan
        that sleeps an instance on idle stops every container, so cAdvisor
        goes quiet and "down" is precisely what a naive rule concludes.
        That layer overrides this.

        Asking the instance, rather than testing a field core does not
        have, is what keeps the sleep feature out of core entirely.
        """
        self.ensure_one()
        return False

    def _liveness_covered_by_metrics(self):
        """Return True when metrics are the authority on ``running`` here.

        Arbitration, not preference. Both the metrics cron and the SSH
        health probe can determine whether an instance is up, and with
        observability on they would otherwise both write the flag on
        their own schedules — agreeing most of the time, and flapping the
        instance's state whenever they briefly did not.

        Metrics win while they are fresh because they are continuous and
        cheap; the SSH probe remains the fallback and takes over by
        itself the moment the readings go stale, so there is no window
        where nobody decides.
        """
        self.ensure_one()
        settings = self.env["cloud.settings"].sudo()._get_system()
        if not settings.metrics_enabled:
            return False
        if not self.metrics_last_seen:
            return False
        age = (
            fields.Datetime.now() - self.metrics_last_seen
        ).total_seconds()
        return age <= _LIVENESS_HANDOVER_SECONDS

    @api.model
    def _ages_by_instance(self, base, expression, user, token):
        """Return ``{instance id: seconds since last seen}``, or ``None``.

        ``None`` is "the question could not be asked" — a transport or
        protocol failure — and callers must treat it as unknown rather
        than as an answer. An empty dict is a real answer: the backend
        replied and nothing matched.

        :param str base: metrics backend root
        :param str expression: PromQL returning one sample per instance
        :param str user: metrics account this panel authenticates as
        :param str token: password half of that credential
        :rtype: dict | None
        """
        try:
            samples = promql_query(base, expression, token=token, user=user)
        except Exception as exc:  # noqa: BLE001 — logged, never fatal
            _logger.warning(
                "[metrics] could not refresh instance liveness: %s", exc,
            )
            return None

        ages = {}
        for labels, age_seconds in samples:
            raw = (labels or {}).get("instance_id")
            if not raw:
                continue
            try:
                ages[int(raw)] = age_seconds
            except (TypeError, ValueError):
                continue
        return ages

    @api.model
    def _cron_refresh_running_from_metrics(self):
        """Update ``running`` for instances the metrics backend covers.

        Two questions, not one. The first is which instances the backend
        reports on at all; the second is how long since each one's
        ``odoo`` container was seen. Only the second decides the flag —
        ``running`` has always meant *that* container, the same thing the
        SSH probe measures, and asking about any container of the stack
        answers a different question. A sleeping tenant keeps its
        database and backup containers up, so the loose form said "yes"
        all night and the flag never fell: the sleep/wake tracking that
        hangs off it never fired, and the panel showed a tenant asleep as
        running.

        Fail-safe, three times over:

        * a backend that cannot be reached updates nothing — silence is
          not evidence that instances stopped;
        * an instance the backend has never reported on is left untouched
          rather than marked stopped, so a host whose agents are not
          installed yet keeps whatever the SSH telemetry says; and
        * a fleet that reports containers but not one ``odoo`` among them
          is a broken query or a missing label far more plausibly than
          every instance stopping at once, so that too changes nothing.
        """
        settings = self.env["cloud.settings"].sudo()._get_system()
        if not settings.metrics_enabled:
            return
        base = (settings.metrics_central_url or "").strip()
        if not base:
            return
        user, token = settings._metrics_auth()

        covered = self._ages_by_instance(
            base, _COVERAGE_EXPRESSION, user, token,
        )
        if not covered:
            return
        odoo_ages = self._ages_by_instance(
            base, _ODOO_EXPRESSION, user, token,
        )
        if odoo_ages is None:
            return
        if not odoo_ages:
            _logger.warning(
                "[metrics] %d instance(s) report containers but none "
                "reports an %r container — leaving liveness untouched",
                len(covered), _ODOO_SERVICE,
            )
            return

        now = fields.Datetime.now()
        # The stamping runs on its own READ COMMITTED cursor, opened
        # only now that the HTTP query is done: these are the very rows
        # the SSH health probe writes ``last_health_check`` on, and
        # under the default snapshot isolation whichever of the two
        # arrived second lost the row outright. See ``_concurrency``.
        with read_committed_cursor(self.env.registry) as cr:
            env = self.env(cr=cr)
            instances = (
                env["cloud.instance"].sudo().browse(list(covered)).exists()
            )
            for inst in instances:
                age = odoo_ages.get(inst.id)
                running = age is not None and age <= _SEEN_WINDOW_SECONDS
                vals = {"metrics_last_seen": now}
                if inst.running != running:
                    vals["running"] = running
                    _logger.info(
                        "[metrics] instance %s running: %s → %s",
                        inst.name, not running, running,
                    )
                # ``metrics_last_seen`` is stamped even when nothing
                # changed: it is what tells the SSH health probe that
                # liveness is already covered here, and "no change" is
                # exactly the steady state where that matters most.
                inst.write(vals)

    @api.model
    def _metrics_liveness_window(self):
        """Return the freshness window, in seconds, for tests and docs."""
        return _SEEN_WINDOW_SECONDS
