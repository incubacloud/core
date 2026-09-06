"""Notice when one of the platform's own scheduled actions goes quiet.

Everything the platform does on a schedule — backups, dunning, the pool,
the rollout, the audits — hangs off ``ir.cron``. A cron that is switched
off keeps no queue and raises nothing; it simply stops happening, and
every consequence of it stops happening too, somewhere else, later.

That is not hypothetical. The deploy pipeline pauses these crons for the
length of its window and resumes them at the end; a run that was killed
rather than aborted never reached the resume, and twenty-three of the
manager's twenty-four scheduled actions stayed off for five days. The
nightly backup of the free pool's host was among them. Nothing reported
it, and nothing could have: no job failed, no alert fired, because the
work was never attempted.

**What counts as suspicious.** A cron that has run at least once and is
now inactive. Never asking what the module *meant* is deliberate: a
declaration lives in an XML file that is not readable from a running
database, and one that says ``active=False`` on purpose (the secret
rotation, which is opt-in) would then need an exception list that drifts.
"Used to run, does not any more" needs no such list — it is a fact the
database already holds, and it describes exactly the failure above.
"""
import logging
from datetime import timedelta

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

#: How far past its own next run a cron may sit before it is worth
#: saying so. The deploy pipeline switches these off on purpose for the
#: length of its window, which is minutes; a cron still overdue hours
#: later was not switched back on, and that is the case worth an alert.
STOPPED_GRACE_HOURS = 6

#: Modules whose scheduled actions belong to us. Odoo's own crons are
#: left alone: several ship disabled by design (fetchmail, the pending
#: sales mail) and turning one off is a legitimate configuration choice
#: nobody needs an alert about.
OUR_MODULES = (
    "incubacloud",
    "incubacloud_saas_manager",
    "incubacloud_oidc_provider",
)

ALERT_CODE = "crons_disabled"


class IrCron(models.Model):
    _inherit = "ir.cron"

    @api.model
    def _disabled_platform_crons(self):
        """Return our inactive crons that are overdue, furthest first.

        Read with ``sudo`` and through the ``active_test`` context: the
        whole point is to find rows the default domain hides.

        Overdue is measured against ``nextcall`` — when this cron was
        due to run next — and never against ``lastcall``. That was the
        original rule and it was wrong in a way only production shows:
        ``lastcall`` says how long ago it *ran*, so a cron that runs
        once a day is always "six hours stale" by that measure, and
        every deploy that paused one raised an alert naming all of
        them. Measured on 6 September: twenty-nine of them, mid-window,
        with the fleet healthy. Alerting on our own maintenance is how
        this alert stops being read.

        ``nextcall`` answers the question actually being asked. Odoo
        advances it whenever the cron runs, and a paused cron keeps the
        one it had — so during a deploy window a daily cron is still
        hours from due and says nothing, while one left switched off
        falls behind and speaks up.

        Still requires ``lastcall``: a cron that has never run is off
        because it ships that way (the secret rotation is opt-in), and
        turning it on would be a decision rather than a repair.

        :rtype: recordset of ``ir.cron``
        """
        data = self.env["ir.model.data"].sudo().search([
            ("model", "=", "ir.cron"),
            ("module", "in", list(OUR_MODULES)),
        ])
        crons = (
            self.sudo()
            .with_context(active_test=False)
            .browse(data.mapped("res_id"))
            .exists()
        )
        cutoff = fields.Datetime.now() - timedelta(hours=STOPPED_GRACE_HOURS)
        return crons.filtered(
            lambda c: not c.active and c.lastcall and c.nextcall
            and c.nextcall < cutoff
        ).sorted(key=lambda c: c.nextcall, reverse=True)

    @api.model
    def _cron_check_disabled(self):
        """Raise one alert while any of our scheduled actions is off.

        One alert and not one per cron: they go off together — a deploy
        pauses them as a group — so a row each would be twenty-three
        copies of a single fact, which is how an alert list stops being
        read.

        :return: how many were found stopped
        :rtype: int
        """
        Alert = self.env["cloud.alert"].sudo()
        existing = Alert.search(
            [("code", "=", ALERT_CODE), ("state", "=", "active")],
            limit=1,
        )
        stopped = self._disabled_platform_crons()
        if not stopped:
            existing.write({"state": "dismissed"})
            return 0

        names = stopped.mapped("cron_name")
        oldest = min(stopped.mapped("nextcall"))
        vals = {
            "code": ALERT_CODE,
            "level": "warning",
            "message": (
                f"{len(stopped)} scheduled action(s) of the platform are "
                f"switched off and are not running: {', '.join(names[:5])}"
                + (f" and {len(names) - 5} more" if len(names) > 5 else "")
                + f". The furthest behind was due to run on {oldest}."
            ),
            "payload": {
                "crons": [
                    {
                        "id": cron.id,
                        "name": cron.cron_name,
                        "last_run": str(cron.lastcall),
                        "due": str(cron.nextcall),
                    }
                    for cron in stopped
                ],
            },
        }
        if existing:
            existing.write(vals)
        else:
            Alert.create(vals)
        _logger.warning(
            "[crons] %d platform scheduled action(s) are switched off: %s",
            len(stopped), ", ".join(names),
        )
        return len(stopped)
