"""Post-migrate for 1.0.111 — hand the new watchdog cron to the bot.

``post_init_hook`` promotes every ``ir.cron`` of this module from the
implicit OdooBot to the dedicated cron user, and it runs only on a fresh
install. A cron added in a later release is therefore created owned by
uid 1 on every existing installation and stays that way — which is
exactly what the "every cron of ours runs as the bot" guard exists to
catch, and why it is re-run here.

Idempotent: the assignment skips crons that already point at the bot.
"""
from odoo import SUPERUSER_ID, api


def migrate(cr, version):
    """Reassign this module's crons to the cron bot user.

    :param cr: database cursor
    :param version: module version being upgraded from
    """
    if not version:
        return
    env = api.Environment(cr, SUPERUSER_ID, {})
    env['res.users']._incubacloud_ensure_cron_bot()
    env['res.users']._incubacloud_assign_cron_user_id(
        module_name='incubacloud',
    )
