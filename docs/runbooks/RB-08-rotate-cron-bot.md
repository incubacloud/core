# RB-08: The cron bot user

**Severity:** planned
**Typical trigger:** a review asks when the cron bot was last rotated,
or a credential is added to it and later has to be revoked.
**Who runs it:** ops + security.

Every `ir.cron` from the `incubacloud*` modules runs as the cron bot
user (login `__incubacloud_cron__`, created by the post-init hook).
It is the identity behind most of the write paths in the control
plane: 53 scheduled actions in production as of 2026-09-10, plus the
OIDC signing-key rotation, which sat on uid 1 until
`incubacloud_oidc_provider` 19.0.1.0.16 — its module never called the
provisioning hook, and the old diagnosis query matched crons by name,
which this one's does not contain.

> **Read this before rotating anything.** Until 2026-09-10 this runbook
> described a credential rotation. It was wrong on all three counts,
> and running it would have archived the control plane's identity
> while changing nothing about security. What was measured:
>
> * **There is no credential to rotate.** The bot's `password` column
>   is NULL and it owns zero `res.users.apikeys` rows. Nobody can
>   authenticate as it; it exists only to be named by `ir_cron.user_id`.
> * **Archiving it does not stop the crons.** `_get_all_ready_jobs`
>   selects from `ir_cron` alone — it never joins `res_users` — and
>   `_process_job` builds `api.Environment(cr, job['user_id'], {})`
>   straight from the id, with no active check. Verified in devel: the
>   bot was archived and a cron still ran.
> * **`_incubacloud_ensure_cron_bot()` does not undo it.** On a user
>   that already exists it *only aligns groups*. It does not reset a
>   password and does not re-activate. So the old step 1 archived the
>   bot, step 2 left it archived, and the old step 3's own check
>   (`active = true`) would have failed with nothing in the procedure
>   to fix it.

## Symptoms / triggers

- A review asks who owns the scheduled actions, or whether any cron
  slipped back to `uid=1`.
- A module was added whose crons do not run: it probably never called
  the provisioning hook.
- A credential *was* attached to the bot (a password set by hand, an
  API key issued for an integration) and now has to go.

## Diagnosis

Inventory current cron ownership, by the module that ships each cron
— not by its name, which is how the OIDC rotation went unseen:

```sql
db$ SELECT d.module, c.id, c.cron_name, u.login, c.active
    FROM ir_cron c
    JOIN ir_model_data d ON d.model = 'ir.cron' AND d.res_id = c.id
    JOIN res_users u ON u.id = c.user_id
    WHERE d.module LIKE 'incubacloud%'
    ORDER BY d.module, c.id;
```

You should see `__incubacloud_cron__` on every row. If you see
`uid=1` (OdooBot), the hook did not run for that module — run it
(below), and if the module has no call to it at all, add one to its
`post_init_hook` and a migration, as `incubacloud_oidc_provider`
19.0.1.0.16 does.

Confirm the bot still carries no credential:

```sql
db$ SELECT id, login, active, password IS NOT NULL AS has_password
    FROM res_users WHERE login = '__incubacloud_cron__';
db$ SELECT count(*) FROM res_users_apikeys
    WHERE user_id = (SELECT id FROM res_users
                     WHERE login = '__incubacloud_cron__');
```

`has_password = f` and `0` keys is the expected, healthy state.

## Resolution

### A · A cron is not owned by the bot

Re-run the provisioning hook for the module that owns it. This is
idempotent and safe on a live system — it only adds group
memberships, re-points `user_id` off uid 1, and scopes each bot-owned
cron's server action to `incubacloud.group_cloud_manager`. Do not
re-point `user_id` by hand instead: without that group, Odoo 19 refuses
the action to any user who cannot write its model, and the bot
deliberately cannot write most of them.

```python
env['res.users']._incubacloud_ensure_cron_bot()
for module in ('incubacloud',
               'incubacloud_saas_manager',
               'incubacloud_oidc_provider',
               'incubacloud_tenant'):
    env['res.users']._incubacloud_assign_cron_user_id(
        module_name=module,
    )
```

Then re-run the Diagnosis query: every row must show
`__incubacloud_cron__`.

Smoke-test one cron:

```python
env.ref('incubacloud.cron_cloud_terminal_route_gc').method_direct_trigger()
```

### B · A credential was attached to the bot and has to be revoked

This is the only case that is a rotation, and it is only reachable
if somebody gave the bot a credential it does not ship with.

Revoke the API keys:

```sql
db$ DELETE FROM res_users_apikeys
    WHERE user_id = (SELECT id FROM res_users
                     WHERE login = '__incubacloud_cron__');
```

Clear a hand-set password:

```sql
db$ UPDATE res_users SET password = NULL
    WHERE login = '__incubacloud_cron__';
```

Neither touches `ir_cron`, so no scheduled action is interrupted:
the crons name the user by id and never authenticate as it. Re-run
the Diagnosis credential query; it must be back to `f` and `0`.

### C · You want a genuinely new identity

Archiving the old bot and creating a new one is **not** supported by
the current helpers: `_incubacloud_ensure_cron_bot` reuses the login
and will not mint a second user. Doing it by hand means creating the
user, granting the three groups
(`incubacloud.group_cloud_manager`, `base.group_user`,
`queue_job.group_queue_job_manager`), re-pointing all 53 crons, and
moving the XML-id — and it buys nothing while the bot has no
credential to compromise. Do not do it as hygiene. If a real reason
appears, the helpers need to grow the capability first, with a test.

## Rollback

Case A changes only group memberships and `ir_cron.user_id`; re-run
it if in doubt, it is idempotent.

Case B is a revocation, so there is nothing to roll back to — issue a
fresh credential if the integration that used it still needs one.

If you archived the bot following the pre-2026-09-10 version of this
runbook, the crons kept running, but put it back anyway so the panel
shows the identity correctly:

```sql
db$ UPDATE res_users SET active = true
    WHERE login = '__incubacloud_cron__';
```

## References

- [`models/res_users_ext.py`](../../incubacloud/models/res_users_ext.py)
  — `_incubacloud_ensure_cron_bot` + `_incubacloud_assign_cron_user_id`.
  Read the first before assuming what it does to an existing user.
- [`migrations/1.0.2/post-migrate.py`](../../incubacloud/migrations/1.0.2/post-migrate.py)
- `odoo/addons/base/models/ir_cron.py` — `_get_all_ready_jobs` and
  `_process_job`, which is where "archiving stops the crons" falls apart.
