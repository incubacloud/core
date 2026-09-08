# Instances

An **instance** is a running Odoo deployment — one container, one database,
one filestore. It belongs to a project and runs on a host.

## Concepts

- **Production instance** — customer-facing. Re-deploys go through the safe-rebuild
  flow (boot test before swap). One per project.
- **Staging instance** — test copy. Re-deploys are direct. As many as your plan allows.
- **Sleeping instance** (SaaS Free plan) — automatically suspended after ~30 minutes
  without traffic to save resources. Wakes up on the next request (the first request
  after a nap takes a few seconds).

!!! info "IncubaCloud SaaS"
    Instances on the hosted service are served through a CDN, which caps a single
    request at **100 MB** and at **100 seconds** to first byte. See
    [Service limits](../reference/limits.md) for what to use instead when you hit
    either one.

## Lifecycle

```
deploy → running → rebuild → running → ... → archive or delete
```

A rebuild updates the image and modules without downtime (production) or
restarts the container (staging).

## Ending an instance

Both endings remove the containers, the database and the files from the host.
They differ in what happens to the **backups**.

!!! warning "Deleting destroys the backups too"
    An instance's backups belong to that instance. **Delete completely** empties
    them before the containers come down — there is no option to keep them, and
    nothing to restore from afterwards. If you might want the data later,
    archive instead, or [download a backup](../backups/restore.md) first.

    Because it cannot be undone, the panel asks you to type the instance name.

**Archive** keeps one restorable copy. A fresh full backup is taken at that
moment — not the last nightly one, so nothing since it is lost — and everything
older is pruned, leaving exactly one copy. The instance moves to the
**Archived** tab of its project, where you can see the size of that copy and
when it was last verified.

From there you can:

- **Revive** it — deploy it again, on the original host or any other, and
  restore the copy into it.
- **Delete** it — which destroys the copy as well, and again asks for the name.

An archived instance keeps its name reserved inside its project: creating a new
instance with that name is refused, because it would compute the same backup
path and write into the copy being kept.

!!! note "Archiving without a backup destination"
    An instance with no backup backend has no copy to keep, so archiving it
    keeps only the record. The panel says so and asks you to confirm in
    writing.

## Common tasks

- [Deploy your first instance](../getting-started/first-deploy.md)
- Rebuild after pushing changes to your repo (Instance detail → Rebuild)
- [View logs](logs.md) (Instance detail → Logs). Odoo's log is kept one file per day and survives rebuilds: pick a day, search every day at once, or download one
- Open a shell on the container (Instance detail → Shell)
- [Restore from a backup](../backups/restore.md)
- [Refresh a staging with production data](#refresh-from-production)
- Add a custom domain (Instance detail → Networking → Domain)

## Refresh from production

**Instance detail → Refresh from production** replaces a staging instance's
database and filestore with a copy of its project's production, keeping the
staging's own code (repositories and branches) untouched. It is the button you
press when your test copy has drifted away from real data.

Two data sources:

- **Latest backup** (recommended) — restores the most recent snapshot from the
  production's backup destination. No extra load on production.
- **Live dump from production** — dumps the production database on the spot, so
  you get the data as of right now. It costs a `pg_dump` on a live database, and
  it is the only option when the production has no backup destination configured
  (the dialog then picks it for you).

**Neutralize the database** is on by default: the restored copy comes up with
scheduled actions and outgoing mail servers disabled and Odoo's test banner
showing. Leave it on unless you are deliberately testing a cron or a mail flow —
a staging carrying production's data will otherwise invoice, dun and email your
real customers.

The refresh runs as two jobs (a download on the production, a restore on the
staging) that you can follow in the activity timeline. If the download fails the
restore never starts and the staging is left untouched. Refreshing does **not**
run a module update: if the staging's branch lacks a module the restored database
has installed, use a rebuild afterwards.

Cloning a production to a new staging (**Project → Clone to staging**) applies
the same neutralization.

## Auto-update

If you push commits to a connected repo, two settings control what happens:

- **Auto-rebuild** — trigger a rebuild automatically when commits land on the
  connected branch. Off by default.
- **Auto-update modules** — during rebuild, run `click-odoo-update` to update
  only the modules whose checksum changed. On by default.

Both live under `Instance detail → Networking`.

## See also

- [Hosts](../hosts/index.md) — where instances run.
- [Backups](../backups/index.md) — how to keep their data safe.

!!! note "Reference page is in progress"
    A full per-screen reference for the Instance detail UI is coming soon.
