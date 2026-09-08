# Backups

Backups go to **your own S3 bucket** — AWS, MinIO, Backblaze B2, Wasabi, or any
S3-compatible service. You hold the keys. We run the schedule and the encryption.

## How it works

1. You register a **backup backend** (your S3 endpoint + credentials + a passphrase).
2. You attach the backend to a project (or set it as the global default).
3. The platform runs a nightly backup on every production instance and
   uploads the encrypted bundle to your bucket.
4. Manual backups are available any time from the instance detail.

The backup format is the standard Odoo dump (`dump.sql + filestore/`) wrapped
in an encrypted archive.

## Retention by plan

!!! info "IncubaCloud SaaS"
    Plan-based retention applies to the hosted service. Self-hosted deployments
    configure retention per backend.

| Plan | Automatic backup retention |
| --- | --- |
| Free | None (manual backups only) |
| Starter | 7 days |
| Professional | 14 days |
| Business | 30 days |

Manual backups never expire. They count against your bucket storage,
not against the retention window.

## What happens to backups when an instance ends

Backups belong to the instance that made them, and they never outlive it.

| You choose | The instance | Its backups |
| --- | --- | --- |
| **Delete completely** | removed from the host and from the panel | **all destroyed**, before the containers come down |
| **Archive** | removed from the host, kept in the panel | **exactly one copy kept**, taken at that moment |

There is no third option, and no "delete the instance but leave the backups":
a chain nobody owns is one nobody can find, restore or prune, while it keeps
consuming your bucket.

Archiving takes a **fresh full backup first** and prunes everything older, so
the copy is from the moment you archived rather than from the last nightly run.
That copy still counts against your bucket storage — you can see its size in the
project's Archived tab — and it stays until you revive the instance or delete it.

!!! warning "Deleting cannot be undone"
    Both deleting an instance and deleting an archived one destroy the objects
    in your bucket. Download a backup first if you might need the data.

## Managed Backup Storage

!!! info "IncubaCloud SaaS — paid add-on"

If you'd rather not bring your own bucket, the platform can provision one for
you: a dedicated bucket with its own scoped credentials, handed to you as a
ready-to-use backup backend. Three tiers:

| Tier | Included storage | Monthly | Overage |
| --- | --- | --- | --- |
| Starter | 20 GB | 2.99 € | 0.05 €/GB |
| Standard | 100 GB | 8.99 € | 0.04 €/GB |
| Pro | 500 GB | 29.99 € | 0.03 €/GB |

The bucket lives on **Cloudflare R2 in the European Union**, and the backups in
it are encrypted with your passphrase before they leave the host — see
[Service limits](../reference/limits.md#where-managed-backups-are-stored).

Usage is measured periodically; storage beyond the included amount is billed as
overage on your subscription invoice. If you cancel the add-on, backups are kept
for a 30-day retention window before the bucket is purged. Downgrading to a
smaller tier gives you a grace period to get usage under the new limit.

## Encryption

Every backup is encrypted with the **passphrase** you set on the backend before
it leaves the host. We don't store the passphrase in clear and we can't recover it.
Treat it like a master key — store a copy in your password manager.

## What lives where

- **Bucket** — your S3, encrypted bundles. We never see the raw data.
- **IncubaCloud database** — backend metadata (endpoint, region, bucket name).
  Credentials are encrypted at rest with our own platform key.

## Common tasks

- Set up your first backup backend (use the [marketing site quickstart](https://www.incubacloud.io/docs/backups))
- [Restore a backup](restore.md)
- Receive an email when a backup completes (Backend detail → Notifications)
- Override the project-level backend on a single instance
  (Instance detail → Settings → Backup backend)

!!! note "Reference page is in progress"
    A full per-screen reference for the Backup backend UI is coming soon.
