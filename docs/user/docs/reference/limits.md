# Service limits

!!! info "IncubaCloud SaaS"
    This page describes the hosted service at incubacloud.io. A self-hosted
    deployment of the open core module sits behind whatever you put in front
    of it, so none of these numbers apply to it.

Instances on the hosted service are served through a CDN. That buys you TLS,
caching and protection against floods, and it comes with two limits that you
can run into from inside your own Odoo.

## One request may carry at most 100 MB

A single HTTP request cannot carry more than **100 MB** of body. Past that the
CDN answers `413 Request Entity Too Large` and your Odoo never sees the upload.

In practice this bites when you attach a very large file, or import one, from
the Odoo web client.

**What to do instead**

| You are… | Use |
| --- | --- |
| Restoring a database dump | [Restore a backup](../backups/restore.md) — the browser route sends the file in pieces, so the 100 MB ceiling does not apply. For very large dumps, the SSH or link routes bypass the CDN entirely. |
| Attaching a large document | Store it in object storage and attach the link, or split the file. |
| Importing a large data file | Split the import into several files. |

## One request may take at most 100 seconds

The CDN waits **100 seconds** for your instance to start answering. If a request
takes longer to produce its first byte, the CDN gives up and returns
`524 A timeout occurred` — even though your Odoo usually keeps working and
finishes the job in the background.

This is a limit on a *single request*, not on the work itself. It shows up on
things like a report over a very large date range, a heavy import run
synchronously, or a query with no index behind it.

**What to do instead**

- Narrow the range or the batch, and run the operation in several passes.
- Prefer Odoo's scheduled actions for long jobs: they run server-side with no
  request waiting on them.
- If an operation you need genuinely cannot finish in 100 seconds,
  [tell us](https://www.incubacloud.io/contactus) — that is usually a sign the
  operation should be moved to a background job.

!!! note "A 524 does not mean the work was lost"
    The request was abandoned, not the job. Reload the page before repeating the
    operation: quite often it completed.

## Where managed backups are stored

If you use **Managed Backup Storage** (the paid add-on that provisions a bucket
for you instead of you bringing your own), the bucket lives on **Cloudflare R2
in the European Union** — the endpoint is `eu.r2.cloudflarestorage.com`, and the
data does not leave that jurisdiction.

Backups are encrypted with your passphrase before they leave the host, so the
storage provider holds ciphertext only. See [Backups](../backups/index.md).

If you bring your own bucket, backups live wherever your bucket lives and this
does not apply.

## Third parties in the path

Traffic to instances on the hosted service is proxied by **Cloudflare**, which
therefore processes connection metadata (source address, hostname, request
headers) on our behalf. Cloudflare also stores managed backup buckets, as
described above.

For the contractual side — the full list of the providers we rely on, and the
data-protection terms that govern them — see the
[privacy policy](https://www.incubacloud.io/privacy) and the
[terms of service](https://www.incubacloud.io/terms).

## See also

- [Restore a backup](../backups/restore.md) — the routes that are not limited by
  request size.
- [Backups](../backups/index.md) — retention, encryption and storage.
- [Instances](../instances/index.md) — lifecycle and sleeping instances.
