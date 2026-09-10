# IncubaCloud Operational Runbooks

Concrete steps for recurring operational scenarios. Each runbook is
self-contained: symptoms → diagnosis → resolution → rollback, with
exact commands an on-call operator can paste.

All commands assume you run them from the doodba checkout root
(`/home/<user>/.../incubacloud-doodba/`) unless stated otherwise.

## Index

| # | Runbook | Severity | When to use |
|---|---------|----------|-------------|
| [RB-01](RB-01-rotate-secret-key.md) | Rotate `INCUBACLOUD_SECRET_KEY` (MultiFernet) | planned | Scheduled rotation, suspected leak |
| [RB-02](RB-02-restore-master-db.md) | Restore master DB from off-site backup | critical | Control-plane DB lost or corrupted |
| [RB-03](RB-03-orphan-terminal-subprocesses.md) | Clean up orphan terminal subprocesses | warning | High memory, stray `python -m incubacloud.terminal_subprocess` |
| [RB-04](RB-04-tune-rate-limits.md) | Tune rate limits | warning | Legitimate 429s, false-positive throttling |
| [RB-05](RB-05-triage-failed-job.md) | Triage a failed `queue.job` / `cloud.alert` | critical | `job_failed` alert in the Alerts panel |
| [RB-06](RB-06-multi-worker-checklist.md) | Multi-worker deployment checklist | planned | Before enabling `workers>1` |
| [RB-07](RB-07-webhook-replay-investigation.md) | Investigate a webhook replay | info | `GitHub webhook replay ignored` log line |
| [RB-08](RB-08-rotate-cron-bot.md) | The cron bot user | planned | A cron is not owned by the bot, or a credential was attached to it |
| [RB-09](RB-09-docker-prune-failed.md) | `docker_prune` failed for a host | warning | Disk alert on host, failing prune cron |
| [RB-10](RB-10-github-app-rate-limited.md) | GitHub App / PAT rate-limited or revoked | critical | Webhooks silent, `403`/`401` in logs |
| [RB-11](RB-11-metrics-backend-unreachable.md) | Metrics backend unreachable — alerting is blind | critical | `metrics_backend_unreachable` alert, empty dashboards |
| [RB-12](RB-12-custom-domain-certificate.md) | Serve a domain with an existing certificate | planned | Wildcard or customer-supplied cert instead of Let's Encrypt |
| [RB-13](RB-13-rollback-panel-deploy.md) | Roll back a bad panel deploy | critical | Panel broken after `deploy-update`, failed migration mid-window |
| [RB-14](RB-14-restore-mailserver.md) | Restore the mail server | critical | Mail host lost or mail data corrupted; DKIM keys at risk |
| [RB-15](RB-15-bump-copier-template-pin.md) | Bump the doodba template pin | planned | Adopting a newer doodba-copier-template release |
| [RB-16](RB-16-tenant-sees-no-metrics.md) | A tenant sees no metrics | routine | Empty charts or missing Monitoring section for one tenant |
| [RB-17](RB-17-instance-log-archive.md) | An instance's log archive is broken | warning | `instance_logs_unhealthy` alert, no days in the log viewer |
| [RB-18](RB-18-tune-host-edge-protection.md) | Tune host edge protection | planned | Proxy 429s on an instance, enabling the host conn-rate cap, provider without anti-DDoS |
| [RB-19](RB-19-restore-large-backup.md) | Get a large backup onto a host and restore it | planned | A dump too large for the browser, or a host nobody holds credentials for |
| [RB-20](RB-20-neutralize-restored-copy.md) | Restore a copy of production without arming it | planned | Developing against real data, reproducing a bug, rehearsing a migration |
| [RB-21](RB-21-origin-certificate.md) | Issue the origin certificate for the fleet | planned | Preparing hosts to be served through the CDN, replacing the certificate |
| [RB-22](RB-22-rotate-smtp-relay-credential.md) | Rotate the SMTP relay credential | critical | The shared `notifications@` password leaked, or scheduled rotation |

## Conventions

- Commands prefixed with `$` run on the operator workstation.
- Commands prefixed with `odoo$` run inside the Odoo container
  (`docker compose exec odoo bash`, then the command).
- Commands prefixed with `db$` run inside a `psql` session on the
  master database.
- SQL assumes the database is named `prod`; adjust if you run a
  different layout.
- Every runbook has a **Rollback** section — read it before
  starting, not when things are on fire.
