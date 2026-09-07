# Changelog

All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.118] — 2026-09-08

### Fixed

- **The error scrape kept reading past the end of the traceback.** `grep -A`
  prints a fixed number of lines after each ERROR header, and the parser
  filed everything that was not another ERROR as context — including the
  INFO records logged after the failure. Those spent the tail budget that
  1.0.115 introduced to keep the exception: in a real alert the exception
  was line 1 of a 14-line tail, thirteen werkzeug requests behind it. A
  group now closes at the next log record of any level, as it already did
  at grep's own `--` marker.
- **The probe could not read an instance still logging to its container.**
  `docker compose logs` prefixes every line with `odoo-1  | `, and both
  readers of that output are anchored to the start of the line on purpose:
  one so asyncssh's echo of the scrape is never harvested as an error, the
  other so only a real Odoo record is counted. The fallback error scrape
  therefore produced no groups at all — an instance that has not been
  rebuilt since file logging shipped could never raise
  `instance_error_logs` — and the counter behind `instance_logs_unhealthy`
  (`fallback`, Odoo unable to write to the log file) read zero on every
  instance since it shipped. Both readings now pass `--no-log-prefix`.

## [1.0.117] — 2026-09-07

### Fixed

- **Every instance's mail container announced its own updates, under the same
  name.** docker-mailserver ships an `update-check` service that asks GitHub
  for the latest release and mails postmaster once per container start. Which
  tag an instance runs is the panel's call (`smtp_relay_version`), so the
  announcement is advice the container cannot act on — and it arrived at fleet
  scale: copier renders the hostname as `smtp.<relay domain>`, so all twelve
  instances relaying through one domain reported themselves as the same host,
  and a free tenant restarts on every Sablier wake, turning "once per start"
  into dozens of identical mails a day at the postmaster address. The compose
  override the panel writes now sets `ENABLE_UPDATE_CHECK=0` on the `smtp`
  service. It goes there rather than in `.docker/smtp.env` or the compose
  files because `copier update` regenerates all three on every rebuild, which
  would drop it. The switch lands on each instance at its next deploy or
  rebuild.

## [1.0.116] — 2026-09-07

### Fixed

- **A brand-new tenant opened on months of somebody else's history.** A warm
  spare keeps its `cloud.instance` record when a tenant claims it, so the job
  list of a one-hour-old tenant began with the weeks of pool rebuilds and
  health checks logged before the handover — 107 foreign rows ahead of its own
  9, with nothing marking the boundary. `cloud.instance._job_history_floor()`
  is a new hook (`False` in core: an instance normally owns its whole history)
  that `cloud.job` now honours in both the instance timeline and the history
  page. Jobs older than the floor are hidden, counted, and one click away —
  they stay in the database, because the machine is the same machine and those
  failures still explain today's.
- **The warm spare built during a signup was stamped with the customer.** The
  pool refills eagerly from inside the signup request so the next customer does
  not wait for the cron, and `sudo()` raises privileges without changing
  `env.uid` — so the project, instance and build job of the *next* customer's
  spare all carried the current one's user. Four weeks later that spare was
  handed to somebody else, who found a stranger listed as its author. Warm
  builds now run as the platform's own bot, the same user the pool crons
  already use. `res.users._get_cron_bot()` exposes it (XML-id first, login
  fallback, empty rather than raising).
- **The same bug, twice more, found by auditing every platform table in
  production.** `sudo()` raises privileges but leaves `env.uid` alone, so
  any work the platform does inside somebody else's request is authored by
  them — and that author reaches `queue_job.user_id`, meaning the executor
  *runs* as them and every row it writes inherits it.
  - The **GitHub webhook** is `auth="public"`, so a push to core produced
    348 fleet-rebuild jobs, 357 `queue_job` rows and 192,523 log chunks all
    authored by the public user. Elevated in the controller and again in
    `cloud.github.event._dispatch`, so a replay or a shell reprocessing a
    stuck event is covered too.
  - **Alerts** inherited whichever producer tripped them: 16 `job_failed`
    from the public user, and a customer listed as the author of a
    `metrics_acl_sync_failed` on infrastructure they never saw. Elevating
    inside `raise_alert`/`resolve_alert` covers all 19 call sites at once.
  - The **tenant→master API** (`/saas/*`, token-authenticated so `env.uid`
    is the public user) now elevates in `_resolve_tenant`; its create sites
    go through `tenant.env`. The tenant is still named by `tenant_id` on
    every row — what changes is who *acted*.
  - The **tenant OIDC client**, a platform credential, was authored by the
    tenant it authenticates (14 rows).
  `as_platform()` is the single helper for all of this: elevate once at the
  entry point and the whole chain below inherits it. A structural test
  (`test_platform_actor_invariant`) now fails the build if an
  `auth="public"`/`"none"` route enqueues, dispatches or raises an alert
  without it — verified to flag the webhook as it was written before this
  release.

## [1.0.115] — 2026-09-06

### Fixed

- **The error-log alert kept the useless half of the traceback.** The probe
  stored 25 lines after each ERROR header, which in an Odoo cron failure is
  `ir_cron` → `ir_actions` → `safe_eval` and nothing else: the exception type
  and message, the only lines that say what broke, fell off the end. Capture
  is now 60 lines and a group is compacted to head + `… N line(s) skipped …`
  + tail, so trimming always eats the middle and the last line survives.
  This is what left a fleet-wide broken cron undiagnosable for a week.
- **The panel never rendered the traceback it had.** The alert card showed
  the ERROR headers and dropped `context` on the floor, so reading a stack
  meant querying the database by hand. It is now shown under each group.
- **An error alert was dismissed five minutes after it was raised.** The
  probe's window is the time since the last check, so an error that fires
  every six hours produced an alert the next clean cycle closed — two
  notifications minutes apart, and nothing left in a panel that filters to
  active by default. `instance_error_logs` now closes only after
  `_ERROR_QUIET_HOURS` (24 h) without the error being seen again.

### Added

- `cloud.alert.last_raised_at`: when the condition was last observed,
  stamped on every raise and shown as "last seen" in the alert history, so
  an alert that keeps being re-raised no longer reads as days old. Nullable;
  consumers fall back to `create_date`.

## [1.0.114] — 2026-09-06

### Fixed

- **The job that retires stored certificates did not check that it had.** The write reports the exit status of a shell redirection, which succeeds over a store that ends up truncated and says nothing about whether the proxy came back — so the job could report success while the host went on serving exactly the certificates it was told to stop serving, which is the silence the retirement exists to end. It now reads the store back once the proxy is up and fails the job if a retired name is still there, if the document does not parse, or if it cannot be read at all. Reading it through the container also answers a question nothing asked before: a container that is not running cannot be read from, so a restart that did not take is now a failure rather than a green step.

- **The scheduled-action watchdog cried wolf on every deploy.** It measured how long a cron had been stopped from `lastcall` — when it last *ran* — so a cron that runs once a day was six hours stale while working perfectly, and the deploy pipeline pausing it for a few minutes was enough to report it. Measured on 6 September: one alert naming twenty-nine scheduled actions, raised mid-window, with the fleet healthy. Noise on this particular alert is expensive, because it is the only thing that notices work silently not happening. It now measures against `nextcall` — when the cron was due to run next — which a pause leaves untouched: a daily cron paused during a deploy window is still hours from due and says nothing, while one left switched off falls behind and speaks up. Crons that have never run stay excluded, as before.


### Removed

- **The hourly watchdog for switched-off scheduled actions, and its
  `crons_disabled` alert.** It existed to notice the one thing a killed
  `deploy-update` could leave behind: our crons paused, and nobody left to
  switch them back on. That failure is now impossible rather than detected:
  before pausing anything, the pipeline arms a timer on the host itself, and
  the host switches them back on if the run never gets to. A detector for a
  hazard our own tooling created belonged in the tooling — not in every
  database this module is installed in, where it ran every hour on each
  tenant watching thirty crons that nothing ever pauses. The alert history
  keeps the rows it raised; nothing raises that code any more.

---

## [1.0.113] — 2026-09-06

### Fixed

- **The watchdog's own tests read the manager's history as their own.** `cloud.alert` rows for `crons_disabled` survive in any database the check has run on, and what a leftover does depends on its state: an *active* one is reused rather than added, so "it raised an alert" finds a row the test never caused; a *dismissed* one is not reused, so a second row appears and "exactly one alert" counts two. Development databases carry the first, the manager's own carried the second, and between them every assertion in the suite was resting on whichever the database happened to hold. Caught by the deploy's boot test against a clone of production, where four of them failed at once. The tests now clear those rows in `setUp` rather than filtering around them — the reuse means a leftover changes what the code under test *does*, not merely what the assertions can see.

---

## [1.0.112] — 2026-09-06

### Fixed

- **Handing a host a certificate did not stop it serving the old ones.** Traefik publishes everything in its own ACME store under the default TLS store when it starts, and the handshake picks by server name before any router is consulted — so a name whose router was changed to serve the host's certificate went on being answered with the stored one, indefinitely. Measured on 2.11: an entry in the store wins even when its only router asks for the default, and even when it has no router at all. Six tenants moved behind a CDN were still presenting certificates they can no longer renew, with correct routers, correct labels and nothing in the logs to say so. The two jobs that install the certificate and restart the proxy now retire the entries the host has started serving itself, immediately before the restart. An entry is only retired when *every* name on it is one this host covers and a CDN answers for — a certificate covering a mixture is left alone, because retiring it would take the names still reached directly down to a throwaway. A store that cannot be read, or cannot be parsed, is left exactly as it is: the names on it cannot obtain another certificate from behind a CDN, so losing one is not recoverable.

---

## [1.0.111] — 2026-09-06

### Fixed

- **A sleeping instance read as running, and everything behind that flag stopped happening.** `running` was derived from "has any container of this instance been seen recently", and an instance put to sleep keeps its database and backup containers up — so the answer was yes all night and the flag never fell. It now asks about the `odoo` container specifically, which is what `running` has always meant and what the SSH probe measures. Measured against production: five free tenants, four of them asleep, all six reported running. Downstream, none of them was ever marked sleeping, and the activity clock behind the 14-day auto-suspend was being refreshed as though somebody had visited. Three fail-safes, not two: a fleet that reports containers but not one `odoo` among them is a broken query far more plausibly than every instance stopping at once, and changes nothing.

- **The instance card showed one reading printed once per service.** Every service dot was drawn from the single `running` flag, so `db` and `odoo` could never disagree and a stopped companion was invisible. The health probe has always computed the state of each container and threw it away after alerting on it; it is now kept in `service_states` and the card draws each dot from its own reading, falling back to the old behaviour until the first probe lands.

### Added

- **"Asleep" is now a thing the panel can say.** Being down on purpose and being down are not the same thing to show an operator, and until now both read as "Stopped". Instances answer `_stop_is_expected` — always False here, since base knows of no legitimate reason for a deployed instance to be stopped — and the layer that schedules sleep overrides it.

- **An alert when one of our scheduled actions is switched off and stays off.** A cron that is off raises nothing and queues nothing; the work simply never happens. A deploy pauses these for the length of its window and a run that was killed rather than aborted never resumed them: twenty-three of the manager's twenty-four scheduled actions stayed off for five days, the nightly backup of the free pool's host among them, with nothing to report it. The rule is "has run before, is off now, and has been for longer than a deploy window" — no list of what should be running, which would drift away from what the modules declare.

---

## [1.0.110] — 2026-09-05

### Fixed

- **Installing the host's certificate failed on every hardened host.** Traefik runs as root inside its container and owns `certs/` on any host it has already written an ACME store into, so a host whose jobs run as the unprivileged operator the hardening playbook creates could not move a file in there. Measured on a real host: every other step of the job succeeded and this one died on `Permission denied`, leaving the host with the CDN's ranges and without the certificate it is supposed to serve — the exact half-state that makes a proxy answer handshakes with a throwaway. The plain move is still tried first, so a host without sudo behaves exactly as before; only the fallback is new. Exercised against real shells with the directory owned both ways, and on the removal path.

---

## [1.0.109] — 2026-09-05

### Added

- **A host can say whether a router should ask for a certificate or serve the one it holds.** Asking a certificate authority for a name that now answers through a CDN can never succeed — the challenge reaches the CDN, not the host — and nothing reports it: the proxy keeps serving the certificate it already obtained until that one expires, then starts answering handshakes with a throwaway. Serving the held certificate too early is worse and faster, because a certificate issued for a CDN's benefit is trusted by that CDN and by no browser. `cloud.host._router_tls_mode` answers both at once, and only says `default` when a CDN stands in front of the name *and* the held certificate covers it. Coverage is read from the certificate's own subject alternative names rather than derived from a base domain, so the answer stays right for a purchased wildcard or an internal CA as much as for a CDN's origin certificate.
- **A domain's certificate now follows its host by default.** `cert_resolver` gains `auto`, which asks the host serving the domain instead of being maintained row by row — the previous default meant every domain had to be revisited by hand whenever a host moved behind a CDN, and forgetting one failed silently months later. Existing rows sitting on the old default are moved to `auto`, which resolves to exactly what they did before on every host reached directly. An explicit `letsencrypt`, `custom` or `none` is still honoured as typed.
- **The firewall and the proxy stay on the same list.** Both have to trust the same CDN ranges, and only one of them was being kept current: the proxy is re-shipped by a daily job over SSH, while the firewall's copy was written by the hardening playbook, which runs on Ansible at host creation and then effectively never. A range the CDN published afterwards was accepted by the proxy and dropped before reaching it. The ranges now live in named nftables sets rather than written into the rule, and `push_trusted_proxies` refreshes them — as one `nft -f` document, because flushing and refilling in two commands leaves a window where the set is empty and the rule matches nobody. A host whose ruleset predates the sets is left alone, and its inlined ranges keep working until the next hardening run. Both paths and both rulesets were exercised against a real `nft`.
- **Odoo records the visitor again, not the proxy in front of them.** Odoo reads the last entry of the forwarded chain, with `x_for=1` fixed in its own source. A reverse proxy appends the address it was reached from before passing the request on — and does so *after* its middlewares run, measured on a real Traefik v2.11, so nothing configurable inside the proxy can change what ends up last. Behind a CDN the chain therefore reads `<visitor>, <edge>` and every session is recorded against one of the CDN's own addresses, with nothing to say so: the site works. A `post_load` hook now corrects the chain from the header the proxy states the visitor in, and only when the connection came from an address configured as trustworthy — an unproven header is written by whoever is calling. Off unless both are configured, so an installation reached directly is untouched. Traefik's own middlewares were measured too and turned out to be *correct* already: they read the chain before that append, so the rate limit and the allowlists were keying on the visitor all along.
- **The webhook routers follow it too.** A route may carry `tls_mode`; `default` renders an empty TLS section, which turns TLS on and leaves the certificate to the host's default store. Verified against a real Traefik v2.11 rather than reasoned about, because a resolver named in that section makes Traefik ignore the store it was just given a certificate in.

### Changed

- `cloud.instance.domain.cert_resolver` defaults to `auto` instead of `letsencrypt`. No router changes on this release: `auto` resolves to Let's Encrypt for every host that is not behind a CDN holding a certificate covering the name.

---

## [1.0.108] — 2026-09-04

### Fixed

- **Neutralization was aborting, so restored copies stayed armed.** A copy of production restored for development holds the SSH keys that open every host and the tokens that create and destroy servers, and `odoo neutralize` is what removes them. It runs as a single transaction, and this one named `cloud_settings.vps_restore_public_key` — a column removed some time ago. Postgres rejected the statement, the whole script rolled back including Odoo's own half, and the log line saying so scrolled past. Copies believed to be neutralized were fully capable of reaching production, and one did.
- **Six secrets survived neutralization even when it succeeded.** The list of what to clear is written by hand, so it drifted behind the fields: the host's default TLS key, a job's secret payload, the metrics and Grafana credentials, the OVH API keys, the origin certificate, a tenant's metrics token, the backup request credential buffer, and the host terminal sessions. Restore upload grants are now dropped as well, since they name hosts that the copy must not reach.

### Added

- **The list is checked against the registry instead of by hand.** `TestNeutralize` reads every encrypted field of every installed module and requires some module's script to clear it, and separately refuses any script naming a column the database no longer has — the failure that made the whole mechanism a no-op. Both halves were verified to fail before they were left passing.
- **[RB-20](docs/runbooks/RB-20-neutralize-restored-copy.md)** — restoring a copy of production without arming it, and how to confirm it worked rather than assume it did, including the trap that a module update reloads cron data and switches them all back on.

---

## [1.0.107] — 2026-09-04

### Added

- **A host says whether a CDN answers for it.** What defends a host depends on how it is reached, and that was inferred rather than recorded: declaring trusted proxy ranges was enough to make the rate limit key on the forwarded chain. On a host reached directly that chain is absent, so Traefik keyed every visitor under the same empty value — one bucket shared by everyone, measured against a real Traefik 2.11 rather than reasoned about. The two facts are now separate: ranges decide whose forwarded headers are believed, `behind_cdn` decides whether the limit reads them. A host that declared ranges by hand keeps its behaviour through the upgrade.
- **A host can be given its certificate instead of obtaining one.** Behind a CDN the challenge never arrives — the proxy terminates TLS first — so ACME cannot work there. Traefik now serves a certificate supplied on the host record as its default, shipped and removed by the same jobs that ship the proxy settings. Generic on purpose: an origin certificate from a CDN, an internal CA or a purchased wildcard all fit.
- **The firewall knows the difference too.** On a host behind a CDN the per-source connection cap on 80/443 becomes an allowlist of the CDN's ranges, because behind a proxy every visitor arrives from a handful of edge addresses and a per-source cap would throttle the CDN and protect nobody. It waits for the host to also be refusing direct traffic at the proxy, so the two halves cannot be enabled in an order that leaves the host answering no one.
- **Backups too large for one request can be uploaded from the browser.** The archive is sent in 32 MiB pieces and rebuilt on the staging path the restore already used, so no proxy in front of the panel caps it. An interrupted piece is re-sent on its own: the server keys on the offset, acknowledges one that already landed, and refuses one that would leave a hole. The ceiling is now the panel's disk, and configurable (`incubacloud.restore_upload_max_bytes`).
- **A one-use SSH key for archives that should not pass through the panel at all.** The old rsync flow printed a command and assumed the operator could authenticate to the host — true on a machine they own, false on a managed one, which left no route at all for a large archive there. The platform now lends its access instead of sharing it: a generated key confined by `rrsync -wo` to a single directory, `restrict`, and an expiry OpenSSH enforces by itself. The private half is shown once and never stored. Before anything is restored, the host reports the name, size and SHA-256 of what actually arrived — the control that makes a file somebody else could have placed there useless.
- **Restore from a link.** `https`, `sftp` or `ftp`: the host downloads the archive itself, resumably, with no size limit and nothing crossing the operator's connection. The address is validated here, not there — allowed scheme, every resolved address public, no redirects followed — and pinned into the download so the name cannot answer differently by the time the host dials it. Credentials are split off the URL, stored encrypted apart from the job payload, and delivered as a `netrc` file rather than a command line `ps` would show.

### Fixed

- **The proxy ranges reached a host that has no proxy in front of it.** The SaaS policy treated every host the platform operates as one the CDN answers for. That is true of the panel host and false of the hosts serving tenants, whose DNS records are created unproxied on purpose — a fact this repository's own host-protection plan measured in August and this one's changelog stated in the same release that shipped `ipStrategy`. The policy now turns on the host's own flag.

## [1.0.106] — 2026-09-03

### Added

- **A disruptive action warns before it runs.** `push_trusted_proxies` ends by restarting Traefik, and on the host that serves the panel that takes the panel's own requests and its bus connection down for a few seconds — so the operator's reward for pressing it was a "connection interrupted" error and no explanation. Job types can now carry a confirmation notice, which the host and instance action bars show before enqueueing anything; the one on this action says what is about to happen. The mechanism belongs to the job type so an extension can warn without touching the front end.

### Fixed

- **A pluggable action gave no sign it had been triggered.** `enqueue` only creates the job and hands it to the worker, so the acknowledgement was a row appearing in Recent Activity 300 ms later via the bus, at the bottom of the page, while the operator watched the button at the top. Pressing again looked like the only option — and on this action the second press lands exactly in the window where the proxy is restarting, which is how a job that succeeded came to look like a button that was broken twice over. The host bar now reports the queueing, refreshes the activity list eagerly rather than waiting for a bus event it is about to lose, and refuses a second press while the first is in flight. The instance bar had the guard and the eager refresh already; only the host was missing them.
- **The extension actions were unlabelled icons.** Every other button in those bars carries its name, so a shield with no text next to a shield with text ("Re-trust Key") was unreadable — the operator could not find the action at all. They now render like their neighbours, with the icon, the name, and a spinner while the job is being queued.

## [1.0.105] — 2026-09-03

### Fixed

- **The panel rendered a blank page.** Two methods added to the host form and the settings screen were written with a trailing comma, which separates entries in an object literal and is a syntax error between class methods. Odoo bundles this JavaScript at runtime rather than building it here, so nothing failed until the bundle was parsed in a browser: one console message, a white page, and everything upstream green — the boot test, the suite, the health check. CI now parses every front-end file as an ES module, which is the cheapest check that would have caught it and needs no toolchain. It was missing entirely: nothing in this repo looked at JavaScript before.

## [1.0.104] — 2026-09-03

### Added

- **The panel can protect its own webhook endpoint.** The allowlist walked a host's deployed instances, which for an installation that is not this platform means it protected the customers' instances — which do not serve the endpoint — and left unprotected the one thing that does: the panel itself, which is not a `cloud.instance` and so was invisible to anything looking for one. Four settings now describe it (host, hostname, backend URL, optional wildcard) and only the named host publishes the router. A layer that already knows the answer fills them in instead of making an operator type them, which is the difference between core being usable alone and core being a component of something else.
- **The host form shows the ranges actually applied, not just the override.** The box on the form is an override; on a host where a policy supplies the list, it is empty by design and said nothing about what was in force. It now sits above a read-only line naming the effective ranges and where they come from, and warns when the host's Traefik is still running the previous list. The direct-access note was reasoning about the box rather than the applied list, which is exactly backwards for the one control that can lock an origin out of its own visitors.
- **`push_trusted_proxies` is a button on the host.** Applying a proxy change otherwise needed a full setup run, which reinstalls tooling this has nothing to do with. The job also re-anchors the config-drift indicator, but only when the proxy fields are the sole difference — it ships two documents where a full setup ships five, so claiming more would hide a real pending change.

### Fixed

- **A mistyped range is refused instead of silently dropped.** The read path skips entries it cannot parse, which is right on a request path but meant a typo narrowed who we believe with nothing said about it — the same silent narrowing this whole mechanism exists to prevent. Both the host field and the settings field now reject the write, naming the entries at fault. The docstring claiming the UI already validated has been corrected; it never did.

## [1.0.103] — 2026-09-03

### Fixed

- **The webhook allowlist no longer publishes against a posture the host is not running.** Two daily crons decide this between them — one learns the CDN's ranges, the other publishes the allowlist — and nothing ordered them. Whichever ran first won, and one of the two orderings is broken: an allowlist published before the host has been told about the CDN compares against the connecting address, which behind a CDN is always an edge and never GitHub, so it refuses every delivery. Silently, which is the whole reason this control needed a silence alarm in the first place. A host now records the proxy ranges its Traefik was actually given, and the allowlist is held back whenever that differs from what the panel intends — which also closes the narrower race where the ranges are known but the proxy has not restarted with them yet.

## [1.0.102] — 2026-09-02

### Added

- **Hosts can declare the proxies in front of them, and core acts on it.** A host now carries `trusted_proxy_ranges`, and a full setup renders them into `entryPoints.forwardedHeaders.trustedIPs` on both entrypoints. That one setting is what separates an `X-Forwarded-For` a client wrote from one our own edge appended: Traefik discards the header on every connection that is not from a declared range. Everything that keys on client identity rests on it — measured against Traefik v2.11, an allowlist reading the forwarded chain without it matches nothing and rejects 100% of traffic. Empty by default, which leaves a host behaving exactly as before.
- **The per-source rate limit keys on the visitor, not the edge.** With trusted ranges declared, `ratelimit` gains `sourceCriterion.ipStrategy.depth: 1`, so a CDN edge stops being one bucket shared by everyone behind it. Deliberately not applied without them: measured, a forwarded-chain strategy on a host that answers its visitors directly reads an absent header and Traefik keys every visitor under the same empty value — one bucket for the whole internet, worse than the address-keyed limit it replaced.
- **`block_direct_access` — refuse traffic that skipped the edge.** Prepends an allowlist middleware to the https entrypoint chain, so a request that did not arrive through a trusted proxy is refused before HSTS, rate-limit accounting or a backend lookup. Off by default, and ignored while no trusted range is set, where it would lock out every visitor the host has. The http entrypoint is left alone: it only redirects, and a redirect leaks nothing.
- **`push_trusted_proxies` — apply that without a full setup run.** `trustedIPs` is static configuration: Traefik reads it once at start-up, so a change needs the proxy restarted rather than a file drop. The job ships both documents together because they are interlocked — a host whose entrypoint names a middleware its file provider does not define answers 500 on every router it serves.
- **`push_github_webhook_edge` and the routes it publishes.** A Traefik router per hostname of every deployed instance on the host, restricting the webhook path to GitHub's published source ranges. Verifying an HMAC signature means hashing the whole body, so inside the endpoint a forged signature can only be bounded, never made free; refused at the edge it costs nothing. The allowlist reads the forwarded chain on a host that declared a trusted proxy and the connecting address on one that did not, because an unproven forwarded header is written by whoever is calling. Removal runs first and always: a stale allowlist rejects deliveries silently, while no allowlist merely leaves them unfiltered.
- **`client_ip()` — one answer to "who is asking", used by every limit.** Odoo's `--proxy-mode` applies `ProxyFix(x_for=1)`, which takes the last entry of the forwarded chain. That is correct with one proxy in front and wrong with two, and a host behind a CDN always has two: the CDN, and the reverse proxy on the host. Confirmed against the shipped werkzeug 3.0.1 — a chain of `<client>, <edge>` resolves to the edge. The helper walks the chain from the right, discarding hops inside the declared ranges, and returns the connecting address when none are declared.

### Changed

- **The webhook allowlist moved from the SaaS layer into core.** It is a capability of any installation that receives GitHub deliveries, not a property of this platform, so core owns the ranges, the refresh and the executor, and the SaaS layer keeps only the policy: which of *our* hosts get it and what sits in front of them. The migration re-points the external identifiers rather than letting core insert a second `cloud.job.type` with a code the SaaS copy already holds — the unique index would have refused it, and core updates first.
- **The refresh republishes a host whose routes moved, not only one whose ranges did.** Each host's rendered document is compared against a digest of what it last received, so a host that gained or lost an instance is republished on the next daily run.

## [1.0.101] — 2026-09-02

### Added

- **An alert for GitHub webhook deliveries going quiet.** The webhook endpoint is about to sit behind a source-address allowlist at the edge, and that allowlist has a failure mode nothing else in the system can see: a range GitHub adds and we never mirror stops deliveries with no error anywhere — pushes simply stop triggering rebuilds. An hourly cron now raises `github_webhook_silent` when no delivery has been recorded for `github_webhook_silence_hours` (default 48) while a GitHub App is configured, and resolves it as soon as traffic returns. Silence is measured against the newest event of any kind, so a run of processing failures still counts as "the edge is letting GitHub through" — those have their own alert. An install that never wired GitHub up stays quiet, matching `resolve_webhook_secret`, which returns before hashing anything when no App exists.
- **`github/meta.py` — the published webhook source ranges, read defensively.** `fetch_hook_ranges()` reads the `hooks` key of `api.github.com/meta` through the existing no-redirect opener, bounded to 1 MiB, and refuses the whole document unless every entry parses as a network and the list is a plausible length. Half-understanding that document would mean building an allowlist that silently drops deliveries, so partial trust is not an option: it either fully parses or it raises.

## [1.0.100] — 2026-09-01

### Fixed

- **The GitHub project import let any authorised user pin the workers indefinitely.** `/cloud/import_project` and `/cloud/fetch_odoojs_submodules` cloned the remote repository — plus every submodule — into a temporary directory and then ran `git show` over it, synchronously, inside the HTTP request. There was no per-user quota, no global concurrency limit and no ceiling on how much the operation could download or how long it could take, so anyone able to create a project could occupy every worker with repeated imports of a large repository. The import no longer runs Git at all: it reads trees and blobs through the GitHub API under a shared budget of 250 requests, 32 MiB and 120 seconds, with explicit ceilings on tree entries, repositories, submodules, `conf.d` files, domains, manifests and YAML nodes/depth. Manifests get their own 128 KiB cap and their AST is bounded to 10.000 nodes and depth 50 before `literal_eval`, because `ast.parse` cannot be interrupted once started. The deadline is re-checked around every HTTP call, during YAML walking and between ORM writes; a savepoint drops any partially created project if it expires mid-creation.
- **The App and PAT tokens travelled in the process command line.** Authenticating a clone means embedding the credential in the remote URL, which leaves it in `argv`, in `origin` and potentially in error output. Now both credentials only ever appear in an `Authorization` header, and no authenticated remote is created.

### Added

- **Configurable hourly quotas for the two GitHub operations.** `cloud.settings` gains `rate_limit_github_previews_per_hour` (default 10) and `rate_limit_github_imports_per_hour` (default 5), both editable from the Rates tab and validated as positive. Preview and import share a single non-blocking global advisory lock so only one costly GitHub operation runs per manager at a time; that limit stays fixed because raising it changes worker capacity directly. The quota hit is committed in a short independent cursor *after* the lock is granted, so an admitted attempt still counts even if the request later rolls back, and the row is never held during the remote access.
- **`try_advisory_xact_lock` in `models/_concurrency.py`.** A transaction-scoped, non-blocking advisory lock whose key is hashed together with the current database OID, since PostgreSQL advisory locks are cluster-global rather than database-local. Used here for the import lock and consumed by `incubacloud_website` to serialise Free signups per user.

## [1.0.99] — 2026-08-31

### Fixed

- **The preferences modal was an id-to-name oracle over every project on the platform.** `/cloud/save_user_preferences` sanitised the personal mute list with `cloud.project.sudo().browse(ids).exists()` — sudo skips ACLs *and* record rules, so any id that existed anywhere was accepted — and `/cloud/get_user_preferences` then read the list back and returned each project's `name`. Write anything, read the name. The docstring's reasoning ("muting only restricts the caller's own notifications, so no visibility check is needed beyond existence") holds for the *effect* of a mute and fails for what the read side hands back. Reach was every internal user: `/cloud` renders on `_is_internal()` alone with no cloud role required, and because the whole path went through sudo it worked even for someone with no `ir.model.access` on `cloud.project` at all. Both ends now go through `_filtered_access('read')`, which returns the permitted subset instead of raising, so an id beyond the caller's record rules is dropped silently and a caller with no cloud role still saves the rest of the form. The read side also stops reading the m2m off `env.user`, which is sudoed by construction (`Environment.user` returns `self(su=True)`) — the explicit `.sudo()` there had been a no-op sitting on top of an implicit one.
- **`_capped_search` counted with sudo what it listed without it.** `total` came from `Model.sudo().search_count(dom)` while `records` came from a plain `search`, so `/cloud/get_projects` — which has no role gate — told a stakeholder scoped by `rule_project_member` to a single project how many projects exist on the whole platform, and computed `truncated` from that same number, firing the truncation banner on a list that was never clipped. The count now honours record rules, matching `cloud_get_config` and `cloud_get_dashboard`, which already did the same counts correctly a few dozen lines away. No behaviour change for the other three call sites: the backup-backend routes are manager-gated and `cloud.host` carries no `ir.rule`.

Metadata disclosure only — no record, credential or job was ever reachable through either path. Audit point BUG-004; its third bullet (the portal's global tenant count) died with the portal team pages in `incubacloud_website` 19.0.1.24.0.

---

## [1.0.98] — 2026-08-30

### Fixed

- **The uniqueness of a metric rule's code never existed.** `cloud.metric.rule` declared it as `_sql_constraints`, an attribute Odoo 19 does not read: `_add_sql_constraints` applies `_table_objects`, which only `models.Constraint`/`models.Index` descriptors populate. Nothing failed and nothing warned, and the database agreed — no unique index on `code` in any environment. It matters because `code` is the alert's dedup key, as the field's own help says: `_cron_evaluate` raises and resolves through `raise_alert(rule.code, ...)` / `resolve_alert(rule.code, ...)`, and `cloud.alert` dedups on `(code, host, instance)`. Two active rules on one code therefore share a single alert row, and on every cron pass the rule that is not breaching resolves the alert the breaching one just raised — a genuine alert that switches itself off

### Changed

- The rule-code uniqueness is now a partial unique index over **active** rules. Only active rules are evaluated, so only among them can two rules fight over an alert; a plain `UNIQUE (code)` would also reserve an archived rule's code for ever, which nobody asked for. Same shape as `cloud_alert_active_target_uidx`
- Migration `1.0.98` **archives** — never deletes — any active rule whose code another active rule already holds, keeping the one that carries an xmlid (or the oldest). The rows are operator configuration: they stay visible and reversible, and re-enabling one without fixing its code now hits the constraint and is told why. Our own databases are clean (devel and production: 6 rules, 6 codes); the migration is there for the tenant databases that cannot be surveyed from here

## [1.0.97] — 2026-08-30

### Fixed

- **A hostname could stop a host setup halfway through, with no attacker involved.** `_build_inverseproxy` splices `wildcard_domain` into the Traefik router rule through the *replacement* argument of `re.sub`, where Python interprets backslashes: a domain carrying `\1` spliced in a capture group and one carrying `\d` raised `re.error: bad escape`, killing `full_setup` mid-run. A backtick closed the rule early and turned the dashboard router into a catch-all. Both substitutions now pass a function, whose return value is used verbatim
- **`cloud.host.wildcard_domain` was `required=True` and nothing else** — no shape, no length, no character set — even though the value is read back by everything the platform generates for that machine. A constraint now refuses anything that is not an RFC 1123 hostname. Shape only, deliberately: that table also holds hosts an operator named, where `h.local` on an internal network is a fair name. Comparison is case-insensitive and the stored value is never rewritten, so the production row recorded as `Tenants1.incubacloud.io` stays writable and nobody's typing is silently canonicalised

### Changed

- Wildcard-domain rules move to `incubacloud/net/hostname.py` and are now the single source for every door that accepts one. The internal-address blocklist and the platform-reserved list are opt-in flags there, applied only where the value means "a public DNS name a tenant chose"

## [1.0.96] — 2026-08-30

### Fixed

- **A test could leave the process decrypting with the wrong key.** `test_password_utils` swaps `INCUBACLOUD_SECRET_KEY` for a throwaway one inside `patch.dict`, which restores the environment variable on exit but not the Fernet cached in the module global. Every later reader in that process then decrypted real ciphertext with a key that never wrote it, and the symptom — a CRITICAL naming a production row as unreadable — points at data corruption that is not there. The cached instance is now cleared after each of those tests, so the next reader re-initialises from the real environment; a test exercises the guarantee through `doCleanups` rather than assuming it

## [1.0.95] — 2026-08-30

### Fixed

- **One broken thing produced one alert per attempt.** `job_failed` alerts were created outright, skipping the dedup rule every other producer goes through, so a cron job that kept failing stacked a row *and* a mail/Telegram/webhook per attempt — fourteen identical criticals in six and a half hours on 2026-08-24, burying everything else in the panel. A repeat now refreshes the open alert and counts on it (`occurrences`), keyed by job type and target through a domain shared with the dismissal path so raising and clearing cannot drift apart. Failures of *different* job types on one host stay separate incidents
- **The same alert could be filed twice.** `raise_alert` searched and then created, and Odoo cursors are REPEATABLE READ: two producers firing together each read a snapshot without the other's row and both inserted — the host-metrics and instance-health probes did exactly that 142 ms apart on 2026-08-29. A partial unique index on `(code, host, instance) WHERE state='active'` now decides it, since a lock cannot: under snapshot isolation the loser still cannot see the winner's row. Losing that race is treated as success, inside a savepoint, so the job that lost it does not roll back over an alert that already exists
- The health probe's `_inst_alert`/`_resolve_inst_alert` were a second copy of that rule and the one that had drifted; both now delegate to the model. Resolutions of instance-scoped alerts consequently reach Telegram and webhooks too, which the hand-rolled dismissal never did
- **`instance_unresponsive` fired on instances that were merely starting, and outlived the container.** A running container whose Odoo is not listening yet is what every boot looks like from outside (`curl` exits 7 or 56), and Free tenants boot several times a day. It now needs the same two consecutive failures CPU and memory already required. It is also resolved on every branch where the container is not running — asleep, down, missing or skipped — because a stopped container cannot be failing to answer: an alert raised just before a tenant went back to sleep used to stay critical for as long as the tenant slept, measured at ten hours and forty minutes
- **`host_unreachable` fired on jobs that then succeeded.** `execute` judged from the retry counter which attempt was the last and alerted there, but the runner can hand a job one more attempt than the budget — so every such alert on 2026-08-29 was followed by the same job connecting and finishing `done`. Deciding when to stop retrying is now queue_job's alone; the alert hangs off the terminal state, where "it gave up" is a fact
- **A lost row race became a failed job and an alert.** The SSH probe stamps `last_health_check` on `cloud_instance` while the metrics cron stamps `metrics_last_seen` on the same rows, and under snapshot isolation the second one was aborted outright even though the columns are disjoint. Both writers now run on their own READ COMMITTED cursor — the liveness cron's stamp, and the private cursor every executor's `on_success`/`on_failure` already used — so the loser waits for the row instead of losing it. The same hazard could have failed a deploy *after* it had succeeded, if the cron stamped the row while the deploy's outcome hook was open. Retrying would not have been enough: PostgreSQL's error reaches Odoo's SQL layer, which logs `bad query` at ERROR before any Python can catch it, and the tenant log scraper reported those lines straight back as an `instance_error_logs` alert. Serialisation failures that still escape are handed to queue_job, which already retries them, instead of being wrapped as permanent failures

### Changed

- Connection-retry budget for the monitoring probes raised from 3 attempts to 10 (~90 s to ~10 min). Three was shorter than the routine maintenance of the hosts being probed: `unattended-upgrades` reboots them inside its 04:00 window, which took Tenants1 out for two minutes, and a network blip on the same day took it out for four — both paged. A host that is genuinely gone is still critical ten minutes later, and `metrics_host_absent` covers the same ground meanwhile
- `docs/architecture.md` documents the 04:00 UTC host maintenance window and how the monitoring is sized around it

## [1.0.94] — 2026-08-28

### Fixed

- **A purge of an archived copy could delete a live instance's backups.** A backup prefix is derived from the instance name, so a new instance taking that name inherits the prefix — and the purge emptied everything under it. On the happy path the window was narrow, but the dangerous case was the retry: a purge that failed today and ran again next month would find a live instance in that prefix and empty it in silence, reporting success. The purge now carries `PURGE_BEFORE`, the instant the deletion was decided, and deletes only objects older than it. Whatever the successor writes is newer, so the purge is safe to land at any later time
- The cutoff is stamped once, on the first `delete_archived`, and reused by every retry — taking "now" on a retry would reproduce exactly the bug it prevents. It is cleared when an instance is revived, because a deletion that was decided and then reverted must not bound a future purge: that one would predate the chain written since, delete nothing, and still report success
- An unparseable `PURGE_BEFORE` is refused rather than ignored. Falling back to the unconditional purge is the one outcome the cutoff exists to prevent, so a bad value must never mean "carry on"

## [1.0.93] — 2026-08-27

### Added

- **"Keep in panel" now means archived, not abandoned.** It takes a fresh full backup at that moment and prunes everything older, so exactly one restorable copy survives instead of a chain nobody maintains — the retention prune ran inside the very container the teardown removes, so what used to be left behind aged forever. The copy's location is frozen onto the record (`custom_backup_dst`) because the computed path is derived from the project and the name, either of which can move afterwards: a tenant deletion detaches the project and the computed path silently falls back to a shared `.../default/` prefix. Everything that touches the copy from then on — verification, revival, deletion — reads the frozen value
- **An Archived tab on the project, with what each copy costs.** It appears only when the project has archived instances, and shows for each one where its copy is, how big it was at the last check and how long ago that check happened. The state comes from a nightly cron and never from the render: listing a bucket prefix per row would put a network call behind every page view, so the panel reports what it last saw and says how old that reading is rather than presenting a week-old check as current
- **Reviving an archived instance.** It deploys again on any host — the original may be gone, full, or have been the reason for archiving — and restores the frozen copy into it. The copy is re-checked live at that moment, not read from the cron's stamp: a deploy that succeeds followed by a restore that finds nothing leaves an empty instance where the operator expected their data
- **Deleting an archived instance takes its chain with it**, through a container created for that one command and thrown away. Reviving in order to delete would be a full deploy — domains, Traefik, minutes of host resources — with all of its own failure modes, to destroy something. The record is unlinked only once the prefix is verified empty, so an interruption leaves a record whose chain is gone (deletable again) rather than a chain with no record, which nothing could ever find. It asks for the instance name in writing, and refuses outright when there is no host left to run the container on
- **A daily check that an archived copy is still there.** "The backend answers" is not "the copy is there": a provider lifecycle rule or a manual delete empties the prefix while the credentials and the bucket stay perfectly healthy, and every reachability check still passes. `unreachable` is kept apart from `missing` on purpose — one is waited out, the other means the data is gone — so a network blip never raises a false alarm about data loss. A copy that is really gone raises a critical alert immediately, rather than being discovered when someone presses revive

### Changed

- **Where an archived copy lives is manager-only.** The frozen destination and the backend's name are the same bucket metadata every other endpoint has been gated on since SEC-009, and in SaaS that storage is ours rather than the tenant's. Everyone who can see the project still sees that a copy exists, how big it is and when it was last verified — none of which says where it is
- **An archived instance's name stays reserved in its project.** Creating a new instance with that name is refused with a message that names the archived one — otherwise the new instance would compute the same backup path and write into the copy the archived record was keeping
- The purge program that empties a prefix now lives in one place (`scripts/lib/purge_prefix.sh`), shared by the deletion purge and the archived purge. Two copies would have been two chances to fix a bug in one and not the other, and the drift would only ever show up as objects surviving a deletion

## [1.0.92] — 2026-08-27

### Changed

- **Deleting an instance now clears its backups first, or does not happen.** Nothing pruned them afterwards — the retention job runs inside the very container the teardown destroys — so every completely-deleted instance left a chain behind that no instance owned, and on a managed destination it kept consuming a quota the customer cannot reach from the panel. `Delete completely` now empties the instance's prefix before the containers come down, through the instance's own `backup` container: the only thing that holds the credentials, the endpoint and the destination, and the only moment anything can still reach the storage
- **If the purge fails the instance is not deleted.** Tearing down first would strand the objects with nothing left able to delete them, so the step carries `stop_on_failure` and there is deliberately no "delete anyway". The failure raises an alert that names its own fix — `backup_purge_service_missing`, `backup_purge_unauthorized` or `backup_purge_failed` — classified from the script's exit code, never by matching duplicity's or boto's wording, which would silently downgrade every diagnosis to the catch-all the day either changes phrasing. An already-empty prefix answers 10 and is not a failure: the invariant already holds
- **`Delete completely` asks for the instance name.** It is now irreversible in a way it was not, and the expensive mistake it guards against is deleting the wrong instance, not deleting by accident — so it asks for the name rather than a fixed word, matched exactly, with the name deliberately not selectable inside the dialog
- The purge is gated on `_owns_instance_lifecycle`, so the two move cleanups that reuse these teardown commands against a host the instance has left never reach it — their instance is alive elsewhere and those backups are still its own. Free tenants are excluded by `_backup_enabled()`, the same gate that decides whether the container is deployed at all, with no branch naming them

## [1.0.91] — 2026-08-27

### Fixed

- **A completed instance deletion reported as failed.** Observed in production: the teardown removed the containers, images, volumes, logrotate config and directory, logged `✓ Instance 'prod' removed from host`, and then raised `AttributeError: 'DeleteInstanceExecutor' object has no attribute '_host'`. `_host()` was a convention — six host-scoped executors each define it as `return self.job.host_id` — that `AbstractSSHExecutor` never provided, and two instance-scoped callers assumed. It is now defined once on the base class
- **Every successful move between hosts ended with its cleanup job failed.** `MoveCleanupSourceExecutor.on_success` made the same call, but unconditionally rather than on a rare path, so the last step of a working move always raised. Besides the false failure, the source host's observability labels were never refreshed and kept advertising an instance that had left it
- Both success handlers now have tests. Neither had any: the suite referenced `move_cleanup_source` only as a job-type string in the gate and chain tests, so no `on_success` in either executor was ever executed and the `AttributeError` sat there undetected

## [1.0.90] — 2026-08-27

### Fixed

- **A backup uploaded from the browser could never reach the host it was meant to restore.** The upload is served by `odoo` and consumed by `odoo_runner`, and since the job runner was split out those are separate containers sharing exactly one mount — the data directory. The archive was staged in `/tmp`, which is private to each, so the path handed across in the job payload named a file the executor could not open. It answered *"Backup file not found on Odoo server. Please re-upload and try again."* — advice that reproduces the same failure forever. Uploads now stage under the data dir, which both halves can reach; a test pins that the writer and the validator agree on that location
- **Every one of those attempts also stranded up to 2 GiB.** The only `unlink` for a staged archive lives in the executor, so it ran in the container that could not see the file. Even within one container the deletion sat after the SFTP transfer with no `try/finally`, so any failed transfer — host down, disk full, connection dropped — left the archive behind. Both restore paths that stage locally (`browser` and `from_job`) now release the file in a `finally`, and a daily cron sweeps uploads whose job never ran at all, which no `finally` can cover
- **The terminal GC cron was deciding liveness from PIDs belonging to another container.** `os.kill(pid, 0)` is meaningful only where the process was spawned; terminals come from `odoo`, crons run in `odoo_runner`. An unrelated live process there answers "alive" for a dead route, and a working terminal looks dead because its PID does not exist — and since both containers start their processes in the same low range, collisions are the common case. The cron now reaps by `last_seen`, refreshed by the controller that does own the PID; the inline check on the web side is unchanged. Affects `cloud.terminal.route` and `cloud.host.terminal.route`

## [1.0.89] — 2026-08-26

### Fixed

- **The GitHub webhook let an unsigned request cost more than it should.** The endpoint is public, POST and CSRF-exempt because GitHub cannot authenticate any other way — trust comes from an HMAC over the body — and deciding a signature is false *requires* hashing the whole body, so a forged-signature flood always costs something. What was wrong was how much. Odoo's default cap is 128 MiB while GitHub itself never sends more than 25 MB, so the endpoint accepted five times any legitimate delivery; measured, that is 147 ms of CPU per request spent on HMAC alone before the signature can be known to be false. The route now declares `max_content_length` of 32 MiB, which werkzeug enforces from `Content-Length` — an oversized delivery is answered 413 without a byte being read
- **The body was read before anything decided from the headers.** A request missing the mandatory `X-GitHub-Delivery` still paid for a full read before being told it was malformed. Header checks now come first, and a `X-Hub-Signature-256` that is not shaped like one (`sha256=` plus 64 hex) is refused without reading the body. That is not the trust boundary — the HMAC still is — just the cheapest possible refusal
- The cap is declared per route on purpose, and a test pins the restore upload's 2 GiB next door: a global limit, or a `maxRequestBodyBytes` on the Traefik `buffering` middleware (which hangs off the router for the whole host), would have broken file-upload restores

---

## [1.0.88] — 2026-08-26

### Fixed

- **Deleting a backup backend only looked at one of the three ways an instance reaches it.** An instance resolves its destination as `instance.backup_backend_id or project.backup_backend_id or <global default>`, but the guard searched only for direct assignments — so a backend used as a project default, or as the **global default inherited by the entire fleet**, could be deleted without a single warning. That search also ran with the default `active_test`, which hides archived instances: exactly the records whose backup chains are still sitting in the bucket. The guard now asks `_deletion_blockers()`, which reports all three routes at once and counts archived instances, and the refusal names what it is protecting — marking archived ones as such — instead of only saying no
- The refusal no longer implies the backups themselves are at stake. Deleting the backend record never removes an object from the bucket; it removes the panel's only pointer to them, and the message now says exactly that

### Changed

- **A destructive confirmation dialog opens with Cancel focused, not Confirm.** `IcConfirmDialog` focused the confirm button on mount for muscle memory, which meant an Enter pressed before the dialog had been read confirmed the delete. `isDanger` dialogs now open on Cancel; ordinary confirmations keep Confirm, so the common flow stays one keypress and the extra Tab is spent only where it buys something
- **The "Remove instance" dialog says what it actually does.** It read "Containers will be stopped and the directory deleted" — true, and misleading by omission: the teardown runs `docker compose down -v`, so **both** options destroy the database and the filestore and they differ only in whether the record survives. Each option now carries its own line — "Keep in panel" preserves repos, dependencies, domains and resource limits as a redeployable draft that comes back empty; "Delete completely" also removes the record and its configuration — and the dialog states what becomes of the backups: kept, but no longer maintained, because the retention prune runs inside the very backup container the teardown destroys. An instance with no backup destination is told that nothing here is recoverable

---

## [1.0.87] — 2026-08-24

### Fixed

- **The metrics account sync verified itself with a password it was never given.** `MetricsAclSyncExecutor` overrides `get_extra_vars` without calling `super()` — deliberately, because the parent announces "Deploying the metrics central", which a sync must not claim — and the one thing that fell out of the child's dict was `ic_operator_plain`. The playbook's boundary probe then authenticated as `operator` with no password at all, vmauth answered **401**, and the job failed *after* having already written and reloaded the access-control list. Two consequences, both silent: `on_success` never ran, so the granted list was never recorded, so the cron saw drift forever and re-enqueued every 30 minutes; and the play died before provisioning the new account's Grafana organisation and rewriting `orgMapping`, leaving that tenant's user landing in the default organisation. The sync only runs when there is an account to grant, so the bug shipped on 14 Aug and lay dormant until the next customer signed up
- `tasks/vmauth_acl_apply.yml` no longer defaults the operator password to `omit`. That hedge is what turned a missing variable into a 401 indistinguishable from the frontier itself having broken; undefined now fails as undefined
- A structural test walks each observability playbook (following `include_tasks`), collects every `ic_*` name it reads and never defines, and asserts the executor's own `get_extra_vars` supplies it — so an override that drops a variable fails in CI rather than at a customer's gateway

- **A rebuild could fail because Odoo was writing its own log.** `instance_logs.sh` puts `logs/` *inside* the copier project directory, which is a git repository, and nothing excluded it. `rebuild.sh commit-dirty` staged and committed the live `odoo.log` — ~20k-line diffs, on every rebuild of every instance — but Odoo kept writing, so the tree went dirty again in the sub-second before `copier update` looked, and copier refuses to run on a dirty tree. The rebuild then ran its 26 remaining steps to completion and failed at the very end on the deferred error, leaving the instance rebuilt, restarted and healthy but flagged "Changes not deployed" and skipping the template update. Only the instance with live traffic hit it; its idle sibling, rebuilt in the same second, did not
- `ic_git_exclude_logs` (new, in `scripts/lib/common.sh`) writes `/logs/` to `.git/info/exclude` and untracks whatever earlier rebuilds committed, leaving every file on disk. It runs from `commit-dirty` **before** staging, so it takes effect in the same rebuild rather than the next one, and from `instance_logs.sh install`, so a freshly deployed instance is born clean. `.git/info/exclude` and not `.gitignore` because copier owns the latter, and editing it would provoke the very template conflict this avoids

---

## [1.0.86] — 2026-08-23

### Security

- **The role gates protected the buttons, not the actions.** `cloud.job.enqueue` and `enqueue_chain` are public model methods: any internal user with create access on `cloud.job` can call them over JSON-RPC, and the panel itself calls them directly for several actions. The capability checks that decide who may deploy, back up or delete lived in the HTTP controllers and in the SPA, so a direct call skipped them. The only server-side check covered ten host-level job types; everything else was open to whoever could reach the model
- Enqueueing is now authorised per job type against a minimum role, server-side, in `_check_job_type_allowed`: lifecycle and deploy jobs need Consultant; backups, restores and exports need Developer; host-level, observability and host-move jobs need Administrator. The gate covers every dispatch path — `enqueue`, `enqueue_chain`, **`retry_job` and `unblock_and_enqueue`** (a retry runs under the *retrying* user, so without it a Consultant could relaunch a failed higher-role job of their project). The map is **fail-closed** — an unmapped code demands Administrator — and a structural test forces every declared job type to be listed, so a new one cannot ship ungated by omission
- This closes real escalations, not hypothetical ones. A Developer could enqueue `move_cutover` (which rewrites an instance's host with no further check) or `move_cleanup_source` (which runs the delete teardown — `compose down` plus `rm -rf` — on a host and never reaches the guarded `unlink`), and could start the remote teardown of a **production** instance: the manager check lived in `unlink()`, which runs *after* the instance is already gone from the host. Deleting a production instance is now refused at enqueue, before any command is sent
- **Executors are trusted readers of the host connection material.** Jobs run under the environment of whoever enqueued them, while the SSH endpoint and credential are field-gated to Developer — so a Consultant-triggered deploy or rebuild failed with an access error inside the worker, and had done since those gates were introduced. The executor now reads the host record elevated when it opens the connection (constructor, transport, Ansible inventory), which is what the original hardening intended; everything else keeps the caller's environment, so ORM guards and audit attribution are unchanged. The elevation stays out of `ssh_connect_kwargs()`, which is public and returns the password

### Removed

- Dead job types `pause_instance` and `clone_data`: no executor, no caller, no jobs ever recorded. The `clone_to_staging` **feature** is untouched — it chains deploy, download and restore, and never used the `clone_data` type
- The `delete_project` executor, orphaned since project deletion stopped queueing remote cleanup. Its job type record stays: historical jobs still reference it

---

## [1.0.85] — 2026-08-23

### Security

- **ACLs granted read to the lowest cloud role without any record rule to scope it (SEC-009).** Every role inherits the Stakeholder (`group_cloud_user`) read grant, so a model whose only rule targeted a higher group left the low roles with unrestricted read: a stakeholder or consultant could `search([])` over the whole system by raw RPC and read infrastructure they were never meant to see — host SSH endpoints, backup-backend buckets/endpoints, GitHub webhook payloads (pusher identities, commit messages, contributor emails), and — on the SaaS side — VPS requests/reservations (provider VM and firewall IDs) and backup reservations. Latent today (only Administrators exist) but the lower roles are part of the product
- `cloud.github.event` and `cloud.host.whitelist` lose the Stakeholder read ACL — both are now Administrator-only, closing the raw-RPC leak. The former's record rule only named the Project-Manager group, so it never restricted the lower roles it was written to protect; it is removed as dead
- `cloud.instance.pending.push` keeps the ACL (its "pending pushes" panel is legitimately read by a project member) but gains a member-scoped record rule + a PM+ all rule, mirroring the other instance-child models: a stakeholder now sees pending pushes only for instances of projects they belong to, not every project's commit metadata
- The host SSH endpoint (`ip_address`, `user`, `port`) is now field-gated at the ORM layer to **Developer** — the same gate the host credential (`password`/`key_file`) already carries, and the lowest role that opens SSH jobs: jobs run under the user who enqueued them, so a stricter gate would have failed every Developer-triggered deploy/rebuild/backup inside the executor. Roles below Developer get neither the endpoint nor the credential, by raw RPC or otherwise. `allowed_ssh_ips` (hardening configuration) and the backup-backend `s3_access_key_id` are gated to Administrator, like the S3 secret already was. The instance serializers (`get_instance`, `get_project_full`, `get_host_instances`, `get_project_instances`) redact the SSH endpoint below Developer (so a Developer's restore dialog still builds a working rsync command) and the bucket path below Administrator, as `get_hosts` already did
- The backup-backend list endpoint (`/cloud/get_backup_backends`) was the one backend route missing its capability gate; it now checks `manage_settings` like all its siblings

---

## [1.0.84] — 2026-08-23

### Added

- **The nftables connection-rate cap is now settable per host.** A new `http_conn_rate` field on the host (default 0 = off) is handed to the hardening playbook as `ic_http_conn_rate`, so the forward-hook meter added in 1.0.83 can be turned on for a single host from the panel (Host → Settings) and pushed with the next hardening run. It stays off until a real value is set; enable it only after rehearsing the change on a throwaway VPS (RB-18), since an unrehearsed drop on that hook can break Docker's published ports. The SaaS hardening executor inherits the wiring unchanged

---

## [1.0.83] — 2026-08-22

### Security

- **Nothing throttled HTTP traffic to the instances.** Tenant domains resolve straight to their host, not through a CDN, so a login flood reached Odoo's pbkdf2 hasher directly — the same asymmetric CPU-DoS as SEC-008 on the panel, but against the tenant sites, and unbounded: a single source could saturate a host's workers
- Traefik now carries a per-source-IP `rateLimit` middleware, attached as a default of the `https` entrypoint so it reaches every copier-generated tenant router without editing a single generated compose file — the same mechanism the HSTS header already uses. Requests are throttled by client IP before they can reach a worker (default 300/min, burst 100 per IP: generous for a human, a wall for a flood)
- The threshold lives in the host's watched `config.yml`, so it is tunable live with no image rebuild. Existing hosts are retrofitted in place by `init_traefik_templates`: the middleware is added to the dynamic config and referenced on the entrypoint as an interlocked pair that fails closed, exactly like the HSTS retrofit — a reference to a middleware the file provider does not define would 500 the whole host, so the reference is only written once the middleware is, and only onto the entrypoint chain this project manages (the one HSTS marks), never an operator's own
- Direct traffic only by design: `sourceCriterion` defaults to the real remote IP, correct when a host is reached directly. A host placed behind a trusted CDN (the panel behind Cloudflare, or a tenant fronting their own domain) must set `sourceCriterion.ipStrategy` so the limit keys on the real client and not a handful of edge IPs
- **Defence in depth at the host layer**: the hardening ruleset gained an optional per-source new-connection cap on 80/443, on the nftables **forward** hook — the path tenant traffic actually takes, since it is DNAT'd to the Traefik container and never crosses the input chain. It ships **off** (`ic_http_conn_rate` unset renders the current byte-for-byte ruleset) and is enabled per host only after a throwaway-VPS rehearsal: an unrehearsed drop on that hook is what took the fleet down on 2026-08-14. Both rendered states validate under `nft -c`, keep balanced braces and never use `flush ruleset`
- The layered model — provider L3/L4 anti-DDoS (assumed, e.g. Hetzner/OVH), host conn-rate, Traefik per-IP, app counters — is documented in `docs/architecture.md`, and the ops actions (tuning the Traefik limit live, the behind-CDN `ipStrategy`, rehearsing and enabling the nftables cap, the provider-without-anti-DDoS gap) in the new runbook RB-18

---

## [1.0.82] — 2026-08-22

### Security

- **The GitHub App's RSA private key was stored in clear**, in the same row whose `webhook_secret` was already encrypted — the `EncryptedChar` import sat four lines above the plaintext field. Verified against production: 1675 bytes of PEM readable with a plain `SELECT`. Anyone with a database dump, a filesystem backup or read access to the table could sign App JWTs and act as the installed App
- The key is now an `EncryptedText` field, encrypted at rest with the same Fernet chain as every other secret. A post-migrate encrypts the existing row and is idempotent, so re-running it is harmless
- **`EncryptedChar` and the new `EncryptedText` share one implementation** (`EncryptedFieldMixin`). A PEM is multi-line, so it needs a `text` column, but a separate class would have escaped `_rotate_all_secrets` — which discovers what to rotate by `isinstance` — leaving ciphertext that key rotation silently skips. Rotation now tests for the shared mixin, so any future shape is picked up automatically
- The GitHub settings panel reports `has_private_key` through `_has_encrypted` instead of a bare truthiness read, so a key the current `INCUBACLOUD_SECRET_KEY` cannot open no longer takes the whole settings screen down with it

---

## [1.0.81] — 2026-08-22

### Security

- **Notification webhooks are the one outbound URL a user chooses, and they were guarded by a `startswith('https://')` check at save time.** The senders then handed the URL to a bare `urllib.request.urlopen`, which follows redirects by default and permits the https → http downgrade, so a single 302 left the checked destination. Nothing ever looked at where the hostname resolved, and a check at save time says nothing about where the name points minutes later when the notification is sent
- Measured from the production manager container on 2026-08-22, with only a TCP connect and no request sent: `169.254.169.254:80` (cloud metadata), `127.0.0.1:8069` (its own Odoo) and `db:5432` (the internal Postgres) all answer. There is no egress filter behind the application check — the manager host has never been through the hardening playbook
- Outbound webhook delivery now goes through a single guarded client (`net/outbound.py`): https only, no credentials in the URL, port 443, and every address the hostname resolves to must be public — loopback, RFC1918, link-local (which is where the metadata service lives), reserved, multicast, CGNAT and their IPv6 equivalents including IPv4-mapped forms are refused, and a name answering with a mix of public and private addresses is refused whole
- **The socket is pinned to the address that passed validation.** Resolving, approving and then letting the stack resolve again is a TOCTOU, and DNS rebinding exists to exploit exactly that window; the hostname is kept for SNI, the `Host` header and certificate validation, so pinning does not weaken TLS
- Redirects are refused outright rather than re-validated, matching what this codebase already did for its GitHub calls. The response is read up to a bound and discarded, so the channel stays blind: no body, no status, no error detail that could turn a webhook into a probe of the internal network
- The three Telegram calls moved to the existing no-redirect opener. The host is fixed, but the URL carries a user-supplied bot token and the bare opener followed redirects
- **`/cloud/save_user_preferences` now refuses share users.** The route is `auth='user'` with no group check, so a portal customer could store a webhook URL; it stayed inert only because both senders filter `share = False` in other files. The SPA that owns the form is internal-only, so no legitimate caller is affected — what this removes is a trap that any future widening of the notification audience would have sprung
- Fixed-host GitHub calls were already using the no-redirect opener. The user-chosen destination — the only one that carries real risk — was the one left on the bare call

---

## [1.0.80] — 2026-08-20

### Fixed

- **The daily prune stopped deleting the warm pool's networks.** `docker system prune` also prunes networks, and a project's network is the one resource here that can be neither protected nor safely swept. Labelling it changes its definition, so `docker compose` recreates it and tears a live stack down mid-command — that was tried and it left tenants stopped. Leaving it unlabelled was justified by the claim that protecting the containers already protects the network, "because Docker keeps a network alive while any container, running or stopped, holds an endpoint on it". **That claim is false.** Stopping a container tears its sandbox down and releases the endpoint, so a stopped stack's network counts as unused and goes, however well its containers are labelled
- Measured in production on 2026-08-20: the prune deleted `ic-tenant-d51130c9_default` and `ic-tenant-85b154fe_default`, the networks of the only two warm spares in `ready` — the ones handed to the next customer who signs up. Their containers survived, so the post-prune check reported `✓ All managed stacks intact` while neither stack could start. It surfaced five hours later as a failed free-pool backup, on the one instance whose backup path has to wake the stack
- The failure is not obvious from the outside because compose *recreates* containers whose definition changed and merely *starts* the rest — and a started container keeps the network id it was created with. `db` is precisely such a container in both the claim and the backup flows, so the daemon answers `network <id> not found` and the whole `up` fails
- The play now runs `docker container prune`, `docker image prune` and `docker builder prune` instead of `docker system prune`. Networks occupy no disk, so never touching them reclaims exactly as much as before — the 12.86 GB of the run that caused this were images and build cache
- **The post-prune verification covers networks now.** It only ever inventoried containers, which is why it certified two broken stacks as intact. It checks `<project>_default` for every deployed instance, exempting those with an active job for the same reason the container check does: a rebuild's `compose down` legitimately takes the network with it
- The reclaimed-space line is a sum now. Three prunes print three totals, and reading the output backwards would have reported whatever the build cache freed and called it the total

---

## [1.0.79] — 2026-08-20

### Fixed

- **Two image builds on one host no longer collide.** Jobs serialise per *instance* — deliberately, so one tenant's deploy does not block another's — but every build on a host runs `docker compose build` against the same daemon, and upstream doodba's Dockerfile mounts the apt cache with a BuildKit id shared across the machine. Two builds reaching `apt-get install` together produce `Could not get lock /var/cache/apt/archives/lock` and one of them dies. Measured in production: the release rollout enqueued two rebuilds in the same second on the same host, one built for 456 s and the other failed 75 s in. `RebuildInstanceExecutor` now carries a per-host advisory lock, so at most one build runs per host and the loser is **deferred 30 s, not failed**
- The distinction matters more than the collision. A failed rebuild is what the rollout's guard reads as "this release is not safe to spread", so a single unlucky pair of builds latched the whole fleet — core and tenant module alike — until an operator re-ran the job by hand. A deferral costs thirty seconds and the rollout never notices
- The lock sits on `RebuildInstanceExecutor` because that is the only class in the codebase that issues `docker compose build`; every rebuild variant (manual, tenant, warm, apply-plan) subclasses it, so one placement covers all of them. It shares its namespace with the warm-pool lock that solved this for warm builds first — two lock families each holding their own would still collide — and `WarmHostLockMixin` is now an alias of it

---

## [1.0.78] — 2026-08-20

### Security

- **The session cookie now carries `Secure` and `SameSite=Lax`.** Odoo emits it with `HttpOnly` and nothing else, which left two ways for it to escape: a user who types the bare domain makes one cleartext request before the redirect to HTTPS, and that request carries the cookie; and the cookie travels on cross-site requests. `Secure` is added only when the request itself is secure (`X-Forwarded-Proto` under `proxy_mode`), so a development instance over plain HTTP is untouched and keeps working. `SameSite=Lax` is added only to `session_id` — the livechat and website visitor cookies may legitimately need cross-site delivery, and `Lax` is safe for the OIDC flows here because the authorization endpoint is reached by a top-level GET navigation. Both wrappers only ever tighten: a caller that already asked for a value keeps it
- **Traefik actually sends `Strict-Transport-Security` now.** It did not, anywhere — not on the panel and not on a single tenant. The `secure` middleware that carries the header is defined on every host, complete and correct, and referenced by no router: it hangs off the `doodba` chain, and the routers copier generates reference only their own per-project middlewares. Meanwhile the middleware that *is* applied to the panel set `forceSTSHeader` with `stsSeconds` at zero, and Traefik writes no header at all when the max-age is zero. Fixed in the only two places that reach everything: `stsSeconds` on the panel's own middleware, and a new minimal `hsts` middleware wired as the default middleware of the `https` entrypoint, which covers every router on a host — tenants, the catch-all, the metrics gateway — without editing a single generated compose file
- **`secure` is deliberately *not* what the entrypoint defaults to.** It sets `frameDeny`, which would blank out the panel's two Grafana iframes and break Odoo's own website editor, and `stsIncludeSubdomains`/`stsPreload`, which would make an expired tenant certificate unreachable with no click-through. The `hsts` middleware carries a one-year max-age and nothing else; the remaining headers are a separate decision, taken one at a time
- Both Traefik edits ship as idempotent retrofits on the stored per-host templates, in the same conservative style as the metrics and access-log ones: they add what is missing, they leave a hand-edited file alone, and they are a no-op on a shape they do not recognise. The two are **interlocked and fail closed**: the entrypoint reference is only written when the dynamic config actually defines the middleware, because a `hsts@file` that does not resolve is not a missing header — Traefik answers 500 on every router of that entrypoint, which is the whole host. The reverse order (a middleware nobody references) is harmless. `traefik_yml` is part of the config-drift snapshot, so touching it marks every host as needing a `full_setup` — which is accurate, because a static Traefik change only takes effect when the proxy restarts

---

## [1.0.77] — 2026-08-19

### Added

- **Odoo now writes its log to a file on the host, archived one file per day.** Docker keeps a container's output inside the container, and a rebuild recreates the container by design — so the log an operator wants three days after the fact had already been discarded, and the size cap added in 1.0.76 bounds that window further. Each instance gets `logs/odoo.log` bind-mounted from its own directory and a logrotate config on the host (`daily`, `dateext`, `delaycompress`, `nocreate`), which turns it into `odoo.log.<date>` and then `odoo.log.<date>.gz`, kept for `cloud.settings.odoo_log_archive_days` days (60 by default). The file outlives the container, so a rebuild no longer takes the history with it. Existing instances pick it up on their next rebuild
- **The flag rides on the compose `command`, not on `odoo.conf`.** The panel runs one-shot containers whose output has to keep reaching the job log — module installs and the `click-odoo-update` boot test — and `docker compose run` replaces the command, so those runs are untouched by construction; a `logfile` in the conf would have silently swallowed every one of them, including third-party tooling with no flag to opt out. The override replaces the whole command, so each environment's own arguments are reproduced with it: `prod.yaml` sets none (the image's CMD applies) and `test.yaml` pins `--workers=3 --max-cron-threads=1`, which staging would otherwise lose. A test asserts both, and RB-15 now says to re-check them when the template pin moves
- **The log viewer reads the archive**: a day picker, search executed on the host (a day of logs is megabytes and the answer is usually a handful of lines), and a download button that hands over a whole day gzipped. An instance not rebuilt yet keeps showing the container's output, so the viewer never goes blank during the transition. A plain day the host compressed after it was listed (a viewer left open over midnight) still opens and downloads from its `.gz` twin instead of coming back empty
- **The day picker filters as you type and can search every day at once.** Sixty days is not a dropdown: it is a list nobody can scan, and it only helps at all if you already know the date. The picker is the same type-to-filter widget the SPA uses for any set that grows (with ◀ ▶ to step day by day), and pressing Enter in the filter box sweeps the whole archive on the host — newest day first, bounded by a timeout — and marks the days that match with their hit counts, so "which day was it" is a question the panel answers instead of one the operator has to guess. The sweep emits a completion marker: one cut short by its timeout says so, because reporting it as "no matches" would be a lie in exactly the moment someone is hunting an incident
- **`instance_logs_unhealthy`** — the archive's two silent failures now have a watchdog. Odoo falling back to the container's output (the mount is not writable — Docker creates a missing bind-mount source as root, which is why the directory is created and chowned before the stack ever starts) and a live log that grew past 512 MB (nothing is rotating it). Both look perfectly healthy from every other reading the probe takes

### Security

- **Reading logs is rate-limited and audited.** The reads share one per-user cap (`rate_limit_logs_per_min`, 60/min — the viewer polls the live tail every 4 s, so a tighter cap would break one open viewer), counted in a bucket per endpoint family (`logs_tail_`, `logs_list_`, `logs_day_`): the viewer fires the listing and the tail the instant it opens, and one shared bucket made those two upserts contend for the same row on every open — a serialization failure Odoo retried silently while the server log filled with it. The cross-day sweep and the download share a much tighter cap (`rate_limit_log_search_per_min`, 6/min) because each one makes the customer's host decompress days of logs or ship a whole day through the panel. Both caps sit on the Rates tab with the caps that were already there. Opening the viewer, sweeping every day (with the term) and downloading a day now write an audit row, so "who read whose logs" has an answer; the live tail's polling deliberately writes none, or one row every four seconds would bury the rest
- **What a log read may cost is configurable instead of baked into a release**: `log_download_max_mb` (64), `log_search_max_files` (60) and `log_search_timeout_s` (30) on Settings → General → Instance Logs. The numbers guard someone else's host, which is exactly the kind of thing that should not need a deploy to change
- **Every command that touches the archive refuses anything that is not a regular file.** `logs/` belongs to the container's uid so Odoo can write it, the panel's terminal hands a Developer a shell *inside that container* on purpose (`terminal_session` never opens a host login shell), and the reader runs on the host as the SSH user — root on an unhardened one. A symlink planted from inside the container as `logs/odoo.log.<date>` would therefore have made the log viewer read any host file the SSH user can, which is precisely the escalation the confined terminal exists to prevent. The listing offers regular files only (`find -type f`), and the read, the download and the cross-day sweep each check `[ -f … ] && [ ! -L … ]` before opening anything. Verified by planting a symlink to `/etc/passwd` and watching all four paths ignore it — and kept verified: a test module now runs every one of those commands through `sh` against a temporary `logs/` holding real files and a planted link, so the guard is exercised rather than grepped for
- **A planted file cannot use up the sweep's budget, and the health probe does not follow links either.** Executing the sweep for real showed that its candidate list came from `ls -1t odoo.log*`, which ranks a freshly planted symlink (or any junk named `odoo.log.*`) as the newest entry: skipped, yes, but each still took one of the `log_search_max_files` slots, so sixty of them would have left the sweep with nothing real to read and an honest "no matches" to report. Candidates now come from `find -type f` restricted to logrotate's exact shapes, ordered by mtime. The same executed test on the health probe showed that its ERROR scrape picked "the newest archive" with the same `ls -1t` and that `tail`/`stat` on `logs/odoo.log` would follow a link put in the live file's place — a planted link would have carried host-file lines that look like Odoo errors into an alert. Both readings now take regular files only

### Changed

- **The health probe scrapes ERROR lines from the file instead of `docker compose logs --since`.** The file has no `--since`, so the window is applied by timestamp with an awk state machine that keeps the untimestamped lines following each header — the traceback belongs to the error above it, and filtering by timestamp alone would have thrown away exactly the context 1.0.75 added. It reads the newest archive alongside the live file because rotation happens at midnight and the window straddles it once a day, and falls back to the container's output for an instance that has not been rebuilt yet

## [1.0.76] — 2026-08-18

### Added

- **Every service in the compose override now carries a `json-file` log limit** (`max-size` × `max-file`, `10m` × 3 by default). doodba's Odoo logs to stdout, the copier template sets no logging driver, and Docker's default json-file log grows until something stops it — on a host set up by `full_setup` alone nothing does, since only `host_hardening` writes a `daemon.json` with `log-opts`. Left alone, a busy production instance fills its host's disk within months and takes Postgres and every other instance on the host down with it, silently. The override that deploy and rebuild already write for resource limits and the protect label is where the guarantee belongs: per service, so it holds on any host regardless of how it was set up; on hardened hosts it merely restates the daemon default. Existing instances pick it up on their next rebuild, which recreates the containers anyway — no retrofit job, no manual step
- **`cloud.settings.container_log_max_size` / `container_log_max_file`**, exposed on Settings → General as "Container Log Rotation". Read at render time and deliberately kept out of the per-instance config snapshot: bumping the retention must not light the fleet's "Changes not deployed" pill (that has happened twice for other renders), it simply lands on each instance's next rebuild. The size is validated against Docker's grammar in one canonical lower-case spelling so a typo fails at save time instead of at every stack's next `docker compose up`
- **A registry sweep in the tests asserts the limit on every deploy flavour**, in core and in the SaaS module — the same class of guard that the protect-label incident earned: a flavour whose override stops calling `super()` would ship stacks without the limit and nobody would notice until a disk filled

## [1.0.75] — 2026-08-18

### Added

- **The `instance_error_logs` alert now carries the traceback, not just the headline.** The probe greps the container log anchored to the Odoo log-level field, and a Python traceback's lines carry no level of their own, so the payload held a line saying `Exception during request handling` and nothing that could explain it. When three of those arrived on 2026-08-16, the rebuild an hour later recreated the container and took the only copy of the stack with it. The grep now keeps the lines following each header and files them under the fingerprint they belong to, one sample per group, bounded so a log stuck in a loop cannot inflate the serialized payload
- **The snapshot behind `applied_config_hash` is stored alongside it.** The hash answers whether the saved configuration is still what the last deploy shipped, and nothing else: when the whole fleet lit its "Changes not deployed" pill on 2026-08-18, finding out *what* had moved meant rebuilding the snapshot by hand and testing hypotheses against it. `_config_drift_diff()` now names the keys. Instances anchored before this field existed return nothing rather than guessing
- **A structural gate freezes the shape of the config snapshot.** Editing what `_render_copier_answers` emits moves every instance's hash at once, with nobody having touched a thing — it has happened twice, and both times the fleet stayed dirty until each instance was rebuilt or re-anchored by hand. The test fails on any key added or removed and says what the release owes the fleet. It asserts on keys rather than values, which differ legitimately between an empty CI database and a real one

## [1.0.74] — 2026-08-18

### Fixed

- **The removal of the default organisation's unfiltered datasource did not remove anything.** 1.0.73 dropped the provisioning file and deleted the row through Grafana's HTTP API; Grafana flags what it provisioned from a file as read-only and answers `403 Cannot delete read-only data source`, so the deployment failed at that task with production's datasource still in place — and dropping the file on its own leaves the row orphaned and serving, which reads as fixed and is not. `deleteDatasources` is not one way to remove a provisioned datasource, it is the only one: the file is written again, declaring the deletion instead of the datasource, and left in place so every run reasserts it. Grafana reads provisioning at startup and this deployment gives it no reason to restart, so the provisioning reload endpoint applies it in place

## [1.0.73] — 2026-08-17

### Fixed

- **Grafana's default organisation held a datasource with no account filter**, and the default organisation is where Grafana drops a login whose `groups` claim matches no entry in `orgMapping`. File provisioning carries no orgId, so the datasource the central deployment provisioned from a file could only ever land there — pointed at vmauth's operator path, which spans every account. The fallback was therefore the most privileged view in the system, reachable by a tenant whose account exists but is not yet in the map. The deployment now provisions none and deletes the one an earlier deployment left behind; the operator loses nothing, since OIDC puts them in their own account's organisation, filtered like everyone else's. A cross-account view, if ever wanted, belongs in that organisation as a datasource named for what it is
- **The account sync skipped the organisation map whenever it had no new accounts to grant** — the common case, and the one that mattered. The organisations are the only part that needs a new account; `orgMapping` names every one of them and is rewritten whole, so gating it left an account minted and unmapped until the next full deployment of the central, with its user landing in the default organisation for the entire window. A revocation-only sync also left the map naming an account that no longer existed. The include is no longer gated: every loop inside it is over the new-account list and does nothing when it is empty, so the cost of running it anyway is one request

## [1.0.72] — 2026-08-17

### Added

- **`deploy_instance_executor._repo_merge_ref(repo, branch)`** — the ref `repos.yaml` merges for a repo, split out of the renderer so a subclass can answer from somewhere other than the repo row. Same behaviour as before (`commit_sha or branch`); the seam exists because a pin written on a different transaction than the one rendering the file is invisible to it — Odoo opens its cursors `REPEATABLE READ`, so the render's snapshot predates the commit and no amount of cache invalidation reveals it

## [1.0.71] — 2026-08-16

### Fixed

- **The fleet's "Instances observed" counter reported one instance more than the fleet has**, on every panel with at least one host reporting containers — a panel with a single instance read 2, and an empty one would have read 1. `instance_id` is attached by the agent's relabelling and only to containers that belong to an instance, so the agents' own stack and the proxy never carry it. Grouping by a label the series do not have does not drop them: PromQL collects them all into one group keyed on the empty string, and that group counted as an instance. Filtered to the series that carry the label, with `or vector(0)` so an empty fleet still reads 0 instead of falling back to "No data" — until now the phantom group guaranteed a number was always drawn
- Third appearance of this same omission: the instance picker and the liveness cron already filter on `instance_id!=""`, and the fleet counter was the surface left out. Pinned by a test so the next reader of the trio finds all three agreeing

## [1.0.70] — 2026-08-16

### Added

- **`cloud.instance._periodic_maintenance_domain()`** — one extension point for the daily maintenance crons, so a layer that deploys instances they have no business touching says so once instead of reimplementing each cron. `cron_refresh_backup_list` and `cron_instance_health` AND it into their own domain; core adds nothing to it

### Fixed

- The SaaS layer had been carrying **copies** of both cron bodies to add a single filter, and the copies stopped receiving the guards added here afterwards. The one that mattered was "only instances whose compose file declares a `backup` service": a free-plan tenant declares none, so this side skipped it and the copy did not, and every free tenant got a daily `backup_list` shelling into a container that does not exist. `docker compose exec` answers `service "backup" is not running` for a service that is stopped **and** for one that was never declared — so it read as a sleeping stack rather than a missing service, and the diagnosis went the wrong way for a while. A failed job and a warning alert per free tenant per day, and the alert never resolved, since a clean run is what clears it
- The docstring of `cron_refresh_backup_list` now says which of the two `exec` answers it is guarding against, because they are indistinguishable from the message alone

## [1.0.69] — 2026-08-16

### Removed

- **Reverts the whole of 1.0.68**, because the failure it guarded against does not occur. The reasoning behind it had a gap: `frame-ancestors 'self'` only bites when the identity provider has to *render* its login page inside the frame, and it never does when the browser already carries a provider session — the authorize step answers with a redirect, and a redirect is not something a framing rule can block. Since every panel is entered through that same provider, having a session there is the normal state and not a lucky one, so the embed simply works. The link and its note were an answer to a question nobody was asking, and the note in particular told a reader looking at working charts that signing in was impossible
- What is left behind is the measurement itself, rewritten in `docs/observability-operations.md` as a statement of why the embed works and what it depends on, so nobody has to re-derive it from headers a year from now
- Also gone: the `kiosk` parameter that only the removed link passed, and the structural test that required every embed to offer a way out — that rule described a constraint this system does not have

## [1.0.68] — 2026-08-16

### Fixed

- **An embedded dashboard can no longer be a blank rectangle with nothing to click.** Grafana delegates its sign-in to the panel's own identity provider, and that provider answers with `content-security-policy: frame-ancestors 'self'` — so the browser refuses to paint the login page inside a frame served from any other subdomain. Both surfaces that embed a dashboard now carry a link that opens the same dashboard in a tab of its own, where the sign-in completes normally
- *(Superseded the same day by 1.0.69, which reverts all of this. Kept in the log because it was released and ran in production: see that entry for why the premise was wrong.)*

## [1.0.67] — 2026-08-15

### Changed

- **One definition of "observability is configured", replacing four.** The nav entry read the master switch; the Monitoring page read the switch *and* the Grafana URL; the Settings tab read who owns the settings; the instance Metrics tab read none of them. Four surfaces each deciding it for themselves is four ways to disagree, and the disagreement that shipped was a panel offering a Monitoring entry whose only possible message was an instruction to open a Settings tab that same panel hides — a dead end reachable by anyone whose settings are injected rather than owned. `cloud.settings._observability_capabilities()` is now the single answer, and it is three independent facts rather than one boolean pretending to be enough: `collect` (the data layer is on), `dashboards` (there is something to look at — collection *and* a Grafana), and `configure` (this panel's own operator edits these settings). Collapsing those three into two flat flags is what made the contradiction expressible in the first place
- Every UI surface consumes the descriptor and none re-derives it. The Monitoring entry now appears when there are dashboards to show, **or** when there are none and this operator is the one who could set them up — so a self-hosted panel that switched observability on without a Grafana URL keeps its actionable prompt, and a panel that can act on neither is offered neither. The instance Metrics tab drops the charts block entirely in that last case rather than printing an instruction to nowhere, and keeps Recent requests, which needs no Grafana at all
- `configure` is published as `True` and left for the layer above to contradict, exactly as the flag it replaces was: core has no notion of a panel whose settings arrive from elsewhere, and acquiring one to fix this would have been the wrong repair

## [1.0.66] — 2026-08-15

### Fixed

- **Instance liveness was querying the metrics central with no credentials at all.** `promql_query` attaches auth only when handed both halves — `auth=(user, token) if (token and user) else None` — so the liveness cron, which unpacked `user, token` and then forwarded only `token=`, queried anonymously. The central answered 401, the caller logged a warning and returned, and `running` silently stopped being refreshed from metrics: every instance kept whatever it last had, which feeds `sleeping`, then `last_activity_at`, then the auto-suspend clock. One of three call sites; the other two always passed both. Beyond the fix, a structural test now reads the source and refuses any `promql_query` call missing either keyword, because a behavioural test would have to be written once per call site — which is exactly what had not happened, for any of them

## [1.0.65] — 2026-08-15

### Fixed

- **The backup listing no longer shells into stacks that are stopped.** `cron_refresh_backup_list` already skipped instances whose compose stack defines no `backup` service, but "defined" and "running" are not the same precondition: `docker compose exec` needs the container up, and a stopped stack answers `service "backup" is not running` with status 1 — a failed job and an alert, every day, for as long as the stack stays down. Warm spares are what surfaced it: they ship stopped by design and hold no customer data at all, yet their own rebuild writes `backup` into `compose_services`, so the moment a spare was refreshed it became a permanent daily failure that listing its backups could never have made succeed. The cron now requires the instance to be running, which is the same condition the executor depends on and also covers a tenant asleep behind its wake gate

## [1.0.64] — 2026-08-15

### Changed

- **Grafana's identity configuration left the compose file, so adding an account no longer recreates it.** The organisation map names every account, so it changed with every tenant — and it lived in the container's environment, which means `up -d` recreated Grafana and dropped every open session for a change that concerned one account. That cost is what made automating the grant look unacceptable in the first place. Measured in a lab against Grafana 11.2.0: the SSO settings API writes to Grafana's own database, **overrides** the `GF_AUTH_GENERIC_OAUTH_*` environment (the provider's `source` flips from `system` to `database`), and applies live — the login page served the new configuration with the container's restart count still at zero. The deployment and the account sync now both push the provider through that API, and the compose file carries none of it: since the database wins, a copy in the environment would be a second source that silently loses. The PUT replaces the whole provider block rather than patching a field, so the complete configuration travels — including `orgAttributePath`, whose absence silently sends every login to the default organisation while the token carries the right claim, which this codebase has already paid for once
- `_grafana_oidc()` and `_grafana_org_mapping()` join the account list on `cloud.settings`. With that, neither central job needs a SaaS subclass at all: the tenant-aware behaviour follows the data instead of being re-declared on each job, and `observability_central_ext` has nothing left to declare

## [1.0.63] — 2026-08-14

### Changed

- **The access-control list is assembled by the settings model, not by the job that writes it.** Reconciliation has to compare the same set without being an executor, and two places assembling "who should have access" is exactly how the gateway and the database drifted apart in the first place. `cloud.settings._desired_metrics_accounts()` is now the single source; the deployment and the sync both read it. A layer that adds accounts — the SaaS manager adds one per tenant — extends the model instead of overriding every job that touches the list, so the tenant-aware behaviour follows the data rather than having to be re-declared each time

## [1.0.62] — 2026-08-14

### Added

- **Granting a metrics account is now an act of its own, instead of a side effect of redeploying the central.** The access-control list vmauth enforces was only ever written by the full deployment. For a self-hosted panel that is airtight: there is one account, minted by that same deployment, so minting and granting are literally the same act and cannot drift. A shared central breaks the equivalence — accounts are minted whenever a panel is added, while the list stays a snapshot of whoever existed the last time somebody deployed, so everyone minted afterwards holds a credential the gateway has never heard of and their agents retry against a 401 forever. Re-running the full deployment would fix it and is the wrong tool: it rewrites the compose file, recreates whatever differs, and resets Grafana's admin password. The new `sync_metrics_accounts` job does only the part that grants — rewrite the document, reload the proxy, provision the organisations the new accounts need — from the same task files the deployment uses, so the two cannot disagree about what the boundary looks like. It never touches the compose file, so it cannot recreate VictoriaMetrics, Loki or Grafana: granting an account is a sub-second reload of one proxy, which is what makes automating it uncontroversial
- **The panel now records what the gateway was actually told, not what it intended.** `metrics_accounts_deployed` holds the accounts the last successful deployment or sync put in force, and `metrics_central_host_id` holds the host carrying the stack. Without the first, "the gateway has never heard of this account" and "we have not told this panel about it yet" are indistinguishable, and nothing can decide whether handing out a credential will authenticate or fail forever. Both are written from what the run was built from rather than from the database as it stands afterwards, so an account minted while the playbook is running is not recorded as granted — because on the gateway it is not

### Changed

- The vmauth document, its reload-and-verify, and the per-account Grafana provisioning moved into task files shared by the deployment and the sync. The dashboards fileglob moved with them, which changes what its relative path resolves against — an error that does not fail but silently provisions organisations with no dashboards at all, so the task file now asserts the glob is non-empty

## [1.0.61] — 2026-08-14

### Fixed

- **Hardening no longer takes Docker's packet rules down with it.** The nftables ruleset opened with `flush ruleset`, which deletes *every* nft table on the host — including the filter/nat chains Docker programs through iptables-nft. The daemon does not notice and never re-adds them, so every published port silently loses its DNAT: containers stay up and answer on localhost while the outside world gets nothing, and the host still passes an ICMP and SSH check. Re-running hardening on a live host therefore took an entire tenant fleet offline, and it had never surfaced before because hardening only ever ran on fresh hosts, ahead of `full_setup` installing Docker — the flush had nothing to destroy yet. The ruleset now replaces only its own table (`table inet filter` / `delete table inet filter`, the idiom that also works on a first run when the table does not exist), leaving every other table untouched. Verified against a live `nft`: a foreign table created between two passes survives the second one

## [1.0.60] — 2026-08-13

### Security

- **The fail2ban exemption list no longer inherits the firewall's catch-all.** 1.0.59 gave the sshd jail an `ignoreip` built straight from the SSH allowlist, on the reasoning that those addresses are already the only ones the firewall lets near the port. That reasoning only holds while the allowlist names addresses. It degrades to `0.0.0.0/0` whenever no operator IP is known — deliberately, since locking every operator out is worse than a reachable port — and both production hosts sit in exactly that state, so the jail would have been written exempting every source on the internet. fail2ban would have stopped banning anyone while the config still read like a hardened one: no error, no log line, nothing to notice. The list is now built in its own fact that drops catch-alls and keeps named addresses, and the test asserts the filter rather than the mere presence of `ignoreip` — the weaker assertion is what let the flaw through in the first place

## [1.0.59] — 2026-08-13

### Fixed

- **The rebuild's boot test can no longer take the tenant down with it.** Its throwaway Postgres was started *on* the project's compose network, so it held an endpoint there for the length of the test. Any reconciliation `docker compose` decided to do in that window could not remove the network to recreate it, the step died with `has active endpoints`, and `stop_on_failure` aborted the job with `db` and `smtp` already stopped under a live `odoo` — twice on 13 August, every tenant on the host serving 502 until the containers were recreated by hand. The throwaway Postgres is now published on the project network's *gateway* instead of joining it: reachable from every container on that bridge, invisible to compose, which stays free to reconcile whatever it likes. If the gateway cannot be resolved the step fails outright rather than falling back to the old behaviour, so the rebuild stops with the instance still running its previous image
- **A failed boot test now puts the stack back.** The cleanup ran from the tail of the script, which `set -e` skips the moment anything upstream fails — precisely when the stack most needs restoring. It moved to an `EXIT` trap that restarts whatever was running before the test. Deliberately `docker compose start` and not `up`: `up` would re-evaluate the image and deploy the very build the boot test just rejected, and would reconcile networks, so the restore could trip over the same drift as the failure it is cleaning up after
- **Metric alerts stop chasing hosts that were decommissioned on purpose.** Retiring a host does not remove its series from the central, so `metrics_host_absent` kept measuring the silence of a machine the operator had destroyed and re-raising a critical alert that could never resolve. Host-scoped rules now skip archived hosts entirely — nothing measured on a machine that left the fleet is worth an alert — and archiving a host closes whatever it still had open, through `resolve_alert` so the external channels see the closure rather than an incident that stays open forever
- **Deleting several instances from one host no longer queues one observability install per deletion.** Five removals queued five identical playbook runs, and that stampede is what fed the serialization race of 13 August: the losing transactions were rolled back and re-run by queue_job, which then reported failures for teardowns that had already finished. A refresh now collapses onto an install that is queued but not yet started. Nothing is lost, because the playbook renders its label map when it runs rather than when it was queued; a job already `started` is deliberately not matched, since it rendered its map at launch and a change arriving mid-flight does need its own run

### Security

- **fail2ban no longer bans the panel.** The sshd jail shipped without `ignoreip`, so three failed authentications from the panel — one agent offering too many keys reaches that on its own — banned it for the full `bantime`. The panel is the only thing that manages a host, so every job against the banned host failed with `ConnectionRefusedError` for a solid hour, as happened to a tenant host on 13 August. Customers were unaffected throughout (80/443 are never involved); management and monitoring were not. The jail now exempts the same allowlist nftables enforces, the control IP included. Those addresses are already the only ones the firewall lets near the SSH port, so fail2ban was adding nothing against them while being able to lock us out

## [1.0.58] — 2026-08-13

### Fixed

- **A teardown that already finished no longer reports itself as failed.** `on_success` commits on its own cursor, so when the job's own transaction dies afterwards the remote work survives the rollback — and queue_job re-queues the job. That happens for real whenever several instances are deleted at once on one host: the sibling jobs finish within the same instant, their closing writes lose a serialization race, and every one of them runs a second time. The retry then asked a record that no longer existed for its remote directory and died with `Expected singleton`, so a clean removal showed up in the panel as a failure and raised an alert for a host that was already tidy. The teardown now recognises the case and finishes as the no-op it is. Only an *unlinked* instance takes that path: an archived one still exists and still has its directory on the host, so it is torn down exactly as before

## [1.0.57] — 2026-08-13

### Fixed

- **The override no longer labels the project's default network, which was tearing live stacks down.** 1.0.56 stamped the protect label on the network as well as on the services. Adding a label changes the network's definition, and `docker compose` answers that by *recreating* it — so on any instance whose network predates the label, the next compose command stopped the running containers to rebuild the network underneath them. It then failed either way: a rebuild's boot test died with `has active endpoints` (its temporary Postgres was still attached) and a plain `up` with `is not connected to the network`, leaving three tenants stopped instead of started. Labelling the network was never necessary: Docker keeps a network alive while any container — running or stopped — still holds an endpoint on it, so containers that survive the prune keep their network alive with them. It only disappeared before because the containers disappeared first

## [1.0.56] — 2026-08-12

### Fixed

- **The prune protection now covers everything the panel deploys, on every path.** The `incubacloud.protect=1` label was stamped only by the SaaS warm-pool *deploy* executor, and a warm *rebuild* resolves to core's rebuild — a class that never passed through it. Every rebuild therefore rewrote `docker-compose.override.yml` without the label and handed the stopped stack back to the next nightly prune, which is why the free-host backups kept failing after 1.0.35 supposedly fixed them: measured on the live host, not one container or network carried the label. The label is now stamped by core's deploy override on every service and on the project's default network, unconditionally, so it cannot depend on which subclass rendered the file. The invariant is "the panel deployed it and it may legitimately sit stopped" — a warm spare, a Sablier-slept free instance, a manually stopped one — and what the panel deploys is destroyed by `delete_instance`, never by the prune
- **A stopped `odoo` container and a missing one are no longer the same thing to the health probe.** It listed only running containers, so a pruned stack and a sleeping one both read as "not running" and got the same generic `instance_down`. The probe now lists stopped containers too and says which case it found; a *missing* container always alerts, while a merely stopped one can be declared expected by a layered module through the new `_odoo_stop_is_expected` hook (core has no notion of scheduled sleep and keeps treating it as an incident). Companion services are still graded while an instance sleeps, since only `odoo` is put to sleep

### Added

- **The prune now proves it did no harm.** The playbook inventories the containers that survived and the executor compares them against the `odoo`/`db` containers every deployed instance on that host must have, raising a critical `prune_swept_managed` alert naming what is missing and resolving it once the stack is whole again. Instances with a job in flight are exempt, since a rebuild legitimately leaves the stack containerless for a while. With the labelling fixed this should never fire — it exists because the silent version of this failure went unnoticed for two days, surfacing only as a failed backup
- The prune log now says what was deleted, counted by kind, and names the networks it removed instead of only reporting the reclaimed space

## [1.0.55] — 2026-08-12

### Fixed

- **"Disk used per instance" legended every series identically.** The per-instance disk collector labelled its samples `instance`, which is the one label a scraper owns: Prometheus sets it to the target address and renames the exposed one to `exported_instance`. Every series on a host therefore arrived as `node-exporter:9100` — distinct series, correct numbers, one repeated legend. Only visible once 1.0.54 made the metric exist at all, since the collector had never produced a sample. It now labels the name `instance_name`, which nothing else claims, and the panel legends by it. A test pins the panel's legend to a label the collector actually emits and refuses the reserved one. Re-running the observability agents on a host applies it.

## [1.0.54] — 2026-08-12

### Fixed

- **The fleet's staleness panel showed one host and hid the rest.** Every agent in the fleet scrapes on the same wall-clock tick — Prometheus derives its jitter offset from the job and target address, and those are identical on every host (`node` / `node-exporter:9100`); only the external labels differ. So the healthy hosts produce the same value at the same timestamp, bit for bit, and on a shared time axis the last series drawn covered all the others. The panel is now a state timeline: one lane per host, which cannot overlap. Its expression is untouched — it is deliberately the same one the host-down rule alerts on — and the green/red break is pinned to that rule's own threshold, so panel and alert cannot drift apart. A test now enforces both halves.
- **Monitoring's Hosts and Instances tabs rendered an unnamed subject.** The embed passed no `var-host`/`var-instance`, so Grafana fell back to the first value its variable query returned, alphabetically; kiosk mode then hid the picker that would have said which one. Every host and instance but one was unreachable from that tab, with nothing on screen indicating it. Both tabs now carry a searchable picker and pin the subject explicitly.
- **The instance picker offered a bucket that is not an instance.** cAdvisor labels any container the scrape config cannot attribute — the proxy, the whitelist, the metrics stack itself — with the raw target address, which is the same literal string on every host. It sorts before every real instance, so it was exactly what the dashboard opened on. The picker now lists only containers that carry an instance id, and the panels scope to a host as well: container names repeat across hosts and an instance name is only unique within its project, so filtering by instance alone could add up two machines without saying so.
- **Every chart now says what its numbers are.** No panel in any of the three dashboards declared a unit, so a memory reading rendered as `10000000000`. Units are set per panel (bytes, percent, seconds, requests/second), with an axis label where Grafana has no unit to offer; a test fails any new chart panel that omits both.
- **Traefik legends dropped the provider suffix.** Service names arrive as `name@docker`/`name@file`; the two Traefik panels now strip it in the query, so the legend reads as the service.
- **"Disk used per instance" was empty on every host, always.** The generated collector tested `[ -d "~/project/instance" ]` with the tilde still literal — bash never expands one that reaches it as data, inside quotes or through a variable — so `du` never ran and the metrics file held nothing but its two header lines, which reads as "no data" rather than as a fault. The path is now resolved while the collector is rendered, which is where the remote home directory is known. This is the same expansion the scripts that go through `run_script()` already do; this generator was the one that did not.
- **The proxy access log never reached a provisioned host.** `traefik.yml` gained a JSON access log, but the stored per-host copies are only ever filled when empty, so the change reached new hosts only and "Recent requests" stayed empty forever on every existing one. Upgrading now merges the block into each host's saved copy — a minimal merge, never a regeneration, so a host that customised its template keeps what it configured. Re-run full setup afterwards to ship it.
- **The `secure` middleware was missing its header set on hosts provisioned before it grew one.** The same one-way template problem: HSTS, clickjacking, MIME-sniffing and referrer headers are now merged into the saved `config.yml` of hosts still on the older version, leaving any value the host set itself alone.

### Added

- **Hosts report when their saved configuration is behind the shipped templates.** Config drift only ever answered "is what we saved what we shipped" — a host could be perfectly clean by that measure and still be running a template from before a feature existed, which is exactly how the access log went unnoticed. Host detail now also shows which specific settings the saved copy lacks. It reports missing settings only: a value the host set differently is its own configuration, not drift, and settings that are the same feature written another way (a file provider reading a directory rather than a single file) are recognised as equivalent rather than flagged forever.

## [1.0.53] — 2026-08-12

### Fixed

- **The instance and host dashboards render again.** Both carried their `$instance`/`$host` template variable's query in the legacy plain-string format Grafana 9 used, plus a datasource pinned to a UID (`victoriametrics`) that only ever existed by convention, never by actually matching what the API assigns on creation. Grafana 11 tries to auto-upgrade the legacy format on load and failed, surfacing "Templating: Failed to upgrade legacy queries" and leaving the fleet-wide Hosts/Instances tabs with no data — panels still rendered wherever a URL param handed them `$instance` directly (the per-instance embed), which is what made this easy to miss. The query now uses the structured object form real Grafana 11 dashboards ship with, and the variable drops its pinned datasource entirely — same as every panel already does, which is why panels never broke: falling back to whichever datasource is default in the org it loads into

## [1.0.52] — 2026-08-11

### Fixed

- **Every account's Grafana organisation now actually gets its own datasource — and its own dashboards.** Switching the admin session to an organisation and creating its datasource were two separate tasks, each looping over every account on its own; Grafana's "current org" is a persistent property of the authenticated admin, not a per-request header, so by the time the datasource task's loop started, the switch task had already finished its own loop and left every write landing in whichever org was switched to last. Measured in production: 9 accounts, 2 datasources ever created, one of them holding a DIFFERENT account's credential. Switch and write are now one block per account, so the org is never stale when written to; an existing-but-wrong datasource is corrected in place rather than silently left behind (a bare create only ever 409s on a name collision, it can't fix one)
- **Dashboards were never visible outside Grafana's default organisation.** The file-based dashboard provider carries no `orgId`, so the fleet/instance/host dashboards only ever loaded into org 1 — and every account lands in its own organisation instead, where the panel's embed showed "Dashboard not found" and a `dashboards:read` permission error. Each account's organisation now gets its own copy of the same three dashboards, created via the API right after its datasource; since none of their panels pin an explicit datasource, each copy binds to whichever one is default in the org it lands in

## [1.0.51] — 2026-08-11

### Fixed

- **The embedded Grafana now actually feels embedded.** The panel embeds it in an iframe on an already-authenticated session, but Grafana still opened on its own native login form and made the operator click "Sign in with IncubaCloud" by hand before the OIDC exchange even started — inside an iframe that reads as "asks me to log in again" even though nothing was actually wrong. `GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN` skips straight to `/oauth/authorize`; with the panel session already live, the whole round-trip completes with no visible login screen. The basic-auth path used only for the server-to-server admin API swap is unaffected and still reachable directly if ever needed

## [1.0.50] — 2026-08-11

### Fixed

- **Grafana's org_mapping now actually reads the account claim.** 1.0.49 wired the account list into `GF_AUTH_GENERIC_OAUTH_GROUPS_ATTRIBUTE_PATH`, which feeds Grafana's team-sync feature — a different thing from org_mapping, which reads `org_attribute_path` instead. With no `org_attribute_path` set, org_mapping had nothing to match against and silently fell back to Grafana's default organisation, Viewer role, regardless of what the id_token or userinfo carried. Caught live: the id_token decoded to the correct `"groups":["acct_…"]`, `/oauth/userinfo` returned the same, and the operator still landed in "Main Org." — the claim was right, Grafana just wasn't reading it from where org_mapping looks. Renamed to `GF_AUTH_GENERIC_OAUTH_ORG_ATTRIBUTE_PATH`

## [1.0.49] — 2026-08-11

### Fixed

- **Grafana's OIDC login now actually completes.** The central's `oidc.client` requires PKCE by default, but the playbook never told Grafana to send a `code_challenge` — the provider's `/oauth/authorize` would have rejected every login attempt with a 400. It also never told Grafana where the account claim lives, so the per-account `org_mapping` had nothing to match against and everyone would have landed in Grafana's default organisation. Both are now wired into the OIDC branch: `GF_AUTH_GENERIC_OAUTH_USE_PKCE` and `GF_AUTH_GENERIC_OAUTH_GROUPS_ATTRIBUTE_PATH`. The claim itself, the corrected `/oauth/*` endpoints and the account-keyed org mapping live in the SaaS layer, which is the only one that knows tenants — and their accounts — exist

## [1.0.49] — 2026-08-09

<!-- TODO(prune-protect): renumber to the next free version before committing — 1.0.49 was taken above. -->

### Fixed

- **Every deploy flavour now stamps the prune-protect label — in the base executor, unconditionally.** The label that keeps `docker system prune -af --filter "label!=…"` away from panel-managed stacks lived in one SaaS subclass, so any rebuild whose class chain skipped it rewrote the compose override *without* the label — and the nightly prune then swept the stopped stack. Measured in production: zero labelled containers, zero labelled networks, the warm pool deleted daily, two days of failed free-host backups. The invariant is "deployed by the panel, may legitimately sit stopped" (a warm spare, a plan-slept instance, a manual stop), so the base deploy executor now labels every service and the default network for every flavour, and a structural test sweeps the executor registry so a future flavour cannot lose it again

### Added

- **The prune now proves what it did.** The maintenance playbook inventories the surviving containers after pruning, and the job compares that against the `odoo`/`db` containers every deployed instance must have — a swept managed stack raises a critical alert the minute it happens, instead of surfacing days later as a failed backup. The job log also gains a per-kind summary of what was deleted (networks by name — containers are printed by ID, which explains nothing once they are gone)
- **The health probe now tells "stopped" apart from "gone".** `docker compose ps` without `-a` shows neither, so a slept instance and a pruned one produced the same generic alert. The probe now sees stopped containers, says "missing (pruned, or never created)" when there is no container at all, and asks a hook whether a stopped-but-present `odoo` was scheduled — core always answers no; the SaaS layer answers from the tenant's plan, so a sleeping Free instance reads healthy while its companion containers are still graded

## [1.0.48] — 2026-08-09

### Changed

- **Documentation caught up with the system it describes.** The operations guide still showed a stack with no gateway, told operators to press a per-host button that no longer exists and to deploy a central via a job name that is now one setting away; the user reference still said metrics were manager-only and listed configuration steps that are now done for you. Both were rewritten, including the account boundary and *why* it rejects rather than sanitises — that rule came from measurement, and a reader who does not know it will eventually "simplify" it back into a hole
- The metrics-backend runbook now diagnoses through the gateway (the only published port), tells the two credentials apart, and explains what a 400 on a query that used to work actually means
- **New runbook: a tenant sees no metrics.** Five links in a chain, each failing differently, and only one of them the tenant's problem — with the explicit note that "ask them to enable something" is never the answer, because enrolment converges on its own
- Spanish translations complete: 1564 entries, none untranslated, none fuzzy

## [1.0.47] — 2026-08-09

### Changed

- **Turning observability on is one decision and one button.** The tab presented six fields and no answer to the only question an operator actually has on that screen — is this working? It now asks the single thing that cannot be derived (which host runs the central), and the button deploys the stack and, when it comes up, fills in the endpoints, generates the credential and switches observability on. A single-host setup never has to open the rest, which is folded away under Advanced. What genuinely cannot be derived is left empty and said out loud: agents on hosts *other* than the central's need a public HTTPS endpoint, which requires DNS and a certificate — inventing one would leave a fleet quietly failing to push, and that is worse than an empty field
- The tab also states, in one line, whether metrics are being collected and whether charts are available — the question the six fields never answered

## [1.0.46] — 2026-08-09

### Added

- **Alerts can now describe an instance, not just the host it happens to sit on.** Every seeded rule was host-scoped, so "this instance is broken" had no way of being said and landed, at best, as a symptom on its host's page. Rules gained a scope: instance-scoped ones resolve through the label the agents attach and raise against the instance itself. Two ship with it — an instance that stopped reporting containers, and an instance returning sustained server errors. The second only became expressible now that HTTP samples are attributed per instance, and it catches what no container metric can: an Odoo that is up and failing looks perfectly healthy to cAdvisor
- **A suppression hook so sleeping instances do not page anybody.** An instance a plan puts to sleep stops every container on purpose; cAdvisor goes quiet, and a naive rule concludes it is down. Every Free instance would then raise a critical alert nightly, and operators would learn to ignore the one that matters. Core has no notion of sleeping — that is a SaaS feature — so it asks the instance and the SaaS layer answers. Going to sleep also clears an alert already raised, rather than freezing it on screen

### Changed

- The guard that stops a seeded rule from aggregating away the label its alert is attributed by is now **scope-aware**: it previously demanded the host label on every rule, which an instance rule has no business carrying

## [1.0.45] — 2026-08-09

### Added

- **Access logs are collected centrally, with the same account boundary as metrics.** Reading them live over SSH answers "who is hitting this instance right now"; it cannot answer "was this happening yesterday", "which instances are seeing a spike in 401s", or alert on any of it. A collector on each host now ships the proxy's access lines to a log store beside VictoriaMetrics. The account is imposed exactly as it is for metrics — set from the authenticated user, never taken from what the sender claims — which was measured in a throwaway stack before being relied on: a collector pushing with a forged account header lands under its own account, and a reader forging the header still sees only its own lines
- Retention is **14 days and deliberate**: these lines carry the IP addresses of our tenants' end users, so the store keeps what an incident needs and no more

### Changed

- The log endpoint is **derived from the metrics one** rather than configured separately — on the gateway the two sit side by side, and one fewer field to fill in is one fewer to get wrong. An endpoint that does not follow that shape (a self-hosted operator pointing at their own backend) disables collection instead of guessing a URL, because a collector retrying forever against something that does not exist looks like a fault rather than an absence

## [1.0.44] — 2026-08-09

### Fixed

- **Grafana had no route to a browser at all.** The previous release moved it behind the gateway and removed its host port, which is right, but nothing then proxied it: the embed could only ever have rendered a blank frame, with no error to explain why. The gateway now serves it under `/grafana/`, and Grafana is told to build its links with that prefix — without which every asset 404s and the result looks identical to the original bug

### Added

- **One Grafana organisation per account, each with a datasource it cannot widen.** Grafana refuses a datasource outside a user's organisation, so this is the ring behind the gateway's own account filter: even a fault in the query path cannot cross accounts. Verified in a throwaway Grafana rather than assumed — a datasource created in one organisation is invisible from another, and the create/lookup/switch/create sequence behaves as the playbook expects, including the 409 that re-running produces
- **An operator-only path to Grafana's admin API.** File provisioning cannot create organisations, so the API is the only way and it needs a credential. Rather than distributing Grafana's admin password, the gateway authenticates the caller with the operator credential and then swaps in Grafana's own before proxying — so the panel never holds it, and rotating it is a redeploy of the central instead of a change everywhere that talks to it

## [1.0.43] — 2026-08-09

### Changed

- **Observability settings can be hidden by the layer above.** A new `can_configure_observability` feature flag gates the Monitoring tab in Settings. Core leaves it on, so a self-hosted operator configures their own stack as before; SaaS tenant panels turn it off, because there the account, credential and endpoints are injected at deploy time and re-pushed afterwards. Showing an editable copy would let a tenant point their agents elsewhere, or simply drift from what was pushed and then look broken to both sides

## [1.0.42] — 2026-08-09

### Added

- **A Metrics tab on the instance page.** When one instance is in trouble, the fleet view is the wrong place to look, and it was the only place there was. The tab embeds that instance's dashboard pinned to it, and underneath shows the requests the charts cannot describe: status-code breakdown, the client IPs hitting hardest, the paths they are hitting, and the most recent requests with IP, method, path and status. The dashboard variable in the URL is a view filter and never a boundary — what a viewer can see is decided by the gateway from the credentials the datasource authenticates with, so editing it by hand only moves within what that account could already read
- **A monitoring readout on the host page.** Whether a host is actually reporting was previously invisible, which is half of why manual enrolment was confusing: an unmonitored host looked exactly like a monitored one, and there was no way to tell whether the button still needed pressing. It now says whether the agents are installed, whether data is arriving, and whether an install keeps failing — a health readout, not a prompt, since enrolment converges on its own

### Changed

- **Fleet metrics moved out of the settings area and are hidden until they exist.** The entry hung at the bottom of the sidebar after Settings, as though it were something you configure rather than something you look at; it now sits with the other operational views, next to Hosts. It also disappears entirely while observability is off, instead of offering a section whose only possible message is "not configured"
- **Metrics and the access log are visible from the developer role upwards**, where they were manager-only. Whoever debugs a slow or attacked instance is exactly the person who needs them, and requiring the manager role turned every incident into a relay race

## [1.0.41] — 2026-08-09

### Added

- **The proxy access log, and a per-instance view of it.** Metrics say an instance is being hammered; they carry neither the client IP nor the requested path, so they cannot say what is being done to it or let you block it — the difference between an alert and an answer. Traefik's access log was never switched on; it now is, in JSON, with headers dropped so cookies and `Authorization` never land on disk. It goes to stdout rather than a file on purpose: a file needs rotation, an unrotated access log on a busy host fills the disk, and Docker's json-file driver already rotates every container's output at 10 MB fleet-wide. The panel reads a slice on demand over SSH and summarises it — request count, status-code breakdown, top client IPs, top paths — and stores nothing, because these lines contain the IP addresses of somebody else's end users. Attribution uses `RouterName`/`ServiceName`, which each line carries in full and which is the same key the metric relabelling joins on, so it survives custom domains, redirects and multi-domain instances rather than depending on a Host-header lookup

### Fixed

- **`cloud.instance.running` had two writers and no arbitration.** The SSH health probe and the metrics liveness cron both decide whether an instance is up, on their own schedules. They agree most of the time, and the state flapped whenever they briefly did not — a race that only appears once observability is enabled, which is to say it was waiting rather than absent. Metrics now own the flag while their readings are fresh (`cloud.instance.metrics_last_seen`, written only by the cron); the SSH probe keeps doing everything metrics cannot — HTTP probing, error-log scraping — and takes the flag back by itself the moment the readings go stale, so there is no window where nobody decides

## [1.0.40] — 2026-08-09

### Added

- **Metrics accounts, so one panel cannot read or poison another's data.** The central used to be protected by a single fleet-wide secret that was valid for both reading and writing and was copied onto every host — workable while one panel owned its own backend, untenable the moment several share one. Each panel now has an account (`metrics_account`) and a credential scoped to it, and the central derives the label it stamps on every series from whoever authenticated rather than from anything the agent claims. That distinction is the whole point: an agent runs on a machine its owner has root on, so its claim about who it is can never be trusted. A second, separate credential covers the operator's unfiltered view and is deliberately never written to a host. Measured against VictoriaMetrics 1.102 before being designed around: repeated `extra_filters[]` are ORed and the last `extra_label` wins, so a gateway that merely *appends* its own filter is bypassable in both directions — hence the write path discards the agent's query string outright and the read path rejects (400) anything carrying those parameters instead of trying to sanitise it
- **Per-instance HTTP attribution.** Traefik's request rates, status codes and latencies were already being scraped and thrown away unattributed, on the documented belief that its service names were copier-time literals unrelated to anything we control. They are not: the panel runs `copier copy` itself and feeds it `project_name = doodba_project_name`, the same string it forces into `COMPOSE_PROJECT_NAME`, so the names are derived and the scrape config now relabels them onto the owning instance. The earlier conclusion came from surveying doodba projects scaffolded by hand, which is not how any panel-deployed instance is built
- **Reconciliation of observability enrolment.** A cron every 15 minutes enrols any host that should be reporting and is not, with a per-host back-off and an alert once failures persist

### Changed

- **Observability is applied to every host instead of being installed by hand.** The button on the host page is gone. It had been justified as "how an operator refreshes the labels after adding instances", a task that became automatic when deploy/move/remove started refreshing them; what remained was a button whose only purpose was enrolment — and enrolment is not a decision, since there is no host to which observability does not apply. Leaving it there implied a step that could be forgotten, and forgetting it produced a silently unmonitored host. Enabling observability is now itself the instruction: the next reconciliation tick enrols everything pending. The chain from host setup stays, but only as an accelerator — if it fails, the cron picks the host up, which is precisely what used to be missing
- Grafana no longer runs anonymously and VictoriaMetrics no longer publishes a port; both sit behind the gateway, which is now the only way in

### Fixed

- **Two bugs that shared one cause: `last_probed` meant "somebody read this host's specs", and was being used to answer two questions it could not answer.** Both the metrics reader and the SSH telemetry job write it, so (a) the guard deciding whether a host had agents installed saw the entire fleet as enrolled — the opposite of what its comment claimed — and (b) the SSH fallback's self-disabling check read a field the SSH job itself had just written, so with observability on and agents not actually reporting it stood down on the strength of its own footprint, resuming only when the freshness window expired and then standing down again. That degraded the fallback from every five minutes to roughly every fifteen, oscillating, exactly when it was the only thing collecting. Enrolment is now recorded explicitly (`metrics_agents_state`) and metric freshness has its own field written by the reader alone (`metrics_last_seen`). Both bugs were latent: they could only bite once observability was switched on, which it never has been

## [1.0.39] — 2026-08-09

### Changed

- **The Traefik scrape job no longer claims its samples cannot be attributed to an instance.** The note there stated there was no sound join key between a Traefik service name and a `cloud.instance`, and concluded that per-instance HTTP had to wait for a later observability phase. That conclusion came from surveying doodba projects scaffolded by hand, where `project_name` is whatever their author typed — it does not describe instances the panel deploys, which is all of them: `cloud_instance._render_copier_answers()` passes `project_name = doodba_project_name`, the very string the deploy forces into `COMPOSE_PROJECT_NAME`, and nothing overrides that method in any of the three modes. Service and router names are therefore derived rather than guessed (`<doodba_project_name>-<version, dots as dashes>-prod-<main|longpolling>@docker`), as confirmed against a running proxy. The comment now records the real rule, why the old survey misled, and the one extra path SaaS adds — tenant panels sit behind a Sablier router and report under `<tenant.slug>-svc@file`, a mapping that belongs to the manager layer. No behaviour changes; the relabelling itself is still unwired. The point is that the next person to read it will not re-derive the wrong answer and shelve the feature again

## [1.0.38] — 2026-08-08

### Changed

- **Dependencies now travel with the code a rebuild ships.** A repo line without a pinned commit is aggregated at the tip of its branch, so every rebuild pulled whatever upstream had published since — while the pip list stayed frozen at whatever the repo's `requirements.txt` said the day the line was created (it was read on create, and never again). An OCA repo adding a module that needs a new library, or bumping the floor of one it already used, produced a build with the new code and without the library it imports. Deploy and rebuild now re-read the `requirements.txt` of every unpinned repo just before writing `pip.txt`, in the same job that pulls the code. Pinned repos are skipped — frozen code, frozen dependencies — and a failed fetch falls back to the stored list, because a blip at GitHub must not stop the fleet
- **Merging those requirements knows who wrote each line.** Re-reading upstream on every rebuild would have turned each routine version bump into a conflict marker and a blocking alert per instance, for a decision nobody actually has to make. Each package now records the repo that authored its spec (`pip_dependency_sources`, on projects and instances): a repo changing a line it wrote is applied and reported in the job log, while a spec that contradicts the operator — or another repo — still becomes the usual conflict marker, files a `pip_conflict` alert and stops the job until a human picks a side. Absence of an entry means the operator owns the line, so existing records need no migration: ownership is claimed lazily the first time a repo declares a spec that already matches. Editing the field by hand takes those lines back, resolving a conflict in the repo's favour hands the line to it, and nothing upstream removes is ever deleted — the job log just notes the package is gone from the manifest. `incubacloud.requirements_resync_enabled=0` restores the old frozen behaviour

## [1.0.37] — 2026-08-08

### Fixed

- **Ansible-backed jobs no longer die with an empty log on images that lack ansible-runner.** A tenant ordering an on-demand VPS watched `host_hardening` fail with a blank log page: since the Phase 3 migration to Ansible, every host-state executor (hardening, probe, prune, delete, whitelist, observability) needs `ansible-core`/`ansible-runner` at runtime, but this repo's `requirements.txt` — the file whose contents deployments merge into their pip dependencies — never declared them, so any image built from it ran without them. The executor's early guard then raised before the first log line, the only failure path in the whole pipeline that leaves no trace in the job log (the reason surfaced only in `queue_job.exc_message` and the alert excerpt). Both halves are fixed: `requirements.txt` now pins `ansible-core==2.21.2` and `ansible-runner==2.4.3` (matching the panel image), and the two early guards — missing ansible-runner, undefined playbook — write their reason into the job log before raising, so a job that cannot even start still says why on its own log page

## [1.0.36] — 2026-08-07

### Fixed

- **Standalone dialogs now follow the light theme.** The shared modal chrome (`.ic-modal`, `.ic-frow`, `.ic-btn`, `.ic-alert`) painted itself with literal dark hex values, a leftover from when the `--rl-*` tokens did not resolve outside `.ic-app` — relay.scss has since defined them on `:root` for exactly that case, and both files ship in the same /cloud bundle. Under `data-ic-theme="light"` every dialog built on that chrome (nine across core, saas manager and tenant — the tenant's "Order new VPS" among them) rendered as a hybrid: dark panel and header, paper-white theme-following inputs inside it, and a Cancel button whose ink-coloured label sat invisible on the dark footer. The chrome now uses the tokens, so it matches the active theme at any mount point; the overlay scrim and drop shadows stay literal darks in both themes, same convention as the slide-over scrim
- **The light theme now reaches every corner of the SPA.** A sweep of all stylesheets found the same disease the modal chrome had, in more places: the import-dialog styled with the pre-redesign dark palette in literal hex; the instance and host detail screens building elevation from white-alpha glazes (invisible over paper) and two custom properties that no longer exist anywhere (`--text-muted`, `--text-primary` — their dark fallbacks always won); toasts and code/log panels frozen dark by literal SCSS constants; Tailwind-era accent colors (`#ef4444`, `#34d399`, `#F87171`…) instead of the Relay state tokens; and light-pastel status pills and banners doing the reverse damage to the dark theme. 118 literals across 20 files now resolve through `--rl-*` tokens — toast and code-panel tints via `color-mix()` over the themed surface so they stay opaque — and the "info" hue, which existed as five slightly different literal cyans, is now a proper token family (`--rl-cyan` + dim/soft/fg/text, with a light variant) alongside a new `--rl-red-fg`. One real dark-theme bug fell out of the sweep: primary buttons in the saas screens used white-on-green at 1.9:1 contrast; they now use `--rl-green-fg` like every other green control
- **SearchSelect placeholders can finally be translated.** Every dropdown passed its placeholder as a quoted OWL expression (`placeholder="'Type to search hosts…'"`), a form the i18n extractor never sees — the strings were absent from the .pot, so no .po could ever cover them and Spanish tenants met English placeholders in an otherwise translated dialog. All 34 such props across core, saas manager and tenant now use the `.translate` attribute suffix (the standard the web client's own dialogs use), the component's built-in "Search…" / "— select —" defaults go through `_t()`, and two plain inputs in the header that had borrowed the quoted-expression syntax — rendering the quotes into the visible placeholder — lost their stray quotes. The regenerated .pot picked up 19 new terms, all translated in `es.po`

## [1.0.35] — 2026-08-07

### Fixed

- **The nightly Docker prune no longer wipes containers that are stopped on purpose.** `docker system prune -af` removes every stopped container, and the exclusion filter meant to spare them (`--filter "label!=incubacloud.protect=1"`) lived in a dependent module as a patch of `get_commands` — a method this executor stopped calling the day it moved to Ansible. Nothing failed, so the loss went unnoticed until a prune landed between a warm instance's rebuild and that night's backup and took the instance's containers with it, failing the backup for the whole host. The filter now belongs to the playbook itself, fed the label from the executor so Python and playbook cannot drift apart, and a structural test pins that the prune command carries it

## [1.0.34] — 2026-08-07

### Fixed

- **Every confirmation dialog outside the instance page works again.** Extracting the shared `confirmVia` helper rewired all five components to call it but added the import to only one of them, so the host, project, settings and backup-backend panels each reached for an undefined global: ten confirmations — "Delete Host" and the SaaS "Open Host Shell" among them — died with `ReferenceError: confirmVia is not defined` the moment the button was pressed. Nothing caught it because the bundle parses fine and the reference is only resolved on the click
- A structural test now refuses any SPA file that calls a `utils/` export it never imported. This is the check a JavaScript `no-undef` would make, done in the Python suite so the pipeline needs no linter to catch the next omitted import

## [1.0.33] — 2026-08-06

### Fixed

- **A new template question no longer writes a placeholder secret into `backup.env`.** The doodba template v9.7.0 adds `backup_backend_password`, whose default is the literal string `example-backup-backend-password`; since deploys run copier with `--defaults`, any question we leave unanswered takes its default. The answers file now sets it empty, which keeps the line out of the rendered file entirely. Only password-capable duplicity backends read it — ours authenticate with AWS keys — so nothing was broken, but a fake credential in a live env file is not something to ship

- **The host list no longer flickers while a job runs.** Every background refresh replaced the rendered fleet with the loading skeleton for about 120 ms, so a running job — which notifies watchers twice a second — turned the page into a strobe. The skeleton now belongs to the first paint and to the Retry button; bus events and tab refocus take a silent path that leaves the cards in place. A failed background refresh no longer replaces good data with the error stub either

### Changed

- **Executors notify on output, not on the clock.** The run loop published a bus event every half-second for the whole life of a job, whether or not anything had been written. A job sitting in a silent multi-minute `docker compose build` therefore cost every open panel a full refetch twice a second for nothing. The tick now publishes only when it actually persisted log rows; the final drain still publishes unconditionally so watchers settle on the last state, and the standalone log page keeps its own fallback poll
- **Job events reach only the users allowed to read the job**, resolved through the same visibility helper the email and external notifiers use. A stakeholder no longer receives traffic for the projects they are not a member of
- **Job events now name their target** (`host_id`, `instance_id`, `project_id`), so a panel can ignore an event that does not concern it without asking the server what the event was about. The instance page used to spend one `load_jobs` call per event — for every job in the fleet, not just its own — purely to learn that. Naming the target is safe because the audience is ACL-filtered first; the host page and the tenant page regain filters that had been dropped for costing an extra round-trip
- Refreshed collections are merged by id instead of replaced wholesale, so a refresh only re-renders the rows that changed. This also fixes an active host search being cleared by a background refresh whenever every host happened to match the query

## [1.0.32] — 2026-08-06

### Added

- Revoking a host's trusted SSH key on an endpoint change now raises a critical alert (`host_key_revoked`) through every notification channel, and re-running "Trust SSH Key" resolves it. The revocation used to leave only an audit row, so a host could sit unreachable — excluded from every cron, refusing to build SSH connections — with nothing telling the operator to re-verify the key
- **Machine-identity check on re-trust.** A revocation now records the fingerprint of the key it dropped, and the next capture is compared against it: an identical fingerprint proves the machine did not change and the endpoint edit was administrative, while a different one raises a critical `host_key_changed` alert naming both fingerprints. The verdict reaches the operator who clicked (toast), the panel (alert) and the audit log. This is the verification actually available to us — our provider exposes no console output or metadata carrying host keys — so the alert text no longer asks for an out-of-band check the platform cannot support. Unlike the revocation alert, a change alert is not auto-resolved: it records a past event and waits for a human to dismiss it
- Host key fingerprints are visible in the panel (host overview, `SHA256:…` in the same form `ssh-keygen -lf` prints), alongside the fingerprint of a pending revocation

### Fixed

- **The SSH host key fingerprint was never logged.** The capture read the key *type* field instead of the key blob, so the base64 decode always failed and the log line fell back to a message with no fingerprint in it — the mechanism meant to let an operator verify a TOFU capture had never produced a single fingerprint since it was written

- **Hosts hardened by the panel became unreachable for Ansible-backed jobs.** Hardening rotates the SSH port without revoking the trusted key (same machine), but the stored `known_hosts` line kept the label captured on port 22. OpenSSH files a non-default port under `[ip]:port` and reads the bare form as port 22 only, so it treated those hosts as unknown and failed host-key verification; asyncssh accepts either form, which is why the SSH executors and the terminal never noticed. Hardening now re-files the verified key under the rotated endpoint, and a migration repairs existing hosts. Recurring Docker Prune was the only job affected in practice — it had been failing on every hardened host since the Ansible executors landed in 1.0.20

## [1.0.31] — 2026-08-04

### Added

- **Refresh from production**: replace a staging instance's database and filestore with a copy of its production's, keeping the staging's own code. Pick the latest backup snapshot or an on-demand live dump; the dialog falls back to the live dump when the production has no backup destination. Runs as the existing `backup_download` → `restore_instance` pair, so both instances keep their running-job protection and their timeline entries
- `backup_download` accepts `time='live'` on production for an on-demand dump, alongside the duplicity snapshot path
- `restore_instance` accepts `neutralize` and `reset_base_url` payload flags

### Changed

- **Chained restores no longer round-trip through the core.** Clone to staging, refresh from production and host moves used to relay the full backup ZIP (database + filestore) as a base64 `ir.attachment` — the whole archive in the core's RAM twice and in its database for up to 2 hours. The download step now stages the archive on the host (`handoff='host'`) and the restore consumes it in place when both run on the same machine, or streams it source host → core disk → target host (`mode='from_host'`) when they don't. Memory stays flat regardless of archive size, and a failed restore stays retryable because the staged copy is only removed on success. Operator-facing downloads (backup, neutralized dump, export) keep the attachment but now write it via `raw`, halving their peak memory
- **Staging clones are now neutralized.** `Clone to staging` (including GitHub PR previews) restores with `--neutralize`, so the copy comes up with scheduled actions and outgoing mail servers disabled and Odoo's test banner on. Previously a clone inherited production's live crons and mail servers, which could invoice, dun and email real customers from a test copy
- A restored copy's `web.base.url` is rewritten to the target instance's own domain, and any inherited `web.base.url.freeze` is dropped, instead of keeping the source's URL until the next admin login

### Fixed

- Cloning a production with no backup destination no longer fails mid-chain on the duplicity path (leaving the fresh staging deployed but empty): the clone falls back to an on-demand live dump, same as the refresh dialog
- The Developer requirement for cloning and refreshing is now enforced on the model methods themselves, closing the direct-RPC path that only the panel routes used to gate

## [1.0.9] — 2026-07-12

### Added

- Telegram and HMAC-signed webhook push notifications for job state changes, with per-channel configuration, chat-id auto-detect and test-message actions
- Unified alert notification pipeline: every alert (including job failures, routed through their `job_failed` alert) dispatches to email, Telegram and webhook from a single code path
- Instance activity timeline split into active and recent jobs with an overflow indicator
- Watchdog cron that recovers instances stranded by a cross-host move that failed before cutover

### Fixed

- Cross-host move pipeline: fresh backup before transfer, only the `odoo` service stopped on the source, chained `queue.job` cleanup on failure
- Traefik proxy restarted after Full Setup so it re-reads its static configuration
- Webhook payload timestamp serialized as a string for JSON compatibility

## [1.0.8] — 2026-07-07

### Added

- Server-side role gate on job enqueue: host-level job types require the Administrator role

### Fixed

- Backup/restore hardening and Traefik ACME storage persistence

## [1.0.7] — 2026-07-04

### Added

- Alerts & notifications overhaul: alert dedup and auto-resolve, dismissed-alert garbage collection, per-user notification preferences (level, muted projects), email channel with immediate or daily-digest mode

## [1.0.6] — 2026-06-28

### Added

- Server-side pagination for backups, audit logs and alert history
- Light theme and Relay UI redesign
- Host pools-aware placement hook and cross-host instance move
- Webhook auto-rebuild can be declined per instance; auto-rebuild guards for archived instances/hosts

### Fixed

- Backup container hostname capped at 64 bytes; S3 301 redirects reported as backend connection errors

## [1.0.5] — 2026-06-10

### Added

- Transient host-connection failures retried automatically before alerting
- Host-scoped job serialization (running-job guard per host)

### Fixed

- Cron-bot server actions authorized for the Odoo 19 cron pre-check

## [1.0.1 – 1.0.4] — April–May 2026

### Added

- Multi-VPS DNS support, executor consolidation and terminal UX improvements
- Instance filter and searchable host/instance selectors in the SPA
- User documentation site (mkdocs-material) at docs.incubacloud.io

## [1.0.0] — 2026-03-29

### Added

- Initial public release of IncubaCloud Core for Odoo 19.

<!-- Rebuild routing check: two pushes in a row (1/2). -->

<!-- Rebuild routing check: two pushes in a row (2/2). -->
