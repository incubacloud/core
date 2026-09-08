# RB-22: Rotate the SMTP relay credential

**Severity:** critical
**Typical trigger:** the relay password was exposed (a log, a screen
share, a transcript), or periodic rotation.
**Who runs it:** ops.

The whole fleet sends mail as **one shared mailbox**,
`notifications@incubacloud.io`, against `mail.incubacloud.io:587`.
There is no per-instance account — creating a mailbox per tenant was
considered and dropped, because it would put mailbox provisioning in
the signup path.

One account means one rotation touches **twelve places**:

| # | Where | What holds it |
|---|-------|---------------|
| 1 | `mailserver` on Cloud 1 | the mailbox itself — **the authority** |
| 2 | `.docker/smtp.env` of the panel stack | `RELAY_PASSWORD` |
| 3 | `cloud.settings.saas_smtp_password` | template for new tenants |
| 4–13 | `cloud.instance.smtp_relay_password` × 10 | per instance, **and rendered into its stack** |

Rows 4–13 are the reason this is not a two-minute job: the credential
goes through `_render_copier_answers()`, so **writing the field is not
enough** — each instance needs a rebuild for `copier update` to write
the new value into its compose.

## Symptoms / triggers

- The password appeared somewhere it should not have.
- A `535 authentication failed` in the panel's SMTP test, or in an
  instance's mail log, after someone changed the mailbox by hand.
- Scheduled rotation.

## Resolution

### 1. Change the mailbox password (the authority)

```bash
$ ssh -i ~/.ssh/id_ed25519_cloud root@95.217.1.126 \
    'docker exec -ti mailserver setup email update notifications@incubacloud.io'
```

Let it prompt for the password. Do **not** pass it as an argument —
that puts it in the host's process list and in your shell history.

The other five mailboxes (`reinier@`, `support@`, `legal@`,
`privacy@`, `dmarc.report@`) have their own passwords and are not
affected.

### 2. Enter it in the panel

Panel → Settings → SMTP → the relay password field. Save.

### 3. Prove it authenticates — before propagating

Click **Test SMTP** in that same screen. It logs in with the value you
just saved, against the configured host/port.

**Do not skip this.** `invoke propagate-smtp-credential` checks that
the stored value is non-empty, that it is not a known-leaked
fingerprint, and that the username matches what the instances already
use — but it **never attempts a login**. A mistyped password passes
all three guards and lands on ten instances, breaking mail for every
tenant at once. This step is the only thing standing between a typo
and that outcome.

If the test fails, fix the value here and re-test. Nothing has been
propagated yet.

### 4. Propagate

From the doodba checkout root:

```bash
$ invoke propagate-smtp-credential --dry-run   # read back, change nothing
$ invoke propagate-smtp-credential
```

The secret never travels back over the SSH channel in readable form:
the remote snippet prints it on a marked line, the remote shell
redirects that output into a `0600` temporary file that a `trap`
deletes, rewrites the panel's `.docker/smtp.env` from it, restarts the
`smtp` container, and returns **only a `sha256[:12]` fingerprint**.

That single call covers stores 2, 3 and 4–13's database fields.

### 5. Rebuild the instances

```bash
$ invoke propagate-smtp-credential --rebuild
```

Tenants only, and both exclusions are deliberate:

- **Instance 118 (the panel)** is not rebuilt by the rollout; its
  stack comes from the root repo.
- **Warm spares** are not rebuilt — `tenant_rebuild_instance` refuses
  an instance with no tenant, and they do not need it:
  `warm_claim_instance` uploads freshly rendered answers and runs
  `copier update` when the spare is claimed.

### 6. Verify — without a single authentication attempt

Because the mail server is ours, the new value can be checked against
the stored hash **offline**. No login, so no chance of tripping
fail2ban with a wrong guess:

```bash
$ ssh -i ~/.ssh/id_ed25519_cloud root@95.217.1.126 \
    'set -a; . /root/incubacloud/production/.docker/smtp.env; set +a; \
     H=$(docker exec mailserver awk -F"|" "/^notifications@/{print \$2}" \
         /tmp/docker-mailserver/postfix-accounts.cf); \
     docker exec mailserver doveadm pw -t "$H" -p "$RELAY_PASSWORD" >/dev/null 2>&1 \
       && echo MATCH || echo NOMATCH'
```

`MATCH` proves two things at once: the propagated value is the one the
mail server accepts, and — since Dovecot keeps exactly one hash per
account — **the old password no longer authenticates**.

Then confirm mail actually flows:

```bash
$ ssh -i ~/.ssh/id_ed25519_cloud root@95.217.1.126 \
    'docker logs mailserver --since 1h 2>&1 | grep sasl_username | tail -5'
```

Successful relays appear as `sasl_method=PLAIN,
sasl_username=notifications@incubacloud.io` on a queue-id line;
failures appear as `SASL … authentication failed`.

## Rollback

There is no "undo" on the mailbox: whatever hash the mail server holds
is what the fleet must present. If a rotation goes wrong, roll
*forward* — set the mailbox password again (step 1), re-enter it (step
2), test (step 3), propagate (step 4). The propagation task is
idempotent; instances already holding the right value are skipped.

Until steps 4–5 finish, tenants whose stack still renders the previous
password get `535` on every send and their mail queues locally, so
mail is delayed, not lost.

## Caveats

- **IMAP is exposed** (143/993 on the mail server) and the mailbox
  keeps received mail, so this credential grants *reading* as well as
  sending. After any suspected leak, review the mailbox for unfamiliar
  access, not just for outgoing spam. A send-only account does not
  need IMAP; disabling it would bound the next leak.
- The panel's `Test SMTP` button reads the **saved** setting, not the
  form field — save before testing.
- `invoke propagate-smtp-credential` refuses to run if the panel still
  holds a fingerprint known to have leaked, which is why step 2 comes
  before step 4.

## References

- `tasks_local.py` — `propagate_smtp_credential`, its guards and its
  no-leak transport.
- [RB-14](RB-14-restore-mailserver.md) — restoring the mail server
  itself (DKIM keys, accounts, mailboxes).
- [RB-01](RB-01-rotate-secret-key.md) — rotating
  `INCUBACLOUD_SECRET_KEY`, which is what encrypts these fields at
  rest.
