# RB-01: Rotate `INCUBACLOUD_SECRET_KEY` (MultiFernet)

**Severity:** planned
**Typical trigger:** scheduled rotation (quarterly), or suspected key leak.
**Who runs it:** ops + security.

Encrypted secrets (`s3_secret_access_key`, `passphrase`, SSH
credentials, SMTP passwords, …) are encrypted with Fernet. The
`INCUBACLOUD_SECRET_KEY` env var is a comma-separated list of Fernet
keys; the first entry is the **primary** (used for encryption), the
rest are legacy keys still accepted for decryption. Rotation moves
every ciphertext from the old primary to a new primary and then
drops the old key from the env var.

## Symptoms / triggers

- Scheduled 90-day rotation calendar event.
- Incident response after a leak: the old key may have been read.
- Before re-homing a deployment to a new secret store.

## Diagnosis

Check which keys are active and how many rows are still encrypted
with a legacy key:

```sql
db$ SELECT
       CASE WHEN s3_secret_access_key LIKE 'enc:%' THEN 'encrypted'
            ELSE 'other' END AS state,
       COUNT(*)
    FROM cloud_backup_backend
    GROUP BY 1;
```

`odoo log` will show `INCUBACLOUD_SECRET_KEY has N keys loaded (rotation
in progress)` at boot when more than one key is configured.

## Pre-flight — do this before anything else

**Measure the pending count while the chain still holds one key.**

```python
env['cloud.settings']._get_system().rotation_pending_count()
# {'total': 0, 'by_column': {}}   ← clear to start
```

With a single key configured this MUST be zero. Anything else is a
value the *current* key cannot open, and it will still be there at
step 6 — whose gate is this number reaching zero. Start a rotation
with one of those inside and the gate never opens: you either wait
forever, or you get tired and retire the old key while something
legitimately still needs it.

The 2026-09-10 rotation found exactly one:
`cloud_instance(118).odoo_admin_user_password`, unreadable since April.
It was dead data — that instance is the panel itself, it has no tenant
attached, and the panel has no `admin` user at all — so regenerating it
cost nothing. But had it been missed, step 6 would have been
unreachable.

Fix every row this reports before continuing; see *When a secret will
not decrypt* below for how.

## Resolution

1. **Generate the new primary key** (on your workstation, not on
   production):

   ```bash
   $ python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

2. **Prepend the new key** to `INCUBACLOUD_SECRET_KEY` in the
   production env file. Keep the current primary as the second
   entry so existing ciphertext keeps decrypting:

   ```bash
   # BEFORE:  INCUBACLOUD_SECRET_KEY=OLD
   # AFTER:   INCUBACLOUD_SECRET_KEY=NEW,OLD
   ```

3. **Restart the stack** so the new env is read:

   ```bash
   $ invoke restart
   ```

4. **Enable the rotation cron** (disabled by default). In Odoo UI:
   Settings → Technical → Scheduled Actions → "Rotate Encrypted
   Secrets (MultiFernet)" → set Active = True. It runs hourly and
   re-encrypts one batch per tick so nothing moves all at once.

5. **Monitor progress** with the pending count, and only with it:

   ```python
   env['cloud.settings']._get_system().rotation_pending_count()
   # {'total': 0, 'by_column': {}}   ← done, safe to retire the old key
   # {'total': 7, 'by_column': {'cloud_host.password': 7}}  ← not yet
   ```

   Every rotation pass also writes this line to the log:

   ```
   Rotation status: N value(s) still not on the primary key.
   ```

   > **Do not wait for the "rotated" tally to reach zero — it never
   > will.** A Fernet token carries a timestamp and a random IV, so
   > re-encrypting the same secret with the same key produces a
   > different string every time. The sweep compares the new string
   > with the old one, they never match, and it therefore rewrites
   > every row on every pass for as long as the cron runs. Measured on
   > 2026-09-09: two consecutive passes over the same six seeded
   > secrets each reported 12 rotated values. That tally answers "how
   > much did I rewrite", not "how much is left".
   > `rotation_pending_count` asks which key opens each ciphertext,
   > which is a property of the data, so it converges.
   >
   > A value nothing can decrypt counts as **pending**. That is
   > deliberate: it keeps the old key in the chain instead of
   > stranding the row. Investigate those before continuing — see
   > *When a secret will not decrypt* below.

   > **The token's timestamp is not evidence of anything.** Fernet
   > stamps each token, but `MultiFernet.rotate` deliberately
   > *preserves* the original stamp when it re-encrypts. After a
   > successful rotation the tokens still read April, May, whenever
   > they were first written. Reading those stamps and concluding the
   > rotation never ran is a trap that cost real time on 10-sep. The
   > only valid checks are `rotation_pending_count` and trying to
   > decrypt with each key in the chain.


6. **Disable the rotation cron** once `rotation_pending_count()` returns
   `{'total': 0, ...}`. Anything else means at least one secret still
   needs the old key, and step 7 would make it unreadable forever.
   If it will not reach zero, you skipped the pre-flight: something was
   already stranded before you started.

7. **Remove the old key** from `INCUBACLOUD_SECRET_KEY`:

   ```bash
   # INCUBACLOUD_SECRET_KEY=NEW
   ```

   Restart once more. From this moment the old key cannot decrypt
   anything anymore — the window is closed.

## Rollback

If step 3 fails (service won't start), restore the previous
`INCUBACLOUD_SECRET_KEY` value and restart. No ciphertext has been
touched yet.

If step 5 is in-flight and a row fails to re-encrypt, keep both
keys in the env var. The row stays decryptable under OLD and will
be retried next tick. Do **not** remove OLD until the rotation cron
has completed a full pass with zero errors.

## Key custody

The key is not recoverable. Lose it and every stored secret — host
passwords, backup passphrases, GitHub credentials — is permanently
unreadable, and a restore of the database alone will not bring the
panel back. Treat it as a separate artifact from the backups.

Rules:

- **At least two copies, in different places.** A password manager
  entry plus an offline copy kept somewhere physically different is
  enough. One copy is not a copy.
- **Never store the key alongside the database backup.** Whoever
  obtains that bucket must not obtain the key with it — that is the
  whole point of encrypting the columns.
- **Write down *where* the copies are, never the value itself.** The
  restore procedure needs to tell an operator where to look; it must
  never be the thing that leaks the key.
- **Verify the copies work.** A key you have never restored from is a
  key you are assuming works. The panel restore drill exercises this
  end to end.
- **A retired key is kept, not destroyed.** Every backup taken before
  the rotation holds ciphertext only the old key opens. Restore one
  without it and all stored secrets are unreadable — including the
  `cloud_host.key_file` rows, which are the only copy of those VPSs'
  SSH key, so those machines become unreachable for good. Keep it in
  custody labelled with the date it stopped being primary.
- **Take a backup right after step 7.** Until one runs, no backup in
  existence can be restored with the key the panel is now using. The
  daily job closes this on its own within a day; triggering it closes
  it in a minute.

## When a secret will not decrypt

If a value was written with a key that is no longer in the chain (or
its ciphertext is corrupted), any read of it raises **and** opens a
critical `cloud.alert` with code
`encrypted_value_unreadable:<model>.<field>`, pointing at the record.

The value cannot be recovered without the original key. Resolution:
put the old key back in `INCUBACLOUD_SECRET_KEY` (as a trailing entry)
if you still have it, or set the secret again from source — regenerate
the host password, re-enter the backup passphrase, re-issue the token.
Dismiss the alert once the value is readable again.

## References

- [`models/password_utils.py`](../../incubacloud/models/password_utils.py) — MultiFernet loader & `rotate_value()`.
- [`models/encrypted_char.py`](../../incubacloud/models/encrypted_char.py) — read path and the unreadable-secret alert.
- [`data/rotate_secrets_cron.xml`](../../incubacloud/data/rotate_secrets_cron.xml) — the rotation cron definition.
- `tests/test_password_utils.py::TestMultiFernetRotation` — integration tests of the mechanism.
