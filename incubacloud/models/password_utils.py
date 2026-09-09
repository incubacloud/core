"""
Fernet-based symmetric encryption for sensitive fields (passwords, passphrases).

Key resolution:
  The environment variable INCUBACLOUD_SECRET_KEY MUST be set in all
  environments (production, staging, local dev, test). There is no
  fallback key. A fallback dev key is useless when restoring a
  production database locally — the data was encrypted with the
  production key, not the dev key — and actively dangerous because it
  masks a misconfiguration.

  Generate a key with:
    python -c "from cryptography.fernet import Fernet; \\
               print(Fernet.generate_key().decode())"

Key rotation (MultiFernet):
  The env var accepts a *comma-separated* list of Fernet keys. The
  first key is the primary (used to encrypt new values); every key in
  the list can decrypt. That lets operators rotate keys without a
  flag-day: generate a new key, prepend it to the list, redeploy; old
  ciphertext keeps working because the old key is still in the list.
  Once every row has been re-encrypted (via rotate_value below) the
  retired key can be dropped from the env var.

  Examples:
    INCUBACLOUD_SECRET_KEY="<primary>"                  # single key
    INCUBACLOUD_SECRET_KEY="<new_primary>,<old_key>"    # rotation

The prefix ``enc:`` distinguishes already-encrypted values from
plain-text values that may exist in older records before this feature
was introduced.

Failure mode (fail-loud):
  ``encrypt_value`` and ``decrypt_value`` raise when the key is
  missing or invalid, instead of silently writing plain text.
"""
import logging
import os
import secrets

_logger = logging.getLogger(__name__)

_ENCRYPTED_PREFIX = "enc:"
_KEY_ENV_VAR = "INCUBACLOUD_SECRET_KEY"

# Lazy-loaded MultiFernet instance (single Fernet wrapped if only one key)
_fernet = None


class IncubacloudCryptoError(RuntimeError):
    """Raised when encryption/decryption cannot proceed safely."""


def _key_error_message():
    return (
        f"{_KEY_ENV_VAR} environment variable is not set or invalid. "
        "Generate a key with: "
        'python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())" '
        f"and expose it to the Odoo container as {_KEY_ENV_VAR}. "
        "To rotate, set a comma-separated list with the new primary "
        "key first and the old key second."
    )


def _parse_keys(raw):
    """Split the env var on ',' and strip blanks. Returns a list of
    non-empty byte strings (Fernet accepts bytes)."""
    return [k.strip().encode() for k in raw.split(',') if k.strip()]


def _get_fernet(env=None):
    """Return a MultiFernet initialised from the env var, or None.

    Single-key config returns a MultiFernet with one Fernet — encrypt
    and decrypt behave identically to a bare Fernet, so the rest of
    the module doesn't need to know whether rotation is in progress.
    """
    global _fernet
    if _fernet is not None:
        return _fernet

    try:
        from cryptography.fernet import Fernet, MultiFernet
    except ImportError:
        _logger.error(
            "cryptography library not installed. "
            "Run: pip install cryptography"
        )
        return None

    raw_key = os.environ.get(_KEY_ENV_VAR, "").strip()
    if not raw_key:
        _logger.error(
            "%s environment variable is not set.", _KEY_ENV_VAR,
        )
        return None

    keys = _parse_keys(raw_key)
    if not keys:
        _logger.error(
            "%s is set but contains no usable keys.", _KEY_ENV_VAR,
        )
        return None

    try:
        fernets = [Fernet(k) for k in keys]
    except Exception as e:
        _logger.error("Invalid %s: %s", _KEY_ENV_VAR, e)
        _fernet = None
        return None

    # MultiFernet.encrypt always uses fernets[0], so the operator
    # controls which key is primary via the order in the env var.
    _fernet = MultiFernet(fernets)
    if len(fernets) > 1:
        _logger.info(
            "%s has %d keys loaded (rotation in progress); new values "
            "will be encrypted with the first key.",
            _KEY_ENV_VAR, len(fernets),
        )
    return _fernet


def key_is_configured():
    """Return True if the secret key is present and valid.

    Safe to call from a post-init hook without triggering side effects.
    """
    return _get_fernet() is not None


def encrypt_value(value, env=None):
    """Encrypt *value* and return ``enc:<base64>``.

    Raises:
        IncubacloudCryptoError: when the secret key is missing or invalid.
        Exception: the underlying Fernet error is propagated unchanged if
            encryption itself fails for any reason.
    """
    if not value:
        return value
    if isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX):
        return value  # already encrypted
    f = _get_fernet(env)
    if f is None:
        raise IncubacloudCryptoError(_key_error_message())
    token = f.encrypt(value.encode()).decode()
    return f"{_ENCRYPTED_PREFIX}{token}"


def decrypt_value(value, env=None):
    """Decrypt a ``enc:<base64>`` value and return plain text.

    Legacy plain-text values (no ``enc:`` prefix) are returned unchanged —
    migration code relies on this pass-through behaviour.

    Raises:
        IncubacloudCryptoError: when the secret key is missing or invalid.
        ValueError: when decryption fails (key rotated or data corrupted).
    """
    if not value:
        return value
    if not (isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX)):
        return value  # plain-text legacy value
    f = _get_fernet(env)
    if f is None:
        raise IncubacloudCryptoError(_key_error_message())
    try:
        token = value[len(_ENCRYPTED_PREFIX):].encode()
        return f.decrypt(token).decode()
    except Exception as e:
        raise ValueError(
            "Failed to decrypt stored secret; the encryption key may have "
            "been rotated or the ciphertext corrupted."
        ) from e


def is_encrypted(value):
    """Return True if *value* was encrypted by this module."""
    return isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX)


def rotate_value(value, env=None):
    """Re-encrypt *value* with the current primary key.

    Use this to migrate secrets to a freshly-rotated key without
    decrypt/encrypt dance. Pass-through for plain-text legacy values
    and empties. ``MultiFernet.rotate`` decrypts with any configured
    key and re-encrypts with the first (primary).

    Returns the new ``enc:<token>`` string.
    """
    if not value:
        return value
    if not (isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX)):
        return value  # plain legacy value, nothing to rotate
    f = _get_fernet(env)
    if f is None:
        raise IncubacloudCryptoError(_key_error_message())
    try:
        old_token = value[len(_ENCRYPTED_PREFIX):].encode()
        new_token = f.rotate(old_token).decode()
    except Exception as e:
        raise ValueError(
            "Failed to rotate stored secret; key may be missing from "
            "the MultiFernet chain or the ciphertext is corrupted."
        ) from e
    return f"{_ENCRYPTED_PREFIX}{new_token}"


def is_on_primary_key(value, env=None):
    """Return whether *value* is already encrypted with the primary key.

    This is the question a key rotation actually has to answer, and
    until now nothing could: the rotation counts how many rows it
    *rewrote*, and it rewrites every row on every pass. Fernet puts a
    timestamp and a random IV in each token, so re-encrypting the same
    plaintext with the same key yields a different string every time
    and the "rotated" tally never reaches zero. An operator following
    RB-01 to the letter would wait forever for a number that cannot
    converge — or drop the old key on a hunch, which strands whatever
    had not moved yet, permanently.

    Asking the ciphertext which key opens it converges, because it is a
    property of the data rather than of the last write.

    :param value: a stored ``enc:`` string. Empty and plain-text legacy
        values return ``True``: there is nothing for a rotation to move,
        so counting them as pending would never let it finish either.
    :param env: optional Odoo environment, for the key lookup.
    :return: ``True`` when the primary key alone can decrypt it.
    :rtype: bool
    """
    if not value:
        return True
    if not (isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX)):
        return True
    f = _get_fernet(env)
    if f is None:
        raise IncubacloudCryptoError(_key_error_message())
    # ``MultiFernet._fernets`` is the ordered chain; the first entry is
    # the primary, the one ``encrypt`` uses. Decrypting with just that
    # one is what separates "already moved" from "still on an old key".
    primary = f._fernets[0]
    token = value[len(_ENCRYPTED_PREFIX):].encode()
    try:
        primary.decrypt(token)
    except Exception:  # noqa: BLE001 — any failure means "not primary"
        return False
    return True


def generate_password(length=20):
    """Return a cryptographically strong URL-safe password (~27 chars for length=20)."""
    return secrets.token_urlsafe(length)
