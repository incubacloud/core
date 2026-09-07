"""GitHub App webhook receiver.

Endpoint: POST /cloud/github/webhook
Auth:     public (signature validated via HMAC-SHA256)

Responsibilities:
- Read raw body bytes before any parsing
- Delegate signature validation to the credential service
- Persist the event in ``cloud.github.event``
- Route it through ``cloud.github.event._dispatch()`` (inline, see below)
- Return 200 OK or 401 Unauthorized

``_dispatch()`` runs *inside* the request on purpose: it only does DB
work — mark the event processed, create/patch records, **enqueue**
follow-up ``cloud.job`` rows — and the heavy lifting (rebuilds,
provisioning) happens later in those queued jobs. Keeping the routing
inline preserves the "every path ends processed" retention invariant
without a second async layer; if routing ever grows real work, move it
behind ``queue_job`` instead of letting the request slow down (GitHub
retries after ~10s, and the HMAC anti-replay guard would reject the
retry as a duplicate).
"""

import json
import logging
import re

from psycopg2 import errors as pg_errors

from odoo import http
from odoo.http import request

from ..models.res_users_ext import as_platform
from ._client_ip import client_ip
from ._rate_limit import Rule, first_tripped

_logger = logging.getLogger(__name__)

# GitHub caps a webhook payload at 25 MB, so nothing legitimate comes
# close to Odoo's 128 MiB default. That headroom protects nobody and is
# paid in full by whoever floods the endpoint: the body is read and
# HMAC'd before its signature can be known to be false, and verifying a
# signature *requires* hashing the whole body — there is no shortcut.
# The cost cannot be removed here, only bounded, and this is the size
# half of that bound (the per-IP limit below is the rate half).
_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024

# Shape of X-Hub-Signature-256: the literal prefix plus a SHA-256 digest
# in hex. Checked from the headers alone, so a request that cannot
# possibly carry a valid signature is refused before the body is read.
# It does not stop an attacker who fakes the shape — nothing here can —
# but it makes unshaped junk free to reject.
_SIGNATURE_RE = re.compile(r'^sha256=[0-9a-f]{64}$')


class GitHubWebhookController(http.Controller):

    @http.route(
        "/cloud/github/webhook",
        type="http",
        auth="public",
        csrf=False,
        methods=["POST"],
        save_session=False,
        # Per route, not global: the restore upload next door declares
        # 2 GiB and must keep it. Werkzeug enforces this from the
        # Content-Length header, so an oversized delivery is answered
        # 413 without a byte of the body being read.
        max_content_length=_MAX_PAYLOAD_BYTES,
    )
    def github_webhook(self, **_kwargs):
        # Rate-limit by client IP *before* reading the body or doing
        # HMAC work — a forged-signature flood otherwise forces us to
        # hash every request before we can reject it. GitHub itself
        # tolerates the 429 by backing off and re-delivering, so
        # legitimate traffic is not lost.
        ip = client_ip()
        if first_tripped(Rule(
            f'webhook_ip:{ip}',
            cap_key='rate_limit_webhook_per_min',
            log_tag=f'webhook ip={ip}',
        )):
            return request.make_response(
                "Rate limit exceeded. Retry after 60s.\n",
                status=429,
                headers=[
                    ("Content-Type", "text/plain"),
                    ("Retry-After", "60"),
                ],
            )

        # Headers first, body second. Both checks below are decided
        # from the headers alone, and reading the body is the expensive
        # part — it is what a flood is trying to make us do. Reversing
        # this (as it was) meant every malformed request still cost a
        # full read before being told it was malformed.
        event_type: str = request.httprequest.headers.get("X-GitHub-Event", "")
        delivery_id: str = request.httprequest.headers.get("X-GitHub-Delivery", "")
        signature: str = request.httprequest.headers.get("X-Hub-Signature-256", "")

        # GitHub always sends X-GitHub-Delivery. A missing header means
        # this is not a real webhook call — reject before doing any
        # HMAC work so a malformed client cannot pollute the event log
        # or bypass the anti-replay unique constraint (which only
        # applies to non-empty delivery_id).
        if not delivery_id:
            _logger.warning(
                "GitHub webhook missing X-GitHub-Delivery header (event=%s)",
                event_type,
            )
            return request.make_response(
                "Missing X-GitHub-Delivery header.\n",
                status=400,
                headers=[("Content-Type", "text/plain")],
            )

        # A signature that is not even shaped like one cannot validate
        # against any secret, so hashing the body to find that out is
        # pure waste. Deliberately not a security boundary — the HMAC
        # below is — just the cheapest possible refusal.
        if not _SIGNATURE_RE.match(signature):
            _logger.warning(
                "GitHub webhook malformed X-Hub-Signature-256 "
                "(delivery=%s, event=%s)", delivery_id, event_type,
            )
            return request.make_response(
                "Signature validation failed.\n",
                status=401,
                headers=[("Content-Type", "text/plain")],
            )

        payload_bytes: bytes = request.httprequest.get_data()

        secret = request.env["cloud.github.credential.service"].sudo().resolve_webhook_secret(payload_bytes, signature)

        if secret is None:
            # No secret configured — reject to prevent unauthenticated deployments
            _logger.error(
                "GitHub webhook rejected: no webhook secret configured "
                "(delivery=%s, event=%s). "
                "Configure a webhook secret in the GitHub App settings.",
                delivery_id, event_type,
            )
            return request.make_response(
                "Webhook secret not configured.\n",
                status=401,
                headers=[("Content-Type", "text/plain")],
            )
        elif not secret:
            # Secret is configured but signature did not validate
            _logger.warning(
                "GitHub webhook HMAC validation failed "
                "(delivery=%s, event=%s)", delivery_id, event_type
            )
            return request.make_response(
                "Signature validation failed.\n",
                status=401,
                headers=[("Content-Type", "text/plain")],
            )

        try:
            payload_data = json.loads(payload_bytes) if payload_bytes else {}
        except Exception:
            payload_data = {}

        payload_str = payload_bytes.decode("utf-8", errors="replace")
        action = payload_data.get("action", "")

        # Anti-replay: the unique index on delivery_id raises
        # UniqueViolation if GitHub (or an attacker) resends the same
        # delivery. Swallow it and return 200 — returning a non-2xx
        # would make GitHub retry the same delivery forever. The event
        # was already processed on the first insert, so handlers are
        # skipped here to avoid double rebuilds / PR churn.
        try:
            with request.env.cr.savepoint():
                # The route is ``auth="public"``, and ``sudo()`` does not
                # change ``env.uid`` — so without this the event, the
                # fleet rebuilds it dispatches, their ``queue_job`` rows
                # and every log chunk those executors wrote were all
                # authored by the public user. GitHub pushed; the
                # platform acted.
                Event = as_platform(request.env["cloud.github.event"])
                event = Event.create({
                    "event_type": event_type,
                    "action": action,
                    "delivery_id": delivery_id,
                    "payload": payload_str,
                })
        except pg_errors.UniqueViolation:
            _logger.info(
                "GitHub webhook replay ignored: delivery=%s event=%s action=%s",
                delivery_id, event_type, action,
            )
            return request.make_response(
                "Duplicate delivery — already processed.\n",
                status=200,
                headers=[("Content-Type", "text/plain")],
            )

        _logger.debug(
            "GitHub webhook persisted: event=%s action=%s delivery=%s",
            event_type, action, delivery_id,
        )

        # Routing (and the "every path ends processed" invariant behind
        # retention) lives on the model, next to the handlers themselves.
        event._dispatch(payload_data)

        return request.make_response(
            "OK\n",
            status=200,
            headers=[("Content-Type", "text/plain")],
        )
