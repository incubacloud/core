"""Tests for the Traefik frame-guard retrofit (HDR-001).

The public pages of a host send no ``frame-ancestors`` and no
``X-Frame-Options``, so anything served there can be put inside an iframe
and overlaid. The control is a ``headers`` middleware attached as an
https-entrypoint default, the only place a response header can be added
once and reach every copier-generated router.

Two properties make this one different from its HSTS and rate-limit
siblings, and they are what these pin:

* It is **off unless asked for**. A tenant's own site may legitimately be
  embedded by its customers, and this reaches every router on the host,
  so core ships the capability and leaves the policy to whoever runs it.
* It **sets** rather than adds. The source list is a policy that moves,
  and clearing it has to take the header back out — an allow-list left
  behind after the feature is turned off is the failure to avoid.
"""
import yaml

from odoo.tests.common import TransactionCase

from ..models.cloud_host import CloudHost


_SEED_CONFIG = """\
http:
  middlewares:
    compress:
      compress: "true"
    hsts:
      headers:
        forceSTSHeader: "true"
        stsSeconds: 31536000
"""

#: The https entrypoint of a host the HSTS retrofit already reached: the
#: managed chain, recognisable by ``hsts@file``.
_SEED_TRAEFIK = """\
entryPoints:
  http:
    address: ":80"
  https:
    http:
      tls: "true"
      middlewares:
        - hsts@file
        - ratelimit@file
    address: ":443"
"""

_SOURCES = "'self' https://panel.example.com"


class TestFrameguardMiddleware(TransactionCase):
    """The dynamic half: the middleware that carries the policy."""

    def test_empty_sources_write_nothing(self):
        """The default is no header at all, not an empty policy."""
        out = CloudHost._set_traefik_frameguard_middleware(_SEED_CONFIG, "")
        self.assertEqual(out, _SEED_CONFIG)
        self.assertNotIn("frameguard", out)

    def test_sources_define_the_middleware(self):
        out = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )
        parsed = yaml.safe_load(out)
        header = parsed["http"]["middlewares"]["frameguard"]["headers"]
        self.assertEqual(
            header["contentSecurityPolicy"],
            f"frame-ancestors {_SOURCES}",
        )

    def test_x_frame_options_is_never_sent(self):
        """It cannot express 'self and that other origin', so pairing it
        would block the very embed the source list exists to keep."""
        out = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )
        self.assertNotIn("frameDeny", out)
        self.assertNotIn("X-Frame-Options", out)

    def test_the_seed_survives(self):
        out = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )
        parsed = yaml.safe_load(out)
        self.assertIn("compress", parsed["http"]["middlewares"])
        self.assertIn("hsts", parsed["http"]["middlewares"])

    def test_setting_twice_does_not_duplicate(self):
        once = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )
        twice = CloudHost._set_traefik_frameguard_middleware(once, _SOURCES)
        self.assertEqual(once, twice)

    def test_a_new_policy_replaces_the_old_one(self):
        """The list moves; a stale allow-list is the failure to avoid."""
        first = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, "'self'",
        )
        second = CloudHost._set_traefik_frameguard_middleware(first, _SOURCES)
        parsed = yaml.safe_load(second)
        self.assertEqual(
            parsed["http"]["middlewares"]["frameguard"]["headers"][
                "contentSecurityPolicy"
            ],
            f"frame-ancestors {_SOURCES}",
        )
        self.assertEqual(second.count("frameguard:"), 1)

    def test_clearing_removes_the_middleware(self):
        """Turning the feature off has to take the header back out."""
        on = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )
        off = CloudHost._set_traefik_frameguard_middleware(on, "")
        self.assertEqual(off, _SEED_CONFIG)

    def test_a_value_with_colons_stays_one_scalar(self):
        """Every URL carries a colon; unquoted it would break the YAML."""
        out = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, "'self' https://a.example.com:8443",
        )
        parsed = yaml.safe_load(out)
        self.assertEqual(
            parsed["http"]["middlewares"]["frameguard"]["headers"][
                "contentSecurityPolicy"
            ],
            "frame-ancestors 'self' https://a.example.com:8443",
        )

    def test_a_file_without_the_mapping_is_left_alone(self):
        """Guessing where to insert is how a retrofit breaks a proxy."""
        hand_written = "tls:\n  options:\n    default:\n      minVersion: X\n"
        self.assertEqual(
            CloudHost._set_traefik_frameguard_middleware(
                hand_written, _SOURCES,
            ),
            hand_written,
        )


class TestFrameguardEntrypoint(TransactionCase):
    """The static half: the reference that makes the middleware apply."""

    def setUp(self):
        super().setUp()
        self.with_mw = CloudHost._set_traefik_frameguard_middleware(
            _SEED_CONFIG, _SOURCES,
        )

    def test_reference_added_when_the_middleware_exists(self):
        out = CloudHost._set_traefik_entrypoint_frameguard(
            _SEED_TRAEFIK, self.with_mw,
        )
        chain = yaml.safe_load(out)["entryPoints"]["https"]["http"][
            "middlewares"
        ]
        self.assertEqual(chain, ["hsts@file", "ratelimit@file",
                                 "frameguard@file"])

    def test_no_reference_without_the_middleware(self):
        """Fails closed: naming a middleware the file provider does not
        define makes Traefik answer 500 on every router of the host."""
        out = CloudHost._set_traefik_entrypoint_frameguard(
            _SEED_TRAEFIK, _SEED_CONFIG,
        )
        self.assertEqual(out, _SEED_TRAEFIK)

    def test_reference_removed_when_the_middleware_goes(self):
        on = CloudHost._set_traefik_entrypoint_frameguard(
            _SEED_TRAEFIK, self.with_mw,
        )
        off = CloudHost._set_traefik_entrypoint_frameguard(on, _SEED_CONFIG)
        self.assertEqual(off, _SEED_TRAEFIK)

    def test_idempotent(self):
        once = CloudHost._set_traefik_entrypoint_frameguard(
            _SEED_TRAEFIK, self.with_mw,
        )
        twice = CloudHost._set_traefik_entrypoint_frameguard(
            once, self.with_mw,
        )
        self.assertEqual(once, twice)

    def test_an_operators_own_chain_is_not_extended(self):
        """``hsts@file`` marks the chain we manage; anything else is the
        operator's, and appending to it blind breaks their proxy."""
        theirs = _SEED_TRAEFIK.replace("- hsts@file\n", "")
        self.assertEqual(
            CloudHost._set_traefik_entrypoint_frameguard(
                theirs, self.with_mw,
            ),
            theirs,
        )
