"""Retiring certificates the host has stopped serving from.

Installing a certificate on a host does not decide what its visitors
are handed. Traefik publishes everything in its own store under the
default TLS store when it starts, and the handshake picks by server
name before any router is consulted — so a name whose router was
changed to serve the host's certificate keeps being answered with the
stored one until that one is gone from the store.

Measured on Traefik 2.11, and the reason six tenants moved behind a CDN
went on presenting certificates they can no longer renew: the routers
were right, the store was stale, and nothing said so.

Two ways to get this wrong, so both are pinned:

* keeping an entry the host now covers leaves the original failure in
  place, silently, until the certificate expires; and
* dropping one the host does *not* cover takes a name still reached
  directly down to a throwaway certificate, immediately and visibly.
"""
import json

from odoo.tests.common import TransactionCase

from ._certs import make_pair

ZONE = ("*.example.test", "example.test")


def store(*entries, resolver="letsencrypt"):
    """Return an ACME store document holding *entries*.

    :param entries: ``(main, sans)`` pairs, one per stored certificate
    :param str resolver: name of the resolver holding them
    :rtype: str
    """
    return json.dumps({
        resolver: {
            "Account": {"Email": "ops@example.test"},
            "Certificates": [
                {
                    "domain": {"main": main, "sans": list(sans)},
                    "certificate": "Y2VydA==",
                    "key": "a2V5",
                    "Store": "default",
                }
                for main, sans in entries
            ],
        },
    })


def mains(document):
    """Return the main name of every entry left in *document*."""
    return [
        entry["domain"]["main"]
        for resolver in json.loads(document).values()
        for entry in resolver.get("Certificates") or []
    ]


class AcmeStoreCase(TransactionCase):

    def setUp(self):
        super().setUp()
        cert, key = make_pair(ZONE)
        self.host = self.env["cloud.host"].create({
            "name": "acme-store-host",
            "ip_address": "10.0.0.21",
            "user": "ubuntu",
            "wildcard_domain": "example.test",
            "behind_cdn": True,
            "tls_default_cert": cert,
            "tls_default_key": key,
        })

    def prune(self, document):
        return self.host._prune_acme_store(document)


class TestWhatIsRetired(AcmeStoreCase):

    def test_a_name_the_host_now_serves_itself_is_retired(self):
        document, retired = self.prune(store(("a.example.test", [])))
        self.assertEqual(retired, ["a.example.test"])
        self.assertEqual(mains(document), [])

    def test_the_rest_of_the_store_is_left_intact(self):
        """The account is what the resolver needs to renew anything at
        all; losing it would take down the names being kept."""
        document, _ = self.prune(
            store(("a.example.test", []), ("keep.elsewhere.test", [])),
        )
        loaded = json.loads(document)["letsencrypt"]
        self.assertEqual(loaded["Account"], {"Email": "ops@example.test"})
        self.assertEqual(mains(document), ["keep.elsewhere.test"])

    def test_every_name_on_an_entry_has_to_be_covered(self):
        """A certificate covering a mixture is kept: retiring it would
        take the name still reached directly down with it."""
        document, retired = self.prune(
            store(("a.example.test", ["b.elsewhere.test"])),
        )
        self.assertEqual(retired, [])
        self.assertEqual(mains(document), ["a.example.test"])

    def test_all_the_names_are_reported_not_just_the_first(self):
        _, retired = self.prune(
            store(("a.example.test", ["b.example.test"])),
        )
        self.assertEqual(retired, ["a.example.test", "b.example.test"])

    def test_more_than_one_resolver_is_walked(self):
        document = json.dumps({
            "letsencrypt": {"Certificates": [
                {"domain": {"main": "a.example.test"}},
            ]},
            "buypass": {"Certificates": [
                {"domain": {"main": "b.example.test"}},
            ]},
        })
        pruned, retired = self.prune(document)
        self.assertEqual(sorted(retired), ["a.example.test", "b.example.test"])
        self.assertEqual(mains(pruned), [])


class TestWhatIsKept(AcmeStoreCase):

    def test_a_name_still_reached_directly_is_kept(self):
        """Its challenge still completes, and the host's own
        certificate does not cover it — retiring it would serve a
        certificate no browser trusts."""
        _, retired = self.prune(store(("customer.example.com", [])))
        self.assertEqual(retired, [])

    def test_a_name_the_certificate_does_not_cover_is_kept(self):
        """Two labels down: the zone wildcard covers one."""
        _, retired = self.prune(store(("a.b.example.test", [])))
        self.assertEqual(retired, [])

    def test_a_host_reached_directly_retires_nothing(self):
        """Nothing has moved: every router still asks a CA, and every
        stored certificate is still the right answer."""
        self.host.behind_cdn = False
        _, retired = self.prune(store(("a.example.test", [])))
        self.assertEqual(retired, [])

    def test_an_entry_naming_nothing_is_kept(self):
        """Unreadable is not the same as covered."""
        document = json.dumps({"letsencrypt": {"Certificates": [
            {"certificate": "Y2VydA=="},
        ]}})
        _, retired = self.prune(document)
        self.assertEqual(retired, [])


class TestAStoreThatCannotBeRead(AcmeStoreCase):
    """Rewriting one costs every certificate on it, and the names that
    still need them cannot obtain another from behind a CDN."""

    def test_something_that_is_not_json_is_returned_as_it_came(self):
        document, retired = self.prune("<html>504</html>")
        self.assertEqual(document, "<html>504</html>")
        self.assertEqual(retired, [])

    def test_an_empty_store_is_returned_as_it_came(self):
        self.assertEqual(self.prune(""), ("", []))

    def test_a_document_of_the_wrong_shape_is_returned_as_it_came(self):
        self.assertEqual(self.prune("[]"), ("[]", []))

    def test_a_resolver_holding_no_list_is_skipped(self):
        document = json.dumps({"letsencrypt": {"Certificates": None}})
        self.assertEqual(self.prune(document), (document, []))


class TestNothingToDo(AcmeStoreCase):

    def test_a_store_with_nothing_to_retire_comes_back_untouched(self):
        """Byte-identical, so the caller can tell "nothing changed" from
        "changed to the same thing" and skip writing to production."""
        document = store(("customer.example.com", []))
        self.assertEqual(self.prune(document), (document, []))

    def test_a_host_with_no_certificate_of_its_own_retires_nothing(self):
        self.host.tls_default_cert = False
        self.host.tls_default_key = False
        _, retired = self.prune(store(("a.example.test", [])))
        self.assertEqual(retired, [])
