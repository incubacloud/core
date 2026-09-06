"""Command shapes for the two jobs that change what the edge does.

Both are convergence tools: re-running one must leave the host matching
what the panel currently says, including when the answer is "carry
nothing". The removal half is the one worth pinning — a stale allowlist
rejects deliveries silently, where no allowlist merely leaves them
unfiltered, so removal has to happen whether or not anything replaces it.
"""
import asyncio
import json
from unittest.mock import MagicMock

from odoo.tests.common import TransactionCase

from ..github.edge import EDGE_CONFIG_FILENAME
from ..models import acme_store
from ..models.full_setup_executor import FullSetupExecutor
from ..models.github_webhook_edge import RANGES_PARAM
from ..models.github_webhook_edge_executor import (
    PushGitHubWebhookEdgeExecutor,
)
from ..models.push_trusted_proxies_executor import PushTrustedProxiesExecutor
from ..models.transport import CommandResult, SSHTransport

from ._certs import make_pair

RANGES = ["192.30.252.0/22"]
EDGE_PROXY = ["198.51.100.0/24"]


def _store(main):
    """Return an ACME store document holding one certificate for *main*."""
    return json.dumps({"letsencrypt": {"Certificates": [
        {"domain": {"main": main, "sans": []}, "Store": "default"},
    ]}})


def _store_json():
    """Return a store holding nothing — what a full retirement leaves."""
    return json.dumps({"letsencrypt": {"Certificates": []}})


#: Covered by the fixture host's own certificate, so it is served from
#: that one now and the stored entry is what keeps overriding it.
STORE_WITH_COVERED = _store("a.edge-exec.example.com")
#: A customer's own domain: still reached directly, still renewable,
#: and not covered by anything this host holds.
STORE_WITHOUT_COVERED = _store("shop.customer.example")


class EdgeExecutorCase(TransactionCase):

    def setUp(self):
        super().setUp()
        self.host = self.env["cloud.host"].create({
            "name": "edge-exec-host",
            "ip_address": "10.0.0.11",
            "user": "ubuntu",
            "wildcard_domain": "edge-exec.example.com",
        })

    def _executor(self, cls, code):
        """Build *cls* against a job of type *code* for the fixture host."""
        job_type = self.env["cloud.job.type"].search(
            [("code", "=", code)], limit=1,
        )
        self.assertTrue(job_type, f"job type {code} must be declared")
        job = self.env["cloud.job"].create({
            "host_id": self.host.id,
            "job_type_id": job_type.id,
            "name": code,
        })
        return cls(job, self.host)

    def _commands(self, cls, code):
        return dict(self._executor(cls, code).get_commands())


class TestWebhookEdgeCommands(EdgeExecutorCase):

    def _cmds(self):
        return self._commands(
            PushGitHubWebhookEdgeExecutor, "push_github_webhook_edge",
        )

    def test_a_host_with_nothing_to_publish_still_removes(self):
        commands = self._cmds()
        self.assertEqual(
            list(commands), ["Remove stale GitHub webhook allowlist"],
        )
        self.assertIn(EDGE_CONFIG_FILENAME, commands[
            "Remove stale GitHub webhook allowlist"
        ])

    def test_removal_runs_before_installation(self):
        self._publish_something()
        labels = list(self._cmds())
        self.assertEqual(labels[0], "Remove stale GitHub webhook allowlist")
        self.assertEqual(labels[1], "Install GitHub webhook allowlist")

    def test_the_document_lands_in_the_watched_directory(self):
        self._publish_something()
        install = self._cmds()["Install GitHub webhook allowlist"]
        self.assertIn(f"~/traefik/dynamic/{EDGE_CONFIG_FILENAME}", install)
        # Moved into place, never written there directly: Traefik would
        # parse a half-written document and drop the routers.
        self.assertIn("mv ", install)

    def _publish_something(self):
        """Give the host one deployed instance and a source range."""
        settings = self.env["cloud.settings"].sudo()._get_system()
        settings.github_webhook_allowlist = True
        self.env["ir.config_parameter"].sudo().set_param(
            RANGES_PARAM, "\n".join(RANGES),
        )
        project = self.env["cloud.project"].create({"name": "Edge Exec Proj"})
        instance = self.env["cloud.instance"].create({
            "name": "exec",
            "project_id": project.id,
            "environment": "production",
            "host_id": self.host.id,
            "odoo_version": "19.0",
        })
        instance._transition("deployed")
        self.assertTrue(self.host._github_webhook_document())


class TestTrustedProxyCommands(EdgeExecutorCase):

    def _cmds(self):
        return self._commands(
            PushTrustedProxiesExecutor, "push_trusted_proxies",
        )

    def test_both_documents_are_installed_together(self):
        # A host whose entrypoint names a middleware its file provider
        # does not define answers 500 on every router it serves.
        move = self._cmds()["Move Traefik configuration"]
        self.assertIn("~/traefik/traefik.yml", move)
        self.assertIn("~/traefik/config.yml", move)

    def test_the_dynamic_copy_is_refreshed(self):
        # The file provider reads config.yml from the dynamic directory
        # on a host that has been through full setup.
        refresh = self._cmds()["Refresh the dynamic configuration"]
        self.assertIn("~/traefik/dynamic/config.yml", refresh)

    def test_the_proxy_is_restarted(self):
        # trustedIPs is static configuration: Traefik reads it once at
        # start-up, so a file drop alone would change nothing.
        restart = self._cmds()["Restart Traefik"]
        self.assertIn("-p inverseproxy", restart)
        self.assertIn("restart proxy", restart)

    # ── Installing the certificate must not depend on who owns the
    # directory ──────────────────────────────────────────────────────
    #
    # Traefik runs as root inside its container and owns ``certs/`` on
    # any host it has already written an ACME store into. A host whose
    # jobs run as the unprivileged operator the hardening playbook
    # creates therefore cannot move a file in there — measured on a
    # real host, where every other step of this job succeeded and this
    # one died on ``Permission denied``.

    _INSTALL = "Install the default certificate"

    def test_the_certificate_lands_in_the_traefik_store(self):
        command = self._cmds()[self._INSTALL]
        self.assertIn("~/traefik/certs/default.crt", command)
        self.assertIn("~/traefik/certs/default.key", command)

    def test_the_plain_move_is_tried_before_reaching_for_sudo(self):
        """A host without sudo has to keep working exactly as it did."""
        command = self._cmds()[self._INSTALL]
        plain = command.index('mv "$1" "$2" 2>/dev/null')
        escalated = command.index('sudo mv "$1" "$2"')
        self.assertLess(plain, escalated)

    def test_every_write_into_that_directory_can_escalate(self):
        """Creating it, both moves, the mode, and the removal."""
        command = self._cmds()[self._INSTALL]
        self.assertIn("|| sudo mkdir -p ~/traefik/certs", command)
        self.assertIn("|| sudo chmod 600 ~/traefik/certs/default.key", command)
        self.assertIn("|| sudo rm -f ~/traefik/certs/default.crt", command)

    def test_the_private_key_is_owner_only(self):
        self.assertIn(
            "chmod 600 ~/traefik/certs/default.key",
            self._cmds()[self._INSTALL],
        )

    def test_a_host_given_nothing_has_the_store_emptied(self):
        """A store naming files that are not there makes Traefik answer
        every handshake with a throwaway certificate."""
        command = self._cmds()[self._INSTALL]
        self.assertIn("rm -f ~/traefik/dynamic/tls-default.yml", command)
        self.assertIn("~/traefik/certs/default.crt", command.split("else")[1])

    # ── The firewall has to believe the same list as the proxy ───────
    #
    # The proxy gets its list from this job. The firewall got its from
    # the hardening playbook, which runs on Ansible at host creation and
    # then effectively never — so a range the CDN published afterwards
    # was accepted by the proxy and dropped before reaching it, and the
    # daily job that noticed had nothing it could update.

    _FIREWALL = "Refresh the firewall allowlist"

    def _filtering_host(self, ranges="203.0.113.0/24\n2001:db8::/32"):
        self.host.write({
            "behind_cdn": True,
            "block_direct_access": True,
            "trusted_proxy_ranges": ranges,
        })

    def test_a_host_that_filters_nothing_is_left_alone(self):
        self.assertNotIn(self._FIREWALL, self._cmds())

    def test_declaring_ranges_without_refusing_direct_access_does_not(self):
        """The firewall half only exists once the proxy refuses too."""
        self.host.write({
            "behind_cdn": True,
            "trusted_proxy_ranges": "203.0.113.0/24",
        })
        self.assertNotIn(self._FIREWALL, self._cmds())

    def test_a_filtering_host_gets_todays_ranges(self):
        self._filtering_host()
        command = self._cmds()[self._FIREWALL]
        self.assertIn("203.0.113.0/24", command)
        self.assertIn("2001:db8::/32", command)

    def test_the_two_families_go_to_their_own_sets(self):
        """nftables cannot hold both in one set."""
        self._filtering_host()
        command = self._cmds()[self._FIREWALL]
        self.assertIn("ic_cdn_v4 { 203.0.113.0/24 }", command)
        self.assertIn("ic_cdn_v6 { 2001:db8::/32 }", command)

    def test_it_is_applied_as_one_transaction(self):
        """Flushing and refilling in two commands leaves a window in
        which the set is empty and the rule matches nobody."""
        self._filtering_host()
        command = self._cmds()[self._FIREWALL]
        self.assertEqual(command.count("nft -f -"), 1)
        self.assertNotIn("nft flush set", command)

    def test_it_does_nothing_on_a_host_without_the_set(self):
        """One hardened before the sets existed. Its inlined ranges keep
        working until the next hardening run replaces them."""
        self._filtering_host()
        command = self._cmds()[self._FIREWALL]
        self.assertIn("nft list set inet filter ic_cdn_v4", command)
        self.assertIn("else echo", command)

    def test_a_host_with_no_ipv4_range_is_left_alone(self):
        """What the playbook treats as "no allowlist at all". Flushing
        to empty would take the host off the network."""
        self._filtering_host(ranges="2001:db8::/32")
        self.assertNotIn(self._FIREWALL, self._cmds())

    def test_the_firewall_is_refreshed_after_the_proxy_restarts(self):
        """Order matters only in that neither half may be skipped; the
        proxy owns the connection, so it goes first."""
        self._filtering_host()
        labels = list(self._cmds())
        self.assertLess(
            labels.index("Restart Traefik"), labels.index(self._FIREWALL),
        )


class AcmePruneCase(EdgeExecutorCase):
    """Retiring what the proxy obtained before the host was given a
    certificate of its own.

    Installing the certificate is only half of that change. Traefik
    publishes its whole ACME store under the default TLS store at
    start-up and picks by server name before consulting a router, so
    until an entry is gone from the store it keeps winning — which is
    how six tenants went on presenting certificates they can no longer
    renew, with correct routers and nothing in the logs.
    """

    _STEP = "Retire stored certificates"

    def setUp(self):
        super().setUp()
        cert, key = make_pair(("*.edge-exec.example.com",))
        self.host.write({
            "behind_cdn": True,
            "tls_default_cert": cert,
            "tls_default_key": key,
        })

    def _prepared(self, cls, code, stored, exit_status=0):
        """Run *cls*'s preparation against a host whose store is *stored*.

        :return: ``(executor, files it staged for upload)``
        """
        executor = self._executor(cls, code)
        transport = MagicMock(spec=SSHTransport)
        transport.run.return_value = CommandResult(
            stdout=stored, exit_status=exit_status,
        )
        asyncio.run(executor.before_execute(transport))
        return executor, transport.upload_text_files.call_args[0][0]


class TestRetiringStoredCertificates(AcmePruneCase):

    def _run(self, stored, exit_status=0):
        return self._prepared(
            PushTrustedProxiesExecutor, "push_trusted_proxies",
            stored, exit_status,
        )

    def test_a_covered_name_is_staged_out_of_the_store(self):
        executor, files = self._run(STORE_WITH_COVERED)
        self.assertIn(acme_store.LOCAL_PATH, files)
        self.assertNotIn("a.edge-exec.example.com",
                         files[acme_store.LOCAL_PATH])

    def test_the_step_runs_before_the_proxy_restarts(self):
        """A restart is what makes the proxy forget them; doing it the
        other way round would leave the old store loaded."""
        executor, _ = self._run(STORE_WITH_COVERED)
        labels = [label for label, *_ in executor.get_commands()]
        self.assertLess(
            labels.index(self._STEP), labels.index("Restart Traefik"),
        )

    def test_nothing_to_retire_stages_nothing_and_adds_no_step(self):
        executor, files = self._run(STORE_WITHOUT_COVERED)
        self.assertNotIn(acme_store.LOCAL_PATH, files)
        self.assertNotIn(self._STEP, dict(executor.get_commands()))

    def test_a_store_that_cannot_be_read_is_left_alone(self):
        """A proxy that is not running answers nothing. Writing a store
        built from that would cost every certificate on it."""
        executor, files = self._run("", exit_status=1)
        self.assertNotIn(acme_store.LOCAL_PATH, files)
        self.assertNotIn(self._STEP, dict(executor.get_commands()))

    def test_a_host_with_no_certificate_of_its_own_retires_nothing(self):
        """With nothing to fall back on, retiring an entry would leave
        the name answered by a throwaway."""
        self.host.write({"tls_default_cert": False, "tls_default_key": False})
        executor, files = self._run(STORE_WITH_COVERED)
        self.assertNotIn(acme_store.LOCAL_PATH, files)
        self.assertNotIn(self._STEP, dict(executor.get_commands()))

    def test_the_certificate_is_still_installed_alongside(self):
        """The two halves ship together or the host serves neither."""
        _, files = self._run(STORE_WITH_COVERED)
        self.assertTrue(
            [path for path in files if path.endswith("-default.crt")],
        )


class TestTheWriteKeepsTheStoreUsable(EdgeExecutorCase):
    """Traefik refuses a store any other account can read, and then
    obtains nothing at all — silently."""

    def test_it_writes_through_the_existing_file(self):
        # ``cat >`` keeps the mode the file already has; moving a new
        # file over it would not.
        self.assertIn("sh -c 'cat > /etc/traefik/acme/acme.json'",
                      acme_store.WRITE_COMMAND)

    def test_it_reaches_the_store_through_the_container(self):
        """It lives in a named volume, not on the host filesystem."""
        self.assertIn("exec -T proxy", acme_store.WRITE_COMMAND)
        self.assertIn("exec -T proxy", acme_store.READ_COMMAND)

    def test_the_staged_copy_does_not_survive_a_success(self):
        self.assertIn(f"rm -f {acme_store.LOCAL_PATH}",
                      acme_store.WRITE_COMMAND)

    def test_a_failed_write_is_still_a_failed_step(self):
        """Sequenced with ``;`` the removal's exit status would mask it,
        and the host would report a prune that never happened."""
        self.assertIn(f"&& rm -f {acme_store.LOCAL_PATH}",
                      acme_store.WRITE_COMMAND)


class TestFullSetupConverges(AcmePruneCase):
    """A host set up again has to end up where a settings push would
    leave it, or the two jobs disagree about the same host."""

    def test_the_step_lands_before_the_proxy_comes_up(self):
        executor, _ = self._prepared(
            FullSetupExecutor, "full_setup", STORE_WITH_COVERED,
        )
        labels = [label for label, *_ in executor.get_commands()]
        self.assertLess(
            labels.index(self._STEP), labels.index("Start Traefik"),
        )

    def test_a_first_setup_has_no_store_to_prune(self):
        """Nothing is running yet, so the read fails — which is also
        the honest answer: there is nothing there."""
        executor, files = self._prepared(
            FullSetupExecutor, "full_setup", "", exit_status=1,
        )
        self.assertNotIn(acme_store.LOCAL_PATH, files)
        self.assertNotIn(self._STEP, dict(executor.get_commands()))


class TestTheJobChecksItsOwnWork(AcmePruneCase):
    """Writing the store is not evidence that the store changed.

    The write step reports the exit status of a redirection. That
    succeeds over a file that ends up truncated, and says nothing about
    whether the proxy came back at all — so without a read-back the job
    reports success while the host goes on serving exactly the
    certificates it was told to stop serving. Retiring one cannot be
    undone from behind a CDN, which is why this half is not optional.
    """

    def _executor_with_store(self, stored):
        executor, _ = self._prepared(
            PushTrustedProxiesExecutor, "push_trusted_proxies", stored,
        )
        return executor

    def _confirmed(self, executor, stdout, exit_status=0):
        """Run parse_results over a given read-back of the store."""
        results = {
            label: {"stdout": "", "exit_status": 0}
            for label, *_ in executor.get_commands()
        }
        results[acme_store.CONFIRM_LABEL] = {
            "stdout": stdout, "exit_status": exit_status,
        }
        return executor.parse_results(results)

    def test_the_store_is_read_back_after_the_restart(self):
        executor = self._executor_with_store(STORE_WITH_COVERED)
        labels = [label for label, *_ in executor.get_commands()]
        self.assertIn(acme_store.CONFIRM_LABEL, labels)
        self.assertLess(
            labels.index("Restart Traefik"),
            labels.index(acme_store.CONFIRM_LABEL),
            "reading before the restart proves nothing about what it "
            "came back holding",
        )

    def test_an_emptied_store_is_accepted(self):
        executor = self._executor_with_store(STORE_WITH_COVERED)
        self.assertEqual(self._confirmed(executor, _store_json()), [])

    def test_a_name_that_survived_fails_the_job(self):
        executor = self._executor_with_store(STORE_WITH_COVERED)
        errors = self._confirmed(executor, STORE_WITH_COVERED)
        self.assertTrue(errors)
        self.assertIn("a.edge-exec.example.com", errors[0])

    def test_a_store_that_cannot_be_read_fails_the_job(self):
        """Which is also what a proxy that did not come back looks
        like: the read goes through the container."""
        executor = self._executor_with_store(STORE_WITH_COVERED)
        errors = self._confirmed(executor, "", exit_status=1)
        self.assertTrue(errors)

    def test_a_store_that_does_not_parse_fails_the_job(self):
        """Traefik holds no certificates at all from one it cannot
        read, and answers every handshake with a throwaway."""
        executor = self._executor_with_store(STORE_WITH_COVERED)
        self.assertTrue(self._confirmed(executor, "{tru"))

    def test_another_name_left_in_the_store_is_not_our_business(self):
        """Only what this run set out to retire is checked. A customer
        domain still reached directly keeps its certificate, and
        reading that as a failure would fail every healthy run."""
        executor = self._executor_with_store(STORE_WITH_COVERED)
        self.assertEqual(
            self._confirmed(executor, STORE_WITHOUT_COVERED), [],
        )

    def test_a_run_with_nothing_to_retire_adds_no_check(self):
        executor = self._executor_with_store(STORE_WITHOUT_COVERED)
        labels = [label for label, *_ in executor.get_commands()]
        self.assertNotIn(acme_store.CONFIRM_LABEL, labels)
        self.assertEqual(executor.parse_results({}), [])
