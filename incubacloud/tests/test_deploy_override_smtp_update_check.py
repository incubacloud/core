"""The instance ``smtp`` container must not poll GitHub for releases.

docker-mailserver ships an ``update-check`` service that asks GitHub for
the latest release and, when the running image is older, mails
postmaster once per container start. Three things turn that into a
flood here: copier renders the hostname as ``smtp.<relay domain>``, so
all twelve instances relaying through ``incubacloud.io`` announce
themselves under the *same* name; free tenants restart on every Sablier
wake, so "once per start" is several times a day each; and the tag the
instances run (``smtp_relay_version``) is the panel's to move, never
the container's to announce.

The override the panel writes on every deploy and rebuild is where the
switch belongs: ``copier update`` regenerates ``common.yaml``,
``prod.yaml`` and ``.docker/smtp.env``, so anything written there is
lost on the next rebuild.
"""
import yaml

from odoo.tests.common import TransactionCase

from odoo.addons.incubacloud.models.deploy_instance_executor import (
    DeployInstanceExecutor,
)
from odoo.addons.incubacloud.models.rebuild_instance_executor import (
    RebuildInstanceExecutor,
)
from odoo.addons.incubacloud.models.registry import executor_registry


class _SmtpOverrideCase(TransactionCase):

    def setUp(self):
        super().setUp()
        self.project = self.env["cloud.project"].create({"name": "Updchk Proj"})
        self.host = self.env["cloud.host"].create({
            "name": "updchk-host",
            "ip_address": "192.0.2.63",
            "user": "ubuntu",
            "wildcard_domain": "updchk.example.com",
        })
        self.instance = self.env["cloud.instance"].create({
            "name": "updchkinst",
            "project_id": self.project.id,
            "environment": "production",
            "host_id": self.host.id,
            "smtp_relay_host": "smtp.example.com",
        })

    def _executor(self, executor_cls, job_type_code, inst=None):
        """Build *executor_cls* around a fresh job on *inst*."""
        inst = inst or self.instance
        job_type = self.env["cloud.job.type"].search(
            [("code", "=", job_type_code)], limit=1,
        )
        self.assertTrue(job_type, f"job type {job_type_code} must exist")
        job = self.env["cloud.job"].create({
            "name": f"Updchk {job_type_code}",
            "host_id": self.host.id,
            "instance_id": inst.id,
            "job_type_id": job_type.id,
        })
        return executor_cls(job, self.host)

    def _override(self, executor):
        raw = executor._resource_override_content()
        self.assertTrue(raw, "override must never be None")
        return raw, yaml.safe_load(raw)


class TestSmtpUpdateCheckDisabled(_SmtpOverrideCase):

    def test_deploy_disables_the_update_check(self):
        executor = self._executor(DeployInstanceExecutor, "deploy_instance")
        _raw, data = self._override(executor)
        self.assertIn("smtp", data["services"])
        self.assertEqual(
            data["services"]["smtp"].get("environment"),
            {"ENABLE_UPDATE_CHECK": "0"},
        )

    def test_rebuild_disables_the_update_check(self):
        """``copier update`` regenerates the compose files every rebuild,
        so the rebuild flavour has to re-ship the switch too."""
        executor = self._executor(RebuildInstanceExecutor, "rebuild_instance")
        _raw, data = self._override(executor)
        self.assertEqual(
            data["services"]["smtp"].get("environment"),
            {"ENABLE_UPDATE_CHECK": "0"},
        )

    def test_value_is_quoted_as_a_string(self):
        """A bare ``0`` is a YAML integer; compose wants scalars it can
        hand to the container as text, and the file stays unambiguous."""
        raw, _data = self._override(
            self._executor(DeployInstanceExecutor, "deploy_instance")
        )
        self.assertIn("ENABLE_UPDATE_CHECK: '0'", raw)

    def test_no_other_service_gets_an_environment_block(self):
        """odoo and db take their environment from doodba's env_files;
        an ``environment:`` here would merge into them for no reason."""
        _raw, data = self._override(
            self._executor(DeployInstanceExecutor, "deploy_instance")
        )
        for svc, entry in data["services"].items():
            if svc == "smtp":
                continue
            self.assertNotIn(
                "environment", entry,
                f"service {svc!r} must not carry an environment block",
            )

    def test_limits_label_and_logging_survive_alongside_it(self):
        self.instance.write({"smtp_memory_limit": "512m", "smtp_cpus": 1.0})
        _raw, data = self._override(
            self._executor(DeployInstanceExecutor, "deploy_instance")
        )
        smtp = data["services"]["smtp"]
        self.assertEqual(smtp["mem_limit"], "512m")
        self.assertEqual(smtp["cpus"], 1.0)
        self.assertTrue(smtp.get("labels"))
        self.assertTrue(smtp.get("logging"))
        self.assertEqual(smtp["environment"], {"ENABLE_UPDATE_CHECK": "0"})

    def test_instance_without_relay_renders_no_smtp_service(self):
        """No relay means the service is stripped from prod.yaml; naming
        it in the override would break ``docker compose`` outright."""
        # Its own project: one production instance per project is a
        # database-level exclusion constraint.
        other = self.env["cloud.project"].create({"name": "Updchk Proj 2"})
        norelay = self.env["cloud.instance"].create({
            "name": "updchknorelay",
            "project_id": other.id,
            "environment": "production",
            "host_id": self.host.id,
        })
        _raw, data = self._override(
            self._executor(
                DeployInstanceExecutor, "deploy_instance", inst=norelay,
            )
        )
        self.assertNotIn("smtp", data["services"])

    def test_staging_renders_no_smtp_service(self):
        staging = self.env["cloud.instance"].create({
            "name": "updchkstag",
            "project_id": self.project.id,
            "environment": "staging",
            "host_id": self.host.id,
            "smtp_relay_host": "smtp.example.com",
        })
        _raw, data = self._override(
            self._executor(
                DeployInstanceExecutor, "deploy_instance", inst=staging,
            )
        )
        self.assertNotIn("smtp", data["services"])

    def test_every_registered_deploy_flavour_disables_it(self):
        """Registry sweep: a flavour that breaks super() fails here."""
        flavours = {
            code: cls
            for code, cls in executor_registry.all().items()
            if isinstance(cls, type)
            and issubclass(cls, DeployInstanceExecutor)
        }
        self.assertIn("deploy_instance", flavours)
        self.assertIn("rebuild_instance", flavours)
        for code, cls in flavours.items():
            with self.subTest(job_type=code, executor=cls.__name__):
                _raw, data = self._override(self._executor(cls, code))
                if "smtp" not in data["services"]:
                    continue
                self.assertEqual(
                    data["services"]["smtp"].get("environment"),
                    {"ENABLE_UPDATE_CHECK": "0"},
                )
