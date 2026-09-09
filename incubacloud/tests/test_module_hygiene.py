"""Mechanical guards for migration folders that never run.

A migration is the one kind of code that has no test of its own and no
second chance: it runs once, during an upgrade, or it does not run at
all. Odoo decides which folders to execute in
``odoo/modules/migration.py`` and the three ways of losing one are all
silent — the module still loads, the upgrade still succeeds, and the
suite still passes.

The three, in the order they bite:

* **The manifest was not bumped.** ``migrate_module`` runs a folder only
  when ``installed < folder <= manifest``, so a folder numbered above
  the declared version is skipped for good. Bumping the manifest later
  does not help either: by then the module is already installed at that
  version, and the left-hand comparison excludes it.
* **The folder name is not a version Odoo recognises.**
  ``_verify_upgrade_version`` drops anything ``VERSION_RE`` rejects with
  a ``warning``, which nobody reads during an upgrade.
* **The folder holds no script Odoo will run.** Only files whose name
  starts with ``pre-``, ``post-`` or ``end-`` are collected; a folder of
  helpers alone contributes nothing.

Deliberately duplicated in ``incubacloud_saas_manager``'s own hygiene
suite rather than imported from here: each repository then guards its
own modules without its CI depending on the other one being present.
"""
import ast
import pathlib

from odoo.modules.migration import VERSION_RE
from odoo.modules.module import adapt_version
from odoo.release import major_version
from odoo.tests.common import BaseCase
from odoo.tools.parse_version import parse_version

#: Prefixes ``MigrationManager._get_migration_files`` collects. Anything
#: else in the folder is a helper at best.
_RUNNABLE_PREFIXES = ("pre-", "post-", "end-")

#: Runs on every version change, so it is exempt from the ordering rule.
_ALWAYS = "0.0.0"


def _convert_version(version):
    """Return *version* as ``migrate_module`` compares it.

    Mirrors the ``convert_version`` closure in
    ``odoo/modules/migration.py``: more than two dots means the folder
    already names a server series, anything shorter is prefixed with
    this one. It is a closure, so it cannot be imported — this is the
    only piece of Odoo's rule reproduced here rather than reused.
    """
    if version == _ALWAYS or version.count(".") > 2:
        return version
    return f"{major_version}.{version}"


def _modules_with_migrations():
    """Yield ``(module name, adapted version, migrations dir)`` per module.

    Walks the repository this test file lives in, so a module is covered
    the moment it exists on disk — including one not currently linked
    into the addons path, which is exactly when a stray folder goes
    unnoticed.
    """
    repo = pathlib.Path(__file__).resolve().parents[2]
    for manifest_path in sorted(repo.glob("*/__manifest__.py")):
        migrations = manifest_path.parent / "migrations"
        if not migrations.is_dir():
            continue
        manifest = ast.literal_eval(manifest_path.read_text())
        yield (
            manifest_path.parent.name,
            adapt_version(str(manifest.get("version", "1.0"))),
            migrations,
        )


def _migration_folders():
    """Yield ``(module name, adapted version, folder name, path)``."""
    for module, version, migrations in _modules_with_migrations():
        for folder in sorted(p for p in migrations.iterdir() if p.is_dir()):
            yield module, version, folder.name, folder


class TestEveryMigrationCanRun(BaseCase):

    def test_no_migration_folder_is_above_the_manifest_version(self):
        """A folder numbered past the manifest is dead on arrival."""
        stranded = []
        for module, version, name, _path in _migration_folders():
            if name == _ALWAYS or not VERSION_RE.match(name):
                continue  # covered by the name test below
            folder = parse_version(_convert_version(name))
            declared = parse_version(_convert_version(version))
            if folder > declared:
                stranded.append(
                    f"{module}: migrations/{name} > manifest {version}"
                )
        self.assertFalse(
            stranded,
            "migration folder(s) above the declared version — Odoo will "
            "never run them; bump the manifest in the same commit:\n%s"
            % "\n".join(stranded),
        )

    def test_every_migration_folder_name_is_a_version_odoo_accepts(self):
        """A name VERSION_RE rejects is dropped with a warning nobody sees."""
        rejected = [
            f"{module}: migrations/{name}"
            for module, _version, name, _path in _migration_folders()
            if not VERSION_RE.match(name)
        ]
        self.assertFalse(
            rejected,
            "migration folder name(s) Odoo's VERSION_RE rejects, so it "
            "skips them with a log warning:\n%s" % "\n".join(rejected),
        )

    def test_every_migration_folder_holds_a_script_odoo_will_run(self):
        """A folder of helpers alone contributes nothing to the upgrade."""
        empty = [
            f"{module}: migrations/{name}"
            for module, _version, name, path in _migration_folders()
            if not any(
                script.name.startswith(_RUNNABLE_PREFIXES)
                for script in path.glob("*.py")
            )
        ]
        self.assertFalse(
            empty,
            "migration folder(s) with no pre-/post-/end- script, so "
            "nothing in them runs:\n%s" % "\n".join(empty),
        )
