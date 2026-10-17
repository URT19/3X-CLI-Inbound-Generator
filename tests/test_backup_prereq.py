import json
import os
import shutil
import stat
import tarfile
import tempfile
import unittest

from config.settings import Settings, load_settings, save_settings
from core.menu import CONFIRM_WORD, Menu
from core.prereq import check_prerequisites, install_plan, ubuntu_info, Item
from state.records import append_record
from templates.loader import load_library
from utils.backup import BackupError, create_backup, read_archive, restore_backup, summarize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_project(root):
    """A minimal project tree with templates, settings, cloudflare ports and records."""
    shutil.copytree(os.path.join(ROOT, "inbounds"), os.path.join(root, "inbounds"))
    os.makedirs(os.path.join(root, "config"), exist_ok=True)
    shutil.copy(os.path.join(ROOT, "config", "cloudflare_ports.json"), os.path.join(root, "config"))
    save_settings(os.path.join(root, "config", "settings.json"),
                  Settings(panel_address="203.0.113.4:2053", api_token="SECRET_TOKEN_1234"))
    append_record(os.path.join(root, "state", "local_inbounds"), "direct",
                  {"inbound_id": 1, "name": "02-VMESS-TCP-DIRECT-TLS", "port": 9000})


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()
        make_project(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def test_backup_contains_templates_settings_and_records(self):
        path = create_backup(self.root, self.out, "1.0.0")
        with tarfile.open(path) as tar:
            names = tar.getnames()
        self.assertIn("manifest.json", names)
        self.assertIn("config/settings.json", names)
        self.assertIn("state/local_inbounds/direct.json", names)
        self.assertTrue(any(n.startswith("inbounds/") and n.endswith(".json") for n in names))

    def test_archive_is_private(self):
        path = create_backup(self.root, self.out, "1.0.0")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_round_trip_restores_identical_files(self):
        path = create_backup(self.root, self.out, "1.0.0")
        target = tempfile.mkdtemp()
        try:
            restored = restore_backup(path, target, "1.0.0")
            self.assertIn("config/settings.json", restored)
            self.assertEqual(
                open(os.path.join(target, "config", "settings.json")).read(),
                open(os.path.join(self.root, "config", "settings.json")).read(),
            )
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(target, "config", "settings.json")).st_mode), 0o600)
            load_library(os.path.join(target, "inbounds"))
            self.assertEqual(load_settings(os.path.join(target, "config", "settings.json")).api_token,
                             "SECRET_TOKEN_1234")
        finally:
            shutil.rmtree(target, ignore_errors=True)

    def test_summary_reads_manifest_without_writing(self):
        path = create_backup(self.root, self.out, "1.0.0")
        manifest = summarize(path)
        self.assertEqual(manifest["app_version"], "1.0.0")
        self.assertGreater(len(manifest["files"]), 20)

    def test_tampered_file_is_refused(self):
        path = create_backup(self.root, self.out, "1.0.0")
        bad = os.path.join(self.out, "bad.tar.gz")
        with tarfile.open(path) as src, tarfile.open(bad, "w:gz") as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == "state/local_inbounds/direct.json":
                    data = data.replace(b"9000", b"9999")
                import io
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(BackupError, "Hash mismatch"):
            summarize(bad)

    def test_path_traversal_member_refused(self):
        bad = os.path.join(self.out, "evil.tar.gz")
        import io
        with tarfile.open(bad, "w:gz") as tar:
            data = b'{"backup_version": 1, "files": []}'
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            payload = b"{}"
            info = tarfile.TarInfo("inbounds/../../escape.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        with self.assertRaisesRegex(BackupError, "unexpected entry"):
            summarize(bad)

    def test_invalid_settings_in_backup_refused_and_nothing_written(self):
        path = create_backup(self.root, self.out, "1.0.0")
        bad = os.path.join(self.out, "bad2.tar.gz")
        import io
        staging = tempfile.mkdtemp()
        try:
            with tarfile.open(path) as src:
                members = [(m.name, src.extractfile(m).read()) for m in src.getmembers()]
            fixed = []
            for name, data in members:
                if name == "config/settings.json":
                    data = b'{"verify_tls": "maybe"}'
                fixed.append((name, data))
            # Re-sign the manifest so only the settings check can fail.
            import hashlib
            manifest = json.loads([d for n, d in fixed if n == "manifest.json"][0])
            for entry in manifest["files"]:
                for n, d in fixed:
                    if n == entry["path"]:
                        entry["sha256"] = hashlib.sha256(d).hexdigest()
                        entry["size"] = len(d)
            fixed = [(n, (json.dumps(manifest).encode() if n == "manifest.json" else d)) for n, d in fixed]
            with tarfile.open(bad, "w:gz") as dst:
                for name, data in fixed:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    dst.addfile(info, io.BytesIO(data))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        target = tempfile.mkdtemp()
        try:
            with self.assertRaisesRegex(BackupError, "Settings in backup are invalid"):
                restore_backup(bad, target, "1.0.0")
            self.assertFalse(os.path.exists(os.path.join(target, "config", "settings.json")))
        finally:
            shutil.rmtree(target, ignore_errors=True)

    def test_restore_keeps_safety_copy_of_current_files(self):
        path = create_backup(self.root, self.out, "1.0.0")
        restore_backup(path, self.root, "1.0.0")
        safety = [f for f in os.listdir(os.path.join(self.root, "backups")) if f.endswith(".tar.gz")]
        self.assertEqual(len(safety), 1)


class MenuBackupTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        make_project(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_menu(self, script):
        inputs = iter(script)
        out = []
        menu = Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
                    root=self.root, library_dir=os.path.join(self.root, "inbounds"),
                    settings_path=os.path.join(self.root, "config", "settings.json"))
        menu.run()
        return "\n".join(out)

    def test_menu_backup_creates_archive_in_backups_folder(self):
        text = self.run_menu(["10", "1", "0", "0"])
        self.assertIn("Backup written", text)
        self.assertTrue(any(f.endswith(".tar.gz") for f in os.listdir(os.path.join(self.root, "backups"))))
        self.assertIn("API token", text)

    def test_menu_restore_requires_confirm(self):
        self.run_menu(["10", "1", "0", "0"])
        archive = os.path.join(self.root, "backups", os.listdir(os.path.join(self.root, "backups"))[0])
        text = self.run_menu(["10", "2", archive, "no", "0", "0"])
        self.assertIn("Cancelled", text)

    def test_menu_restore_with_confirm_reloads(self):
        self.run_menu(["10", "1", "0", "0"])
        archive = os.path.join(self.root, "backups", os.listdir(os.path.join(self.root, "backups"))[0])
        text = self.run_menu(["10", "2", archive, CONFIRM_WORD, "0", "0"])
        self.assertIn("Restored", text)

    def test_menu_restore_bad_file_reported(self):
        bogus = os.path.join(self.root, "not-a-backup.tar.gz")
        with open(bogus, "w") as fh:
            fh.write("junk")
        text = self.run_menu(["10", "2", bogus, "0", "0"])
        self.assertIn("valid backup archive", text)


class PrereqTests(unittest.TestCase):
    def test_check_reports_missing_and_present(self):
        found = {"openssl": "/usr/bin/openssl"}
        items = check_prerequisites("/nonexistent/acme.sh",
                                    which=lambda name: found.get(name), python_version=(3, 12))
        by = {i.name: i for i in items}
        self.assertTrue(by["openssl"].ok)
        self.assertFalse(by["curl"].ok)
        self.assertFalse(by["acme.sh"].ok)
        self.assertTrue(by["python3"].ok)

    def test_old_python_is_flagged(self):
        items = check_prerequisites("/x", which=lambda n: "/x", python_version=(3, 8))
        self.assertFalse({i.name: i for i in items}["python3"].ok)

    def test_install_plan_only_for_apt_packages_and_argv_form(self):
        items = [Item("openssl", True, False, ""), Item("curl", False, False, ""),
                 Item("acme.sh", False, False, "")]
        plan = install_plan(items, apt_available=True)
        self.assertEqual(plan, ["apt-get", "install", "-y", "openssl", "curl"])
        self.assertIsNone(install_plan(items, apt_available=False))

    def test_haproxy_and_nginx_are_checked_and_installable(self):
        items = check_prerequisites("/x", which=lambda n: None, python_version=(3, 12))
        by = {i.name: i for i in items}
        self.assertFalse(by["haproxy"].ok)
        self.assertFalse(by["nginx"].ok)
        self.assertFalse(by["haproxy"].required)
        plan = install_plan([by["haproxy"], by["nginx"]], apt_available=True)
        self.assertEqual(plan, ["apt-get", "install", "-y", "haproxy", "nginx"])

    def test_ubuntu_detection(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write('ID=ubuntu\nVERSION_ID="24.04"\n')
        try:
            self.assertEqual(ubuntu_info(fh.name), (True, "ubuntu 24.04"))
        finally:
            os.remove(fh.name)


if __name__ == "__main__":
    unittest.main()
