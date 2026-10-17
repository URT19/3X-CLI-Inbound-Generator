import json
import os
import shutil
import subprocess
import tempfile
import unittest

from config.settings import Settings, load_settings
from core.menu import CONFIRM_WORD, Menu
from certs.checker import default_runner
from tests.test_certs import HAVE_OPENSSL, make_cert


def drive(script, settings, settings_path, cert_root, acme_bin, runner_calls=None, runner=None):
    inputs = iter(script)
    out = []
    calls = runner_calls if runner_calls is not None else []

    def fake_acme(argv):
        if not argv[0].endswith("acme.sh"):
            return default_runner(argv)  # openssl checks run for real
        calls.append(argv)
        if "--installcert" in argv:
            full = argv[argv.index("--fullchain-file") + 1]
            key = argv[argv.index("--key-file") + 1]
            domain_dir = os.path.dirname(full)
            os.makedirs(domain_dir, exist_ok=True)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", key, "-out", full, "-days", "90", "-subj", "/CN=example.test",
                            "-addext", "subjectAltName=DNS:example.test"], check=True, capture_output=True)
        return 0, "", ""

    settings = settings or Settings(cert_root=cert_root)
    menu = Menu(
        None,
        input_fn=lambda p="": next(inputs),
        output_fn=lambda t: out.append(str(t)),
        settings=settings,
        settings_path=settings_path,
        runner=runner or fake_acme,
        acme_bin=acme_bin,
    )
    menu.run()
    return menu, "\n".join(out), calls


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class SslMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "cert")
        self.settings_path = os.path.join(self.tmp, "settings.json")
        self.acme = os.path.join(self.tmp, "acme.sh")
        open(self.acme, "w").close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ssl_not_needed_is_recorded(self):
        menu, text, calls = drive(["5", "1", "example.test", "n", "0", "0"], None,
                                  self.settings_path, self.root, self.acme)
        self.assertIn("SSL not needed", text)
        self.assertEqual(calls, [])
        self.assertEqual(load_settings(self.settings_path).ssl_domains["example.test"], {"needed": False})

    def test_taken_and_valid_is_reported_without_issuing(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=90)
        menu, text, calls = drive(["5", "1", "example.test", "y", "y", "0", "0"], None,
                                  self.settings_path, self.root, self.acme)
        self.assertIn("example.test: ok", text)
        self.assertEqual(calls, [])
        self.assertEqual(menu.settings.ssl_domains["example.test"]["last_state"], "ok")

    def test_taken_and_due_for_renewal_offers_issue(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=10)
        menu, text, calls = drive(["5", "1", "example.test", "y", "y", "n", "0", "0"], None,
                                  self.settings_path, self.root, self.acme)
        self.assertIn("renew", text)
        self.assertEqual(calls, [])

    def test_issue_when_missing_requires_confirm(self):
        menu, text, calls = drive(
            ["5", "1", "example.test", "y", "n", "", CONFIRM_WORD, "0", "0"],
            None, self.settings_path, self.root, self.acme,
        )
        self.assertIn("Planned commands", text)
        self.assertTrue(any("--issue" in c for c in calls))
        self.assertTrue(any("--installcert" in c for c in calls))
        self.assertIn("Done and verified", text)
        self.assertEqual(menu.settings.ssl_domains["example.test"]["last_state"], "ok")

    def test_issue_cancelled_runs_nothing(self):
        _, text, calls = drive(
            ["5", "1", "example.test", "y", "n", "", "no", "0", "0"],
            None, self.settings_path, self.root, self.acme,
        )
        self.assertIn("Cancelled", text)
        self.assertEqual(calls, [])

    def test_missing_acme_is_reported(self):
        _, text, calls = drive(
            ["5", "1", "example.test", "y", "n", "0", "0"],
            None, self.settings_path, self.root, os.path.join(self.tmp, "absent.sh"),
        )
        self.assertIn("acme.sh not found", text)
        self.assertEqual(calls, [])

    def test_invalid_domain_refused(self):
        _, text, calls = drive(["5", "1", "bad domain", "0", "0"], None,
                               self.settings_path, self.root, self.acme)
        self.assertIn("Not a valid domain", text)
        self.assertEqual(calls, [])

    def test_no_private_key_content_is_printed(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=90)
        _, text, _ = drive(["5", "1", "example.test", "y", "y", "0", "0"], None,
                           self.settings_path, self.root, self.acme)
        self.assertNotIn("BEGIN PRIVATE KEY", text)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", text)


if __name__ == "__main__":
    unittest.main()
