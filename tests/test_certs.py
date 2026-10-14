import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from certs.acme import AcmeError, build_issue_plan, run_plan
from certs.checker import check_domain_cert, cert_paths, domain_matches

HAVE_OPENSSL = shutil.which("openssl") is not None


def make_cert(directory, domain, days=90, san=None):
    os.makedirs(directory, exist_ok=True)
    key = os.path.join(directory, "privkey.pem")
    full = os.path.join(directory, "fullchain.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", full, "-days", str(days), "-subj", f"/CN={domain}",
                    "-addext", f"subjectAltName={san or 'DNS:' + domain}"],
                   check=True, capture_output=True)
    os.chmod(key, 0o600)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class RealCertificateTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_valid_certificate_is_ok(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=90)
        s = check_domain_cert(self.root, "example.test")
        self.assertEqual(s.state, "ok")
        self.assertGreater(s.days_left, 80)
        self.assertTrue(s.key_permissions_ok)

    def test_certificate_due_for_renewal(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=10)
        self.assertEqual(check_domain_cert(self.root, "example.test").state, "renew")

    def test_expired_when_now_is_after_expiry(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test", days=5)
        later = datetime.now(timezone.utc) + timedelta(days=30)
        self.assertEqual(check_domain_cert(self.root, "example.test", now=later).state, "expired")

    def test_name_mismatch(self):
        make_cert(os.path.join(self.root, "example.test"), "example.test")
        make_cert(os.path.join(self.root, "other.test"), "other.test")
        shutil.copy(os.path.join(self.root, "other.test", "fullchain.pem"),
                    os.path.join(self.root, "example.test", "fullchain.pem"))
        self.assertEqual(check_domain_cert(self.root, "example.test").state, "mismatch")

    def test_key_does_not_match_certificate(self):
        make_cert(os.path.join(self.root, "a.test"), "a.test")
        make_cert(os.path.join(self.root, "b.test"), "b.test")
        target = os.path.join(self.root, "b.test")
        # Keep b's certificate but swap in a's private key.
        shutil.copy(os.path.join(self.root, "a.test", "privkey.pem"), os.path.join(target, "privkey.pem"))
        os.chmod(os.path.join(target, "privkey.pem"), 0o600)
        self.assertEqual(check_domain_cert(self.root, "b.test").state, "mismatch")

    def test_key_readable_by_others_is_flagged(self):
        d = os.path.join(self.root, "example.test")
        make_cert(d, "example.test")
        os.chmod(os.path.join(d, "privkey.pem"), 0o644)
        s = check_domain_cert(self.root, "example.test")
        self.assertIs(s.key_permissions_ok, False)

    def test_wildcard_name_covers_one_label(self):
        d = os.path.join(self.root, "x.test")
        make_cert(d, "x.test", san="DNS:*.x.test")
        self.assertTrue(domain_matches("a.x.test", ["*.x.test"]))
        self.assertFalse(domain_matches("a.b.x.test", ["*.x.test"]))


class CheckerWithFakeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.domain_dir = os.path.join(self.root, "example.test")
        os.makedirs(self.domain_dir)
        for name in ("fullchain.pem", "privkey.pem"):
            with open(os.path.join(self.domain_dir, name), "w") as fh:
                fh.write("x")
        os.chmod(os.path.join(self.domain_dir, "privkey.pem"), 0o600)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_missing_files(self):
        empty = tempfile.mkdtemp()
        try:
            self.assertEqual(check_domain_cert(empty, "example.test", runner=lambda a: (0, "", "")).state, "missing")
        finally:
            shutil.rmtree(empty)

    def test_unparseable_certificate(self):
        s = check_domain_cert(self.root, "example.test", runner=lambda a: (1, "", "bad"))
        self.assertEqual(s.state, "invalid")

    def test_cert_paths_follow_spec_layout(self):
        full, key = cert_paths("/cert_folder/cert", "sub.domain.com")
        self.assertEqual(full, "/cert_folder/cert/sub.domain.com/fullchain.pem")
        self.assertEqual(key, "/cert_folder/cert/sub.domain.com/privkey.pem")


class AcmePlanTests(unittest.TestCase):
    def test_plan_is_argument_lists_with_panel_style_steps(self):
        plan = build_issue_plan("example.test", "/cert_folder/cert", 80, acme_bin="/x/acme.sh")
        self.assertEqual(len(plan), 3)
        self.assertTrue(all(isinstance(step, list) for step in plan))
        self.assertIn("--standalone", plan[1])
        self.assertIn("letsencrypt", plan[0])
        self.assertIn("/cert_folder/cert/example.test/fullchain.pem", plan[2])
        self.assertIn("/cert_folder/cert/example.test/privkey.pem", plan[2])
        self.assertNotIn("--reloadcmd", " ".join(sum(plan, [])))

    def test_invalid_domain_and_port_refused(self):
        with self.assertRaises(AcmeError):
            build_issue_plan("bad domain", "/c")
        with self.assertRaises(AcmeError):
            build_issue_plan("example.test", "/c", 70000)

    def test_run_plan_stops_at_first_failure(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return (1, "", "") if "--issue" in argv else (0, "", "")

        root = tempfile.mkdtemp()
        try:
            plan = build_issue_plan("example.test", root, 80, acme_bin="/x/acme.sh")
            error = run_plan(plan, root, "example.test", runner)
            self.assertIn("failed", error)
            self.assertEqual(len(calls), 2)  # installcert never runs
        finally:
            shutil.rmtree(root)

    def test_run_plan_sets_key_permissions(self):
        root = tempfile.mkdtemp()
        try:
            d = os.path.join(root, "example.test")
            plan = build_issue_plan("example.test", root, 80, acme_bin="/x/acme.sh")

            def runner(argv):
                if "--installcert" in argv:
                    os.makedirs(d, exist_ok=True)
                    for name in ("fullchain.pem", "privkey.pem"):
                        open(os.path.join(d, name), "w").close()
                return 0, "", ""

            self.assertIsNone(run_plan(plan, root, "example.test", runner))
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "privkey.pem")).st_mode), 0o600)
        finally:
            shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
