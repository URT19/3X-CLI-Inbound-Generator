import json
import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings, load_settings
from core.menu import CONFIRM_WORD, Menu
from core.preflight import validate_payload
from network.cloudflare import CloudflarePorts
from network.paths import generate_all
from panel.client import PanelClient
from state.records import load_records
from templates.loader import load_library
from tests.test_certs import HAVE_OPENSSL, make_cert
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(
    source="t", retrieved="t",
    http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
    https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}),
)
CDN = "cdn.example.test"
DIRECT = "direct.example.test"


class Env:
    def __init__(self, with_certs=True, fixed_port=None, paths=True, cdn_domain=CDN,
                 direct_domain=DIRECT, cloudflare_ips=("203.0.113.1",)):
        self.dir = tempfile.mkdtemp()
        self.cert_root = os.path.join(self.dir, "cert")
        self.state_dir = os.path.join(self.dir, "state")
        if with_certs and HAVE_OPENSSL:
            make_cert(os.path.join(self.cert_root, CDN), CDN, days=90)
            make_cert(os.path.join(self.cert_root, DIRECT), DIRECT, days=90)
        net = NetworkSettings(
            cloudflare_ips=list(cloudflare_ips),
            direct_domain=direct_domain or "",
            cdn_domain=cdn_domain or "",
            port_mode="fixed" if fixed_port else "random",
            fixed_port=fixed_port,
            random_port_low=20000,
            random_port_high=20010,
        )
        self.settings = Settings(cert_root=self.cert_root, network=net,
                                 paths=generate_all() if paths else {}, fingerprint="chrome")
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.ordered = sorted(self.library.values(), key=lambda t: (t.number, t.template_id))

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def index(self, template_id, mode=None):
        pool = [t for t in self.ordered if mode is None or t.connection_mode == mode]
        return next(i for i, t in enumerate(pool, 1) if t.template_id == template_id)

    def run(self, script, panel):
        inputs = iter(script)
        out = []
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        menu = Menu(client, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
                    library=self.library, settings=self.settings, cloudflare=CF,
                    state_dir=self.state_dir)
        menu.run()
        return menu, "\n".join(out)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class TlsFlowTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()

    def tearDown(self):
        self.env.close()

    def test_direct_tls_created_with_settings_values_and_no_prompts(self):
        panel = FakePanel()
        idx = self.env.index("tls_tcp_direct", "direct")
        # Only menu choices and confirmations are typed. No port, path, domain or name prompts.
        script = ["4", "1", str(idx), CONFIRM_WORD, "0"]
        _, text = self.env.run(script, panel)
        self.assertIn("Done and verified", text)
        payload = panel.inbounds[0]
        self.assertTrue(20000 <= payload["port"] <= 20010)
        self.assertEqual(payload["remark"], "02-VMESS-TCP-DIRECT-TLS")
        self.assertEqual(payload["streamSettings"]["tlsSettings"]["serverName"], DIRECT)
        cert = payload["streamSettings"]["tlsSettings"]["certificates"][0]
        self.assertTrue(cert["certificateFile"].endswith(f"{DIRECT}/fullchain.pem"))
        self.assertTrue(cert["keyFile"].endswith(f"{DIRECT}/privkey.pem"))
        self.assertTrue(os.access(cert["certificateFile"], os.R_OK))
        self.assertTrue(os.access(cert["keyFile"], os.R_OK))
        self.assertEqual(payload["streamSettings"]["tlsSettings"]["settings"]["fingerprint"], "chrome")

    def test_cdn_tls_ws_uses_cdn_domain_path_and_certificates(self):
        panel = FakePanel()
        idx = self.env.index("tls_ws_cdn", "cdn")
        script = ["5", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"]  # route, inbound, then hosts
        _, text = self.env.run(script, panel)
        payload = panel.inbounds[0]
        ws = payload["streamSettings"]["wsSettings"]
        self.assertEqual(ws["path"], self.env.settings.paths["cdn_ws"])
        self.assertEqual(ws["host"], CDN)
        self.assertEqual(payload["streamSettings"]["tlsSettings"]["serverName"], CDN)
        self.assertEqual(len(panel.hosts), 1)
        self.assertEqual(panel.hosts[0]["hosts"][0], "203.0.113.1")

    def test_local_record_written_per_connection_type(self):
        panel = FakePanel()
        idx = self.env.index("tls_tcp_direct", "direct")
        self.env.run(["4", "1", str(idx), CONFIRM_WORD, "0"], panel)
        records = load_records(self.env.state_dir, "direct")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["domain"], DIRECT)
        self.assertEqual(records[0]["template_version"], "1.1.0")
        self.assertEqual(load_records(self.env.state_dir, "cdn"), [])

    def test_cdn_record_uses_cdn_domain_and_path(self):
        panel = FakePanel()
        idx = self.env.index("tls_ws_cdn", "cdn")
        self.env.run(["5", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], panel)
        records = load_records(self.env.state_dir, "cdn")
        self.assertEqual(records[0]["domain"], CDN)
        self.assertEqual(records[0]["path"], self.env.settings.paths["cdn_ws"])

    def test_cancel_sends_nothing_and_writes_no_record(self):
        panel = FakePanel()
        idx = self.env.index("tls_tcp_direct", "direct")
        self.env.run(["4", "1", str(idx), "no", "0"], panel)
        self.assertEqual(panel.writes, [])
        self.assertEqual(load_records(self.env.state_dir, "direct"), [])

    def test_missing_certificate_refused_before_sending(self):
        shutil.rmtree(os.path.join(self.env.cert_root, DIRECT))
        panel = FakePanel()
        idx = self.env.index("tls_tcp_direct", "direct")
        _, text = self.env.run(["4", "1", str(idx), "0"], panel)
        self.assertIn("Certificate file not readable", text)
        self.assertEqual(panel.writes, [])

    def test_expired_style_status_refused(self):
        panel = FakePanel()
        idx = self.env.index("tls_tcp_direct", "direct")
        menu_env = self.env
        from certs.checker import CertStatus
        from core import preflight
        original = preflight.resolve_values

        def fake(*a, **k):
            k = dict(k)
            k["status_fn"] = lambda d: CertStatus(d, "expired", "Certificate has expired",
                                                    "", "")
            return original(*a, **k)

        import core.menu as menu_module
        saved = menu_module.resolve_values
        menu_module.resolve_values = fake
        try:
            _, text = menu_env.run(["4", "1", str(idx), "0"], panel)
        finally:
            menu_module.resolve_values = saved
        self.assertIn("SSL for", text)
        self.assertEqual(panel.writes, [])


class MissingSettingsTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(with_certs=False, cdn_domain="", direct_domain="", cloudflare_ips=(), paths=False)

    def tearDown(self):
        self.env.close()

    def test_all_missing_values_listed_and_nothing_sent(self):
        panel = FakePanel()
        idx = self.env.index("tls_ws_cdn", "cdn")
        _, text = self.env.run(["5", "2", str(idx), "0"], panel)
        self.assertIn("Cloudflare IP is not set", text)
        self.assertEqual(panel.writes, [])

    def test_plain_cdn_template_needs_no_certificate(self):
        env = Env(with_certs=False, paths=True)
        try:
            panel = FakePanel()
            idx = env.index("http_ws_cdn_vmess", "cdn")
            env.run(["5", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], panel)
            self.assertEqual(len(panel.inbounds), 1)
            self.assertEqual(panel.inbounds[0]["streamSettings"]["security"], "none")
        finally:
            env.close()


class PayloadCheckTests(unittest.TestCase):
    def test_ws_path_without_slash_is_refused(self):
        payload = {"port": 9000, "remark": "x", "protocol": "vmess", "settings": {},
                   "streamSettings": {"network": "ws", "wsSettings": {"path": "abc"}, "security": "none"}}
        self.assertTrue(any("must start with /" in p for p in validate_payload(payload)))

    def test_reserved_port_and_placeholder_refused(self):
        payload = {"port": 443, "remark": "x", "protocol": "vmess", "settings": {},
                   "streamSettings": {"network": "tcp", "security": "none", "x": "{{PORT}}"}}
        problems = validate_payload(payload)
        self.assertTrue(any("reserved" in p for p in problems))
        self.assertTrue(any("Unresolved" in p for p in problems))


class SettingsMenuTests(unittest.TestCase):
    def run_menu_script(self, script, settings, path=None):
        inputs = iter(script)
        out = []
        menu = Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
                    settings=settings, settings_path=path)
        menu.run()
        return menu, "\n".join(out)

    def test_fingerprint_by_number_and_custom_and_manual(self):
        menu, _ = self.run_menu_script(["3", "9", "2", "0", "0"], Settings())
        self.assertEqual(menu.settings.fingerprint, "firefox")
        menu, _ = self.run_menu_script(["3", "9", "5", "my_custom-1", "0", "0"], Settings())
        self.assertEqual(menu.settings.fingerprint, "my_custom-1")
        menu, _ = self.run_menu_script(["3", "9", "safari", "0", "0"], Settings())
        self.assertEqual(menu.settings.fingerprint, "safari")

    def test_invalid_fingerprint_refused(self):
        menu, text = self.run_menu_script(["3", "9", "bad value!", "0", "0"], Settings())
        self.assertIn("Fingerprint must be", text)
        self.assertEqual(menu.settings.fingerprint, "chrome")

    def test_paths_accept_generated_and_manual(self):
        from network.paths import PATH_KEYS
        # For each key: accept generated (a) or type own (m) for the first key only.
        script = ["3", "8", "n"]  # not automatic: go key by key
        for i in range(len(PATH_KEYS)):
            script += ["m", "/custom-" + str(i)] if i == 0 else ["a"]
        script += ["0", "0"]
        menu, _ = self.run_menu_script(script, Settings())
        paths = menu.settings.paths
        self.assertEqual(paths[PATH_KEYS[0]], "/custom-0")
        self.assertEqual(len(paths), len(PATH_KEYS))
        for key, value in paths.items():
            if key != PATH_KEYS[0]:
                self.assertEqual(len(value.lstrip("/")), 12)

    def test_generated_paths_are_12_characters(self):
        from network.paths import random_path
        for _ in range(20):
            value = random_path()
            self.assertEqual(len(value), 13)
            self.assertTrue(value.startswith("/"))


if __name__ == "__main__":
    unittest.main()


class AutomaticPathsTests(unittest.TestCase):
    def run_menu_script(self, script, settings, path=None):
        inputs = iter(script)
        out = []
        menu = Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
                    settings=settings, settings_path=path)
        menu.run()
        return menu, "\n".join(out)

    def test_default_yes_generates_all_paths_after_confirmation(self):
        from network.paths import PATH_KEYS
        menu, text = self.run_menu_script(["3", "8", "", "", "0", "0"], Settings())
        self.assertEqual(set(menu.settings.paths), set(PATH_KEYS))
        for key in PATH_KEYS:
            self.assertEqual(len(menu.settings.paths[key].lstrip("/")), 12)
        self.assertIn("Request paths saved", text)

    def test_declining_the_final_confirmation_saves_nothing(self):
        menu, text = self.run_menu_script(["3", "8", "", "n", "0", "0"], Settings())
        self.assertEqual(menu.settings.paths, {})
        self.assertIn("Paths were not changed", text)

    def test_automatic_paths_are_different_for_cdn_and_direct(self):
        menu, _ = self.run_menu_script(["3", "8", "", "", "0", "0"], Settings())
        self.assertNotEqual(menu.settings.paths["cdn_ws"], menu.settings.paths["direct_ws"])
