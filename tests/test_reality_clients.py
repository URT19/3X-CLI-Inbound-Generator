import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings, load_settings
from core.menu import CONFIRM_WORD, Menu
from network.hosts import direct_host_payload
from network.paths import generate_all
from panel.client import PanelClient
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HostSniTests(unittest.TestCase):
    def test_tls_and_reality_hosts_always_carry_the_server_name(self):
        for address in ("198.51.100.20", "d.example.test"):
            self.assertEqual(direct_host_payload(1, "x", address, 443, "tls", "d.example.test")["sni"],
                             "d.example.test", address)
            self.assertEqual(direct_host_payload(1, "x", address, 443, "reality", "www.apple.com")["sni"],
                             "www.apple.com", address)

    def test_plain_host_has_no_sni(self):
        self.assertEqual(direct_host_payload(1, "x", "198.51.100.20", 80, "none", "d.example.test")["sni"], "")


class DirectCreationTests(unittest.TestCase):
    def setUp(self):
        import tests.test_certs as tc
        self.dir = tempfile.mkdtemp()
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.cert_root = os.path.join(self.dir, "cert")
        if tc.HAVE_OPENSSL:
            tc.make_cert(os.path.join(self.cert_root, "d.example.test"), "d.example.test", days=90)
        self.settings = Settings(network=NetworkSettings(port_mode="random", random_port_low=44000,
                                                         random_port_high=46000, direct_domain="d.example.test"),
                                 fingerprint="chrome", paths=generate_all(), cert_root=self.cert_root)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def create(self, template_id, panel):
        ordered = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == template_id)
        needs_target = "reality" in template_id
        answers = ["4", "1", "3", str(idx)] + (["1"] if needs_target else []) + [CONFIRM_WORD, "0", "0"]
        inputs = iter(answers)
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
             library=self.library, settings=self.settings,
             settings_path=os.path.join(self.dir, "s.json"), cloudflare=None,
             state_dir=os.path.join(self.dir, "st")).run()

    def test_no_client_is_created_automatically(self):
        import tests.test_certs as tc
        if not tc.HAVE_OPENSSL:
            self.skipTest("openssl not installed")
        panel = FakePanel()
        self.create("tcp_reality_vision_direct", panel)
        self.assertEqual(panel.inbounds[0]["settings"]["clients"], [])
        self.assertFalse([w for w in panel.writes if w[0] == "/clients/add"])

    def test_reality_public_key_is_stored_in_the_inbound(self):
        panel = FakePanel()
        self.create("tcp_reality_vision_direct", panel)
        rs = panel.inbounds[0]["streamSettings"]["realitySettings"]
        self.assertRegex(rs["settings"]["publicKey"], r"^[A-Za-z0-9_\-]{43}$")
        self.assertEqual(rs["settings"]["serverName"], rs["serverNames"][0])

    def test_hysteria_server_name_is_the_direct_domain(self):
        import tests.test_certs as tc
        if not tc.HAVE_OPENSSL:
            self.skipTest("openssl not installed")
        panel = FakePanel()
        self.create("tls_hysteria_direct", panel)
        self.assertEqual(panel.inbounds[0]["streamSettings"]["tlsSettings"]["serverName"], "d.example.test")


if __name__ == "__main__":
    unittest.main()


