import json
import os
import shutil
import tempfile
import unittest

from certs.checker import CertStatus
from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from core.preflight import resolve_values, validate_payload
from network.cloudflare import CloudflarePorts
from network.paths import generate_all
from panel.client import PanelClient
from templates.loader import load_library, render
from tests.test_certs import HAVE_OPENSSL, make_cert
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))
DOMAIN = "direct.example.test"


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class VisionAndTrojanTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cert_root = os.path.join(self.dir, "cert")
        make_cert(os.path.join(self.cert_root, DOMAIN), DOMAIN, days=90)
        self.lib = load_library(os.path.join(ROOT, "inbounds"))
        self.net = NetworkSettings(direct_domain=DOMAIN, direct_domain2=DOMAIN, port_mode="random",
                                   random_port_low=41000, random_port_high=43000)
        self.paths = generate_all()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def build(self, tid):
        t = self.lib[tid]
        res = resolve_values(t, self.net, self.paths, self.cert_root, CF, [],
                             status_fn=lambda d: CertStatus(d, "ok", "", "", ""), fingerprint="chrome")
        self.assertEqual(res.problems, [])
        payload = render(t, res.values, remark="X")
        return payload

    def test_vless_vision_is_tls_tcp_with_direct_certificate_and_no_fallbacks(self):
        payload = self.build("tls_vless_vision_direct")
        self.assertEqual(payload["protocol"], "vless")
        stream = payload["streamSettings"]
        self.assertEqual((stream["network"], stream["security"]), ("tcp", "tls"))
        self.assertEqual(payload["settings"]["fallbacks"], [])
        self.assertEqual(stream["tlsSettings"]["serverName"], DOMAIN)
        self.assertTrue(stream["tlsSettings"]["certificates"][0]["certificateFile"].endswith(f"{DOMAIN}/fullchain.pem"))
        self.assertEqual(validate_payload(payload), [])
        self.assertNotIn("{{", json.dumps(payload))

    def test_trojan_tls_direct_renders_and_validates(self):
        payload = self.build("tls_trojan_tcp_direct")
        self.assertEqual(payload["protocol"], "trojan")
        self.assertEqual(payload["streamSettings"]["security"], "tls")
        self.assertEqual(validate_payload(payload), [])

    def test_menu_creates_trojan_with_direct_domain_and_name(self):
        d = tempfile.mkdtemp()
        try:
            settings = Settings(network=self.net, paths=self.paths, fingerprint="chrome",
                                cert_root=self.cert_root)
            ordered = sorted((t for t in self.lib.values() if t.connection_mode == "direct"),
                             key=lambda t: (t.number, t.template_id))
            idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "tls_trojan_tcp_direct")
            panel = FakePanel()
            inputs = iter(["4", "1", "1", str(idx), CONFIRM_WORD, "0", "0"])
            Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
                 input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
                 library=self.lib, settings=settings, settings_path=os.path.join(d, "s.json"),
                 cloudflare=CF, state_dir=os.path.join(d, "st")).run()
            self.assertEqual(len(panel.inbounds), 1)
            self.assertIn("TROJAN-TCP-DIRECT-TLS", panel.inbounds[0]["remark"])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
