import io
import os
import sys
import unittest
from unittest import mock

from core.menu import Menu
from templates.loader import load_library
from ui.io import safe_input

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SafeInputTests(unittest.TestCase):
    def test_invalid_utf8_bytes_do_not_raise(self):
        fake = io.TextIOWrapper(io.BytesIO(b"\xd8\xb1\n"), encoding="utf-8")
        with mock.patch.object(sys, "stdin", fake):
            value = safe_input("")
        self.assertNotIn("\n", value)
        self.assertTrue(value)  # not an exception; it is simply not a valid option

    def test_normal_line_is_returned(self):
        fake = io.TextIOWrapper(io.BytesIO(b"4\n"), encoding="utf-8")
        with mock.patch.object(sys, "stdin", fake):
            self.assertEqual(safe_input(""), "4")

    def test_eof_raises_eoferror(self):
        fake = io.TextIOWrapper(io.BytesIO(b""), encoding="utf-8")
        with mock.patch.object(sys, "stdin", fake):
            with self.assertRaises(EOFError):
                safe_input("")


class DeprecationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = load_library(os.path.join(ROOT, "inbounds"))

    def test_ws_grpc_httpupgrade_vmess_trojan_are_marked(self):
        self.assertIsNotNone(self.lib["tls_ws_cdn_vmess"].deprecated)
        self.assertIsNotNone(self.lib["tls_grpc_direct"].deprecated)
        self.assertIsNotNone(self.lib["tls_httpupgrade_direct"].deprecated)
        self.assertIsNotNone(self.lib["tls_ws_cdn_vless"].deprecated)
        self.assertIsNotNone(self.lib["tls_trojan_tcp_direct"].deprecated)

    def test_replacements_are_not_marked(self):
        for tid in ("tls_xhttp_direct", "tls_xhttp_cdn_vless", "tcp_reality_vision_direct",
                    "xhttp_reality_direct", "tls_vless_vision_direct", "tls_hysteria_direct"):
            self.assertIsNone(self.lib[tid].deprecated, tid)

    def test_batch_includes_deprecated_and_listing_marks_them(self):
        from panel.client import PanelClient
        from tests.test_writes import FakePanel
        out = []
        inputs = iter(["7", "a", "1", "n", "n", "0"])  # REALITY target, VMess question, then cancel
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=FakePanel()),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.lib).run()
        text = "\n".join(out)
        self.assertIn("[deprecated]", text)
        self.assertIn("Xray-deprecated", text)
        self.assertNotIn("Skipped", text)


if __name__ == "__main__":
    unittest.main()


class StartupSessionCheckTests(unittest.TestCase):
    def test_configured_panel_is_checked_at_start(self):
        from panel.client import PanelClient
        from tests.test_writes import FakePanel
        panel = FakePanel([{"id": 1, "remark": "a", "port": 9000, "enable": True}])
        out = []
        inputs = iter(["0"])
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             auto_check=True).run()
        text = "\n".join(out)
        self.assertIn("connected, 1 inbounds", text)

    def test_failed_start_check_is_shown(self):
        from panel.client import PanelClient
        from tests.test_writes import FakePanel

        class Down(FakePanel):
            def __call__(self, *a, **k):
                return 401, {}, b'{"success": false}'

        out = []
        inputs = iter(["0"])
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=Down()),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             auto_check=True).run()
        self.assertIn("last check failed", "\n".join(out))


class DirectIpHostTests(unittest.TestCase):
    def test_xhttp_host_becomes_the_ip_but_tls_name_stays_the_domain(self):
        from unittest import mock
        import tempfile, shutil
        from certs.checker import CertStatus
        from config.settings import NetworkSettings, Settings
        from core.menu import CONFIRM_WORD
        from panel.client import PanelClient
        from tests.test_writes import FakePanel
        from network import validators
        from network.paths import generate_all
        from network.cloudflare import CloudflarePorts
        from tests.test_certs import HAVE_OPENSSL, make_cert
        if not HAVE_OPENSSL:
            self.skipTest("openssl not installed")
        lib = load_library(os.path.join(ROOT, "inbounds"))
        d = tempfile.mkdtemp()
        try:
            make_cert(os.path.join(d, "cert", "d.example.test"), "d.example.test", days=90)
            settings = Settings(network=NetworkSettings(direct_domain="d.example.test", port_mode="random",
                                                        random_port_low=42000, random_port_high=44000),
                                paths=generate_all(), cert_root=os.path.join(d, "cert"))
            cf = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))
            ordered = sorted((t for t in lib.values() if t.connection_mode == "direct"),
                             key=lambda t: (t.number, t.template_id))
            idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "tls_xhttp_direct")
            panel = FakePanel()
            inputs = iter(["4", "1", "2", "y", str(idx), CONFIRM_WORD, "0", "0"])
            with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
                Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
                     input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
                     library=lib, settings=settings, settings_path=os.path.join(d, "s.json"),
                     cloudflare=cf, state_dir=os.path.join(d, "st")).run()
            self.assertEqual(len(panel.inbounds), 1)
            inbound = panel.inbounds[0]
            self.assertEqual(inbound["streamSettings"]["xhttpSettings"]["host"], "198.51.100.20")
            self.assertEqual(inbound["streamSettings"]["tlsSettings"]["serverName"], "d.example.test")
            self.assertTrue(inbound["enable"])
        finally:
            shutil.rmtree(d, ignore_errors=True)


