import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from network import validators
from network.cloudflare import CloudflarePorts
from network.paths import generate_all, path_key
from panel.client import PanelClient
from state.records import load_records
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t",
                     http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
                     https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}))
DIRECT_DOMAIN = "direct.example.test"
CDN_DOMAIN = "cdn.example.test"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        self.library = load_library(os.path.join(ROOT, "inbounds"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def index(self, template_id, mode):
        pool = sorted((t for t in self.library.values() if t.connection_mode == mode),
                      key=lambda t: (t.number, t.template_id))
        return next(i for i, t in enumerate(pool, 1) if t.template_id == template_id)

    def run_menu(self, script, settings, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.library, settings=settings, cloudflare=CF, state_dir=self.state).run()
        return "\n".join(out)


class PathKeyTests(unittest.TestCase):
    def test_cdn_and_direct_ws_have_different_keys(self):
        paths = generate_all()
        self.assertNotEqual(paths["cdn_ws"], paths["direct_ws"])
        self.assertEqual(path_key("cdn", "ws"), "cdn_ws")

    def test_cdn_template_uses_cdn_path(self):
        from core.preflight import resolve_values
        t = load_library(os.path.join(ROOT, "inbounds"))["tls_ws_cdn_vmess"]
        paths = generate_all()
        cert_dir = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(cert_dir, CDN_DOMAIN))
            for name in ("fullchain.pem", "privkey.pem"):
                open(os.path.join(cert_dir, CDN_DOMAIN, name), "w").close()
            from certs.checker import CertStatus
            net = NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                  port_mode="random", random_port_low=20000, random_port_high=22000)
            res = resolve_values(t, net, paths, cert_dir, CF, [],
                                 status_fn=lambda d: CertStatus(d, "ok", "", "", ""),
                                 connection_address="203.0.113.1")
            self.assertEqual(res.values["PATH_WS"], paths["cdn_ws"])
        finally:
            shutil.rmtree(cert_dir, ignore_errors=True)


class CdnAddressTests(Base):
    def test_cdn_refused_without_cloudflare_ip(self):
        settings = Settings(network=NetworkSettings(cdn_domain=CDN_DOMAIN), paths=generate_all())
        panel = FakePanel()
        out = self.run_menu(["4", "2", "2", "0", "0"], settings, panel)
        self.assertIn("Cloudflare IP is not set", out)
        self.assertEqual(panel.writes, [])


class DirectAddressTests(Base):
    def settings(self):
        return Settings(network=NetworkSettings(direct_domain=DIRECT_DOMAIN, port_mode="random",
                                                random_port_low=20000, random_port_high=22000),
                        paths=generate_all())

    def test_option_1_uses_domain_as_address(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        self.run_menu(["4", "1", "1", str(idx), CONFIRM_WORD, "0", "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], DIRECT_DOMAIN)

    def test_option_2_resolves_ip_and_accepts_it(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
            self.run_menu(["4", "1", "2", "y", str(idx), CONFIRM_WORD, "0", "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "198.51.100.20")

    def test_option_2_manual_address_replaces_resolved_one(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
            self.run_menu(["4", "1", "2", "n", "203.0.113.77", str(idx), CONFIRM_WORD, "0", "0"],
                          self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "203.0.113.77")

    def test_option_3_is_loopback(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        self.run_menu(["4", "1", "3", str(idx), CONFIRM_WORD, "0", "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "127.0.0.1")

    def test_unresolvable_domain_stops_before_templates(self):
        panel = FakePanel()
        with mock.patch("core.menu.resolve_ipv4", side_effect=ValueError("Cannot resolve")):
            out = self.run_menu(["4", "1", "2", "0", "0"], self.settings(), panel)
        self.assertIn("Cannot resolve", out)
        self.assertEqual(panel.writes, [])


if __name__ == "__main__":
    unittest.main()


class FlowOrderTests(Base):
    def test_address_question_comes_before_screen_clear_and_config_list(self):
        events = []
        settings = Settings(network=NetworkSettings(direct_domain=DIRECT_DOMAIN, port_mode="random",
                                                    random_port_low=20000, random_port_high=22000),
                            paths=generate_all())
        idx = self.index("http_tcp_direct_vmess", "direct")
        inputs = iter(["4", "1", "1", str(idx), "n", "0", "0"])

        def ask(prompt=""):
            events.append(("input", prompt.strip()))
            return next(inputs)

        Menu(PanelClient("127.0.0.1:2053", token="T", transport=FakePanel()),
             input_fn=ask, output_fn=lambda t: events.append(("out", str(t))),
             clear_fn=lambda: events.append(("clear", "")), library=self.library,
             settings=settings, cloudflare=CF, state_dir=self.state).run()
        text = [e for e in events]
        address_at = next(i for i, e in enumerate(text) if e[0] == "input" and e[1].startswith("Choose 1, 2 or 3"))
        clear_after = [i for i, e in enumerate(text) if e[0] == "clear" and i > address_at]
        list_at = next(i for i, e in enumerate(text) if e[0] == "out" and "DIRECT inbounds" in e[1])
        self.assertTrue(clear_after)
        self.assertLess(address_at, clear_after[0])
        self.assertLess(clear_after[0], list_at)
