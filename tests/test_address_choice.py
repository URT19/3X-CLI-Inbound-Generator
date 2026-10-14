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
        t = load_library(os.path.join(ROOT, "inbounds"))["tls_ws_cdn"]
        paths = generate_all()
        cert_dir = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(cert_dir, CDN_DOMAIN))
            for name in ("fullchain.pem", "privkey.pem"):
                open(os.path.join(cert_dir, CDN_DOMAIN, name), "w").close()
            from certs.checker import CertStatus
            net = NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                  port_mode="random", random_port_low=20000, random_port_high=20010)
            res = resolve_values(t, net, paths, cert_dir, CF, [],
                                 status_fn=lambda d: CertStatus(d, "ok", "", "", ""),
                                 connection_address="203.0.113.1")
            self.assertEqual(res.values["PATH_WS"], paths["cdn_ws"])
        finally:
            shutil.rmtree(cert_dir, ignore_errors=True)


class CdnAddressTests(Base):
    def test_cdn_uses_chosen_cloudflare_ip_not_direct_domain(self):
        net = NetworkSettings(cdn_domain=CDN_DOMAIN, direct_domain=DIRECT_DOMAIN,
                              cloudflare_ips=["203.0.113.1", "203.0.113.2"],
                              port_mode="random", random_port_low=20000, random_port_high=20050)
        settings = Settings(network=net, paths=generate_all(), cert_root="/nonexistent")
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")  # plain: no certificate needed
        # Choose the second Cloudflare IP, then the template, then confirm the inbound and its host.
        out = self.run_menu(["5", "2", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], settings, panel)
        self.assertIn("Done and verified", out)
        payload_text = json.dumps(panel.inbounds[0]) + json.dumps(panel.hosts)
        self.assertNotIn(DIRECT_DOMAIN, payload_text)
        self.assertEqual(panel.hosts[0]["hosts"][0], "203.0.113.2")
        rec = load_records(self.state, "cdn")[0]
        self.assertEqual(rec["address"], "203.0.113.2")
        self.assertEqual(rec["domain"], CDN_DOMAIN)

    def test_cdn_refused_without_cloudflare_ip(self):
        settings = Settings(network=NetworkSettings(cdn_domain=CDN_DOMAIN), paths=generate_all())
        panel = FakePanel()
        out = self.run_menu(["5", "2", "0"], settings, panel)
        self.assertIn("Cloudflare IP is not set", out)
        self.assertEqual(panel.writes, [])


class DirectAddressTests(Base):
    def settings(self):
        return Settings(network=NetworkSettings(direct_domain=DIRECT_DOMAIN, port_mode="random",
                                                random_port_low=20000, random_port_high=20050),
                        paths=generate_all())

    def test_option_1_uses_domain_as_address(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        self.run_menu(["4", "1", str(idx), CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], DIRECT_DOMAIN)

    def test_option_2_resolves_ip_and_accepts_it(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
            self.run_menu(["4", "2", "y", str(idx), CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "198.51.100.20")

    def test_option_2_manual_address_replaces_resolved_one(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
            self.run_menu(["4", "2", "n", "203.0.113.77", str(idx), CONFIRM_WORD, "0"],
                          self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "203.0.113.77")

    def test_option_3_is_loopback(self):
        panel = FakePanel()
        idx = self.index("http_tcp_direct_vmess", "direct")
        self.run_menu(["4", "3", str(idx), CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertEqual(load_records(self.state, "direct")[0]["address"], "127.0.0.1")

    def test_unresolvable_domain_stops_before_templates(self):
        panel = FakePanel()
        with mock.patch("core.menu.resolve_ipv4", side_effect=ValueError("Cannot resolve")):
            out = self.run_menu(["4", "2", "0"], self.settings(), panel)
        self.assertIn("Cannot resolve", out)
        self.assertEqual(panel.writes, [])


if __name__ == "__main__":
    unittest.main()


class FlowOrderTests(Base):
    def test_address_question_comes_before_screen_clear_and_config_list(self):
        events = []
        settings = Settings(network=NetworkSettings(direct_domain=DIRECT_DOMAIN, port_mode="random",
                                                    random_port_low=20000, random_port_high=20050),
                            paths=generate_all())
        idx = self.index("http_tcp_direct_vmess", "direct")
        inputs = iter(["4", "1", str(idx), "n", "0"])

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


class CloudflarePortRuleTests(Base):
    def settings(self):
        return Settings(network=NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                                port_mode="random", random_port_low=20000, random_port_high=20050),
                        paths=generate_all())

    def test_cloudflare_tls_cdn_uses_https_ports_but_never_443(self):
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        self.run_menu(["5", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], self.settings(), panel)
        port = panel.inbounds[0]["port"]
        self.assertIn(port, {2053, 2083, 2087, 2096, 8443, 8080, 8880, 2052, 2082, 2086, 2095})
        self.assertNotIn(port, {80, 443})

    def test_cloudflare_plain_cdn_uses_http_ports_only(self):
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        self.run_menu(["5", "2", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertIn(panel.inbounds[0]["port"], {8080, 8880, 2052, 2082, 2086, 2095})

    def test_fixed_port_outside_cloudflare_list_is_refused_for_cloudflare_cdn(self):
        settings = self.settings()
        settings.network = NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                           port_mode="fixed", fixed_port=10443)
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        out = self.run_menu(["5", "2", str(idx), "0"], settings, panel)
        self.assertIn("is not a Cloudflare port", out)
        self.assertEqual(panel.writes, [])

    def test_local_cdn_port_does_not_follow_cloudflare_rules(self):
        settings = self.settings()
        settings.network = NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                           port_mode="random", random_port_low=8080, random_port_high=8080)
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        self.run_menu(["5", "3", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], settings, panel)
        self.assertEqual(panel.inbounds[0]["port"], 8080)


class CdnThreeRouteTests(Base):
    def settings(self):
        return Settings(network=NetworkSettings(cdn_domain=CDN_DOMAIN, cloudflare_ips=["203.0.113.1"],
                                                local_ip="127.0.0.1", port_mode="random",
                                                random_port_low=20000, random_port_high=20050),
                        paths=generate_all())

    def test_route_1_is_cloudflare_domain(self):
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        self.run_menu(["5", "1", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertEqual(panel.hosts[0]["hosts"][0], CDN_DOMAIN)
        self.assertEqual(load_records(self.state, "cdn")[0]["address"], CDN_DOMAIN)
        self.assertIn(panel.inbounds[0]["port"], {8080, 8880, 2052, 2082, 2086, 2095})

    def test_route_3_is_local(self):
        panel = FakePanel()
        idx = self.index("http_ws_cdn_vmess", "cdn")
        self.run_menu(["5", "3", str(idx), CONFIRM_WORD, CONFIRM_WORD, "0"], self.settings(), panel)
        self.assertEqual(panel.hosts[0]["hosts"][0], "127.0.0.1")
        self.assertEqual(load_records(self.state, "cdn")[0]["address"], "127.0.0.1")

    def test_route_1_refused_without_cdn_domain(self):
        settings = self.settings()
        settings.network.cdn_domain = ""
        out = self.run_menu(["5", "1", "0"], settings, FakePanel())
        self.assertIn("CDN domain is not set", out)
