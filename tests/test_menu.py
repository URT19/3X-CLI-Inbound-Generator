import json
import os
import stat
import tempfile
import unittest

from config.settings import NetworkSettings, Settings, load_settings
from network.cloudflare import CloudflarePorts
from network.paths import PATH_KEYS
from core.menu import CONFIRM_WORD, Menu
from panel.client import PanelClient
from tests.test_writes import FakePanel, new_payload
from templates.loader import load_library
from ui.style import Style

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_menu(script, panel, files=None, library=None, settings=None, settings_path=None,
             client_factory=None, secret=None, clear_log=None, style=None):
    inputs = iter(script)
    out = []
    client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
    menu = Menu(
        client,
        input_fn=lambda prompt="": next(inputs),
        output_fn=lambda text: out.append(str(text)),
        read_file=lambda p: (files or {})[p],
        library=library or {},
        settings=settings,
        settings_path=settings_path,
        client_factory=client_factory,
        secret_fn=(lambda prompt="": next(secret)) if secret is not None else None,
        clear_fn=(lambda: clear_log.append(1)) if clear_log is not None else None,
        style=style,
    )
    menu.run()
    return menu, "\n".join(out)


class MainMenuTests(unittest.TestCase):
    def test_exit(self):
        _, text = run_menu(["0"], FakePanel())
        self.assertIn("Bye.", text)

    def test_unknown_option(self):
        _, text = run_menu(["x", "0"], FakePanel())
        self.assertIn("Unknown option.", text)

    def test_reports_menu_shows_protocol_support(self):
        import tempfile
        state = tempfile.mkdtemp()
        inputs = iter(["12", "0"])
        out = []
        Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda x: out.append(str(x)),
             state_dir=state).run()
        text = "\n".join(out)
        self.assertIn("Protocol support", text)
        self.assertIn("amneziawg", text)
        self.assertIn("pending", text)

    def test_menu_shows_all_numbered_items_in_order(self):
        _, text = run_menu(["0"], FakePanel())
        for label in ("Check and install prerequisites", "Panel connection",
                      "Generate DIRECT Inbounds", "Generate CDN Inbounds", "Generate FAKE SITE Inbounds",
                      "Generate RELAY Inbounds", "SSL certificate management",
                      "Manage panel inbounds", "Create inbound from template"):
            self.assertIn(label, text)
        self.assertLess(text.index("Generate DIRECT Inbounds"), text.index("Generate CDN Inbounds"))
        self.assertNotIn("Direct with IP", text)

    def test_screen_is_cleared_before_each_render(self):
        log = []
        run_menu(["x", "0"], FakePanel(), clear_log=log)
        self.assertEqual(len(log), 2)  # once per loop iteration

    def test_header_shows_version_and_counts_per_connection_type(self):
        library = load_library(os.path.join(ROOT, "inbounds"))
        _, text = run_menu(["0"], FakePanel(), library=library)
        self.assertIn("v1.19.0", text)
        self.assertIn("direct=18", text)
        self.assertIn("cdn=12", text)
        self.assertIn("fake=0", text)
        self.assertIn("relay=0", text)
        self.assertIn("local=0", text)

    def test_colors_are_off_by_default(self):
        _, text = run_menu(["0"], FakePanel())
        self.assertNotIn("\x1b[", text)

    def test_colors_on_when_style_enabled(self):
        _, text = run_menu(["0"], FakePanel(), style=Style(enabled=True))
        self.assertIn("\x1b[", text)


class PanelConnectionTests(unittest.TestCase):
    def test_check_connection_success(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 1000, "listen": ""}])
        _, text = run_menu(["2", "1", "0", "0"], panel)
        self.assertIn("Connection OK", text)
        self.assertIn("1 inbounds", text)

    def test_check_connection_failure_not_reported_as_zero(self):
        class Down(FakePanel):
            def __call__(self, *a, **k):
                return 401, {}, b'{"success": false}'

        _, text = run_menu(["2", "1", "0", "0"], Down())
        self.assertIn("Connection failed", text)
        self.assertNotIn("0 inbounds", text)

    def test_edit_settings_saves_file_with_restricted_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            created = []

            def factory(settings):
                created.append(settings)
                return PanelClient(settings.panel_address, token=settings.api_token,
                                   transport=FakePanel())

            menu, text = run_menu(
                ["2", "2", "1.2.3.4:2053", "0", "0"], FakePanel(),
                settings=Settings(), settings_path=path,
                client_factory=factory, secret=iter(["SECRET_TOKEN_9999"]),
            )
            self.assertTrue(os.path.exists(path))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            saved = load_settings(path)
            self.assertEqual(saved.panel_address, "1.2.3.4:2053")
            self.assertEqual(saved.api_token, "SECRET_TOKEN_9999")
            self.assertNotIn("SECRET_TOKEN_9999", text)  # never printed in full
            self.assertIn("9999", text)                  # masked suffix only
            self.assertEqual(created[0].panel_address, "1.2.3.4:2053")

    def test_edit_with_bad_address_saves_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")

            def factory(settings):
                raise ValueError("bad address")

            _, text = run_menu(
                ["2", "2", "ftp://x", "0", "0"], FakePanel(),
                settings=Settings(), settings_path=path,
                client_factory=factory, secret=iter(["TOKEN"]),
            )
            self.assertIn("Nothing was saved", text)
            self.assertFalse(os.path.exists(path))


class PanelInboundTests(unittest.TestCase):
    def test_list_inbounds(self):
        panel = FakePanel([{"id": 1, "remark": "x", "protocol": "vless", "port": 9000, "enable": True}])
        _, text = run_menu(["9", "1", "0", "0"], panel)
        self.assertIn("[1] x", text)

    def test_list_empty_panel(self):
        _, text = run_menu(["9", "1", "0", "0"], FakePanel())
        self.assertIn("no inbounds", text)

    def test_panel_actions_refused_when_not_configured(self):
        out = []
        inputs = iter(["9", "1", "0", "0"])
        Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t))).run()
        self.assertIn("Panel is not configured", "\n".join(out))

    def test_delete_cancelled_without_confirm_sends_nothing(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True, "listen": ""}])
        _, text = run_menu(["9", "6", "1", "nope", "0", "0"], panel)
        self.assertIn("Cancelled", text)
        self.assertEqual(panel.writes, [])
        self.assertEqual(len(panel.inbounds), 1)

    def test_delete_confirmed(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True, "listen": ""}])
        _, text = run_menu(["9", "6", "1", CONFIRM_WORD, "0", "0"], panel)
        self.assertIn('"current"', text)
        self.assertIn("Done and verified", text)
        self.assertEqual(panel.inbounds, [])

    def test_add_from_file_with_confirm(self):
        panel = FakePanel()
        files = {"p.json": json.dumps(new_payload())}
        _, text = run_menu(["9", "3", "p.json", CONFIRM_WORD, "0", "0"], panel, files)
        self.assertIn("Done and verified", text)
        self.assertEqual(len(panel.inbounds), 1)

    def test_set_enable_flow(self):
        panel = FakePanel([{"id": 2, "remark": "b", "port": 9000, "enable": True, "listen": ""}])
        run_menu(["9", "5", "2", "d", CONFIRM_WORD, "0", "0"], panel)
        self.assertFalse(panel.inbounds[0]["enable"])


CF = CloudflarePorts(
    source="test",
    retrieved="test",
    http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
    https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}),
)


class NetworkMenuTests(unittest.TestCase):
    def run_net(self, script, path=None, settings=None):
        inputs = iter(["3", *script, "0", "0"])
        out = []
        menu = Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
                    settings=settings, settings_path=path, cloudflare=CF)
        menu.run()
        return menu, "\n".join(out)

    def test_cloudflare_ips_validated_and_saved(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            menu, text = self.run_net(["2", "203.0.113.1, 203.0.113.2", ], path=path, settings=Settings())
            self.assertEqual(menu.settings.network.cloudflare_ips, ["203.0.113.1", "203.0.113.2"])
            self.assertEqual(load_settings(path).network.cloudflare_ips, ["203.0.113.1", "203.0.113.2"])

    def test_invalid_cloudflare_ip_refused(self):
        menu, text = self.run_net(["2", "not-an-ip"], settings=Settings())
        self.assertIn("Not a valid IP", text)
        self.assertEqual(menu.settings.network.cloudflare_ips, [])

    def test_domain_validation(self):
        menu, text = self.run_net(["4", "bad_domain", "5", "cdn.example.com", "n"], settings=Settings())
        self.assertIn("Not a valid domain", text)
        self.assertEqual(menu.settings.network.direct_domain, "")
        self.assertEqual(menu.settings.network.cdn_domain, "cdn.example.com")

    def test_fixed_port_refuses_reserved(self):
        menu, text = self.run_net(["6", "f", "443"], settings=Settings())
        self.assertIn("reserved", text)
        self.assertEqual(menu.settings.network.port_mode, "random")

    def test_fixed_port_saved(self):
        menu, _ = self.run_net(["6", "f", "9443"], settings=Settings())
        self.assertEqual(menu.settings.network.port_mode, "fixed")
        self.assertEqual(menu.settings.network.fixed_port, 9443)

    def test_random_range_validation(self):
        menu, text = self.run_net(["6", "r", "30000", "20000"], settings=Settings())
        self.assertIn("must not be greater", text)
        menu, _ = self.run_net(["6", "r", "20000", "29999"], settings=Settings())
        self.assertEqual((menu.settings.network.random_port_low, menu.settings.network.random_port_high),
                         (20000, 29999))

    def test_local_refuses_public_ip(self):
        menu, text = self.run_net(["7", "8.8.8.8"], settings=Settings())
        self.assertIn("Public IPs are refused", text)
        self.assertIsNone(menu.settings.network.local_port)

    def test_local_refuses_cloudflare_port(self):
        menu, text = self.run_net(["7", "127.0.0.1", "8443"], settings=Settings())
        self.assertIn("Cloudflare", text)
        self.assertIsNone(menu.settings.network.local_port)

    def test_local_accepts_private_non_cloudflare_port(self):
        menu, _ = self.run_net(["7", "127.0.0.1", "10443"], settings=Settings())
        self.assertEqual(menu.settings.network.local_port, 10443)
        self.assertEqual(menu.settings.network.local_ip, "127.0.0.1")

    def test_show_network_runs(self):
        _, text = self.run_net(["1"], settings=Settings())
        self.assertIn("Cloudflare IPs", text)
        self.assertIn("Local address", text)


if __name__ == "__main__":
    unittest.main()
