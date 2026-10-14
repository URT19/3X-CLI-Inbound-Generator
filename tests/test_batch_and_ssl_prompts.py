import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from core.preflight import ip_compatible
from network.cloudflare import CloudflarePorts
from network.paths import generate_all
from panel.client import PanelClient
from state.records import load_records
from templates.loader import load_library
from tests.test_certs import HAVE_OPENSSL, make_cert
from tests.test_template_flow import CDN, CF, Env
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(script, panel, library, settings, state_dir, cloudflare=CF):
    inputs = iter(script)
    out = []
    client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
    Menu(client, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
         library=library, settings=settings, cloudflare=cloudflare, state_dir=state_dir).run()
    return "\n".join(out)


class DefaultYesTests(unittest.TestCase):
    def direct_index(self, template_id):
        ordered = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        return next(i for i, t in enumerate(ordered, 1) if t.template_id == template_id)

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.settings = Settings(network=NetworkSettings(
            direct_ip="203.0.113.10", port_mode="random", random_port_low=20000, random_port_high=20010),
            paths=generate_all())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_enter_at_confirm_means_yes(self):
        panel = FakePanel()
        idx = self.direct_index("http_tcp_direct_vmess")
        out = run(["4", "3", str(idx), "", "0"], panel, self.library, self.settings, self.dir)
        self.assertIn("Done and verified", out)
        self.assertEqual(len(panel.inbounds), 1)

    def test_no_cancels(self):
        panel = FakePanel()
        idx = self.direct_index("http_tcp_direct_vmess")
        out = run(["4", "3", str(idx), "n", "0"], panel, self.library, self.settings, self.dir)
        self.assertIn("Cancelled", out)
        self.assertEqual(panel.writes, [])

    def test_fake_site_needs_a_master_inbound(self):
        out = run(["6", "0"], FakePanel(), self.library, self.settings, self.dir)
        self.assertIn("No VLESS or Trojan inbound", out)

    def test_relay_needs_relay_address(self):
        out = run(["7", "0"], FakePanel(), self.library, self.settings, self.dir)
        self.assertIn("Relay address is not set", out)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class BatchTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.env.settings.network.random_port_high = 20200  # room for many inbounds

    def tearDown(self):
        self.env.close()

    def test_all_cdn_templates_created_with_unique_names_and_ports(self):
        panel = FakePanel()
        out = run(["5", "3", "a", "", "0"], panel, self.env.library, self.env.settings, self.env.state_dir)
        cdn_count = sum(1 for t in self.env.library.values() if t.connection_mode == "cdn")
        self.assertEqual(len(panel.inbounds), cdn_count)
        names = [i["remark"] for i in panel.inbounds]
        ports = [i["port"] for i in panel.inbounds]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(len(set(ports)), len(ports))
        self.assertEqual(len(load_records(self.env.state_dir, "cdn")), cdn_count)
        self.assertIn("Done:", out)

    def test_batch_cancel_sends_nothing(self):
        panel = FakePanel()
        run(["5", "3", "a", "n", "0"], panel, self.env.library, self.env.settings, self.env.state_dir)
        self.assertEqual(panel.writes, [])

    def test_batch_skips_templates_with_missing_values_and_reports_them(self):
        self.env.settings.paths = {}  # every template with a path placeholder is now not ready
        panel = FakePanel()
        out = run(["5", "3", "a", "0"], panel, self.env.library, self.env.settings, self.env.state_dir)
        self.assertIn("skipped", out)
        self.assertEqual(panel.writes, [])


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class SslPromptAfterDomainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cert_root = os.path.join(self.dir, "cert")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_domain(self, script, domain_text):
        inputs = iter(script)
        out = []

        def ask(prompt=""):
            out.append(prompt)  # prompts are part of what the user sees
            return next(inputs)

        settings = Settings(cert_root=self.cert_root)
        menu = Menu(None, input_fn=ask, output_fn=lambda t: out.append(str(t)),
                    settings=settings, settings_path=os.path.join(self.dir, "s.json"))
        menu.run()
        return menu, "\n".join(out)

    def test_missing_certificate_prompts_and_no_skips_issue(self):
        menu, text = self.run_domain(["3", "5", "cdn.example.test", "n", "0", "0"], "x")
        self.assertIn("No valid SSL certificate", text)
        self.assertEqual(menu.settings.network.cdn_domain, "cdn.example.test")
        self.assertIn("cdn.example.test", menu.settings.ssl_domains)

    def test_valid_certificate_needs_no_prompt(self):
        make_cert(os.path.join(self.cert_root, "cdn.example.test"), "cdn.example.test", days=90)
        menu, text = self.run_domain(["3", "5", "cdn.example.test", "0", "0"], "x")
        self.assertIn("cdn.example.test: ok", text)
        self.assertNotIn("Obtain one now", text)

    def test_yes_default_tries_to_obtain_and_reports_missing_acme(self):
        _, text = self.run_domain(["3", "4", "direct.example.test", "", "", "0", "0"], "x")
        self.assertIn("Obtain one now", text)
        self.assertIn("acme.sh not found", text)


if __name__ == "__main__":
    unittest.main()
