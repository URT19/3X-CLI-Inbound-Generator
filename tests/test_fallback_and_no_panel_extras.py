import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from network.paths import generate_all
from panel.client import PanelClient
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FallbackTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = load_library(os.path.join(ROOT, "inbounds"))
        self.settings = Settings(network=NetworkSettings(port_mode="random", random_port_low=48000,
                                                         random_port_high=50000), paths=generate_all())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.lib, settings=self.settings, settings_path=os.path.join(self.dir, "s.json"),
             state_dir=os.path.join(self.dir, "st")).run()
        return "\n".join(out)

    def test_all_fallback_proxies_are_plain_on_loopback_with_fb_names(self):
        panel = FakePanel()
        self.run_menu(["4", "5", "a", "", "0", "0"], panel)
        self.assertEqual(len(panel.inbounds), 5)
        for inbound in panel.inbounds:
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertEqual(inbound["streamSettings"]["security"], "none")
            self.assertIn("FB", inbound["remark"])
            self.assertNotIn("PLAIN", inbound["remark"])
        ws = [i for i in panel.inbounds if i["streamSettings"]["network"] == "ws"]
        self.assertEqual(len(ws), 2)
        for inbound in ws:
            self.assertEqual(inbound["streamSettings"]["wsSettings"]["heartbeatPeriod"], 30)
            self.assertEqual(inbound["streamSettings"]["wsSettings"]["host"], "")

    def test_fallback_paths_are_unique_per_inbound(self):
        panel = FakePanel()
        self.run_menu(["4", "5", "a", "", "0", "0"], panel)
        paths = [i["streamSettings"][k]["path"] for i in panel.inbounds
                 for k in ("wsSettings", "httpupgradeSettings") if k in i["streamSettings"]]
        self.assertEqual(len(paths), 4)
        self.assertEqual(len(set(paths)), 4)

    def test_no_client_or_host_is_ever_sent_to_the_panel(self):
        panel = FakePanel()
        self.run_menu(["4", "5", "a", "", "0", "0"], panel)
        paths = [w[0] for w in panel.writes]
        self.assertFalse([p for p in paths if p.startswith("/clients") or p.startswith("/hosts")])
        self.assertEqual(panel.hosts, [])

    def test_fallback_asks_no_address_question(self):
        panel = FakePanel()
        out = self.run_menu(["4", "5", "0", "0", "0"], panel)  # template prompt, back, exit
        self.assertNotIn("Address for", out)


if __name__ == "__main__":
    unittest.main()
