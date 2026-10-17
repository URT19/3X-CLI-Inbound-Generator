import os
import shutil
import tempfile
import unittest
from unittest import mock

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from network.paths import generate_all
from panel.client import PanelClient
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class IpHostTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = load_library(os.path.join(ROOT, "inbounds"))
        self.settings = Settings(network=NetworkSettings(direct_domain="d.example.test", port_mode="random",
                                                         random_port_low=49000, random_port_high=51000),
                                 paths=generate_all())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script, panel):
        inputs = iter(script)
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
             library=self.lib, settings=self.settings, settings_path=os.path.join(self.dir, "s.json"),
             state_dir=os.path.join(self.dir, "st")).run()

    def test_ip_choice_creates_one_host_named_ip_for_all_created_inbounds(self):
        panel = FakePanel()
        with mock.patch("core.menu.resolve_ipv4", return_value="198.51.100.20"):
            self.run_menu(["4", "1", "2", "y", "a", "1", "n", CONFIRM_WORD, "0", "0"], panel)  # REALITY target, VMess question
        self.assertEqual(len(panel.hosts), 1)
        host = panel.hosts[0]
        self.assertEqual(host["remark"], "IP")
        self.assertEqual(host["hosts"], ["198.51.100.20"])
        self.assertEqual(sorted(host["inboundIds"]), sorted(i["id"] for i in panel.inbounds))
        self.assertGreater(len(host["inboundIds"]), 1)

    def test_domain_choice_creates_no_host(self):
        panel = FakePanel()
        self.run_menu(["4", "1", "1", "a", "n", "0", "0"], panel)
        self.assertEqual(panel.hosts, [])

    def test_loopback_choice_creates_no_host(self):
        panel = FakePanel()
        self.run_menu(["4", "1", "3", "a", "n", "0", "0"], panel)
        self.assertEqual(panel.hosts, [])


if __name__ == "__main__":
    unittest.main()
