import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings
from core.menu import Menu
from network.paths import generate_all
from panel.client import PanelClient
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXISTING = {"id": 1, "remark": "25-VLESS-TCP-DIRECT-REALITY", "port": 30001, "listen": "127.0.0.1",
            "enable": True, "protocol": "vless",
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverNames": ["www.microsoft.com"]}}}


class RealitySniUniqueTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = load_library(os.path.join(ROOT, "inbounds"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.lib, settings=Settings(network=NetworkSettings(port_mode="random",
                                                                         random_port_low=47000,
                                                                         random_port_high=49000),
                                                 paths=generate_all()),
             settings_path=os.path.join(self.dir, "s.json"), state_dir=os.path.join(self.dir, "st")).run()
        return "\n".join(out)

    def test_reality_on_a_used_server_name_moves_to_the_next_default(self):
        panel = FakePanel([dict(EXISTING)])
        ordered = sorted((t for t in self.lib.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "tcp_reality_vision_direct")
        out = self.run_menu(["4", "1", "3", str(idx), "1", "y", "0", "0"], panel)
        new = [i for i in panel.inbounds if i["id"] != 1]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["streamSettings"]["realitySettings"]["serverNames"], ["www.apple.com"])
        self.assertIn("is in use", out)

    def test_custom_server_name_already_in_use_is_refused(self):
        panel = FakePanel([dict(EXISTING)])
        ordered = sorted((t for t in self.lib.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "tcp_reality_vision_direct")
        out = self.run_menu(["4", "1", "3", str(idx), "6", "www.microsoft.com:443", "www.microsoft.com", "0", "0"], panel)
        self.assertIn("already used", out)
        self.assertEqual(len(panel.inbounds), 1)


if __name__ == "__main__":
    unittest.main()
