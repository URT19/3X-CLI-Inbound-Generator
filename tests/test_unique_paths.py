import json
import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from network.paths import generate_all
from panel.client import PanelClient
from state.records import append_record, load_records
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def xhttp_inbound(iid, path):
    return {"id": iid, "remark": f"x{iid}", "port": 30000 + iid, "listen": "127.0.0.1", "enable": True,
            "protocol": "vless", "streamSettings": {"network": "xhttp", "security": "none",
                                                    "xhttpSettings": {"path": path}},
            "settings": {"clients": []}}


class UniquePathTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = load_library(os.path.join(ROOT, "inbounds"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script, panel, settings=None, state=None):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.lib, settings=settings or Settings(network=NetworkSettings()),
             settings_path=os.path.join(self.dir, "s.json"), root=self.dir,
             state_dir=state or os.path.join(self.dir, "st")).run()
        return "\n".join(out)

    def test_batch_of_xhttp_templates_gets_distinct_paths(self):
        from tests.test_certs import HAVE_OPENSSL, make_cert
        if not HAVE_OPENSSL:
            self.skipTest("openssl not installed")
        make_cert(os.path.join(self.dir, "cert", "d.example.test"), "d.example.test", days=90)
        settings = Settings(network=NetworkSettings(direct_domain="d.example.test", port_mode="random",
                                                    random_port_low=46000, random_port_high=48000),
                            paths=generate_all(), cert_root=os.path.join(self.dir, "cert"))
        panel = FakePanel()
        self.run_menu(["4", "1", "3", "a", "1", "n", CONFIRM_WORD, "0", "0"], panel, settings)
        paths = [i["streamSettings"]["xhttpSettings"]["path"] for i in panel.inbounds
                 if "xhttpSettings" in i.get("streamSettings", {})]
        self.assertGreaterEqual(len(paths), 2)
        self.assertEqual(len(paths), len(set(paths)))

    def test_repair_gives_every_shared_path_its_own_value_and_updates_records(self):
        shared = "/SHAREDPATH12"
        panel = FakePanel([xhttp_inbound(1, shared), xhttp_inbound(2, shared), xhttp_inbound(3, "/ownpath0001")])
        state = os.path.join(self.dir, "st")
        append_record(state, "direct", {"inbound_id": 2, "name": "x2", "port": 30002, "path": shared})
        self.run_menu(["6", "8", CONFIRM_WORD, "0", "0"], panel, state=state)
        paths = [i["streamSettings"]["xhttpSettings"]["path"] for i in panel.inbounds]
        self.assertEqual(paths[0], shared)
        self.assertNotEqual(paths[1], shared)
        self.assertEqual(paths[2], "/ownpath0001")
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(load_records(state, "direct")[0]["path"], paths[1])

    def test_repair_cancelled_changes_nothing(self):
        shared = "/SHAREDPATH12"
        panel = FakePanel([xhttp_inbound(1, shared), xhttp_inbound(2, shared)])
        self.run_menu(["6", "8", "n", "0", "0"], panel)
        self.assertEqual(panel.writes, [])

    def test_no_duplicates_means_nothing_to_do(self):
        panel = FakePanel([xhttp_inbound(1, "/a"), xhttp_inbound(2, "/b")])
        out = self.run_menu(["6", "8", "0", "0"], panel)
        self.assertIn("already unique", out)


if __name__ == "__main__":
    unittest.main()
