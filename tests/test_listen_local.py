import os
import shutil
import stat
import tempfile
import unittest

from core.menu import Menu
from panel.client import PanelClient
from tests.test_writes import FakePanel

INBOUNDS = [
    {"id": 1, "remark": "a", "port": 30001, "protocol": "vless", "enable": True, "listen": "",
     "streamSettings": {"network": "tcp", "security": "none"}, "settings": {"clients": []}},
    {"id": 2, "remark": "b", "port": 30002, "protocol": "vless", "enable": True, "listen": "0.0.0.0",
     "streamSettings": {"network": "tcp", "security": "none"}, "settings": {"clients": []}},
    {"id": 3, "remark": "c", "port": 30003, "protocol": "vless", "enable": True, "listen": "127.0.0.1",
     "streamSettings": {"network": "tcp", "security": "none"}, "settings": {"clients": []}},
]


class ListenLocalTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_menu(self, script, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             root=self.root).run()
        return "\n".join(out)

    def test_red_warning_and_exact_confirm_required(self):
        panel = FakePanel([dict(i) for i in INBOUNDS])
        out = self.run_menu(["6", "9", "n", "confirm", "0", "0"], panel)
        self.assertIn("ALL inbounds", out)
        self.assertIn("Not confirmed", out)
        self.assertEqual(panel.writes, [])
        self.assertEqual({i["listen"] for i in panel.inbounds}, {"", "0.0.0.0", "127.0.0.1"})

    def test_confirm_changes_every_other_inbound_to_loopback(self):
        panel = FakePanel([dict(i) for i in INBOUNDS])
        out = self.run_menu(["6", "9", "n", "CONFIRM", "0", "0"], panel)
        self.assertIn("Done: 2 of 2", out)
        self.assertEqual([i["listen"] for i in panel.inbounds], ["127.0.0.1", "127.0.0.1", "127.0.0.1"])

    def test_api_backup_is_saved_private(self):
        panel = FakePanel([dict(i) for i in INBOUNDS])
        self.run_menu(["6", "9", "", "CONFIRM", "0", "0"], panel)
        folder = os.path.join(self.root, "backups")
        files = [f for f in os.listdir(folder) if f.startswith("panel-db-")]
        self.assertEqual(len(files), 1)
        path = os.path.join(folder, files[0])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as fh:
            self.assertTrue(fh.read().startswith(b"SQLite format 3"))

    def test_nothing_to_do_when_all_already_local(self):
        rows = [dict(i, listen="127.0.0.1") for i in INBOUNDS]
        panel = FakePanel(rows)
        out = self.run_menu(["6", "9", "0", "0"], panel)
        self.assertIn("Nothing to do", out)
        self.assertEqual(panel.writes, [])


if __name__ == "__main__":
    unittest.main()
