import unittest

from core.menu import Menu
from panel.client import PanelClient
from panel.errors import PanelError
from panel.writes import eligible_fallback_master
from tests.test_writes import FakePanel as _FP

MASTER = {"id": 5, "remark": "VLESS-TLS", "protocol": "vless", "port": 8443,
          "streamSettings": '{"network":"tcp","security":"tls"}'}
REALITY = {"id": 6, "remark": "VLESS-R", "protocol": "vless", "port": 9443,
           "streamSettings": {"network": "tcp", "security": "reality"}}
WS = {"id": 7, "remark": "VMESS-WS", "protocol": "vmess", "port": 2083,
      "streamSettings": {"network": "ws", "security": "tls"}}


class EligibilityTests(unittest.TestCase):
    def test_master_rules(self):
        self.assertTrue(eligible_fallback_master(MASTER))
        self.assertTrue(eligible_fallback_master(REALITY))
        self.assertFalse(eligible_fallback_master(WS))
        self.assertFalse(eligible_fallback_master({"protocol": "vless", "streamSettings": "not json"}))


class FakeSiteTests(unittest.TestCase):
    def make_panel(self, fallbacks=None):
        panel = _FP([MASTER, REALITY, WS])
        if fallbacks is not None:
            panel.fallbacks[5] = fallbacks
        return panel

    def run_menu(self, script, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t))).run()
        return "\n".join(out)

    def test_sets_fake_site_and_keeps_existing_rules(self):
        existing = [{"id": 1, "masterId": 5, "childId": 11, "name": "trojan", "alpn": "h2",
                     "path": "/tr", "dest": "", "xver": 1, "sortOrder": 0}]
        panel = self.make_panel(existing)
        self.run_menu(["4", "3", "5", "127.0.0.1:8080", "", "0", "0"], panel)
        sent = panel.writes[-1][1]["fallbacks"]
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["childId"], 11)           # existing child rule kept
        self.assertEqual(sent[0]["path"], "/tr")
        self.assertEqual(sent[1]["dest"], "127.0.0.1:8080")
        self.assertEqual(sent[1]["childId"], 0)
        self.assertEqual(sent[1]["name"], "fake-site")

    def test_existing_fake_site_is_replaced_not_duplicated(self):
        existing = [{"id": 1, "masterId": 5, "childId": 0, "name": "fake-site", "dest": "9000",
                     "alpn": "", "path": "", "xver": 0, "sortOrder": 0}]
        panel = self.make_panel(existing)
        self.run_menu(["4", "3", "5", "8080", "", "0", "0"], panel)
        sent = panel.writes[-1][1]["fallbacks"]
        self.assertEqual([r["dest"] for r in sent], ["8080"])

    def test_dry_run_path_is_not_taken_without_confirm(self):
        panel = self.make_panel()
        out = self.run_menu(["4", "3", "5", "8080", "no", "0", "0"], panel)
        self.assertIn("Cancelled", out)
        self.assertEqual(panel.writes, [])

    def test_non_eligible_master_refused(self):
        panel = self.make_panel()
        out = self.run_menu(["4", "3", "7", "0", "0"], panel)
        self.assertIn("Choose one of the listed", out)
        self.assertEqual(panel.writes, [])

    def test_no_master_message(self):
        panel = _FP([WS])
        out = self.run_menu(["4", "3", "0", "0"], panel)
        self.assertIn("No VLESS or Trojan inbound", out)

    def test_bad_address_refused_before_sending(self):
        panel = self.make_panel()
        out = self.run_menu(["4", "3", "5", "443", "0", "0"], panel)
        self.assertIn("cannot be used for a fake site", out)
        self.assertEqual(panel.writes, [])


if __name__ == "__main__":
    unittest.main()
