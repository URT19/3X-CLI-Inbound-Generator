import os
import shutil
import tempfile
import unittest

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from panel.client import PanelClient
from state.records import append_record
from tests.test_writes import FakePanel

INBOUND = {
    "id": 1, "remark": "04-VMESS-HTTPUP-DIRECT-TLS", "port": 30001, "protocol": "vmess", "enable": True,
    "listen": "", "streamSettings": {"network": "xhttp", "security": "tls",
                                     "xhttpSettings": {"path": "/abc", "host": "d.example.test"},
                                     "tlsSettings": {"serverName": "d.example.test"}},
    "settings": {"clients": []},
}


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_repair(self, panel):
        inputs = iter(["9", "8", CONFIRM_WORD, "0", "0"])
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             settings=Settings(network=NetworkSettings()), state_dir=self.state, root=self.dir).run()
        return "\n".join(out)

    def test_direct_ip_inbound_gets_ip_host_header_and_host_address(self):
        panel = FakePanel([dict(INBOUND)])
        panel.hosts.append({"groupId": "g1", "inboundIds": [1], "hosts": ["d.example.test"], "port": 30001,
                            "remark": INBOUND["remark"], "security": "same", "sni": "", "alpn": []})
        append_record(self.state, "direct", {"inbound_id": 1, "name": INBOUND["remark"], "port": 30001,
                                             "address": "198.51.100.20", "security": "tls"})
        out = self.run_repair(panel)
        self.assertIn("Repairs finished: 2 of 2", out)
        self.assertEqual(panel.hosts[0]["hosts"], ["198.51.100.20"])
        self.assertEqual(panel.inbounds[0]["streamSettings"]["xhttpSettings"]["host"], "198.51.100.20")
        self.assertEqual(panel.inbounds[0]["streamSettings"]["tlsSettings"]["serverName"], "d.example.test")

    def test_nothing_to_repair_when_already_matching(self):
        panel = FakePanel([dict(INBOUND, streamSettings=dict(INBOUND["streamSettings"],
                                                              xhttpSettings={"path": "/abc", "host": "198.51.100.20"}))])
        panel.hosts.append({"groupId": "g1", "inboundIds": [1], "hosts": ["198.51.100.20"], "port": 30001,
                            "remark": INBOUND["remark"]})
        append_record(self.state, "direct", {"inbound_id": 1, "name": INBOUND["remark"], "port": 30001,
                                             "address": "198.51.100.20", "security": "tls"})
        inputs = iter(["9", "8", "0", "0"])
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             settings=Settings(network=NetworkSettings()), state_dir=self.state, root=self.dir).run()
        self.assertIn("Nothing to repair", "\n".join(out))
        self.assertEqual(panel.writes, [])

    def test_cancel_changes_nothing(self):
        panel = FakePanel([dict(INBOUND)])
        panel.hosts.append({"groupId": "g1", "inboundIds": [1], "hosts": ["d.example.test"], "port": 30001,
                            "remark": INBOUND["remark"]})
        append_record(self.state, "direct", {"inbound_id": 1, "name": INBOUND["remark"], "port": 30001,
                                             "address": "198.51.100.20", "security": "tls"})
        inputs = iter(["9", "8", "no", "0", "0"])
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
             settings=Settings(network=NetworkSettings()), state_dir=self.state, root=self.dir).run()
        self.assertEqual(panel.writes, [])


if __name__ == "__main__":
    unittest.main()


class HysteriaSniRepairTests(unittest.TestCase):
    def test_ip_host_gets_domain_as_sni_for_tls(self):
        import tempfile, shutil, os
        from config.settings import NetworkSettings, Settings
        from core.menu import CONFIRM_WORD
        from panel.client import PanelClient
        from tests.test_writes import FakePanel
        from state.records import append_record
        d = tempfile.mkdtemp()
        try:
            hy = {"id": 2, "remark": "22-HYSTERIA-HY2-DIRECT-TLS", "port": 25295, "protocol": "hysteria",
                  "enable": True, "listen": "", "streamSettings": {"network": "hysteria", "security": "tls"},
                  "settings": {"version": 2}}
            panel = FakePanel([hy])
            panel.hosts.append({"groupId": "g2", "inboundIds": [2], "hosts": ["d.example.test"], "port": 25295,
                                "remark": hy["remark"], "sni": ""})
            append_record(os.path.join(d, "st"), "direct", {"inbound_id": 2, "name": hy["remark"],
                                                           "port": 25295, "address": "198.51.100.42",
                                                           "security": "tls", "domain": "d.example.test"})
            inputs = iter(["9", "8", CONFIRM_WORD, "0", "0"])
            Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
                 input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
                 settings=Settings(network=NetworkSettings(direct_domain="d.example.test")),
                 state_dir=os.path.join(d, "st"), root=d).run()
            self.assertEqual(panel.hosts[0]["hosts"], ["198.51.100.42"])
            self.assertEqual(panel.hosts[0]["sni"], "d.example.test")
        finally:
            shutil.rmtree(d, ignore_errors=True)
