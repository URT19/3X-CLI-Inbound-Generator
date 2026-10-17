import json
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
from state.inventory import compare
from state.records import append_record, load_records
from templates.loader import load_library
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t",
                     http_ports=frozenset({80, 2095}), https_ports=frozenset({443, 8443}))


class IpCompatibilityTests(unittest.TestCase):
    def test_ip_compatible_templates_have_no_domain_or_certificate(self):
        library = load_library(os.path.join(ROOT, "inbounds"))
        compatible = sorted(t.template_id for t in library.values() if ip_compatible(t))
        self.assertIn("http_tcp_direct_vmess", compatible)
        for tid in compatible:
            self.assertIn(library[tid].connection_mode, ("direct", "fallback"), tid)
            self.assertNotIn("SUBDOMAIN_DIRECT", json.dumps(library[tid].content), tid)
            self.assertNotIn("CERT_DIRECT", json.dumps(library[tid].content), tid)


class DirectIpFlowTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.ordered = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                              key=lambda t: (t.number, t.template_id))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script, settings, panel):
        inputs = iter(script)
        out = []
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        Menu(client, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.library, settings=settings, cloudflare=CF, state_dir=self.state).run()
        return "\n".join(out)

    def settings(self):
        return Settings(network=NetworkSettings(port_mode="random",
                                                random_port_low=20000, random_port_high=22000),
                        paths=generate_all())

    def test_direct_with_loopback_address_recorded(self):
        panel = FakePanel()
        settings = self.settings()
        idx = next(i for i, t in enumerate(self.ordered, 1) if t.template_id == "http_tcp_direct_vmess")
        text = self.run_menu(["4", "1", "3", str(idx), CONFIRM_WORD, "0", "0"], settings, panel)
        self.assertIn("Done and verified", text)
        self.assertRegex(str(panel.inbounds[0]), r"/[A-Za-z0-9]{12}")  # every inbound has its own path
        rec = load_records(self.state, "direct")[0]
        self.assertEqual(rec["address"], "127.0.0.1")

    def test_direct_refused_when_domain_missing_for_domain_choice(self):
        panel = FakePanel()
        text = self.run_menu(["4", "1", "1", "0", "0"], self.settings(), panel)
        self.assertIn("Direct domain is not set", text)
        self.assertEqual(panel.writes, [])


class InventoryTests(unittest.TestCase):
    def test_matched_missing_unknown_and_port_conflicts(self):
        local = {
            "direct": [{"inbound_id": 1, "name": "02-A", "port": 9000},
                       {"inbound_id": 9, "name": "gone", "port": 9100}],
            "cdn": [],
        }
        panel = [
            {"id": 1, "remark": "02-A", "port": 9000},
            {"id": 3, "remark": "manual", "port": 9000},
        ]
        inv = compare(local, panel)
        self.assertEqual([m["id"] for m in inv.matched], [1])
        self.assertEqual([m["id"] for m in inv.missing_on_panel], [9])
        self.assertEqual([u["id"] for u in inv.unknown_on_panel], [3])
        self.assertEqual(inv.port_conflicts, [9000])

    def test_renamed_panel_inbound_counts_as_missing(self):
        inv = compare({"direct": [{"inbound_id": 1, "name": "old", "port": 1}], "cdn": []},
                      [{"id": 1, "remark": "new", "port": 1}])
        self.assertEqual(len(inv.matched), 0)
        self.assertEqual(len(inv.missing_on_panel), 1)


if __name__ == "__main__":
    unittest.main()
