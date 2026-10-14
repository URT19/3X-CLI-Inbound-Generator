import json
import os
import shutil
import tempfile
import unittest

import yaml

from config.settings import Settings
from core.menu import Menu
from panel.client import PanelClient
from state.export import build_inventory, to_yaml
from state.records import append_record
from tests.test_writes import FakePanel

FAKE_TOKEN = "SECRET_TOKEN_ABCD1234"


class BuildTests(unittest.TestCase):
    def test_merges_records_and_marks_unmanaged_panel_inbounds(self):
        rows = [
            {"id": 1, "remark": "01-A", "port": 9000, "protocol": "vless", "enable": True},
            {"id": 2, "remark": "manual", "port": 9100, "protocol": "trojan", "enable": False},
        ]
        local = {"direct": [{"inbound_id": 1, "name": "01-A", "port": 9000, "address": "1.2.3.4",
                             "path": "/p", "security": "tls", "template_id": "t"}], "cdn": []}
        data = build_inventory(rows, local, now=0)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["managed_count"], 1)
        first, second = data["inbounds"]
        self.assertEqual(first["path"], "/p")
        self.assertEqual(first["address"], "1.2.3.4")
        self.assertEqual(first["connection_mode"], "direct")
        self.assertTrue(first["managed"])
        self.assertFalse(second["managed"])
        self.assertIsNone(second["path"])

    def test_renamed_panel_inbound_is_not_merged(self):
        rows = [{"id": 1, "remark": "renamed", "port": 9000, "protocol": "vless", "enable": True}]
        local = {"direct": [{"inbound_id": 1, "name": "01-A", "port": 9000, "path": "/p"}], "cdn": []}
        data = build_inventory(rows, local, now=0)
        self.assertFalse(data["inbounds"][0]["managed"])
        self.assertIsNone(data["inbounds"][0]["path"])


class YamlTests(unittest.TestCase):
    def test_yaml_parses_back_to_same_data(self):
        rows = [{"id": 1, "remark": "01-A: \"quoted\"", "port": 9000, "protocol": "vless", "enable": True}]
        local = {"direct": [{"inbound_id": 1, "name": "01-A: \"quoted\"", "port": 9000,
                             "path": "/abc", "security": "none"}], "cdn": []}
        data = build_inventory(rows, local, now=0)
        self.assertEqual(yaml.safe_load(to_yaml(data)), json.loads(json.dumps(data)))

    def test_empty_inventory_is_valid_yaml(self):
        data = build_inventory([], {"direct": [], "cdn": []}, now=0)
        self.assertEqual(yaml.safe_load(to_yaml(data))["inbounds"], [])


class ExportMenuTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.state = os.path.join(self.root, "state", "local_inbounds")
        append_record(self.state, "direct", {"inbound_id": 1, "name": "01-A", "port": 9000,
                                             "path": "/abc", "address": "1.2.3.4", "security": "none"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_export_writes_json_and_yaml_and_shows_paths(self):
        panel = FakePanel([{"id": 1, "remark": "01-A", "port": 9000, "protocol": "vless", "enable": True,
                            "listen": ""}])
        inputs = iter(["11", "0"])
        out = []
        client = PanelClient("127.0.0.1:2053", token=FAKE_TOKEN, transport=panel)
        Menu(client, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             state_dir=self.state, root=self.root).run()
        text = "\n".join(out)
        exports = os.path.join(self.root, "exports")
        files = os.listdir(exports)
        json_file = next(f for f in files if f.endswith(".json"))
        yaml_file = next(f for f in files if f.endswith(".yaml"))
        self.assertIn(os.path.join(exports, json_file), text)
        self.assertIn(os.path.join(exports, yaml_file), text)
        with open(os.path.join(exports, json_file)) as fh:
            data = json.load(fh)
        self.assertEqual(data["inbounds"][0]["path"], "/abc")
        self.assertEqual(data["inbounds"][0]["name"], "01-A")
        with open(os.path.join(exports, yaml_file)) as fh:
            self.assertEqual(yaml.safe_load(fh)["inbounds"][0]["port"], 9000)

    def test_export_contains_no_token(self):
        panel = FakePanel([{"id": 1, "remark": "01-A", "port": 9000, "protocol": "vless", "enable": True}])
        inputs = iter(["11", "0"])
        client = PanelClient("127.0.0.1:2053", token=FAKE_TOKEN, transport=panel)
        Menu(client, input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
             state_dir=self.state, root=self.root).run()
        for name in os.listdir(os.path.join(self.root, "exports")):
            with open(os.path.join(self.root, "exports", name)) as fh:
                self.assertNotIn(FAKE_TOKEN, fh.read())

    def test_export_without_client_is_refused(self):
        inputs = iter(["11", "0"])
        out = []
        Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             state_dir=self.state, root=self.root).run()
        self.assertIn("Panel is not configured", "\n".join(out))


if __name__ == "__main__":
    unittest.main()


class ReportTests(unittest.TestCase):
    def test_summary_counts_and_conflicts(self):
        from state.reports import summarize
        rows = [{"id": 1, "remark": "01-A", "port": 9000, "protocol": "vless", "enable": True},
                {"id": 2, "remark": "x", "port": 9000, "protocol": "trojan", "enable": False}]
        local = {"direct": [{"inbound_id": 1, "name": "01-A", "port": 9000, "transport": "tcp",
                             "security": "none", "template_id": "t"}], "cdn": []}
        rep = summarize(rows, local)
        self.assertEqual(rep["panel_total"], 2)
        self.assertEqual(rep["panel_enabled"], 1)
        self.assertEqual(rep["matched"], 1)
        self.assertEqual(rep["unmanaged_on_panel"], 1)
        self.assertEqual(rep["port_conflicts"], [9000])

    def test_local_only_summary_has_no_panel_fields(self):
        from state.reports import summarize
        rep = summarize(None, {"direct": [], "cdn": []})
        self.assertNotIn("panel_total", rep)
        self.assertEqual(rep["source"], "local records only")
