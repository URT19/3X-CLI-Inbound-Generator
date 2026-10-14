import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from config.settings import NetworkSettings, Settings, load_settings
from core.menu import CONFIRM_WORD, Menu
from core.preflight import resolve_values, validate_payload
from network import reality
from network.cloudflare import CloudflarePorts
from network.paths import generate_all
from panel.client import PanelClient
from state.export import build_inventory, to_yaml
from state.records import load_records
from templates.loader import load_library, render
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))
HAVE_OPENSSL = shutil.which("openssl") is not None


class KeyAndTargetTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_keypair_is_raw_x25519_in_base64url_without_padding(self):
        priv, pub = reality.generate_keypair()
        for value in (priv, pub):
            self.assertEqual(len(value), 43)
            self.assertNotIn("=", value)
            self.assertEqual(len(base64.urlsafe_b64decode(value + "=")), 32)
        self.assertNotEqual(priv, reality.generate_keypair()[0])

    def test_short_id_is_16_hex(self):
        sid = reality.generate_short_id()
        self.assertRegex(sid, r"^[0-9a-f]{16}$")
        reality.validate_short_id(sid)

    def test_targets_and_custom_values_are_validated(self):
        self.assertEqual(reality.validate_dest("www.apple.com:443"), "www.apple.com:443")
        self.assertEqual(reality.validate_sni("www.apple.com"), "www.apple.com")
        for bad in ("www.apple.com", "bad_host:443", "1.2.3.4:443"):
            with self.assertRaises(reality.RealityError):
                reality.validate_dest(bad)
        with self.assertRaises(reality.RealityError):
            reality.validate_sni("not a domain")

    def test_default_list_ends_with_custom_option_in_menu(self):
        self.assertGreaterEqual(len(reality.DEFAULT_TARGETS), 3)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class RealityTemplateTests(unittest.TestCase):
    def setUp(self):
        self.t = load_library(os.path.join(ROOT, "inbounds"))["tcp_reality_vision_direct"]

    def test_template_uses_reality_without_certificate(self):
        stream = self.t.content["streamSettings"]
        self.assertEqual(stream["security"], "reality")
        self.assertNotIn("tlsSettings", stream)
        self.assertEqual(self.t.security, "reality")
        self.assertEqual(self.t.connection_mode, "direct")

    def test_resolves_renders_and_validates(self):
        net = NetworkSettings(port_mode="random", random_port_low=40000, random_port_high=40010)
        res = resolve_values(self.t, net, {}, "/nonexistent", CF, [], status_fn=None,
                             reality={"dest": "www.apple.com:443", "sni": "www.apple.com"},
                             fingerprint="firefox")
        self.assertEqual(res.problems, [])
        payload = render(self.t, res.values, remark="25-VLESS-TCP-DIRECT-REALITY")
        rs = payload["streamSettings"]["realitySettings"]
        self.assertEqual(rs["dest"], "www.apple.com:443")
        self.assertEqual(rs["serverNames"], ["www.apple.com"])
        self.assertEqual(rs["privateKey"], res.values["REALITY_PRIVATE_KEY"])
        self.assertEqual(rs["shortIds"], [res.values["REALITY_SHORT_ID"]])
        self.assertEqual(rs["fingerprint"], "firefox")
        self.assertEqual(validate_payload(payload), [])
        self.assertNotIn("{{", json.dumps(payload))

    def test_missing_target_refused(self):
        net = NetworkSettings(port_mode="random", random_port_low=40000, random_port_high=40010)
        res = resolve_values(self.t, net, {}, "/x", CF, [], status_fn=None, reality=None)
        self.assertTrue(any("REALITY target is not chosen" in p for p in res.problems))


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class RealityMenuTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        self.settings_path = os.path.join(self.dir, "s.json")
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.settings = Settings(network=NetworkSettings(port_mode="random", random_port_low=40000,
                                                         random_port_high=40050, direct_domain="d.example.test"),
                                 paths=generate_all(), fingerprint="chrome")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def reality_index(self):
        ordered = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        return next(i for i, t in enumerate(ordered, 1) if t.template_id == "tcp_reality_vision_direct")

    def run_menu(self, script, panel):
        inputs = iter(script)
        out = []
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             library=self.library, settings=self.settings, settings_path=self.settings_path,
             cloudflare=CF, state_dir=self.state).run()
        return "\n".join(out)

    def test_reality_created_with_chosen_target_and_keys_kept_private(self):
        panel = FakePanel()
        idx = self.reality_index()
        out = self.run_menu(["4", "3", str(idx), "1", CONFIRM_WORD, "0"], panel)
        self.assertIn("Done and verified", out)
        inbound = panel.inbounds[0]
        rs = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(rs["dest"], reality.DEFAULT_TARGETS[0][1])
        name = inbound["remark"]
        self.assertIn("REALITY", name)
        saved = load_settings(self.settings_path).reality_keys[name]
        self.assertEqual(saved["privateKey"], rs["privateKey"])
        record = load_records(self.state, "direct")[0]
        self.assertEqual(record["reality_public_key"], saved["publicKey"])
        self.assertNotIn("reality_private_key", record)
        self.assertNotIn(saved["privateKey"], json.dumps(record))

    def test_export_contains_no_reality_private_key(self):
        panel = FakePanel()
        idx = self.reality_index()
        self.run_menu(["4", "3", str(idx), "1", CONFIRM_WORD, "0"], panel)
        saved = load_settings(self.settings_path).reality_keys
        data = build_inventory(panel.inbounds and [{"id": i["id"], "remark": i["remark"], "port": i["port"],
                                                    "protocol": i["protocol"], "enable": True}
                                                   for i in panel.inbounds],
                               {"direct": load_records(self.state, "direct"), "cdn": []})
        text = json.dumps(data) + to_yaml(data)
        for entry in saved.values():
            self.assertNotIn(entry["privateKey"], text)

    def test_custom_target_is_validated(self):
        panel = FakePanel()
        idx = self.reality_index()
        custom = len(reality.DEFAULT_TARGETS) + 1
        out = self.run_menu(["4", "3", str(idx), str(custom), "bad target", "x", "0"], panel)
        self.assertIn("host:443", out)
        self.assertEqual(panel.writes, [])

    def test_non_reality_choice_does_not_ask_for_target(self):
        panel = FakePanel()
        ordered = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                         key=lambda t: (t.number, t.template_id))
        idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "http_tcp_direct_vmess")
        out = self.run_menu(["4", "3", str(idx), "n", "0"], panel)
        self.assertNotIn("REALITY target", out)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class RealityTransportVariantTests(unittest.TestCase):
    def setUp(self):
        self.lib = load_library(os.path.join(ROOT, "inbounds"))
        self.net = NetworkSettings(port_mode="random", random_port_low=40000, random_port_high=40010)
        self.paths = generate_all()

    def build(self, template_id):
        t = self.lib[template_id]
        res = resolve_values(t, self.net, self.paths, "/x", CF, [], status_fn=None,
                             reality={"dest": "www.apple.com:443", "sni": "www.apple.com"})
        self.assertEqual(res.problems, [])
        return render(t, res.values, remark="X"), res

    def test_grpc_reality_uses_direct_grpc_path(self):
        payload, _ = self.build("grpc_reality_direct")
        stream = payload["streamSettings"]
        self.assertEqual(stream["network"], "grpc")
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(stream["grpcSettings"]["serviceName"], self.paths["direct_grpc"])
        self.assertEqual(validate_payload(payload), [])

    def test_xhttp_reality_uses_direct_xhttp_path(self):
        payload, _ = self.build("xhttp_reality_direct")
        stream = payload["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"]["path"], self.paths["direct_xhttp"])
        self.assertEqual(validate_payload(payload), [])

    def test_variants_have_no_certificate_and_all_keys(self):
        for tid in ("grpc_reality_direct", "xhttp_reality_direct"):
            payload, res = self.build(tid)
            self.assertNotIn("tlsSettings", payload["streamSettings"])
            self.assertIn("REALITY_PRIVATE_KEY", res.values)
            self.assertNotIn("{{", json.dumps(payload))

    def test_reality_grpc_menu_creates_inbound_named_with_grpc(self):
        import tests.test_reality as me
        dir_ = tempfile.mkdtemp()
        try:
            settings = Settings(network=self.net, paths=self.paths, fingerprint="chrome",
                                cert_root=dir_)
            ordered = sorted((t for t in self.lib.values() if t.connection_mode == "direct"),
                             key=lambda t: (t.number, t.template_id))
            idx = next(i for i, t in enumerate(ordered, 1) if t.template_id == "grpc_reality_direct")
            panel = FakePanel()
            inputs = iter(["4", "3", str(idx), "1", CONFIRM_WORD, "0"])
            Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
                 input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
                 library=self.lib, settings=settings, settings_path=os.path.join(dir_, "s.json"),
                 cloudflare=CF, state_dir=os.path.join(dir_, "st")).run()
            self.assertEqual(len(panel.inbounds), 1)
            self.assertIn("GRPC-DIRECT-REALITY", panel.inbounds[0]["remark"])
        finally:
            shutil.rmtree(dir_, ignore_errors=True)
