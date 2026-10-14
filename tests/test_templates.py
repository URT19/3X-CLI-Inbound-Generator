import json
import os
import unittest

from templates.loader import TemplateError, load_library, render

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "inbounds")
EXPECTED_IDS = {
    "tls_xhttp_direct", "tls_tcp_direct", "tls_ws_direct", "tls_httpupgrade_direct",
    "tls_grpc_direct", "http_httpupgrade_direct", "http_ws_direct_vless",
    "http_tcp_direct_vmess", "http_ws_direct_vmess", "tls_ws_cdn",
    "tls_grpc_cdn_vmess", "tls_xhttp_cdn_vless", "tls_xhttp_cdn_vmess",
    "tls_httpupgrade_cdn_vmess", "tls_ws_cdn_trojan", "http_httpupgrade_cdn_vless",
    "http_httpupgrade_cdn_vmess", "http_ws_cdn_vless", "http_ws_cdn_vmess",
    "http_xhttp_cdn_vless", "http_xhttp_cdn_vmess", "tls_hysteria_direct",
    "tls_tuic_direct", "udp_amneziawg_direct", "tcp_reality_vision_direct",
    "grpc_reality_direct", "xhttp_reality_direct", "tls_vless_vision_direct", "tls_trojan_tcp_direct",
    "tcp_reality_plain_direct",
}


class LibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = load_library(LIB)

    def test_all_reference_templates_are_present(self):
        self.assertEqual(set(self.library), EXPECTED_IDS)
        self.assertEqual(len(self.library), 30)

    def test_no_template_has_a_fixed_port(self):
        for tid, t in self.library.items():
            self.assertEqual(t.content["port"], "{{PORT}}", tid)
            self.assertIn("PORT", t.required_inputs, tid)

    def test_connection_modes_match_source_ids(self):
        for tid, t in self.library.items():
            expected = "cdn" if "_cdn" in tid else "direct"
            self.assertEqual(t.connection_mode, expected, tid)

    def test_only_protocols_from_source_or_panel_example_are_used(self):
        protocols = {t.protocol for t in self.library.values()}
        self.assertEqual(protocols, {"vless", "vmess", "trojan", "hysteria", "tuic", "amneziawg"})

    def test_no_content_id_or_traffic_fields_remain(self):
        for tid, t in self.library.items():
            for key in ("id", "up", "down", "total", "clientStats"):
                self.assertNotIn(key, t.content, f"{tid} still has {key}")

    def test_raw_files_are_valid_json(self):
        for name in os.listdir(LIB):
            with open(os.path.join(LIB, name), encoding="utf-8") as fh:
                json.load(fh)


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = load_library(LIB)

    def inputs_for(self, tid, port=8443):
        values = {"PORT": port}
        for key in self.library[tid].required_inputs:
            values.setdefault(key, f"VAL_{key}")
        return values

    def test_render_cdn_ws_vmess(self):
        t = self.library["tls_ws_cdn"]
        payload = render(t, self.inputs_for("tls_ws_cdn", 8443))
        self.assertEqual(payload["port"], 8443)
        self.assertEqual(payload["tag"], "in-8443-tcp")
        self.assertNotIn("{{", json.dumps(payload))
        self.assertEqual(payload["protocol"], "vmess")

    def test_render_leaves_no_placeholder_for_every_template(self):
        for tid, t in self.library.items():
            payload = render(t, self.inputs_for(tid, 20000))
            self.assertNotIn("{{", json.dumps(payload), tid)

    def test_missing_input_refused(self):
        t = self.library["tls_ws_cdn"]
        values = self.inputs_for("tls_ws_cdn")
        values.pop(next(k for k in t.required_inputs if k != "PORT"))
        with self.assertRaisesRegex(TemplateError, "Missing inputs"):
            render(t, values)

    def test_reserved_port_refused(self):
        t = self.library["tls_xhttp_cdn_vless"]
        with self.assertRaisesRegex(TemplateError, "reserved"):
            render(t, self.inputs_for("tls_xhttp_cdn_vless", 443))

    def test_non_integer_port_refused(self):
        t = self.library["tls_ws_cdn"]
        with self.assertRaises(TemplateError):
            render(t, self.inputs_for("tls_ws_cdn", "abc"))

    def test_render_does_not_mutate_library(self):
        t = self.library["tls_ws_cdn"]
        before = json.dumps(t.content, sort_keys=True)
        render(t, self.inputs_for("tls_ws_cdn", 9000))
        self.assertEqual(before, json.dumps(t.content, sort_keys=True))


class LoaderValidationTests(unittest.TestCase):
    def test_broken_json_reported(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.json"), "w") as fh:
                fh.write("{oops")
            with self.assertRaisesRegex(TemplateError, "invalid JSON"):
                load_library(d)

    def test_file_name_must_match_template_id(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            doc = {
                "template_id": "real", "number": 1, "transport": "tcp",
                "name": "x", "template_version": "1.0.0",
                "connection_mode": "direct", "protocol": "vless", "security": "tls",
                "required_inputs": [], "validation": {}, "content": {},
            }
            with open(os.path.join(d, "other.json"), "w") as fh:
                json.dump(doc, fh)
            with self.assertRaisesRegex(TemplateError, "file name"):
                load_library(d)


if __name__ == "__main__":
    unittest.main()


class ExternalProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = load_library(LIB)

    def test_no_external_proxy_left_inside_stream_settings(self):
        for tid, t in self.library.items():
            self.assertNotIn("externalProxy", t.content.get("streamSettings", {}), tid)

    def test_cdn_templates_with_legacy_proxy_have_host_entries(self):
        for tid in ("tls_ws_cdn", "tls_xhttp_cdn_vless", "http_ws_cdn_vmess"):
            self.assertTrue(self.library[tid].external_proxies, tid)

    def test_host_render_maps_fields_like_panel_source(self):
        from templates.loader import render_hosts
        t = self.library["tls_ws_cdn"]
        values = {"PORT": 8443, **{k: f"VAL_{k}" for k in t.required_inputs if k != "PORT"}}
        hosts = render_hosts(t, values, 42)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["address"], "VAL_WHITELIST_IP")
        self.assertEqual(hosts[0]["port"], 8443)  # source externalProxy port for tls_ws_cdn
        self.assertEqual(hosts[0]["inboundId"], 42)
        self.assertEqual(hosts[0]["security"], "same")
        self.assertNotIn("{{", json.dumps(hosts))
