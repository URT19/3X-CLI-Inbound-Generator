import json
import os
import re
import unittest

from core.preflight import resolve_values, validate_payload
from network.paths import random_secret
from network.cloudflare import CloudflarePorts
from config.settings import NetworkSettings
from certs.checker import CertStatus
from templates.loader import load_library, render

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))


class HysteriaTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_library(os.path.join(ROOT, "inbounds"))["tls_hysteria_direct"]

    def test_udp_tag_and_protocol(self):
        self.assertEqual(self.t.content["protocol"], "hysteria")
        self.assertEqual(self.t.content["streamSettings"]["network"], "hysteria")
        self.assertEqual(self.t.content["tag"], "in-{{PORT}}-udp")

    def test_example_fields_are_kept(self):
        stream = self.t.content["streamSettings"]
        self.assertEqual(stream["hysteriaSettings"], {"version": 2, "udpIdleTimeout": 60})
        self.assertEqual(stream["tlsSettings"]["alpn"], ["h3"])
        self.assertEqual(stream["tlsSettings"]["settings"]["fingerprint"], "chrome")
        self.assertEqual(self.t.content["settings"], {"version": 2})

    def test_placeholders_are_port_password_and_direct_certificate(self):
        placeholders = set(re.findall(r"\{\{([A-Z_]+)\}\}", json.dumps(self.t.content)))
        self.assertEqual(placeholders, {"PORT", "HY_PASSWORD", "CERT_DIRECT", "KEY_DIRECT", "SUBDOMAIN_DIRECT"})

    def test_certificate_comes_from_direct_domain(self):
        cert = self.t.content["streamSettings"]["tlsSettings"]["certificates"][0]
        self.assertEqual(cert["certificateFile"], "{{CERT_DIRECT}}")
        self.assertEqual(cert["keyFile"], "{{KEY_DIRECT}}")


class HysteriaRenderTests(unittest.TestCase):
    def setUp(self):
        self.t = load_library(os.path.join(ROOT, "inbounds"))["tls_hysteria_direct"]
        self.net = NetworkSettings(port_mode="random",
                                   random_port_low=35000, random_port_high=35010)
        self.ok = lambda domain: CertStatus(domain, "ok", "fine", "", "")

    def resolve(self):
        import tempfile
        root = tempfile.mkdtemp()
        cert_dir = os.path.join(root, "direct.example.test")
        os.makedirs(cert_dir)
        for name in ("fullchain.pem", "privkey.pem"):
            open(os.path.join(cert_dir, name), "w").close()
        self.net.direct_domain = "direct.example.test"
        return resolve_values(self.t, self.net, {}, root, CF, [], status_fn=self.ok), root

    def test_password_is_random_alphanumeric_16(self):
        res, _ = self.resolve()
        pwd = res.values["HY_PASSWORD"]
        self.assertRegex(pwd, r"^[A-Za-z0-9]{16}$")

    def test_password_differs_per_inbound(self):
        a = random_secret(16)
        b = random_secret(16)
        self.assertNotEqual(a, b)

    def test_rendered_payload_has_password_and_direct_certificate(self):
        res, _root = self.resolve()
        self.assertEqual(res.problems, [])
        payload = render(self.t, res.values, remark="22-HYSTERIA-HY2-DIRECT-TLS")
        self.assertEqual(payload["protocol"], "hysteria")
        self.assertEqual(payload["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"],
                         res.values["HY_PASSWORD"])
        self.assertNotIn("{{", json.dumps(payload))
        self.assertEqual(validate_payload(payload), [])


if __name__ == "__main__":
    unittest.main()
