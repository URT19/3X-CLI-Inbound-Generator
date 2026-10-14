import os
import random
import unittest

from network.cloudflare import CloudflarePorts
from network.ports import cloudflare_ports_for, pick_cloudflare_port

CF = CloudflarePorts(
    source="t", retrieved="t",
    http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
    https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}),
)


class CloudflareFallbackTests(unittest.TestCase):
    def test_8443_is_preferred_when_free(self):
        allowed = cloudflare_ports_for("tls", CF)
        self.assertEqual(pick_cloudflare_port(allowed, [], rng=random.Random(1)), 8443)

    def test_8443_is_skipped_when_taken(self):
        allowed = cloudflare_ports_for("tls", CF)
        self.assertNotEqual(pick_cloudflare_port(allowed, [8443], rng=random.Random(1)), 8443)

    def test_tls_never_uses_443_or_80(self):
        allowed = cloudflare_ports_for("tls", CF)
        self.assertNotIn(443, allowed)
        self.assertNotIn(80, cloudflare_ports_for("plain", CF))

    def test_exhausted_cloudflare_ports_fall_back_to_random_non_cloudflare_port_with_warning(self):
        from core.preflight import resolve_values
        from config.settings import NetworkSettings
        from certs.checker import CertStatus
        from templates.loader import load_library
        import tempfile, shutil
        from tests.test_certs import HAVE_OPENSSL, make_cert
        if not HAVE_OPENSSL:
            self.skipTest("openssl not installed")
        lib = load_library(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "inbounds"))
        d = tempfile.mkdtemp()
        try:
            make_cert(os.path.join(d, "c.example.test"), "c.example.test", days=90)
            net = NetworkSettings(cdn_domain="c.example.test", port_mode="random",
                                  random_port_low=50000, random_port_high=50010)
            used = sorted(cloudflare_ports_for("tls", CF))
            res = resolve_values(lib["tls_ws_cdn"], net, {"cdn_ws": "/abc"}, d, CF, used,
                                 status_fn=lambda dom: CertStatus(dom, "ok", "", "", ""),
                                 connection_address="c.example.test", cdn_via="cloudflare")
            self.assertEqual(res.problems, [])
            self.assertTrue(50000 <= res.values["PORT"] <= 50010)
            self.assertNotIn(res.values["PORT"], CF.all_ports)
            self.assertTrue(res.warnings and "No Cloudflare port left" in res.warnings[0])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class RealityPortPreferenceTests(unittest.TestCase):
    def test_reality_prefers_8443_when_free(self):
        from core.preflight import resolve_values
        from config.settings import NetworkSettings
        from templates.loader import load_library
        lib = load_library(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "inbounds"))
        net = NetworkSettings(port_mode="random", random_port_low=50000, random_port_high=50010)
        res = resolve_values(lib["tcp_reality_vision_direct"], net, {}, "/x", CF, [], status_fn=None,
                             reality={"dest": "www.apple.com:443", "sni": "www.apple.com"})
        self.assertEqual(res.values["PORT"], 8443)
        self.assertNotIn(443, [res.values["PORT"]])
