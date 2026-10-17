import os
import unittest

from core.menu import CONFIRM_WORD
from network.cdn import CDN_ECH_CONFIG
from network.xhttp_matrix import BASE_ID, MatrixError, build_variants
from templates.loader import load_library
from tests.test_certs import HAVE_OPENSSL
from tests.test_template_flow import CF, Env
from tests.test_writes import FakePanel
from utils.naming import MAX_NAME_LENGTH, build_name

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = load_library(os.path.join(ROOT, "inbounds"))[BASE_ID]
        cls.variants = build_variants(cls.base)

    def test_fifteen_distinct_variants(self):
        self.assertEqual(len(self.variants), 15)
        codes = [v.extra["code"] for v in self.variants]
        self.assertEqual(len(set(codes)), 15)
        self.assertEqual(len({v.template_id for v in self.variants}), 15)

    def test_all_modes_and_alpns_are_covered(self):
        seen = {(v.content["streamSettings"]["xhttpSettings"]["mode"],
                 tuple(v.content["streamSettings"]["tlsSettings"]["alpn"])) for v in self.variants}
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            for alpn in (("http/1.1",), ("h2",), ("h2", "http/1.1")):
                self.assertIn((mode, alpn), seen)

    def test_names_fit_the_limit_and_are_unique(self):
        names = [build_name(v, [], mode_label=v.extra["name_label"]) for v in self.variants]
        self.assertEqual(len(set(names)), 15)
        self.assertTrue(all(len(n) <= MAX_NAME_LENGTH and n[0].isdigit() for n in names), names)

    def test_base_template_is_not_changed(self):
        before = self.base.content["streamSettings"]["xhttpSettings"]["mode"]
        build_variants(self.base)
        self.assertEqual(self.base.content["streamSettings"]["xhttpSettings"]["mode"], before)

    def test_non_xhttp_template_refused(self):
        other = load_library(os.path.join(ROOT, "inbounds"))["tls_ws_cdn_vless"]
        with self.assertRaises(MatrixError):
            build_variants(other)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class MatrixMenuTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(fixed_port=9999)  # fixed port mode must be ignored by the matrix

    def tearDown(self):
        self.env.close()

    def test_creates_all_variants_on_random_non_cloudflare_ports(self):
        panel = FakePanel()
        # generate, matrix, route 2 (IP), ECH yes, finalmask no, confirm batch
        _, text = self.env.run(["4", "6", "2", "y", "n", CONFIRM_WORD, "0", "0"], panel)
        self.assertEqual(len(panel.inbounds), 15, text)
        ports = [i["port"] for i in panel.inbounds]
        self.assertEqual(len(set(ports)), 15)
        for port in ports:
            self.assertNotIn(port, CF.all_ports)
            self.assertNotIn(port, (80, 443, 9999))
            self.assertEqual(port % 10, 3)  # TLS ports end with 3
        names = [i["remark"] for i in panel.inbounds]
        self.assertEqual(len(set(names)), 15)
        self.assertTrue(any("XT-PU-H1" in n for n in names))
        paths = [i["streamSettings"]["xhttpSettings"]["path"] for i in panel.inbounds]
        self.assertEqual(len(set(paths)), 15)
        for inbound in panel.inbounds:
            tls = inbound["streamSettings"]["tlsSettings"]
            self.assertEqual(tls["settings"]["echConfigList"], CDN_ECH_CONFIG)
            self.assertEqual(len(tls["cipherSuites"].split(":")), 13)
        self.assertEqual(len(panel.hosts), 1)
        self.assertEqual(panel.hosts[0]["remark"], "CDN")
        self.assertIn("Created (name, port)", text)


if __name__ == "__main__":
    unittest.main()
