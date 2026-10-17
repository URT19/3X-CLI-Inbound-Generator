import os
import unittest

from templates.loader import load_library, render
from utils.naming import MAX_NAME_LENGTH, NamingError, build_name, validate_custom_name

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class NamingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = load_library(os.path.join(ROOT, "inbounds"))

    def test_every_default_name_fits_limit_and_starts_with_number(self):
        for tid, t in self.library.items():
            name = build_name(t, existing=[])
            self.assertLessEqual(len(name), MAX_NAME_LENGTH, tid)
            self.assertTrue(name[0].isdigit(), tid)
            self.assertTrue(name.isascii(), tid)

    def test_default_names_are_unique_across_library(self):
        names = [build_name(t, existing=[]) for t in self.library.values()]
        self.assertEqual(len(names), len(set(names)))

    def test_known_name_format(self):
        t = self.library["tls_xhttp_cdn_vless"]
        self.assertEqual(build_name(t, []), "12-VLESS-XHTTP-CDN-TLS")
        t = self.library["tls_ws_cdn_vmess"]
        self.assertEqual(build_name(t, []), "14-VMESS-WS-CDN-TLS")

    def test_collision_adds_suffix(self):
        t = self.library["tls_ws_cdn_vmess"]
        base = build_name(t, [])
        self.assertEqual(build_name(t, [base]), base + "-2")
        self.assertEqual(build_name(t, [base, base + "-2"]), base + "-3")

    def test_suffix_never_exceeds_limit(self):
        t = self.library["tls_httpupgrade_cdn_vless"]
        base = build_name(t, [])
        taken = [base] + [f"{base}-{n}" for n in range(2, 10)]
        with self.assertRaises(NamingError):
            build_name(t, taken, max_length=len(base) + 1)

    def test_too_long_base_refused(self):
        t = self.library["tls_ws_cdn_vmess"]
        with self.assertRaises(NamingError):
            build_name(t, [], max_length=5)

    def test_custom_name_rules(self):
        self.assertIsNone(validate_custom_name("07-my-node", []))
        self.assertIn("start with a number", validate_custom_name("my-node", []))
        self.assertIn("longer", validate_custom_name("1" * 33, []))
        self.assertIn("already exists", validate_custom_name("07-x", ["07-x"]))
        self.assertIn("ASCII", validate_custom_name("7-نام", []))
        self.assertIn("empty", validate_custom_name("", []))

    def test_render_uses_given_remark(self):
        t = self.library["tls_tcp_direct"]
        values = {"PORT": 8443, **{k: f"VAL_{k}" for k in t.required_inputs if k != "PORT"}}
        payload = render(t, values, remark="02-VMESS-TCP-DIRECT-TLS")
        self.assertEqual(payload["remark"], "02-VMESS-TCP-DIRECT-TLS")


if __name__ == "__main__":
    unittest.main()
