import unittest

from utils.url import normalize_base_url


class NormalizeBaseUrlTests(unittest.TestCase):
    def test_port_443_without_scheme_uses_https(self):
        self.assertEqual(normalize_base_url("127.0.0.1:443"), "https://127.0.0.1:443")

    def test_other_port_without_scheme_uses_http(self):
        self.assertEqual(normalize_base_url("127.0.0.1:2053"), "http://127.0.0.1:2053")

    def test_explicit_scheme_is_kept(self):
        self.assertEqual(
            normalize_base_url("https://panel.example.com:2053"),
            "https://panel.example.com:2053",
        )

    def test_web_base_path_is_kept_and_trailing_slash_removed(self):
        self.assertEqual(
            normalize_base_url("https://1.2.3.4:443/mysecret/"),
            "https://1.2.3.4:443/mysecret",
        )

    def test_ipv6_with_port_443(self):
        self.assertEqual(normalize_base_url("[::1]:443"), "https://[::1]:443")

    def test_empty_address_rejected(self):
        with self.assertRaises(ValueError):
            normalize_base_url("   ")

    def test_unsupported_scheme_rejected(self):
        with self.assertRaises(ValueError):
            normalize_base_url("ftp://example.com:21")


if __name__ == "__main__":
    unittest.main()
