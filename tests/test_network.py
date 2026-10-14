import os
import random
import unittest

from network.cloudflare import CloudflareDataError, CloudflarePorts, load_cloudflare_ports
from network.ports import PortError, check_port, pick_random_port
from network.validators import is_valid_domain, parse_ip, parse_ip_list, parse_port, is_loopback_or_private

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(
    source="t", retrieved="t",
    http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
    https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}),
)


class CloudflareDataTests(unittest.TestCase):
    def test_real_file_loads_and_matches_documented_lists(self):
        ports = load_cloudflare_ports(os.path.join(ROOT, "config", "cloudflare_ports.json"))
        self.assertEqual(ports.https_ports, frozenset({443, 2053, 2083, 2087, 2096, 8443}))
        self.assertEqual(ports.http_ports, frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}))
        self.assertTrue(ports.source.startswith("https://developers.cloudflare.com"))

    def test_missing_file_reported(self):
        with self.assertRaises(CloudflareDataError):
            load_cloudflare_ports("/nonexistent/x.json")


class ValidatorTests(unittest.TestCase):
    def test_domains(self):
        self.assertTrue(is_valid_domain("sub.example.com"))
        self.assertFalse(is_valid_domain("localhost"))
        self.assertFalse(is_valid_domain("bad_domain.com"))
        self.assertFalse(is_valid_domain("-bad.com"))
        self.assertFalse(is_valid_domain("1.2.3.4"))
        self.assertFalse(is_valid_domain(""))

    def test_ips(self):
        self.assertEqual(parse_ip(" 1.2.3.4 "), "1.2.3.4")
        self.assertEqual(parse_ip_list("1.1.1.1, 2.2.2.2"), ["1.1.1.1", "2.2.2.2"])
        with self.assertRaises(ValueError):
            parse_ip("999.1.1.1")
        with self.assertRaises(ValueError):
            parse_ip_list(" , ")

    def test_ports(self):
        self.assertEqual(parse_port("8443"), 8443)
        for bad in ("0", "70000", "abc", True):
            with self.assertRaises(ValueError):
                parse_port(bad)

    def test_loopback_or_private(self):
        self.assertTrue(is_loopback_or_private("127.0.0.1"))
        self.assertTrue(is_loopback_or_private("10.0.0.5"))
        self.assertFalse(is_loopback_or_private("8.8.8.8"))


class PortPolicyTests(unittest.TestCase):
    def test_reserved_ports_always_refused(self):
        for mode in ("any", "local", "direct", "cdn"):
            for port in (80, 443):
                with self.assertRaises(PortError):
                    check_port(port, mode, [], CF)

    def test_local_refuses_every_cloudflare_port(self):
        for port in CF.all_ports:
            with self.assertRaises(PortError):
                check_port(port, "local", [], CF)

    def test_local_accepts_non_cloudflare_port(self):
        check_port(10443, "local", [], CF)

    def test_local_without_cloudflare_list_refused(self):
        with self.assertRaisesRegex(PortError, "not loaded"):
            check_port(10443, "local", [], None)

    def test_cdn_may_use_cloudflare_port(self):
        check_port(8443, "cdn", [], CF)

    def test_in_use_port_refused(self):
        with self.assertRaisesRegex(PortError, "already used"):
            check_port(9000, "cdn", [9000], CF)

    def test_random_port_stays_in_range_and_avoids_rules(self):
        rng = random.Random(1)
        for _ in range(50):
            port = pick_random_port(8000, 8100, "local", [8001, 8002], CF, rng=rng)
            self.assertTrue(8000 <= port <= 8100)
            self.assertNotIn(port, {8001, 8002})
            self.assertNotIn(port, CF.all_ports)

    def test_random_range_without_free_port_raises(self):
        with self.assertRaises(PortError):
            pick_random_port(443, 443, "any", [], CF, rng=random.Random(0))

    def test_random_range_must_be_ordered(self):
        with self.assertRaises(PortError):
            pick_random_port(9000, 8000, "any", [], CF)


if __name__ == "__main__":
    unittest.main()
