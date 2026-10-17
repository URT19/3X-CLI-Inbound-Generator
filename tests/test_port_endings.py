import random
import unittest

from network.cloudflare import CloudflarePorts
from network.ports import (PortError, check_ruled_port, excluded_ports, pick_ruled_port, port_rule_for)

CF = CloudflarePorts(
    source="t", retrieved="t",
    http_ports=frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095}),
    https_ports=frozenset({443, 2053, 2083, 2087, 2096, 8443}),
)


class PortEndingTests(unittest.TestCase):
    def test_rule_by_security(self):
        self.assertEqual(port_rule_for("none"), "plain")
        self.assertEqual(port_rule_for("tls"), "tls")
        self.assertEqual(port_rule_for("reality"), "reality")

    def test_plain_ports_end_with_80_and_skip_cloudflare_ports(self):
        for seed in range(30):
            port = pick_ruled_port(3000, 40000, "plain", [], CF, rng=random.Random(seed))
            self.assertEqual(port % 100, 80)
            self.assertNotIn(port, CF.all_ports)

    def test_tls_ports_end_with_3_and_skip_cloudflare_ports(self):
        for seed in range(30):
            port = pick_ruled_port(20000, 40000, "tls", [], CF, rng=random.Random(seed))
            self.assertEqual(port % 10, 3)
            self.assertNotIn(port, CF.all_ports)

    def test_reality_ports_end_with_5_and_never_8443(self):
        for seed in range(30):
            port = pick_ruled_port(20000, 40000, "reality", [], CF, rng=random.Random(seed))
            self.assertEqual(port % 10, 5)
            self.assertNotEqual(port, 8443)

    def test_80_443_and_cloudflare_are_always_excluded(self):
        excluded = excluded_ports(CF)
        for port in (80, 443, 8443, 2053, 8080):
            self.assertIn(port, excluded)

    def test_fixed_port_with_wrong_ending_is_refused(self):
        with self.assertRaisesRegex(PortError, "does not match"):
            check_ruled_port(20004, "tls", [], CF)

    def test_fixed_port_on_cloudflare_is_refused(self):
        with self.assertRaisesRegex(PortError, "reserved"):
            check_ruled_port(8443, "tls", [], CF)

    def test_no_candidate_is_reported(self):
        with self.assertRaisesRegex(PortError, "No free port"):
            pick_ruled_port(443, 443, "tls", [], CF)


if __name__ == "__main__":
    unittest.main()
