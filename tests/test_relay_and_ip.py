import os
import shutil
import tempfile
import unittest
from unittest import mock

from config.settings import NetworkSettings, Settings, SettingsError, load_settings, save_settings
from core.menu import Menu
from core.preflight import ip_compatible
from network import validators
from network.cloudflare import CloudflarePorts
from network.paths import generate_all
from network.validators import connection_address
from panel.client import PanelClient
from state.records import load_records
from templates.loader import load_library
from tests.test_writes import FakePanel
from utils.naming import build_name

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))


class AddressTests(unittest.TestCase):
    def test_option_off_keeps_domain(self):
        self.assertEqual(connection_address("cdn.example.com", False), "cdn.example.com")

    def test_option_on_replaces_domain_with_resolved_ipv4(self):
        with mock.patch.object(validators, "resolve_ipv4", return_value="198.51.100.9") as resolver:
            self.assertEqual(connection_address("cdn.example.com", True), "198.51.100.9")
            resolver.assert_called_once_with("cdn.example.com")

    def test_option_on_leaves_plain_ip_alone(self):
        with mock.patch.object(validators, "resolve_ipv4") as resolver:
            self.assertEqual(connection_address("203.0.113.5", True), "203.0.113.5")
            resolver.assert_not_called()

    def test_unresolvable_domain_raises(self):
        with mock.patch("socket.getaddrinfo", side_effect=OSError("nope")):
            with self.assertRaises(ValueError):
                validators.resolve_ipv4("missing.example.invalid")


class NamingTests(unittest.TestCase):
    def test_relay_label_in_name(self):
        library = load_library(os.path.join(ROOT, "inbounds"))
        t = library["tls_tcp_direct"]
        self.assertEqual(build_name(t, [], mode_label="RELAY"), "02-VMESS-TCP-RELAY-TLS")


class SettingsFieldTests(unittest.TestCase):
    def test_new_fields_round_trip(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "s.json")
            save_settings(path, Settings(network=NetworkSettings(relay_address="198.51.100.7",
                                                                 use_ip_addresses=True)))
            loaded = load_settings(path)
            self.assertEqual(loaded.network.relay_address, "198.51.100.7")
            self.assertTrue(loaded.network.use_ip_addresses)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_bad_ip_option_refused(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "s.json")
            with open(path, "w") as fh:
                fh.write('{"network": {"use_ip_addresses": "yes"}}')
            with self.assertRaises(SettingsError):
                load_settings(path)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class RelayFlowTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        self.library = load_library(os.path.join(ROOT, "inbounds"))
        self.settings = Settings(network=NetworkSettings(
            relay_address="198.51.100.7", direct_ip="203.0.113.10",
            port_mode="random", random_port_low=20000, random_port_high=20010),
            paths=generate_all())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_relay_inbound_named_relay_recorded_and_host_points_to_relay(self):
        # Relay lists every direct template (the relay address replaces only the connection address).
        direct = sorted((t for t in self.library.values() if t.connection_mode == "direct"),
                        key=lambda t: (t.number, t.template_id))
        idx = next(i for i, t in enumerate(direct, 1) if t.template_id == "http_tcp_direct_vmess")
        panel = FakePanel()
        inputs = iter(["7", str(idx), "", "", "0"])
        Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
             input_fn=lambda p="": next(inputs), output_fn=lambda t: None,
             library=self.library, settings=self.settings, cloudflare=CF, state_dir=self.state).run()
        self.assertIn("RELAY", panel.inbounds[0]["remark"])
        self.assertEqual(len(panel.hosts), 1)
        self.assertEqual(panel.hosts[0]["hosts"][0], "198.51.100.7")
        self.assertEqual(panel.hosts[0]["inboundIds"][0], panel.inbounds[0]["id"])
        records = load_records(self.state, "relay")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["address"], "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
