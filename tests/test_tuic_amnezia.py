import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from certs.checker import CertStatus
from config.settings import NetworkSettings, Settings, load_settings, save_settings
from core.menu import Menu
from core.preflight import resolve_values, validate_payload
from network import amnezia
from network.cloudflare import CloudflarePorts
from panel.client import PanelClient
from state.records import load_records
from templates.loader import load_library, render
from tests.test_writes import FakePanel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CF = CloudflarePorts(source="t", retrieved="t", http_ports=frozenset({80}), https_ports=frozenset({443}))
HAVE_OPENSSL = shutil.which("openssl") is not None
OK = lambda d: CertStatus(d, "ok", "fine", "", "")


def library():
    return load_library(os.path.join(ROOT, "inbounds"))


def make_cert_dir(root, domain):
    """A real self-signed certificate, so the certificate check passes."""
    from tests.test_certs import make_cert
    make_cert(os.path.join(root, domain), domain, days=90)


class TuicTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.t = library()["tls_tuic_direct"]
        make_cert_dir(self.root, "direct.example.test")
        self.net = NetworkSettings(direct_domain="direct.example.test", port_mode="random",
                                   random_port_low=36000, random_port_high=36010)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_template_shape(self):
        self.assertEqual(self.t.content["protocol"], "tuic")
        self.assertNotIn("streamSettings", self.t.content)
        self.assertEqual(self.t.content["tag"], "in-{{PORT}}-udp")

    def test_renders_with_direct_certificate_and_sni(self):
        res = resolve_values(self.t, self.net, {}, self.root, CF, [], status_fn=OK)
        self.assertEqual(res.problems, [])
        payload = render(self.t, res.values, remark="23-TUIC-TUIC-DIRECT-TLS")
        s = payload["settings"]
        self.assertTrue(s["certificate"].endswith("direct.example.test/fullchain.pem"))
        self.assertTrue(s["private_key"].endswith("direct.example.test/privkey.pem"))
        self.assertEqual(s["sni"], "direct.example.test")
        self.assertEqual(s["clients"], [])
        self.assertEqual(validate_payload(payload), [])
        self.assertNotIn("{{", json.dumps(payload))

    def test_missing_certificate_is_reported_before_sending(self):
        empty = tempfile.mkdtemp()
        try:
            res = resolve_values(self.t, self.net, {}, empty, CF, [], status_fn=OK)
            self.assertTrue(any("not readable" in p for p in res.problems))
        finally:
            shutil.rmtree(empty, ignore_errors=True)


class AmneziaTests(unittest.TestCase):
    def setUp(self):
        self.t = library()["udp_amneziawg_direct"]

    def params(self):
        # Fixed, valid example values (the panel example keys), for offline tests.
        return {
            "privateKey": "WE2EbfJPSsbAfHcjQfuzXROul2a2LHGdxSpumONUX14=",
            "publicKey": "plm+5FDRJ5BmOEB32Pig2K7AFAr2Ma5UwQiYQ5qoYQI=",
            "subnetIp": "10.8.1.0", "subnetCidr": 24, "primaryDns": "8.8.8.8", "secondaryDns": "8.8.4.4",
            "externalInterface": "", "ipv6Enabled": False, "ipv6Subnet": "", "ipv6ExternalInterface": "",
            "jc": 5, "jmin": 43, "jmax": 142, "s1": 76, "s2": 84, "s3": 41, "s4": 15,
            "h1": "46060673", "h2": "1030170436", "h3": "1536548226", "h4": "1683600279",
            "i1": "<r 104>", "i2": "", "i3": "", "i4": "", "i5": "",
            "headerProtectionKey": "rHfjGL3+yd/+cdIBV22ADki5UUNDIkYBUgNQIPh/l9k=",
            "contentPaddingAddition": "11-46", "rekeyAfterTime": "115-150", "rekeyTimeout": "6-10",
            "rejectAfterTime": "196-246", "keepaliveTimeout": "9-15", "maxHandshakeAttempts": "25-36",
            "randomTrailers": True, "disableCookies": True,
        }

    def test_valid_parameters_pass(self):
        amnezia.validate(self.params())

    def test_missing_or_bad_values_refused(self):
        p = self.params()
        del p["jc"]
        with self.assertRaisesRegex(amnezia.AmneziaError, "Missing"):
            amnezia.validate(p)
        p = self.params()
        p["jmin"] = 200
        with self.assertRaisesRegex(amnezia.AmneziaError, "jmin"):
            amnezia.validate(p)
        p = self.params()
        p["h2"] = p["h1"]
        with self.assertRaisesRegex(amnezia.AmneziaError, "different"):
            amnezia.validate(p)

    def test_apply_writes_every_server_value(self):
        payload = render(self.t, {"PORT": 13798, **amnezia.placeholders_for(self.params())}, remark="24-AWG-AWG-DIRECT-PLAIN")
        amnezia.apply_to_payload(payload, self.params())
        self.assertEqual(payload["settings"]["server"]["privateKey"], self.params()["privateKey"])
        self.assertEqual(payload["settings"]["clients"], [])
        self.assertEqual(validate_payload(payload), [])
        self.assertNotIn("{{", json.dumps(payload))

    def test_resolution_needs_saved_parameters(self):
        res = resolve_values(self.t, NetworkSettings(port_mode="fixed", fixed_port=13798), {}, "/x",
                             CF, [], status_fn=OK, amnezia=None)
        self.assertTrue(any("AmneziaWG parameters are not set" in p for p in res.problems))

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_proposal_is_valid_and_keys_are_x25519_sized(self):
        p = amnezia.generate_proposal()
        amnezia.validate(p)
        self.assertEqual(len(base64.b64decode(p["privateKey"])), 32)
        self.assertEqual(len(base64.b64decode(p["publicKey"])), 32)
        self.assertNotEqual(p["privateKey"], amnezia.generate_proposal()["privateKey"])


class AmneziaMenuTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "settings.json")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_menu(self, script):
        inputs = iter(script)
        out = []
        Menu(None, input_fn=lambda p="": next(inputs), output_fn=lambda t: out.append(str(t)),
             settings=Settings(), settings_path=self.path).run()
        return "\n".join(out)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_accept_proposal_saves_to_settings(self):
        self.run_menu(["3", "12", "", "0", "0"])
        saved = load_settings(self.path).amnezia
        amnezia.validate(saved)
        self.assertIn("privateKey", saved)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_edit_one_value(self):
        script = ["3", "12", "n"] + [""] * len(amnezia.ALL_KEYS)
        idx = amnezia.ALL_KEYS.index("jc")
        script[3 + idx] = "7"
        self.run_menu(script + ["0", "0"])
        self.assertEqual(load_settings(self.path).amnezia["jc"], 7)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_invalid_edit_saves_nothing(self):
        script = ["3", "12", "n"] + [""] * len(amnezia.ALL_KEYS)
        idx = amnezia.ALL_KEYS.index("jc")
        script[3 + idx] = "many"
        out = self.run_menu(script + ["0", "0"])
        self.assertIn("whole number", out)
        self.assertFalse(os.path.exists(self.path))


class HysteriaCertificateRuleTests(unittest.TestCase):
    def run_direct_hysteria(self, with_cert):
        d = tempfile.mkdtemp()
        try:
            lib = library()
            t = lib["tls_hysteria_direct"]
            net = NetworkSettings(direct_domain="direct.example.test", port_mode="random",
                                  random_port_low=37000, random_port_high=37010)
            if with_cert:
                make_cert_dir(os.path.join(d, "cert"), "direct.example.test")
            settings = Settings(network=net, paths={}, fingerprint="chrome", cert_root=os.path.join(d, "cert"))
            panel = FakePanel()
            state = os.path.join(d, "state")
            direct_sorted = sorted([x for x in lib.values() if x.connection_mode == "direct"],
                                   key=lambda x: (x.number, x.template_id))
            inputs = iter(["4", "1", str(direct_sorted.index(t) + 1), "", "0"])
            out = []
            Menu(PanelClient("127.0.0.1:2053", token="T", transport=panel),
                 input_fn=lambda p="": next(inputs), output_fn=lambda x: out.append(str(x)),
                 library=lib, settings=settings, settings_path=os.path.join(d, "s.json"),
                 cloudflare=CF, state_dir=state).run()
            return panel, load_records(state, "direct"), "\n".join(out)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_hysteria_with_direct_certificate_is_created_and_password_stored(self):
        panel, records, _out = self.run_direct_hysteria(with_cert=True)
        self.assertEqual(len(panel.inbounds), 1)
        password = panel.inbounds[0]["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"]
        self.assertEqual(records[0]["hysteria_password"], password)

    def test_hysteria_without_certificate_files_is_refused(self):
        panel, records, out = self.run_direct_hysteria(with_cert=False)
        self.assertIn("not readable", out)
        self.assertEqual(panel.inbounds, [])
        self.assertEqual(records, [])


class AmneziaProposalRangeTests(unittest.TestCase):
    def test_many_random_proposals_pass_the_panel_rules(self):
        from unittest import mock
        fixed = ("WE2EbfJPSsbAfHcjQfuzXROul2a2LHGdxSpumONUX14=", "plm+5FDRJ5BmOEB32Pig2K7AFAr2Ma5UwQiYQ5qoYQI=")
        with mock.patch.object(amnezia, "_x25519_pair", return_value=fixed):
            for _ in range(300):
                amnezia.validate(amnezia.generate_proposal())

    def test_s4_above_32_is_refused(self):
        from unittest import mock
        fixed = ("WE2EbfJPSsbAfHcjQfuzXROul2a2LHGdxSpumONUX14=", "plm+5FDRJ5BmOEB32Pig2K7AFAr2Ma5UwQiYQ5qoYQI=")
        with mock.patch.object(amnezia, "_x25519_pair", return_value=fixed):
            p = amnezia.generate_proposal()
        p["s4"] = 51
        with self.assertRaisesRegex(amnezia.AmneziaError, "S4"):
            amnezia.validate(p)
