import unittest

from config.settings import NetworkSettings, Settings
from core.menu import CONFIRM_WORD, Menu
from network.cdn import CDN_ECH_CONFIG, CDN_FINALMASK, CdnError, apply_cdn_options, missing_options
from panel.client import PanelClient
from tests.test_certs import HAVE_OPENSSL
from tests.test_template_flow import CDN, Env
from tests.test_writes import FakePanel
from ui.style import Style

FIXED = {
    "tls_ws_cdn_vless": 8443,
    "tls_httpupgrade_cdn_vless": 2053,
    "tls_xhttp_cdn_vless": 2083,
    "tls_grpc_cdn_vless": 2087,
    "tls_ws_cdn_vmess": 2096,
    "tls_xhttp_su_cdn_vless": 44300,
}
H2_ONLY = {"tls_grpc_cdn_vless", "tls_xhttp_cdn_vless", "tls_xhttp_su_cdn_vless"}


class CdnLibraryTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(with_certs=False)

    def tearDown(self):
        self.env.close()

    def test_only_the_six_fixed_tls_templates_exist(self):
        cdn = {t.template_id: t for t in self.env.library.values() if t.connection_mode == "cdn"}
        self.assertEqual({k: t.fixed_port for k, t in cdn.items()}, FIXED)
        for t in cdn.values():
            self.assertEqual(t.security, "tls", t.template_id)
            expected = ["h2"] if t.template_id in H2_ONLY else ["http/1.1"]
            self.assertEqual(t.content["streamSettings"]["tlsSettings"]["alpn"], expected, t.template_id)

    def test_protocols_and_transports(self):
        by_id = {t.template_id: (t.protocol, t.transport) for t in self.env.library.values()
                 if t.connection_mode == "cdn"}
        self.assertEqual(by_id, {
            "tls_ws_cdn_vless": ("vless", "ws"), "tls_httpupgrade_cdn_vless": ("vless", "httpupgrade"),
            "tls_xhttp_cdn_vless": ("vless", "xhttp"), "tls_grpc_cdn_vless": ("vless", "grpc"),
            "tls_ws_cdn_vmess": ("vmess", "ws"), "tls_xhttp_su_cdn_vless": ("vless", "xhttp")})


class CdnTlsTuningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        from templates.loader import load_library
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.lib = load_library(os.path.join(root, "inbounds"))

    def tls(self, tid):
        return self.lib[tid].content["streamSettings"]["tlsSettings"]

    def test_all_cipher_suites_on_every_cdn_template(self):
        for tid in FIXED:
            suites = self.tls(tid)["cipherSuites"].split(":")
            self.assertEqual(len(suites), 13, tid)
            self.assertEqual(len(set(suites)), 13, tid)

    def test_reject_unknown_sni_is_off_where_asked(self):
        for tid in ("tls_httpupgrade_cdn_vless", "tls_grpc_cdn_vless", "tls_ws_cdn_vmess"):
            self.assertIs(self.tls(tid)["rejectUnknownSni"], False, tid)

    def test_gprc_and_xhttp_alpn_is_h2_only_others_http11(self):
        for tid in FIXED:
            self.assertEqual(self.tls(tid)["alpn"], ["h2"] if tid in H2_ONLY else ["http/1.1"], tid)

    def test_xhttp_pair_packet_up_and_stream_up(self):
        x = self.lib["tls_xhttp_cdn_vless"].content["streamSettings"]["xhttpSettings"]
        self.assertEqual(x["mode"], "packet-up")
        self.assertEqual(x["scMaxBufferedPosts"], 100)
        y = self.lib["tls_xhttp_su_cdn_vless"].content["streamSettings"]["xhttpSettings"]
        self.assertEqual(y["mode"], "stream-up")
        for node in (x, y):
            self.assertIs(node["noSSEHeader"], False)

    def test_stream_up_template_is_an_origin_port_not_a_cloudflare_port(self):
        t = self.lib["tls_xhttp_su_cdn_vless"]
        self.assertEqual((t.fixed_port, t.origin_port), (44300, True))
        self.assertFalse(any(self.lib[k].origin_port for k in FIXED if k != "tls_xhttp_su_cdn_vless"))


class CdnOptionsTests(unittest.TestCase):
    def payload(self):
        return {"streamSettings": {"security": "tls", "tlsSettings": {"settings": {"echConfigList": ""}}}}

    def test_nothing_changes_without_a_yes(self):
        p = self.payload()
        apply_cdn_options(p)
        self.assertEqual(p, self.payload())

    def test_ech_and_finalmask(self):
        p = self.payload()
        apply_cdn_options(p, ech=True, finalmask=CDN_FINALMASK)
        self.assertEqual(p["streamSettings"]["tlsSettings"]["settings"]["echConfigList"], CDN_ECH_CONFIG)
        self.assertEqual(p["streamSettings"]["finalmask"], CDN_FINALMASK)
        self.assertIsNot(p["streamSettings"]["finalmask"], CDN_FINALMASK)

    def test_read_back_check_reports_what_the_panel_dropped(self):
        kept = {"streamSettings": {"security": "tls", "finalmask": CDN_FINALMASK,
                                   "tlsSettings": {"settings": {"echConfigList": CDN_ECH_CONFIG}}}}
        self.assertEqual(missing_options(kept, True, CDN_FINALMASK), [])
        dropped = {"streamSettings": '{"security": "tls", "tlsSettings": {"settings": {"echConfigList": ""}}}'}
        self.assertEqual(missing_options(dropped, True, CDN_FINALMASK), ["ECH config list", "finalmask"])
        self.assertEqual(missing_options(dropped, False, None), [])

    def test_non_tls_payload_refused(self):
        with self.assertRaises(CdnError):
            apply_cdn_options({"streamSettings": {"security": "none"}}, ech=True)

    def test_finalmask_matches_the_given_fragments(self):
        first, second = CDN_FINALMASK["tcp"]
        self.assertEqual(first["settings"]["packets"], "tlshello")
        self.assertEqual(first["settings"]["lengths"], ["0", "104", "1"])
        self.assertEqual(second["settings"]["packets"], "1-1")
        self.assertEqual(second["settings"]["maxSplit"], "11")


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class CdnMenuTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()

    def tearDown(self):
        self.env.close()

    def test_enter_at_template_prompt_creates_all_six_and_one_cdn_host(self):
        panel = FakePanel()
        # generate, CDN, route 2 (IP), ECH no, finalmask no, Enter = all, confirm
        self.env.run(["4", "2", "2", "n", "n", "", CONFIRM_WORD, "0", "0"], panel)
        self.assertEqual(sorted(i["port"] for i in panel.inbounds), sorted(FIXED.values()))
        self.assertEqual(len(panel.hosts), 1)
        self.assertEqual(panel.hosts[0]["remark"], "CDN")
        self.assertEqual(panel.hosts[0]["hosts"], ["203.0.113.1"])
        self.assertEqual(len(panel.hosts[0]["inboundIds"]), 6)
        for inbound in panel.inbounds:
            self.assertIn(inbound["streamSettings"]["tlsSettings"]["alpn"], (["http/1.1"], ["h2"]))
            self.assertNotIn("finalmask", inbound["streamSettings"])
            self.assertEqual(inbound["streamSettings"]["tlsSettings"]["settings"]["echConfigList"], "")

    def test_ech_and_finalmask_yes(self):
        panel = FakePanel()
        self.env.run(["4", "2", "2", "y", "y", "", CONFIRM_WORD, "0", "0"], panel)
        self.assertEqual(len(panel.inbounds), 6)
        for inbound in panel.inbounds:
            stream = inbound["streamSettings"]
            self.assertEqual(stream["tlsSettings"]["settings"]["echConfigList"], CDN_ECH_CONFIG)
            self.assertEqual(stream["finalmask"], CDN_FINALMASK)

    def test_created_inbounds_are_read_back_and_reported(self):
        panel = FakePanel()
        _, text = self.env.run(["4", "2", "2", "y", "y", "", CONFIRM_WORD, "0", "0"], panel)
        self.assertEqual(text.count("ECH and finalmask are stored on the panel"), 6)
        self.assertIn(f"ECH config list: {CDN_ECH_CONFIG}", text)
        self.assertIn("origin port", text)  # the 44300 template warns about the Cloudflare origin rule

    def test_domain_route_uses_registered_domain_and_host_has_the_domain(self):
        panel = FakePanel()
        # route 1, use the registered domain (Enter), ECH no, finalmask no, all, confirm
        self.env.run(["4", "2", "1", "", "n", "n", "a", CONFIRM_WORD, "0", "0"], panel)
        self.assertEqual(len(panel.inbounds), 6)
        self.assertEqual(panel.hosts[0]["hosts"], [CDN])

    def test_domain_route_with_another_domain_saves_it_and_offers_ssl(self):
        panel = FakePanel()
        # route 1, not the registered one, another domain, no SSL yet and do not obtain it, then stop
        menu, text = self.env.run(["4", "2", "1", "n", "other.example.test", "n", "n", "n", "n", "0", "0"], panel)
        self.assertEqual(menu.settings.network.cdn_domain, "other.example.test")
        self.assertIn("other.example.test", text)
        self.assertEqual(panel.inbounds, [])  # no certificate for the new domain: nothing is created

    def test_invalid_route_stops_before_any_write(self):
        panel = FakePanel()
        _, text = self.env.run(["4", "2", "3", "0", "0"], panel)
        self.assertIn("Expected 1 or 2", text)
        self.assertEqual(panel.writes, [])


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class EchDefaultTests(unittest.TestCase):
    def test_enter_at_ech_question_means_yes_and_finalmask_stays_no(self):
        env = Env()
        try:
            panel = FakePanel()
            # route 2 (IP), Enter at ECH, Enter at finalmask, all, confirm
            env.run(["4", "2", "2", "", "", "", CONFIRM_WORD, "0", "0"], panel)
            self.assertEqual(len(panel.inbounds), 6)
            for inbound in panel.inbounds:
                self.assertEqual(inbound["streamSettings"]["tlsSettings"]["settings"]["echConfigList"], CDN_ECH_CONFIG)
                self.assertNotIn("finalmask", inbound["streamSettings"])
        finally:
            env.close()


class PromptColorTests(unittest.TestCase):
    def test_questions_are_yellow_when_color_is_on(self):
        prompts = []
        inputs = iter(["0"])

        def ask(prompt=""):
            prompts.append(prompt)
            return next(inputs)

        Menu(None, input_fn=ask, output_fn=lambda t: None, style=Style(enabled=True)).run()
        self.assertTrue(prompts)
        self.assertTrue(all(p.startswith("\033[33m") for p in prompts), prompts)

    def test_plain_when_color_is_off(self):
        prompts = []
        inputs = iter(["0"])

        def ask(prompt=""):
            prompts.append(prompt)
            return next(inputs)

        Menu(None, input_fn=ask, output_fn=lambda t: None).run()
        self.assertFalse(any("\033" in p for p in prompts))


if __name__ == "__main__":
    unittest.main()
