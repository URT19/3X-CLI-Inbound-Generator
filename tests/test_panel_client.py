import json
import unittest

from panel.client import PanelClient
from panel.errors import (
    PanelAuthError,
    PanelNotFound,
    PanelResponseError,
)


class FakeTransport:
    """Records requests and returns scripted responses. No network access."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, ssl_context):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        status, payload, extra_headers = self.responses.pop(0)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, extra_headers or {}, raw


def ok(obj):
    return 200, {"success": True, "msg": "", "obj": obj}, None


class ListInboundsTests(unittest.TestCase):
    def test_list_uses_bearer_token_and_correct_path(self):
        transport = FakeTransport([ok([{"id": 1, "protocol": "vless", "port": 443}])])
        client = PanelClient("127.0.0.1:443", token="SECRET", transport=transport)

        inbounds = client.list_inbounds()

        self.assertEqual(inbounds[0]["id"], 1)
        call = transport.calls[0]
        self.assertEqual(call["url"], "https://127.0.0.1:443/panel/api/inbounds/list")
        self.assertEqual(call["headers"]["Authorization"], "Bearer SECRET")
        self.assertEqual(call["method"], "GET")

    def test_list_respects_web_base_path(self):
        transport = FakeTransport([ok([])])
        client = PanelClient("https://1.2.3.4:443/mysecret", token="T", transport=transport)
        client.list_inbounds()
        self.assertEqual(
            transport.calls[0]["url"],
            "https://1.2.3.4:443/mysecret/panel/api/inbounds/list",
        )

    def test_success_false_raises_response_error_with_panel_message(self):
        transport = FakeTransport([(200, {"success": False, "msg": "bad things"}, None)])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        with self.assertRaisesRegex(PanelResponseError, "bad things"):
            client.list_inbounds()

    def test_obj_not_a_list_is_rejected(self):
        transport = FakeTransport([ok({"not": "a list"})])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        with self.assertRaises(PanelResponseError):
            client.list_inbounds()

    def test_empty_list_is_a_real_empty_result(self):
        transport = FakeTransport([ok([])])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        self.assertEqual(client.list_inbounds(), [])


class ErrorMappingTests(unittest.TestCase):
    def test_401_and_403_map_to_auth_error(self):
        for status in (401, 403):
            transport = FakeTransport([(status, {"success": False}, None)])
            client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
            with self.assertRaises(PanelAuthError):
                client.list_inbounds()

    def test_404_maps_to_not_found(self):
        transport = FakeTransport([(404, {"success": False}, None)])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        with self.assertRaises(PanelNotFound):
            client.list_inbounds()

    def test_html_response_is_not_treated_as_empty_list(self):
        transport = FakeTransport([(200, b"<html>login page</html>", None)])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        with self.assertRaises(PanelResponseError):
            client.list_inbounds()

    def test_server_error_maps_to_response_error(self):
        transport = FakeTransport([(500, {"success": False}, None)])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        with self.assertRaises(PanelResponseError):
            client.list_inbounds()

    def test_no_credentials_raises_before_any_request(self):
        transport = FakeTransport([])
        client = PanelClient("127.0.0.1:2053", transport=transport)
        with self.assertRaises(PanelAuthError):
            client.list_inbounds()
        self.assertEqual(transport.calls, [])


class SecretHandlingTests(unittest.TestCase):
    def test_repr_never_contains_token(self):
        client = PanelClient("127.0.0.1:2053", token="VERY_SECRET_TOKEN", transport=FakeTransport([]))
        self.assertNotIn("VERY_SECRET_TOKEN", repr(client))

    def test_error_messages_do_not_contain_token(self):
        transport = FakeTransport([(401, {"success": False}, None)])
        client = PanelClient("127.0.0.1:2053", token="VERY_SECRET_TOKEN", transport=transport)
        with self.assertRaises(PanelAuthError) as ctx:
            client.list_inbounds()
        self.assertNotIn("VERY_SECRET_TOKEN", str(ctx.exception))


class LoginFallbackTests(unittest.TestCase):
    def test_login_then_list_uses_session_cookie(self):
        transport = FakeTransport([
            (200, {"success": True, "msg": ""}, {"Set-Cookie": "session=abc123; Path=/; HttpOnly"}),
            ok([{"id": 7}]),
        ])
        client = PanelClient("127.0.0.1:2053", transport=transport)
        client.login("admin", "pw")

        self.assertEqual(transport.calls[0]["url"], "http://127.0.0.1:2053/login")
        self.assertIn("pw", transport.calls[0]["body"].decode())
        self.assertEqual(client.list_inbounds()[0]["id"], 7)
        self.assertIn("session=abc123", transport.calls[1]["headers"]["Cookie"])

    def test_failed_login_raises_auth_error(self):
        transport = FakeTransport([(200, {"success": False, "msg": "wrong password"}, None)])
        client = PanelClient("127.0.0.1:2053", transport=transport)
        with self.assertRaises(PanelAuthError):
            client.login("admin", "bad")


class SingleInboundTests(unittest.TestCase):
    def test_get_inbound_path(self):
        transport = FakeTransport([ok({"id": 5, "remark": "x"})])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        self.assertEqual(client.get_inbound(5)["remark"], "x")
        self.assertTrue(transport.calls[0]["url"].endswith("/panel/api/inbounds/get/5"))

    def test_get_inbound_rejects_bad_id_before_request(self):
        transport = FakeTransport([])
        client = PanelClient("127.0.0.1:2053", token="T", transport=transport)
        for bad in (0, -1, "5"):
            with self.assertRaises(Exception):
                client.get_inbound(bad)
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
