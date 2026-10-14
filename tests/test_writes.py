import json
import unittest

from panel.client import PanelClient
from panel.errors import PanelError, PanelResponseError
from panel.writes import ConfirmationRequired, VerificationFailed


class FakePanel:
    """In-memory fake of the panel. Records every write and applies it to state."""

    def __init__(self, inbounds=None):
        self.inbounds = list(inbounds or [])
        self.next_id = max([i["id"] for i in self.inbounds], default=0) + 1
        self.writes = []
        self.fail_add_silently = False
        self.fail_delete_silently = False
        self.hosts = []
        self.next_host_id = 1
        self.fallbacks = {}

    def __call__(self, method, url, headers, body, ssl_context):
        path = url.split("/panel/api", 1)[1]
        if method == "GET" and path.endswith("/fallbacks") and path.startswith("/inbounds/"):
            iid = int(path.split("/")[2])
            return 200, {}, self._env(self.fallbacks.get(iid, []))
        if method == "POST" and path.endswith("/fallbacks") and path.startswith("/inbounds/"):
            iid = int(path.split("/")[2])
            data = json.loads(body)
            self.writes.append((path, data))
            rules = []
            for i, rule in enumerate(data["fallbacks"]):
                rules.append({"id": i + 1, "masterId": iid, **rule})
            self.fallbacks[iid] = rules
            return 200, {}, self._env(None)
        if method == "GET" and path.startswith("/hosts/byInbound/"):
            iid = int(path.rsplit("/", 1)[1])
            rows = [g for g in self.hosts if iid in g["inboundIds"]]
            return 200, {}, self._env(rows)
        if method == "POST" and path == "/clients/add":
            data = json.loads(body)
            self.writes.append((path, data))
            for iid in data["inboundIds"]:
                for inbound in self.inbounds:
                    if inbound["id"] == iid:
                        inbound.setdefault("settings", {}).setdefault("clients", []).append(data["client"])
            return 200, {}, self._env(None)
        if method == "POST" and path.startswith("/hosts/update/"):
            gid = path.rsplit("/", 1)[1]
            data = json.loads(body)
            self.writes.append((path, data))
            for g in self.hosts:
                if g["groupId"] == gid:
                    g.update({"hosts": data["hosts"], "sni": data.get("sni", g.get("sni", ""))})
            return 200, {}, self._env(None)
        if method == "POST" and path == "/hosts/add":
            data = json.loads(body)
            self.writes.append((path, data))
            self.hosts.append({**data, "groupId": f"g{self.next_host_id}"})
            self.next_host_id += 1
            return 200, {}, self._env(None)
        if method == "GET":
            if path in ("/inbounds/list", "/inbounds/list/slim"):
                return 200, {}, self._env(self.inbounds)
            if path.startswith("/inbounds/get/"):
                iid = int(path.rsplit("/", 1)[1])
                found = [i for i in self.inbounds if i["id"] == iid]
                return 200, {}, self._env(found[0] if found else None, success=bool(found))
        if method == "POST":
            data = json.loads(body) if body else None
            self.writes.append((path, data))
            if path == "/inbounds/add":
                if not self.fail_add_silently:
                    self.inbounds.append({**data, "id": self.next_id})
                    self.next_id += 1
                return 200, {}, self._env(None)
            if path.startswith("/inbounds/del/"):
                iid = int(path.rsplit("/", 1)[1])
                if not self.fail_delete_silently:
                    self.inbounds = [i for i in self.inbounds if i["id"] != iid]
                return 200, {}, self._env(None)
            if path.startswith("/inbounds/setEnable/"):
                iid = int(path.rsplit("/", 1)[1])
                for i in self.inbounds:
                    if i["id"] == iid:
                        i["enable"] = data["enable"]
                return 200, {}, self._env(None)
            if path.startswith("/inbounds/update/"):
                iid = int(path.rsplit("/", 1)[1])
                for idx, i in enumerate(self.inbounds):
                    if i["id"] == iid:
                        self.inbounds[idx] = {**data, "id": iid}
                return 200, {}, self._env(None)
        return 404, {"success": False}, b""

    @staticmethod
    def _env(obj, success=True):
        return json.dumps({"success": success, "msg": "", "obj": obj}).encode()


def new_payload(**overrides):
    base = {"enable": True, "remark": "VLESS-8443", "port": 8443, "protocol": "vless", "listen": ""}
    base.update(overrides)
    return base


class DryRunAndConfirmationTests(unittest.TestCase):
    def test_add_without_confirmation_sends_nothing(self):
        panel = FakePanel()
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaises(ConfirmationRequired):
            client.add_inbound(new_payload())
        self.assertEqual(panel.writes, [])

    def test_dry_run_returns_preview_and_sends_nothing(self):
        panel = FakePanel()
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        preview = client.add_inbound(new_payload(), dry_run=True)
        self.assertTrue(preview["dry_run"])
        self.assertEqual(preview["path"], "/panel/api/inbounds/add")
        self.assertEqual(panel.writes, [])

    def test_delete_without_confirmation_sends_nothing(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaises(ConfirmationRequired):
            client.delete_inbound(1)
        self.assertEqual(panel.writes, [])
        self.assertEqual(len(panel.inbounds), 1)


class AddTests(unittest.TestCase):
    def test_add_confirmed_is_verified_by_reread(self):
        panel = FakePanel()
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        result = client.add_inbound(new_payload(), confirmed=True)
        self.assertTrue(result["verified"])
        self.assertEqual(result["id"], 1)
        self.assertEqual(len(panel.writes), 1)

    def test_silent_add_failure_is_not_reported_as_success(self):
        panel = FakePanel()
        panel.fail_add_silently = True
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaises(VerificationFailed):
            client.add_inbound(new_payload(), confirmed=True)

    def test_reserved_ports_refused_before_any_request(self):
        for port in (80, 443):
            panel = FakePanel()
            client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
            with self.assertRaises(PanelError):
                client.add_inbound(new_payload(port=port), confirmed=True)
            self.assertEqual(panel.writes, [])

    def test_invalid_port_types_refused(self):
        client = PanelClient("127.0.0.1:2053", token="T", transport=FakePanel())
        for bad in (0, 70000, "8443", True):
            with self.assertRaises(PanelError):
                client.add_inbound(new_payload(port=bad), confirmed=True)

    def test_duplicate_remark_refused(self):
        panel = FakePanel([{"id": 3, "remark": "VLESS-8443", "port": 9000, "listen": ""}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaisesRegex(PanelError, "already exists"):
            client.add_inbound(new_payload(), confirmed=True)
        self.assertEqual(panel.writes, [])

    def test_port_conflict_refused(self):
        panel = FakePanel([{"id": 3, "remark": "other", "port": 8443, "listen": ""}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaisesRegex(PanelError, "already used"):
            client.add_inbound(new_payload(remark="new"), confirmed=True)
        self.assertEqual(panel.writes, [])

    def test_panel_rejection_is_surfaced(self):
        class Rejecting(FakePanel):
            def __call__(self, method, url, headers, body, ssl_context):
                if method == "POST":
                    return 400, {}, json.dumps({"success": False, "msg": "bad protocol"}).encode()
                return super().__call__(method, url, headers, body, ssl_context)

        client = PanelClient("127.0.0.1:2053", token="T", transport=Rejecting())
        with self.assertRaises(PanelResponseError):
            client.add_inbound(new_payload(), confirmed=True)


class UpdateSetEnableDeleteTests(unittest.TestCase):
    def test_update_verified_against_fresh_state(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "protocol": "vless", "enable": True, "listen": ""}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        result = client.update_inbound(1, new_payload(id=None, remark="a", port=8444), confirmed=True)
        self.assertTrue(result["verified"])
        self.assertEqual(panel.inbounds[0]["port"], 8444)

    def test_update_dry_run_shows_current_and_new(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "protocol": "vless", "enable": True, "listen": ""}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        preview = client.update_inbound(1, new_payload(remark="a", port=8444), dry_run=True)
        self.assertEqual(preview["current"]["port"], 8443)
        self.assertEqual(panel.writes, [])

    def test_set_enable_verified(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        client.set_enable(1, False, confirmed=True)
        self.assertFalse(panel.inbounds[0]["enable"])

    def test_delete_verified_by_absence(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True}])
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        result = client.delete_inbound(1, confirmed=True)
        self.assertTrue(result["verified"])
        self.assertEqual(panel.inbounds, [])

    def test_silent_delete_failure_detected(self):
        panel = FakePanel([{"id": 1, "remark": "a", "port": 8443, "enable": True}])
        panel.fail_delete_silently = True
        client = PanelClient("127.0.0.1:2053", token="T", transport=panel)
        with self.assertRaises(VerificationFailed):
            client.delete_inbound(1, confirmed=True)


if __name__ == "__main__":
    unittest.main()
