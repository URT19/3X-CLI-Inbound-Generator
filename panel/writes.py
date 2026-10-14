"""Inbound write operations for the 3x-ui panel.

Safety rules (from the project spec):
  - Nothing is sent to the panel unless confirmed=True is passed explicitly.
  - dry_run=True returns the exact request that would be sent, and sends nothing.
  - Success is reported only after the panel state is re-read and matches.
  - Port 80 and 443 are reserved for inbounds and are refused here.
  - Existing inbounds are never overwritten silently (duplicate remark or port is refused).
"""

import json
from typing import Any, Dict, List, Optional

from panel.errors import PanelError, PanelResponseError

RESERVED_PORTS = frozenset({80, 443})
API_PREFIX = "/panel/api/inbounds"


class ConfirmationRequired(PanelError):
    """A write was attempted without explicit confirmation."""


class VerificationFailed(PanelError):
    """The panel accepted the call, but re-reading its state did not match."""


def _require_confirmed(confirmed: bool, action: str) -> None:
    if confirmed is not True:
        raise ConfirmationRequired(f"{action} needs explicit confirmation (confirmed=True)")


def _validate_port(port: Any) -> None:
    if not isinstance(port, int) or isinstance(port, bool):
        raise PanelError("Port must be an integer")
    if not 1 <= port <= 65535:
        raise PanelError("Port must be between 1 and 65535")
    if port in RESERVED_PORTS:
        raise PanelError(f"Port {port} is reserved and cannot be used for an inbound")


FAKE_SITE_NAME = "fake-site"


def eligible_fallback_master(inbound: Dict[str, Any]) -> bool:
    """Fallbacks need a VLESS or Trojan master on raw TCP with TLS or REALITY (panel docs)."""
    if inbound.get("protocol") not in ("vless", "trojan"):
        return False
    stream = inbound.get("streamSettings")
    if isinstance(stream, str):
        try:
            stream = json.loads(stream)
        except ValueError:
            return False
    if not isinstance(stream, dict):
        return False
    return stream.get("network") == "tcp" and stream.get("security") in ("tls", "reality")


class InboundWriteMixin:
    """Mixed into PanelClient. Relies on _post_envelope, list_inbounds and get_inbound."""

    def _check_no_conflict(self, payload: Dict[str, Any], existing: List[Dict[str, Any]]) -> None:
        remark = payload.get("remark")
        port = payload.get("port")
        for item in existing:
            if remark and item.get("remark") == remark:
                raise PanelError(f"An inbound with remark {remark!r} already exists (id {item.get('id')})")
            if item.get("port") == port and item.get("listen", "") in ("", payload.get("listen", "")):
                raise PanelError(f"Port {port} is already used by inbound id {item.get('id')}")

    def list_fallbacks(self, master_id: int) -> List[Dict[str, Any]]:
        obj = self._envelope(f"{API_PREFIX}/{master_id}/fallbacks")
        return obj if isinstance(obj, list) else []

    def set_fake_site(
        self,
        master_id: int,
        dest: str,
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Add or replace the fake-site rule (childId 0, dest only) on a master inbound.

        The panel replaces the whole fallback list on save, so the existing rules are sent back
        unchanged, and only the fake-site rule is added or replaced.
        """
        master = self.get_inbound(master_id)
        if not eligible_fallback_master(master):
            raise PanelError("Master must be a VLESS or Trojan inbound on TCP with TLS or REALITY")
        current = self.list_fallbacks(master_id)
        rules = []
        for rule in current:
            if rule.get("name") == FAKE_SITE_NAME and not rule.get("childId"):
                continue  # replaced below
            rules.append({
                "childId": rule.get("childId") or 0,
                "name": rule.get("name") or "",
                "alpn": rule.get("alpn") or "",
                "path": rule.get("path") or "",
                "dest": rule.get("dest") or "",
                "xver": rule.get("xver") or 0,
                "sortOrder": rule.get("sortOrder") or 0,
            })
        rules.append({"childId": 0, "name": FAKE_SITE_NAME, "alpn": "", "path": "",
                      "dest": dest, "xver": 0, "sortOrder": len(rules)})
        preview = {"method": "POST", "path": f"{API_PREFIX}/{master_id}/fallbacks",
                   "body": {"fallbacks": rules}, "current": current}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Setting the fake site")
        self._post_envelope(preview["path"], {"fallbacks": rules})
        after = self.list_fallbacks(master_id)
        if not any(r.get("dest") == dest and not r.get("childId") for r in after):
            raise VerificationFailed("Fake-site rule not found after save; local state was not updated")
        return {"dry_run": False, "master_id": master_id, "dest": dest, "verified": True,
                "restart_needed": True}

    def add_client(
        self,
        inbound_id: int,
        email: str,
        credential: str,
        flow: str = "",
        protocol: str = "vless",
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Add one client to an inbound (POST /panel/api/clients/add, v3.10.0 ClientCreatePayload).
        VLESS clients get an id (UUID), Trojan clients a password. The flow belongs to the client.
        Verified by reading the inbound back and finding the client email."""
        if not email:
            raise PanelError("Client email is required")
        if protocol == "vless":
            client = {"id": credential, "flow": flow}
        elif protocol == "trojan":
            client = {"password": credential, "flow": flow}
        else:
            raise PanelError(f"Clients are not created by this tool for protocol {protocol!r}")
        body = {
            "client": {**client, "email": email, "security": "", "enable": True, "limitIp": 0,
                       "totalGB": 0, "expiryTime": 0, "subId": "", "tgId": 0, "reset": 0,
                       "comment": ""},
            "inboundIds": [inbound_id],
        }
        preview = {"method": "POST", "path": "/panel/api/clients/add", "body": body}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Adding a client")
        self._post_envelope(preview["path"], body)
        inbound = self.get_inbound(inbound_id)
        settings = inbound.get("settings")
        if isinstance(settings, str):
            settings = json.loads(settings or "{}")
        clients = (settings or {}).get("clients") or []
        if not any(c.get("email") == email for c in clients):
            raise VerificationFailed("Client not found on the inbound after add")
        return {"dry_run": False, "inbound_id": inbound_id, "email": email, "verified": True}

    def list_host_groups(self, inbound_id: int) -> List[Dict[str, Any]]:
        obj = self._envelope(f"/panel/api/hosts/byInbound/{inbound_id}")
        return obj if isinstance(obj, list) else []

    def update_host_address(
        self,
        group: Dict[str, Any],
        new_address: str,
        confirmed: bool = False,
        dry_run: bool = False,
        sni: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Replace the address (and optionally the sni) of an existing host group; other fields are kept."""
        group_id = group.get("groupId")
        if not group_id:
            raise PanelError("Host group has no groupId")
        if not new_address:
            raise PanelError("New address is empty")
        body = {**group, "hosts": [new_address], "port": group.get("port", 0)}
        if sni is not None:
            body["sni"] = sni
        preview = {"method": "POST", "path": f"/panel/api/hosts/update/{group_id}", "body": body}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Updating a host entry")
        self._post_envelope(preview["path"], body)
        after = self.list_host_groups(group["inboundIds"][0])
        if not any(g.get("groupId") == group_id and any(
                h == new_address or h.startswith(f"{new_address}:") for h in (g.get("hosts") or []))
                and (sni is None or g.get("sni") == sni)
                for g in after):
            raise VerificationFailed("Host address not updated; the panel state was not changed locally")
        return {"dry_run": False, "group_id": group_id, "address": new_address, "verified": True}

    def add_host(
        self,
        payload: Dict[str, Any],
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Create one host entry for an inbound.

        Panel v3.10.0 stores hosts as host groups: POST /panel/api/hosts/add takes a HostGroup
        (inboundIds, hosts, port, remark, ...). The payload here keeps the simple form
        (inboundId, address, port, ...) and is converted to a HostGroup for the request.
        Verified by reading /panel/api/hosts/byInbound/{id}.
        """
        inbound_id = payload.get("inboundId")
        if not isinstance(inbound_id, int) or inbound_id <= 0:
            raise PanelError("inboundId must be a positive integer")
        if not payload.get("remark"):
            raise PanelError("host remark is required")
        port = payload.get("port", 0)
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise PanelError("host port must be between 0 and 65535")
        if payload.get("security", "same") not in ("same", "tls", "none", "reality"):
            raise PanelError("host security must be same, tls, none or reality")
        address = payload.get("address")
        if not address:
            raise PanelError("host address is required")

        group = {
            "inboundIds": [inbound_id],
            "hosts": [address],
            "port": port,
            "remark": payload["remark"],
            "security": payload.get("security", "same"),
            "sni": payload.get("sni", ""),
            "alpn": payload.get("alpn", []),
            "sortOrder": payload.get("sortOrder", 0),
        }
        preview = {"method": "POST", "path": "/panel/api/hosts/add", "body": group}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Adding a host entry")

        self._post_envelope("/panel/api/hosts/add", group)

        after = self._envelope(f"/panel/api/hosts/byInbound/{inbound_id}") or []
        matches = [
            g for g in after
            if payload["remark"] == g.get("remark")
            and any(h == address or h.startswith(f"{address}:") for h in (g.get("hosts") or []))
        ]
        if not matches:
            raise VerificationFailed("Host not found after add; local state was not updated")
        return {"dry_run": False, "id": matches[0].get("groupId"), "verified": True}

    def add_inbound(
        self,
        payload: Dict[str, Any],
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Create an inbound. Returns the request preview when dry_run=True."""
        _validate_port(payload.get("port"))
        if not payload.get("remark"):
            raise PanelError("remark is required")
        existing = self.list_inbounds()
        self._check_no_conflict(payload, existing)

        preview = {"method": "POST", "path": f"{API_PREFIX}/add", "body": payload}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Adding an inbound")

        self._post_envelope(f"{API_PREFIX}/add", payload)

        # The panel returns obj=null on add, so verify by re-reading the list.
        after = self.list_inbounds()
        created = [
            i for i in after
            if i.get("remark") == payload["remark"] and i.get("port") == payload["port"]
        ]
        if len(created) != 1:
            raise VerificationFailed("Inbound not found after add; local state was not updated")
        return {"dry_run": False, "id": created[0].get("id"), "verified": True}

    def update_inbound(
        self,
        inbound_id: int,
        payload: Dict[str, Any],
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Replace an inbound's configuration.

        The panel ignores settings.clients and enable in this call. Use the
        clients API and set_enable for those fields.
        """
        current = self.get_inbound(inbound_id)
        _validate_port(payload.get("port"))
        others = [i for i in self.list_inbounds() if i.get("id") != inbound_id]
        self._check_no_conflict(payload, others)

        preview = {
            "method": "POST",
            "path": f"{API_PREFIX}/update/{inbound_id}",
            "body": payload,
            "current": current,
        }
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Updating an inbound")

        self._post_envelope(f"{API_PREFIX}/update/{inbound_id}", payload)

        after = self.get_inbound(inbound_id)
        for key in ("port", "remark", "protocol"):
            if key in payload and after.get(key) != payload[key]:
                raise VerificationFailed(f"Field {key!r} did not match after update")
        return {"dry_run": False, "id": inbound_id, "verified": True}

    def set_enable(
        self,
        inbound_id: int,
        enable: bool,
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        preview = {"method": "POST", "path": f"{API_PREFIX}/setEnable/{inbound_id}", "body": {"enable": enable}}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Changing inbound state")
        self._post_envelope(preview["path"], {"enable": enable})
        after = self.get_inbound(inbound_id)
        if bool(after.get("enable")) != bool(enable):
            raise VerificationFailed("Enable flag did not change after setEnable")
        return {"dry_run": False, "id": inbound_id, "verified": True}

    def delete_inbound(
        self,
        inbound_id: int,
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        current = self.get_inbound(inbound_id)
        preview = {"method": "POST", "path": f"{API_PREFIX}/del/{inbound_id}", "current": current}
        if dry_run:
            return {"dry_run": True, **preview}
        _require_confirmed(confirmed, "Deleting an inbound")
        self._post_envelope(preview["path"])
        remaining_ids = {i.get("id") for i in self.list_inbounds()}
        if inbound_id in remaining_ids:
            raise VerificationFailed("Inbound still exists after delete")
        return {"dry_run": False, "id": inbound_id, "verified": True}
