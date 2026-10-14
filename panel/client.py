"""Read-only client for the 3x-ui panel REST API (v3.9.0 and later).

Verified against the official source (MHSanaei/3x-ui, tags v3.9.0 and v3.10.0):
  - Routes under /panel/api/inbounds are identical in both tags.
  - Bearer tokens must be of scope "admin". Scope "monitor" cannot list inbounds.
  - Responses use the envelope {"success": bool, "msg": str, "obj": ...}.

Write operations live in panel/writes.py and require explicit confirmation.
"""

import json
import ssl
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, List, Optional, Tuple

from panel.errors import (
    PanelAuthError,
    PanelError,
    PanelNotFound,
    PanelResponseError,
    PanelUnreachable,
)
from utils.url import normalize_base_url
from panel.writes import InboundWriteMixin

API_PREFIX = "/panel/api/inbounds"

# transport(method, url, headers, body_bytes, ssl_context) -> (status, response_headers, body_bytes)
Transport = Callable[
    [str, str, Dict[str, str], Optional[bytes], Optional[ssl.SSLContext]],
    Tuple[int, Dict[str, str], bytes],
]


def _default_transport(method, url, headers, body, ssl_context):
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15, context=ssl_context) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise PanelUnreachable(f"Cannot reach panel: {exc.__class__.__name__}") from exc


class PanelClient(InboundWriteMixin):
    """Talks to one 3x-ui panel. Auth is a Bearer admin token, or a login session."""

    def __init__(
        self,
        address: str,
        token: Optional[str] = None,
        verify_tls: bool = True,
        transport: Optional[Transport] = None,
    ):
        self.base_url = normalize_base_url(address)
        self._token = token or None
        self._session_cookie: Optional[str] = None
        self._transport = transport or _default_transport
        self._ssl_context = None
        if self.base_url.startswith("https://") and not verify_tls:
            self._ssl_context = ssl._create_unverified_context()

    def __repr__(self) -> str:  # never reveal the token
        auth = "token" if self._token else ("session" if self._session_cookie else "none")
        return f"PanelClient(base_url={self.base_url!r}, auth={auth})"

    # ---- authentication -------------------------------------------------

    def login(self, username: str, password: str, two_factor_code: str = "") -> None:
        """Create a session cookie with POST /login (used when no token is set)."""
        body = json.dumps(
            {"username": username, "password": password, "twoFactorCode": two_factor_code}
        ).encode()
        status, headers, raw = self._raw("POST", "/login", body=body, json_body=True, auth=False)
        if status in (401, 403):
            raise PanelAuthError("Login rejected by the panel")
        if status == 404:
            raise PanelNotFound("Login endpoint not found; check the web base path")
        payload = self._parse(raw, status)
        if not payload.get("success"):
            raise PanelAuthError(payload.get("msg") or "Login failed")
        cookie = self._extract_session_cookie(headers)
        if not cookie:
            raise PanelResponseError("Login succeeded but no session cookie was returned")
        self._session_cookie = cookie

    @staticmethod
    def _extract_session_cookie(headers: Dict[str, str]) -> Optional[str]:
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                jar = SimpleCookie()
                jar.load(value)
                for name, morsel in jar.items():
                    if "session" in name.lower():
                        return f"{name}={morsel.value}"
        return None

    def _auth_headers(self) -> Dict[str, str]:
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        if self._session_cookie:
            return {"Cookie": self._session_cookie}
        raise PanelAuthError("No token or session. Set an API token or log in first.")

    # ---- low-level request ----------------------------------------------

    def _raw(self, method, path, body=None, json_body=False, auth=True):
        headers = {"Accept": "application/json"}
        if auth:
            headers.update(self._auth_headers())
        if json_body:
            headers["Content-Type"] = "application/json"
        url = self.base_url + path
        return self._transport(method, url, headers, body, self._ssl_context)

    def _request(self, method: str, path: str) -> Any:
        status, _headers, raw = self._raw(method, path)
        return self._parse(raw, status)

    @staticmethod
    def _parse(raw: bytes, status: int) -> Dict[str, Any]:
        if status in (401, 403):
            raise PanelAuthError(
                "Panel rejected the request (HTTP %d). Check the token and its scope; "
                "listing inbounds needs an admin-scope token." % status
            )
        if status == 404:
            raise PanelNotFound("HTTP 404: check the web base path and the panel version")
        if status >= 500:
            raise PanelResponseError(f"Panel server error (HTTP {status})")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PanelResponseError("Panel did not return JSON; check the address and base path") from exc
        if not isinstance(payload, dict):
            raise PanelResponseError("Unexpected response shape")
        return payload

    def _post_envelope(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        status, _headers, raw = self._raw("POST", path, body=body, json_body=payload is not None)
        data = self._parse(raw, status)
        if not data.get("success"):
            raise PanelResponseError(data.get("msg") or "Panel reported failure")
        return data.get("obj")

    def _envelope(self, path: str) -> Any:
        payload = self._request("GET", path)
        if not payload.get("success"):
            raise PanelResponseError(payload.get("msg") or "Panel reported failure")
        return payload.get("obj")

    # ---- read operations ------------------------------------------------

    def check_connection(self) -> bool:
        """Return True if the token or session can read the inbound list."""
        self.list_inbounds()
        return True

    def list_inbounds(self) -> List[Dict[str, Any]]:
        obj = self._envelope(f"{API_PREFIX}/list")
        if not isinstance(obj, list):
            raise PanelResponseError("Inbound list is not an array")
        return obj

    def list_inbounds_slim(self) -> List[Dict[str, Any]]:
        obj = self._envelope(f"{API_PREFIX}/list/slim")
        if not isinstance(obj, list):
            raise PanelResponseError("Slim inbound list is not an array")
        return obj

    def get_inbound(self, inbound_id: int) -> Dict[str, Any]:
        if not isinstance(inbound_id, int) or inbound_id <= 0:
            raise PanelError("Inbound id must be a positive integer")
        obj = self._envelope(f"{API_PREFIX}/get/{inbound_id}")
        if not isinstance(obj, dict):
            raise PanelResponseError("Inbound payload is not an object")
        return obj
