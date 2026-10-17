"""Optional settings for CDN configs: ECH config list and finalmask (TCP fragment).

Both are asked in the menu. Nothing is applied unless the user says yes.
"""

import copy
import json
from typing import Any, Dict, Optional

CDN_ECH_CONFIG = "cloudflare-ech.com+udp://1.1.1.1"

# Given by the user. Applied verbatim as streamSettings.finalmask.
CDN_FINALMASK: Dict[str, Any] = {
    "tcp": [
        {
            "type": "fragment",
            "settings": {
                "packets": "tlshello",
                "lengths": ["0", "104", "1"],
                "delays": ["0"],
                "maxSplit": "0",
            },
        },
        {
            "type": "fragment",
            "settings": {
                "packets": "1-1",
                "lengths": ["114", "1"],
                "delays": ["1"],
                "maxSplit": "11",
            },
        },
    ]
}


class CdnError(ValueError):
    """A CDN payload cannot take the optional settings."""


def apply_cdn_options(payload: Dict[str, Any], ech: bool = False,
                      finalmask: Optional[Dict[str, Any]] = None) -> None:
    """Set the ECH config list and/or finalmask on a CDN inbound payload, in place."""
    if not ech and not finalmask:
        return
    stream = payload.get("streamSettings")
    if not isinstance(stream, dict):
        raise CdnError("CDN payload has no streamSettings object")
    if stream.get("security") != "tls":
        raise CdnError("CDN options need a TLS inbound")
    if ech:
        tls = stream.get("tlsSettings")
        if not isinstance(tls, dict):
            raise CdnError("CDN payload has no tlsSettings object")
        tls.setdefault("settings", {})["echConfigList"] = CDN_ECH_CONFIG
    if finalmask:
        stream["finalmask"] = copy.deepcopy(finalmask)


def missing_options(stored: Dict[str, Any], ech: bool, finalmask: Optional[Dict[str, Any]]) -> list:
    """Compare an inbound read back from the panel with what was requested.
    Returns the names of requested options the panel did not keep ("ECH config list", "finalmask")."""
    stream = stored.get("streamSettings")
    if isinstance(stream, str):
        try:
            stream = json.loads(stream or "{}")
        except ValueError:
            stream = {}
    stream = stream if isinstance(stream, dict) else {}
    missing = []
    if ech:
        tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
        inner = tls.get("settings") if isinstance(tls.get("settings"), dict) else {}
        if inner.get("echConfigList") != CDN_ECH_CONFIG:
            missing.append("ECH config list")
    if finalmask and stream.get("finalmask") != finalmask:
        missing.append("finalmask")
    return missing
