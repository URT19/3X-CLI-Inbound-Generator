"""Host headers for direct inbounds created with an IP address.

When the direct address is an IP, the Host header of the transport (XHTTP, WebSocket, HTTPUpgrade,
gRPC authority) must be that IP, not the domain. TLS server names and certificates stay the domain.
"""

import ipaddress
from typing import Any, Dict, Optional


def is_ipv4_literal(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def apply_ip_host(payload: Dict[str, Any], address: str) -> int:
    """Set the transport Host header to address wherever a host value exists and differs from it.
    Returns how many values were changed."""
    stream = payload.get("streamSettings") or {}
    changed = 0

    def set_value(container: Dict[str, Any], key: str) -> None:
        nonlocal changed
        if container.get(key) and container[key] != address:
            container[key] = address
            changed += 1

    xhttp = stream.get("xhttpSettings")
    if isinstance(xhttp, dict):
        set_value(xhttp, "host")
    ws = stream.get("wsSettings")
    if isinstance(ws, dict) and isinstance(ws.get("headers"), dict):
        set_value(ws["headers"], "Host")
    upgrade = stream.get("httpupgradeSettings")
    if isinstance(upgrade, dict):
        set_value(upgrade, "host")
    grpc = stream.get("grpcSettings")
    if isinstance(grpc, dict):
        set_value(grpc, "authority")
    return changed


def direct_host_payload(inbound_id: int, remark: str, address: str, port: int,
                        security: str, sni_domain: str, public_port: Optional[int] = None) -> Dict[str, Any]:
    """Host entry that sets the address clients use for a direct inbound.

    With an IP as the address, the TLS or REALITY server name (sni) stays the domain, so the
    certificate and the handshake still match. Without TLS, sni is left empty.
    """
    if security in ("tls", "reality"):
        sni = sni_domain  # always the server name: the domain for TLS, the REALITY target for REALITY
    else:
        sni = ""
    return {
        "inboundId": inbound_id,
        "remark": remark,
        "address": address,
        "port": public_port or port,  # subscriptions show the public port (443 behind a proxy)
        "security": "same",
        "sni": sni,
        "alpn": [],
        "sortOrder": 0,
    }
