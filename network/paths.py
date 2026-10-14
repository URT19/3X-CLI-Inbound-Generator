"""Request paths for inbounds that need one.

A path depends on the connection mode and the transport: CDN+WS is a different key from
DIRECT+WS, so each combination gets its own random 12-character value. Link paths
(vmess, vless, trojan) are kept as separate keys. Values are stored in settings.json under "paths".
"""

import re
import secrets
import string
from typing import Dict

MODES = ("direct", "cdn")
TRANSPORT_KEYS = ("ws", "xhttp", "grpc", "httpupgrade", "tcp")
LINK_KEYS = ("vmess", "vless", "trojan")
TRANSPORT_LABELS = {
    "ws": "WebSocket",
    "xhttp": "XHTTP",
    "grpc": "gRPC service",
    "httpupgrade": "HTTPUpgrade",
    "tcp": "TCP config",
}
LINK_LABELS = {"vmess": "VMess link path", "vless": "VLESS path", "trojan": "Trojan link path"}
# Template placeholder -> transport part of the key. Full key: "<mode>_<transport>".
TEMPLATE_PATH_KEYS = {
    "PATH_WS": "ws",
    "PATH_XHTTP": "xhttp",
    "PATH_GRPC": "grpc",
    "PATH_UPGRADE": "httpupgrade",
    "PATH_TCP": "tcp",
}
PATH_KEYS = tuple(f"{mode}_{t}" for mode in MODES for t in TRANSPORT_KEYS) + LINK_KEYS
PATH_LABELS = {
    **{f"{mode}_{t}": f"{mode.upper()} {TRANSPORT_LABELS[t]} path" for mode in MODES for t in TRANSPORT_KEYS},
    **LINK_LABELS,
}
RANDOM_LENGTH = 12
_ALPHABET = string.ascii_letters + string.digits
_VALID = re.compile(r"^/[A-Za-z0-9_\-.]{1,63}$")
_SECRET_ALPHABET = string.ascii_letters + string.digits


def path_key(connection_mode: str, transport_key: str) -> str:
    return f"{connection_mode}_{transport_key}"


def random_path() -> str:
    return "/" + "".join(secrets.choice(_ALPHABET) for _ in range(RANDOM_LENGTH))


def generate_all() -> Dict[str, str]:
    return {key: random_path() for key in PATH_KEYS}


def validate_path(text: str) -> str:
    value = (text or "").strip()
    if value and not value.startswith("/"):
        value = "/" + value
    if not _VALID.match(value):
        raise ValueError("Path may use letters, digits, '_', '-', '.' and must be at most 63 characters")
    return value


def random_secret(length: int = 16) -> str:
    """Random alphanumeric secret, for example a Hysteria salamander password."""
    return "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(length))
