"""Default inbound names.

Format: NN-PROTOCOL-TRANSPORT-MODE-SECURITY, for example 12-VLESS-XHTTP-CDN-TLS.
The name starts with the template number, uses only ASCII, and is limited to
MAX_NAME_LENGTH characters. If the name already exists on the panel, a numeric
suffix (-2, -3, ...) is added while staying within the limit.
"""

from typing import Iterable, Optional

MAX_NAME_LENGTH = 32

TRANSPORT_LABELS = {
    "tcp": "TCP",
    "ws": "WS",
    "grpc": "GRPC",
    "httpupgrade": "HTTPUP",
    "xhttp": "XHTTP",
    "hysteria": "HY2",
    "tuic": "TUIC",
    "amneziawg": "AWG",
}


class NamingError(ValueError):
    """A name cannot be built or does not meet the rules."""


def _base(template, mode_label: Optional[str] = None) -> str:
    try:
        transport = TRANSPORT_LABELS[template.transport]
    except KeyError as exc:
        raise NamingError(f"No label for transport {template.transport!r}") from exc
    security = {"tls": "TLS", "reality": "REALITY"}.get(template.security, "PLAIN")
    return (
        f"{template.number:02d}-{template.protocol.upper()}-{transport}-"
        f"{(mode_label or template.connection_mode).upper()}-{security}"
    )


def build_name(template, existing: Iterable[str], max_length: int = MAX_NAME_LENGTH,
               mode_label: Optional[str] = None) -> str:
    taken = set(existing)
    base = _base(template, mode_label)
    if len(base) > max_length:
        raise NamingError(f"Name {base!r} is longer than {max_length} characters")
    if base not in taken:
        return base
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if len(candidate) > max_length:
            break
        if candidate not in taken:
            return candidate
    raise NamingError("No free name fits within the length limit")


def validate_custom_name(name: str, existing: Iterable[str], max_length: int = MAX_NAME_LENGTH) -> Optional[str]:
    """Return an error message, or None if the custom name is acceptable."""
    if not name:
        return "Name is empty"
    if len(name) > max_length:
        return f"Name is longer than {max_length} characters"
    if not name[0].isdigit():
        return "Name must start with a number"
    if not name.isascii():
        return "Name must use ASCII characters"
    if name in set(existing):
        return f"Name {name!r} already exists on the panel"
    return None
