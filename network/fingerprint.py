"""TLS fingerprint choices for the tlsSettings block of an inbound."""

import re
from typing import Any

PRESETS = ("chrome", "firefox", "safari", "unsafe")
DEFAULT_FINGERPRINT = "chrome"
_VALID = re.compile(r"^[a-z0-9_\-]{1,32}$")


def validate_fingerprint(text: str) -> str:
    value = (text or "").strip().lower()
    if not _VALID.match(value):
        raise ValueError("Fingerprint must be 1 to 32 characters: a-z, 0-9, '_' or '-'")
    return value


def apply_fingerprint(node: Any, fingerprint: str) -> int:
    """Set fingerprint in every tlsSettings.settings block. Returns how many were changed."""
    changed = 0
    if isinstance(node, dict):
        tls = node.get("tlsSettings")
        if isinstance(tls, dict) and isinstance(tls.get("settings"), dict):
            tls["settings"]["fingerprint"] = fingerprint
            changed += 1
        for value in node.values():
            changed += apply_fingerprint(value, fingerprint)
    elif isinstance(node, list):
        for value in node:
            changed += apply_fingerprint(value, fingerprint)
    return changed
