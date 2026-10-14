"""REALITY (VLESS Vision) helpers: key pairs, short IDs and the target (dest / SNI) choices.

REALITY needs no certificate of the server's own. It borrows the TLS handshake of a real site
(dest), so the target must support TLS 1.3 and HTTP/2. The default targets below are suggestions
only: check each one from the server and the client before use (the Xray check is done by the user).
"""

import base64
import re
import secrets
import subprocess
from typing import Dict, List, Optional, Tuple

from network.validators import is_valid_domain, parse_port

# (label, dest, sni). Suggestions only; verify reachability and TLS 1.3 / HTTP/2 yourself.
DEFAULT_TARGETS: List[Tuple[str, str, str]] = [
    ("Microsoft", "www.microsoft.com:443", "www.microsoft.com"),
    ("Apple", "www.apple.com:443", "www.apple.com"),
    ("Bing", "www.bing.com:443", "www.bing.com"),
    ("Amazon", "www.amazon.com:443", "www.amazon.com"),
    ("Yahoo", "www.yahoo.com:443", "www.yahoo.com"),
]
_SHORT_ID = re.compile(r"^[0-9a-f]{2,16}$")


class RealityError(ValueError):
    """A REALITY value is missing or invalid."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_keypair(openssl: str = "openssl") -> Tuple[str, str]:
    """X25519 key pair in the form Xray expects: raw 32-byte keys, base64url without padding."""
    key = subprocess.run([openssl, "genpkey", "-algorithm", "X25519"], capture_output=True, check=False)
    if key.returncode != 0:
        raise RealityError("openssl could not create an X25519 key")
    der = subprocess.run([openssl, "pkey", "-outform", "DER"], input=key.stdout, capture_output=True, check=False)
    pub = subprocess.run([openssl, "pkey", "-pubout", "-outform", "DER"], input=key.stdout,
                         capture_output=True, check=False)
    if der.returncode or pub.returncode or len(der.stdout) < 32 or len(pub.stdout) < 32:
        raise RealityError("openssl could not export the REALITY key pair")
    return _b64url(der.stdout[-32:]), _b64url(pub.stdout[-32:])


def generate_short_id() -> str:
    return secrets.token_hex(8)  # 16 hex characters


def validate_dest(dest: str) -> str:
    value = (dest or "").strip().lower()
    host, sep, port_text = value.rpartition(":")
    if not sep or not is_valid_domain(host):
        raise RealityError("Target must look like host:443 with a domain name")
    parse_port(port_text)
    return value


def validate_sni(sni: str) -> str:
    value = (sni or "").strip().lower()
    if not is_valid_domain(value):
        raise RealityError("Server name (SNI) must be a domain name")
    return value


def validate_short_id(value: str) -> None:
    if not _SHORT_ID.match(value or ""):
        raise RealityError("Short ID must be 2 to 16 hex characters")
