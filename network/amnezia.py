"""AmneziaWG parameters: proposal generation, validation and application to an inbound.

The keys are X25519 (WireGuard) keys made with openssl. Everything else is a random proposal
inside the ranges the panel's example uses. The user confirms or edits the proposal, and the
result is stored in settings.json under "amnezia".
"""

import base64
import re
import secrets
import subprocess
from typing import Dict, Optional

INT_KEYS = ("subnetCidr", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
BOOL_KEYS = ("ipv6Enabled", "randomTrailers", "disableCookies")
RANGE_KEYS = ("contentPaddingAddition", "rekeyAfterTime", "rekeyTimeout", "rejectAfterTime",
              "keepaliveTimeout", "maxHandshakeAttempts")
TEXT_KEYS = ("subnetIp", "primaryDns", "secondaryDns", "externalInterface", "ipv6Subnet",
             "ipv6ExternalInterface", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
             "headerProtectionKey", "privateKey", "publicKey")
ALL_KEYS = INT_KEYS + BOOL_KEYS + RANGE_KEYS + TEXT_KEYS
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RANGE = re.compile(r"^\d+-\d+$")
_B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class AmneziaError(ValueError):
    """An AmneziaWG value is missing or invalid."""


def _x25519_pair(openssl: str = "openssl"):
    key = subprocess.run([openssl, "genpkey", "-algorithm", "X25519"], capture_output=True, check=False)
    if key.returncode != 0:
        raise AmneziaError("openssl could not create an X25519 key")
    der = subprocess.run([openssl, "pkey", "-outform", "DER"], input=key.stdout,
                         capture_output=True, check=False)
    pub = subprocess.run([openssl, "pkey", "-pubout", "-outform", "DER"], input=key.stdout,
                         capture_output=True, check=False)
    if der.returncode or pub.returncode or len(der.stdout) < 32 or len(pub.stdout) < 32:
        raise AmneziaError("openssl could not export the key")
    return base64.b64encode(der.stdout[-32:]).decode(), base64.b64encode(pub.stdout[-32:]).decode()


def generate_proposal(openssl: str = "openssl") -> Dict:
    """Random values inside the ranges the panel accepts (internal/amneziawg/params.go)."""
    private_key, public_key = _x25519_pair(openssl)
    jmin = secrets.randbelow(50) + 40          # 40..89
    s1 = secrets.randbelow(136) + 15           # 15..150
    s2 = secrets.randbelow(136) + 15
    while s1 + 56 == s2:                       # kernel rule: S1+56 != S2
        s2 = secrets.randbelow(136) + 15
    h = set()
    while len(h) < 4:                          # distinct, at least 5
        h.add(secrets.randbelow(2_000_000_000) + 5)
    h1, h2, h3, h4 = [str(x) for x in sorted(h)]
    return {
        "privateKey": private_key,
        "publicKey": public_key,
        "subnetIp": f"10.{secrets.randbelow(200) + 20}.{secrets.randbelow(200) + 20}.0",
        "subnetCidr": 24,
        "primaryDns": "8.8.8.8",
        "secondaryDns": "8.8.4.4",
        "externalInterface": "",
        "ipv6Enabled": False,
        "ipv6Subnet": "",
        "ipv6ExternalInterface": "",
        "jc": secrets.randbelow(4) + 3,        # 3..6
        "jmin": jmin,
        "jmax": jmin + secrets.randbelow(201) + 50,
        "s1": s1,
        "s2": s2,
        "s3": secrets.randbelow(44) + 12,      # 12..55
        "s4": secrets.randbelow(16) + 12,      # 12..27 (panel max 32)
        "h1": h1, "h2": h2, "h3": h3, "h4": h4,
        "i1": f"<r {secrets.randbelow(225) + 32}>",
        "i2": "", "i3": "", "i4": "", "i5": "",
        "headerProtectionKey": base64.b64encode(secrets.token_bytes(32)).decode(),
        "contentPaddingAddition": "11-46",
        "rekeyAfterTime": "115-150",
        "rekeyTimeout": "6-10",
        "rejectAfterTime": "196-246",
        "keepaliveTimeout": "9-15",
        "maxHandshakeAttempts": "25-36",
        "randomTrailers": True,
        "disableCookies": True,
    }


def validate(params: Dict) -> None:
    """Same rules as the panel's ValidateObfuscation and ValidateServerObfuscation."""
    missing = [k for k in ALL_KEYS if k not in params]
    if missing:
        raise AmneziaError(f"Missing AmneziaWG values: {', '.join(missing)}")
    for key in INT_KEYS:
        value = params[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise AmneziaError(f"{key} must be a whole number of 0 or more")
    for key in BOOL_KEYS:
        if not isinstance(params[key], bool):
            raise AmneziaError(f"{key} must be true or false")
    for key in RANGE_KEYS:
        if not isinstance(params[key], str) or not _RANGE.match(params[key]):
            raise AmneziaError(f"{key} must look like 10-20")
    rekey_max = int(params["rekeyAfterTime"].split("-")[1])
    reject_min = int(params["rejectAfterTime"].split("-")[0])
    if rekey_max >= reject_min:
        raise AmneziaError("rekeyAfterTime maximum must be below rejectAfterTime minimum")
    for key in ("subnetIp", "primaryDns", "secondaryDns"):
        if not _IP.match(str(params[key])):
            raise AmneziaError(f"{key} must be an IPv4 address")
    if not 0 <= params["subnetCidr"] <= 32:
        raise AmneziaError("subnetCidr must be between 0 and 32")
    if params["jmin"] > params["jmax"]:
        raise AmneziaError("jmin must not be greater than jmax")
    if not 0 <= params["s4"] <= 32:
        raise AmneziaError(f"invalid S4 value {params['s4']} (must be 0..32)")
    if params["s1"] > 65535 or params["s2"] > 65535 or params["s3"] > 65535:
        raise AmneziaError("S1, S2 and S3 must fit in 16 bits")
    if params["s1"] + 56 == params["s2"]:
        raise AmneziaError("S1+56 must not equal S2")
    if params["s1"] > 1652 or params["s2"] > 1608 or params["s3"] > 1636:
        raise AmneziaError("S1, S2 or S3 is too large for every client to receive")
    if params["headerProtectionKey"] and min(params[k] for k in ("s1", "s2", "s3", "s4")) < 12:
        raise AmneziaError("header protection requires S1 to S4 of 12 or more")
    if not 5 <= min(int(params[k]) for k in ("h1", "h2", "h3", "h4")):
        raise AmneziaError("H values must be at least 5")
    for key in ("h1", "h2", "h3", "h4"):
        if not str(params[key]).isdigit():
            raise AmneziaError(f"{key} must be a number")
    if len({params[k] for k in ("h1", "h2", "h3", "h4")}) != 4:
        raise AmneziaError("h1 to h4 must be different")
    if not _is_b64_32(params["headerProtectionKey"]):
        raise AmneziaError("headerProtectionKey must be a 32-byte base64 key")
    for key in ("privateKey", "publicKey"):
        if not _B64_32.match(str(params[key])):
            raise AmneziaError(f"{key} must be a 32-byte base64 key")


def _is_b64_32(value) -> bool:
    try:
        return len(base64.b64decode(str(value), validate=True)) == 32
    except (ValueError, TypeError):
        return False


def placeholders_for(params: Dict) -> Dict[str, str]:
    """Values for the template placeholders that hold secrets."""
    validate(params)
    return {
        "AWG_PRIVATE_KEY": params["privateKey"],
        "AWG_PUBLIC_KEY": params["publicKey"],
        "AWG_HEADER_KEY": params["headerProtectionKey"],
    }


def apply_to_payload(payload: Dict, params: Dict) -> None:
    """Write every AmneziaWG value into payload.settings.server and empty the client list."""
    validate(params)
    server = payload["settings"]["server"]
    for key in ALL_KEYS:
        server[key] = params[key]
    payload["settings"]["clients"] = []
