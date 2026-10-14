"""Read-only checks of a domain certificate stored under the certificate root.

Layout (from the project spec):
  <cert_root>/<domain>/fullchain.pem
  <cert_root>/<domain>/privkey.pem

File presence alone does not mean the certificate is valid, so the checker also
verifies the domain names, the expiry date, and that the private key matches the
certificate. Key material is never printed or returned.
"""

import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional, Tuple

RENEW_BEFORE_DAYS = 30
COMMAND_TIMEOUT = 30

Runner = Callable[[List[str]], Tuple[int, str, str]]


def default_runner(argv: List[str]) -> Tuple[int, str, str]:
    """Run a command without a shell. Arguments are passed as a list."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", exc.__class__.__name__
    return done.returncode, done.stdout, done.stderr


@dataclass
class CertStatus:
    domain: str
    state: str            # missing, invalid, mismatch, expired, renew, ok
    message: str
    fullchain: str
    privkey: str
    days_left: Optional[int] = None
    not_after: Optional[str] = None
    names: Optional[List[str]] = None
    key_permissions_ok: Optional[bool] = None


def cert_paths(cert_root: str, domain: str) -> Tuple[str, str]:
    base = os.path.join(cert_root, domain)
    return os.path.join(base, "fullchain.pem"), os.path.join(base, "privkey.pem")


def _parse_not_after(text: str) -> Optional[datetime]:
    match = re.search(r"notAfter=(.+)", text)
    if not match:
        return None
    value = " ".join(match.group(1).split())
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_names(san_text: str, subject_text: str) -> List[str]:
    names = re.findall(r"DNS:([^,\s]+)", san_text)
    if names:
        return [n.strip().lower() for n in names]
    cn = re.search(r"CN\s*=\s*([^,\n]+)", subject_text)
    return [cn.group(1).strip().lower()] if cn else []


def domain_matches(domain: str, names: List[str]) -> bool:
    domain = domain.lower()
    for name in names:
        if name == domain:
            return True
        if name.startswith("*.") and domain.endswith(name[1:]) and domain.count(".") == name.count("."):
            return True
    return False


def check_domain_cert(
    cert_root: str,
    domain: str,
    runner: Runner = default_runner,
    now: Optional[datetime] = None,
) -> CertStatus:
    now = now or datetime.now(timezone.utc)
    fullchain, privkey = cert_paths(cert_root, domain)

    def fail(state: str, message: str, **extra) -> CertStatus:
        return CertStatus(domain=domain, state=state, message=message,
                          fullchain=fullchain, privkey=privkey, **extra)

    if not os.path.isfile(fullchain) or not os.path.isfile(privkey):
        return fail("missing", "Certificate or private key file is missing")

    key_mode = stat.S_IMODE(os.stat(privkey).st_mode)
    key_ok = (key_mode & 0o077) == 0

    rc, not_after_out, _ = runner(["openssl", "x509", "-in", fullchain, "-noout", "-enddate"])
    if rc != 0:
        return fail("invalid", "Certificate file cannot be parsed", key_permissions_ok=key_ok)
    not_after = _parse_not_after(not_after_out)
    if not_after is None:
        return fail("invalid", "Cannot read the expiry date", key_permissions_ok=key_ok)

    rc, san_out, _ = runner(["openssl", "x509", "-in", fullchain, "-noout", "-ext", "subjectAltName"])
    rc2, subj_out, _ = runner(["openssl", "x509", "-in", fullchain, "-noout", "-subject"])
    names = _parse_names(san_out if rc == 0 else "", subj_out if rc2 == 0 else "")
    if not domain_matches(domain, names):
        return fail("mismatch", f"Certificate names do not cover {domain}",
                    names=names, not_after=not_after.isoformat(), key_permissions_ok=key_ok)

    rc_cert, cert_pub, _ = runner(["openssl", "x509", "-in", fullchain, "-noout", "-pubkey"])
    rc_key, key_pub, _ = runner(["openssl", "pkey", "-in", privkey, "-pubout"])
    if rc_cert != 0 or rc_key != 0 or not cert_pub.strip() or cert_pub.strip() != key_pub.strip():
        return fail("mismatch", "Private key does not match the certificate",
                    names=names, not_after=not_after.isoformat(), key_permissions_ok=key_ok)

    days_left = (not_after - now).days
    if now >= not_after:
        return fail("expired", "Certificate has expired", names=names,
                    days_left=days_left, not_after=not_after.isoformat(), key_permissions_ok=key_ok)
    if days_left <= RENEW_BEFORE_DAYS:
        return fail("renew", f"Certificate expires in {days_left} days and should be renewed",
                    names=names, days_left=days_left, not_after=not_after.isoformat(),
                    key_permissions_ok=key_ok)
    return fail("ok", f"Certificate is valid for {days_left} more days", names=names,
                days_left=days_left, not_after=not_after.isoformat(), key_permissions_ok=key_ok)
