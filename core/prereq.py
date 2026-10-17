"""Check prerequisites on Ubuntu and plan installs. Installing needs explicit confirmation.

Required: python3 (3.10 or newer) and openssl.
Optional: curl (downloads), acme.sh (SSL issuance, installed by hand), haproxy and nginx
(proxy aggregation on one public port, menu 11).
acme.sh is not installed here. Its installer is a remote script, so it stays a manual step.
"""

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

APT_PACKAGES = {"openssl": "openssl", "curl": "curl", "haproxy": "haproxy", "nginx": "nginx"}


@dataclass
class Item:
    name: str
    required: bool
    ok: bool
    detail: str


def ubuntu_info(os_release_path: str = "/etc/os-release") -> Tuple[bool, str]:
    try:
        with open(os_release_path, encoding="utf-8") as fh:
            fields = dict(line.strip().split("=", 1) for line in fh if "=" in line)
    except OSError:
        return False, "unknown"
    distro = fields.get("ID", "").strip('"')
    version = fields.get("VERSION_ID", "").strip('"')
    return distro == "ubuntu", f"{distro} {version}".strip() or "unknown"


def check_prerequisites(
    acme_bin: str,
    which: Callable[[str], Optional[str]] = shutil.which,
    python_version: Tuple[int, int] = (sys.version_info.major, sys.version_info.minor),
) -> List[Item]:
    py_ok = python_version >= (3, 10)
    items = [
        Item("python3", True, py_ok, f"{python_version[0]}.{python_version[1]}" + ("" if py_ok else " (need 3.10+)")),
        Item("openssl", True, which("openssl") is not None,
             "found" if which("openssl") else "missing (apt package: openssl)"),
        Item("curl", False, which("curl") is not None,
             "found" if which("curl") else "missing (apt package: curl)"),
        Item("haproxy", False, which("haproxy") is not None,
             "found" if which("haproxy") else "missing (apt package: haproxy; needed for menu 11)"),
        Item("nginx", False, which("nginx") is not None,
             "found" if which("nginx") else "missing (apt package: nginx; needed for menu 11)"),
        Item("acme.sh", False, os.path.isfile(acme_bin),
             acme_bin if os.path.isfile(acme_bin) else "missing (install manually; needed for SSL issuance)"),
    ]
    return items


INSTALLABLE = tuple(APT_PACKAGES)


def install_plan(items: List[Item], apt_available: bool) -> Optional[List[str]]:
    packages = [APT_PACKAGES[i.name] for i in items if not i.ok and i.name in APT_PACKAGES]
    if not packages or not apt_available:
        return None
    return ["apt-get", "install", "-y", *packages]
