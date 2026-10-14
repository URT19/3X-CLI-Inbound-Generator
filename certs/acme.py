"""Issue and renew certificates with acme.sh, the same way the panel's installer does.

The panel installer (install.sh at v3.10.0) installs acme.sh, uses Let's Encrypt
with the standalone HTTP-01 listener, and installs the files with --installcert.
This module builds the same commands as argument lists. It never uses a shell.

Notes:
  - HTTP-01 needs the chosen port to be reachable from the internet. The default is 80,
    which is the panel's default. Port 80 is used only during validation, not for inbounds.
  - No service is restarted. The panel installer restarts x-ui through --reloadcmd;
    this module does not, so the operator decides when to restart.
  - acme.sh itself is not installed here. Installing it means running a remote script,
    so that step needs its own approval.
"""

import os
from typing import List, Optional

from network.validators import is_valid_domain
from certs.checker import Runner, cert_paths

DEFAULT_ACME_BIN = os.path.expanduser("~/.acme.sh/acme.sh")


class AcmeError(RuntimeError):
    """An acme.sh step failed or cannot start."""


def build_issue_plan(domain: str, cert_root: str, http_port: int = 80,
                     acme_bin: str = DEFAULT_ACME_BIN) -> List[List[str]]:
    if not is_valid_domain(domain):
        raise AcmeError("Not a valid domain name")
    if not isinstance(http_port, int) or isinstance(http_port, bool) or not 1 <= http_port <= 65535:
        raise AcmeError("HTTP-01 port must be between 1 and 65535")
    fullchain, privkey = cert_paths(cert_root, domain)
    return [
        [acme_bin, "--set-default-ca", "--server", "letsencrypt", "--force"],
        [acme_bin, "--issue", "-d", domain, "--standalone", "--httpport", str(http_port), "--force"],
        [acme_bin, "--installcert", "--force", "-d", domain,
         "--key-file", privkey, "--fullchain-file", fullchain],
    ]


def acme_available(acme_bin: str = DEFAULT_ACME_BIN) -> bool:
    return os.path.isfile(acme_bin)


def run_plan(plan: List[List[str]], cert_root: str, domain: str, runner: Runner) -> Optional[str]:
    """Run the steps in order and stop at the first failure. Returns an error message or None."""
    os.makedirs(os.path.join(cert_root, domain), exist_ok=True)
    for argv in plan:
        rc, _out, err = runner(argv)
        if rc != 0:
            return f"acme.sh step failed (exit {rc}) for {argv[1]}"
    fullchain, privkey = cert_paths(cert_root, domain)
    if os.path.isfile(privkey):
        os.chmod(privkey, 0o600)
    if os.path.isfile(fullchain):
        os.chmod(fullchain, 0o644)
    return None
