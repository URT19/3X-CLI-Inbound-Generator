"""Port policy: which ports an inbound may use.

Rules (from the project spec):
  - 80 and 443 are always reserved.
  - In local mode (HAProxy/Nginx behind the server), no port that Cloudflare
    proxies for HTTP or HTTPS may be used.
  - A port already used by a known inbound is refused.
  - A random port is chosen only from the configured range and only if it passes
    the same checks. The check is repeated before the change is applied, because
    a port that is free now may be taken later.
"""

import random
from typing import Iterable, Optional

from network.cloudflare import CloudflarePorts
from network.validators import RESERVED_PORTS


class PortError(ValueError):
    """A port cannot be used. The message gives the reason."""


def check_port(
    port: int,
    mode: str,
    in_use: Iterable[int],
    cloudflare: Optional[CloudflarePorts],
) -> None:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise PortError("Port must be between 1 and 65535")
    if port in RESERVED_PORTS:
        raise PortError(f"Port {port} is reserved (80 and 443 are never used for inbounds)")
    if mode == "local":
        if cloudflare is None:
            raise PortError("Cloudflare port list is not loaded; local ports cannot be checked")
        if port in cloudflare.all_ports:
            raise PortError(f"Port {port} is a Cloudflare HTTP/HTTPS port and cannot be used in local mode")
    if port in set(in_use):
        raise PortError(f"Port {port} is already used by another inbound")


def pick_random_port(
    low: int,
    high: int,
    mode: str,
    in_use: Iterable[int],
    cloudflare: Optional[CloudflarePorts],
    rng: Optional[random.Random] = None,
    attempts: int = 200,
) -> int:
    if not (1 <= low <= high <= 65535):
        raise PortError("Random port range must satisfy 1 <= low <= high <= 65535")
    rng = rng or random.SystemRandom()
    taken = set(in_use)
    for _ in range(attempts):
        candidate = rng.randint(low, high)
        try:
            check_port(candidate, mode, taken, cloudflare)
        except PortError:
            continue
        return candidate
    raise PortError(f"No free port found in {low}-{high} for mode {mode}")


def cloudflare_ports_for(security: str, cloudflare: Optional[CloudflarePorts]) -> Optional[frozenset]:
    """Ports a CDN inbound may use when it is reached through Cloudflare (a domain or an IP).

    TLS inbounds use the Cloudflare HTTPS ports, plain inbounds the HTTP ports. Ports 80 and 443
    are never used, as required for CDN configurations.
    """
    if cloudflare is None:
        return None
    if security == "tls":
        return frozenset(cloudflare.https_ports) - RESERVED_PORTS
    return frozenset(cloudflare.http_ports) - RESERVED_PORTS


PREFERRED_CLOUDFLARE_PORT = 8443


def pick_cloudflare_port(allowed: frozenset, in_use: Iterable[int],
                         rng: Optional[random.Random] = None) -> int:
    """8443 first when it is free (it is the preferred second HTTPS port), otherwise any free one."""
    taken = set(in_use)
    free = sorted(port for port in allowed if port not in taken)
    if not free:
        raise PortError("No free Cloudflare port left for this inbound")
    if PREFERRED_CLOUDFLARE_PORT in free:
        return PREFERRED_CLOUDFLARE_PORT
    rng = rng or random.SystemRandom()
    return rng.choice(free)
