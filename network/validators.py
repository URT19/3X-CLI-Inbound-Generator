"""Input validation for domains, IP addresses and ports."""

import ipaddress
import re
from typing import List

RESERVED_PORTS = frozenset({80, 443})
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def is_valid_domain(name: str) -> bool:
    value = (name or "").strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return False
    try:
        ipaddress.ip_address(value)
        return False  # an IP address is not a domain
    except ValueError:
        pass
    return all(_LABEL.match(label) for label in value.split("."))


def parse_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError as exc:
        raise ValueError(f"Not a valid IP address: {text!r}") from exc


def parse_ip_list(text: str) -> List[str]:
    items = [p.strip() for p in (text or "").split(",") if p.strip()]
    if not items:
        raise ValueError("At least one IP address is required")
    return [parse_ip(item) for item in items]


def parse_port(text) -> int:
    if isinstance(text, bool):
        raise ValueError("Port must be a number")
    try:
        value = int(str(text).strip())
    except ValueError as exc:
        raise ValueError("Port must be a number") from exc
    if not 1 <= value <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return value


def is_loopback_or_private(text: str) -> bool:
    address = ipaddress.ip_address(text)
    return address.is_loopback or address.is_private


def resolve_ipv4(domain: str) -> str:
    """Return the IPv4 address behind a domain name. Raises ValueError if it cannot be resolved."""
    import socket
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"Cannot resolve {domain}: {exc.__class__.__name__}") from exc
    if not infos:
        raise ValueError(f"No IPv4 address found for {domain}")
    return infos[0][4][0]


def connection_address(value: str, use_ip: bool) -> str:
    """The address clients use. With use_ip on, a domain is replaced by its IPv4 address."""
    if not use_ip or not is_valid_domain(value):
        return value
    return resolve_ipv4(value)


def parse_fake_destination(text: str) -> str:
    """Fallback destination for a fake site: a local port ('8080'), 'host:port' with an IPv4 or
    domain host, or '[ipv6]:port'. Ports 80 and 443 are refused (they would point back at the
    public web ports)."""
    value = (text or "").strip()
    if not value:
        raise ValueError("Fake site address is empty")
    if value.isdigit():
        port = parse_port(value)
        if port in RESERVED_PORTS:
            raise ValueError(f"Port {port} cannot be used for a fake site")
        return str(port)
    if value.startswith("["):
        host, _, port_text = value[1:].partition("]:")
        ip = parse_ip(host)
        if ":" not in ip:
            raise ValueError("Bracketed address must be an IPv6 address")
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep:
            raise ValueError("Use a port, or host:port")
        if not (is_valid_domain(host) or _is_ipv4(host)):
            raise ValueError("Host must be an IPv4 address or a domain name")
    port = parse_port(port_text)
    if port in RESERVED_PORTS:
        raise ValueError(f"Port {port} cannot be used for a fake site")
    return value


def _is_ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False
