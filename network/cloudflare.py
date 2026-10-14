"""Cloudflare proxied ports, read from config/cloudflare_ports.json.

The list is data, not code, so it can be updated when Cloudflare's documentation
changes. Update the file and the "retrieved" date together.
"""

import json
import os
from dataclasses import dataclass
from typing import List

from panel.errors import PanelError


class CloudflareDataError(PanelError):
    """The Cloudflare port file is missing or malformed."""


@dataclass(frozen=True)
class CloudflarePorts:
    source: str
    retrieved: str
    http_ports: frozenset
    https_ports: frozenset

    @property
    def all_ports(self) -> frozenset:
        return self.http_ports | self.https_ports


def _port_list(value, name: str) -> frozenset:
    if not isinstance(value, list) or not value:
        raise CloudflareDataError(f"{name} must be a non-empty list")
    ports = set()
    for item in value:
        if not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 65535:
            raise CloudflareDataError(f"{name} contains an invalid port: {item!r}")
        ports.add(item)
    return frozenset(ports)


def load_cloudflare_ports(path: str) -> CloudflarePorts:
    if not os.path.exists(path):
        raise CloudflareDataError(f"Cloudflare port file not found: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudflareDataError(f"Cannot read Cloudflare port file: {exc.__class__.__name__}") from exc
    if not isinstance(data, dict):
        raise CloudflareDataError("Cloudflare port file must contain a JSON object")
    return CloudflarePorts(
        source=str(data.get("source", "")),
        retrieved=str(data.get("retrieved", "")),
        http_ports=_port_list(data.get("http_ports"), "http_ports"),
        https_ports=_port_list(data.get("https_ports"), "https_ports"),
    )
