"""Resolve every inbound parameter before anything is sent to the panel.

Values come from the saved settings (menu 3), not from questions asked during
creation. The function returns the values and a list of problems. If the list is
not empty, creation is refused and nothing is sent.

Placeholder sources:
  PORT                 network port mode (fixed or random from the range), checked against
                       the ports already used on the panel
  SUBDOMAIN_CDN        network.cdn_domain
  SUBDOMAIN_DIRECT     network.direct_domain
  WHITELIST_IP         first Cloudflare IP (used by the external proxy host entries)
  PATH_*               settings.paths
  CERT_* / KEY_*       <cert_root>/<domain>/fullchain.pem and privkey.pem, which must be
                       readable and pass the certificate check (valid or due for renewal)
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from certs.checker import CertStatus, cert_paths
from config.settings import NetworkSettings
from network.cloudflare import CloudflarePorts
from network.paths import TEMPLATE_PATH_KEYS, path_key, random_path, random_secret
from network.amnezia import AmneziaError, placeholders_for as amnezia_placeholders
from network.reality import RealityError, generate_keypair as reality_keypair, generate_short_id as reality_short_id
from network.ports import (PortError, check_ruled_port, cloudflare_ports_for, pick_cloudflare_port,
                           pick_ruled_port, port_rule_for)
from network.validators import RESERVED_PORTS

PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
ALLOWED_PROTOCOLS = {"vless", "vmess", "trojan", "hysteria", "tuic", "amneziawg"}
NATIVE_PROTOCOLS = {"tuic", "amneziawg"}
PATH_NETWORKS = {"ws", "xhttp", "httpupgrade"}
CERT_PAIRS = {"CERT_CDN": ("cdn", "fullchain"), "KEY_CDN": ("cdn", "privkey"),
              "CERT_DIRECT": ("direct", "fullchain"), "KEY_DIRECT": ("direct", "privkey"),
              "CERT_DIRECT2": ("direct2", "fullchain"), "KEY_DIRECT2": ("direct2", "privkey")}
ACCEPTED_CERT_STATES = ("ok", "renew")


@dataclass
class Resolution:
    values: Dict[str, object] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _needed_placeholders(template) -> List[str]:
    text = json.dumps(template.content) + json.dumps(template.external_proxies)
    return sorted(set(PLACEHOLDER.findall(text)))


def resolve_values(
    template,
    network: NetworkSettings,
    paths: Dict[str, str],
    cert_root: str,
    cloudflare: Optional[CloudflarePorts],
    in_use: List[int],
    status_fn: Callable[[str], CertStatus],
    rng=None,
    amnezia: Optional[Dict] = None,
    connection_address: Optional[str] = None,
    cdn_via: str = "cloudflare",
    reality: Optional[Dict] = None,
    fingerprint: str = "chrome",
) -> Resolution:
    res = Resolution()
    needed = _needed_placeholders(template)

    # PORT
    rule = port_rule_for(template.security)
    through_cloudflare = template.connection_mode == "cdn" and cdn_via == "cloudflare"
    if through_cloudflare:
        # CDN through Cloudflare: only Cloudflare's ports, never 80 or 443.
        allowed = cloudflare_ports_for(template.security, cloudflare)
        if allowed is not None and template.fixed_port:
            # Fixed CDN ports come from the template (see tools/build_cdn_templates.py).
            if template.fixed_port not in allowed and not template.origin_port:
                res.problems.append(
                    f"Port {template.fixed_port} is not a Cloudflare {template.security} port")
            elif template.fixed_port in in_use:
                res.problems.append(f"Port {template.fixed_port} is already used by another inbound")
            else:
                res.values["PORT"] = template.fixed_port
                if template.origin_port and template.fixed_port not in allowed:
                    res.warnings.append(
                        f"{template.name}: port {template.fixed_port} is an origin port. Add a Cloudflare origin "
                        f"rule that sends a Cloudflare port to it, and use that Cloudflare port in the host.")
        elif allowed is None:
            res.problems.append("Cloudflare port list is not loaded; CDN ports cannot be chosen")
        elif network.port_mode == "fixed":
            if network.fixed_port in allowed:
                res.values["PORT"] = network.fixed_port
            else:
                res.problems.append(
                    f"Fixed port {network.fixed_port} is not a Cloudflare port for a "
                    f"{template.security} CDN inbound (menu 3, item 6)")
        else:
            try:
                res.values["PORT"] = pick_cloudflare_port(allowed, in_use, rng=rng)
            except PortError:
                res.problems.append("No Cloudflare port left for this CDN inbound; "
                                    "use a different Cloudflare route or free a port")
    elif network.port_mode == "fixed":
        if not network.fixed_port:
            res.problems.append("Fixed port is not set (menu 3, item 6)")
        else:
            try:
                check_ruled_port(network.fixed_port, rule, in_use, cloudflare)
                res.values["PORT"] = network.fixed_port
            except PortError as exc:
                res.problems.append(f"Port: {exc}")
    else:
        try:
            res.values["PORT"] = pick_ruled_port(
                network.random_port_low, network.random_port_high, rule, in_use, cloudflare, rng=rng)
        except PortError as exc:
            res.problems.append(f"Port: {exc}")

    # Domains and Cloudflare address
    domains = {"cdn": network.cdn_domain, "direct": network.direct_domain,
               "direct2": getattr(network, "direct_domain2", "")}
    if "SUBDOMAIN_DIRECT2" in needed:
        if domains["direct2"]:
            res.values["SUBDOMAIN_DIRECT2"] = domains["direct2"]
        else:
            res.problems.append("Direct domain 2 is not set (menu 3, item 14)")
    if "SUBDOMAIN_CDN" in needed:
        if domains["cdn"]:
            res.values["SUBDOMAIN_CDN"] = domains["cdn"]
        else:
            res.problems.append("CDN domain is not set (menu 3, item 5)")
    if "SUBDOMAIN_DIRECT" in needed:
        if domains["direct"]:
            res.values["SUBDOMAIN_DIRECT"] = domains["direct"]
        else:
            res.problems.append("Direct domain is not set (menu 3, item 4)")
    if "WHITELIST_IP" in needed:
        # For CDN: the Cloudflare IP chosen for this run. For direct: the chosen direct address.
        if connection_address:
            res.values["WHITELIST_IP"] = connection_address
        elif network.cloudflare_ips:
            res.values["WHITELIST_IP"] = network.cloudflare_ips[0]
        else:
            res.problems.append("Cloudflare IP is not set (menu 3, item 2)")

    # Paths
    for placeholder, transport in TEMPLATE_PATH_KEYS.items():
        if placeholder in needed and template.connection_mode == "fallback":
            res.values[placeholder] = random_path()  # fallback inbounds get their own path
            continue
        if placeholder in needed:
            key = path_key(template.connection_mode, transport)
            value = (paths or {}).get(key)
            if value:
                res.values[placeholder] = value
            else:
                res.problems.append(f"{key} path is not set (menu 3, item 8)")

    # Hysteria salamander password: random per inbound, never reused.
    if "HY_PASSWORD" in needed:
        res.values["HY_PASSWORD"] = random_secret(16)

    # REALITY: a new x25519 pair and short ID per inbound; dest and SNI come from the user's choice.
    if any(x.startswith("REALITY_") for x in needed):
        if not reality or not reality.get("dest") or not reality.get("sni"):
            res.problems.append("REALITY target is not chosen")
        else:
            try:
                private_key, public_key = reality_keypair()
                res.values.update({
                    "REALITY_DEST": reality["dest"],
                    "REALITY_SNI": reality["sni"],
                    "REALITY_PRIVATE_KEY": private_key,
                    "REALITY_PUBLIC_KEY": public_key,
                    "REALITY_SHORT_ID": reality_short_id(),
                })
            except RealityError as exc:
                res.problems.append(f"REALITY: {exc}")
    if "FINGERPRINT" in needed:
        res.values["FINGERPRINT"] = fingerprint

    # AmneziaWG keys and header key come from the saved AmneziaWG parameters.
    if any(p.startswith("AWG_") for p in needed):
        if not amnezia:
            res.problems.append("AmneziaWG parameters are not set (menu 3, item 12)")
        else:
            try:
                res.values.update(amnezia_placeholders(amnezia))
            except AmneziaError as exc:
                res.problems.append(f"AmneziaWG parameters: {exc}")

    # Certificates for TLS placeholders
    for placeholder, (kind, part) in CERT_PAIRS.items():
        if placeholder not in needed:
            continue
        domain = domains[kind]
        if not domain:
            res.problems.append(f"{kind} domain is not set; cannot find its certificate")
            continue
        fullchain, privkey = cert_paths(cert_root, domain)
        path = fullchain if part == "fullchain" else privkey
        res.values[placeholder] = path
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            res.problems.append(f"Certificate file not readable: {path}")
            continue
        if part == "fullchain":
            status = status_fn(domain)
            if status.state not in ACCEPTED_CERT_STATES:
                res.problems.append(f"SSL for {domain} is {status.state}: {status.message}")

    unknown = [p for p in needed if p not in res.values and p not in TEMPLATE_PATH_KEYS
               and p not in CERT_PAIRS and p not in ("SUBDOMAIN_CDN", "SUBDOMAIN_DIRECT",
                                                     "WHITELIST_IP", "PORT", "HY_PASSWORD", "FINGERPRINT")
                                                 and not p.startswith(("AWG_", "REALITY_"))
                                                 and p != "SUBDOMAIN_DIRECT2"]
    for name in unknown:
        res.problems.append(f"No source defined for placeholder {name}")
    return res


IP_BLOCKED_PLACEHOLDERS = ("SUBDOMAIN_", "CERT_", "KEY_")


def ip_compatible(template) -> bool:
    """True when the template needs no domain and no certificate (usable with a direct IP)."""
    needed = _needed_placeholders(template)
    return not any(p.startswith(IP_BLOCKED_PLACEHOLDERS) for p in needed)


def validate_payload(payload: dict) -> List[str]:
    """Structural checks on the rendered inbound, run before the panel is called."""
    problems: List[str] = []
    text = json.dumps(payload)
    if "{{" in text:
        problems.append("Unresolved placeholder left in payload")
    port = payload.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        problems.append("Port must be an integer between 1 and 65535")
    elif port in RESERVED_PORTS:
        problems.append(f"Port {port} is reserved")
    if not payload.get("remark"):
        problems.append("Remark (name) is empty")
    if payload.get("protocol") not in ALLOWED_PROTOCOLS:
        problems.append(f"Protocol {payload.get('protocol')!r} is not supported")
    if not isinstance(payload.get("settings"), dict):
        problems.append("settings must be an object")
    if payload.get("protocol") == "vless" and (payload.get("streamSettings") or {}).get("security") == "reality":
        reality_settings = (payload.get("streamSettings") or {}).get("realitySettings") or {}
        for key in ("dest", "privateKey"):
            if not reality_settings.get(key):
                problems.append(f"REALITY {key} is required")
        if not reality_settings.get("serverNames") or not reality_settings.get("shortIds"):
            problems.append("REALITY serverNames and shortIds are required")
        network = (payload.get("streamSettings") or {}).get("network")
        if network == "grpc":
            if not ((payload["streamSettings"].get("grpcSettings") or {}).get("serviceName")):
                problems.append("gRPC serviceName is empty")
        if network == "xhttp":
            if not str(((payload["streamSettings"].get("xhttpSettings") or {}).get("path")) or "").startswith("/"):
                problems.append("xhttp path must start with /")
        return problems
    if payload.get("protocol") in NATIVE_PROTOCOLS:
        settings = payload.get("settings") or {}
        if payload["protocol"] == "tuic":
            for key in ("certificate", "private_key"):
                if not settings.get(key):
                    problems.append(f"TUIC {key} is required")
        else:
            if not isinstance((settings.get("server") or {}).get("privateKey"), str):
                problems.append("AmneziaWG server settings are missing")
        return problems
    stream = payload.get("streamSettings")
    if not isinstance(stream, dict):
        problems.append("streamSettings must be an object")
        return problems
    network = stream.get("network")
    if network in PATH_NETWORKS:
        key = {"ws": "wsSettings", "xhttp": "xhttpSettings", "httpupgrade": "httpupgradeSettings"}[network]
        path = (stream.get(key) or {}).get("path", "")
        if not str(path).startswith("/"):
            problems.append(f"{network} path must start with /")
    if network == "grpc":
        service = (stream.get("grpcSettings") or {}).get("serviceName", "")
        if not service:
            problems.append("gRPC serviceName is empty")
    if stream.get("security") == "tls":
        # Same rule as the panel (validateInboundTLSCertificates): TLS needs a server certificate.
        certs = ((stream.get("tlsSettings") or {}).get("certificates") or [{}])
        first = certs[0] if certs else {}
        if not first.get("certificateFile") or not first.get("keyFile"):
            problems.append("TLS certificate and key paths are required")
    return problems
