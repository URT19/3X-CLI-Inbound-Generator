"""Build inbounds/*.json from the extracted reference templates.

Input : tools/source_templates.json (produced by tools/extract_templates.js
        from templates.js at the commit recorded in SOURCE_COMMIT below).
Output: inbounds/<template_id>.json, one file per template.

The generated files are the default library. Re-run this script only when
the reference source is deliberately updated.
"""

import json
import os
import re
import sys

SOURCE_REPO = "https://github.com/URT19/3x-ui-generator"
SOURCE_COMMIT = "46439c4"
SOURCE_FILE = "templates.js"
TEMPLATE_VERSION = "1.1.0"
ALLOWED_PROTOCOLS = {"vless", "vmess", "trojan", "hysteria", "tuic", "amneziawg"}
NATIVE_PROTOCOLS = {"tuic": "tls", "amneziawg": "none"}  # no streamSettings; transport label and security
EXTRA_TEMPLATES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extra_templates.json")
RESERVED_PORTS = {80, 443}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE_JSON = os.path.join(HERE, "source_templates.json")
OUT_DIR = os.path.join(ROOT, "inbounds")

PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def connection_mode(template_id: str) -> str:
    if template_id.startswith("fb_"):
        return "fallback"
    if "_cdn" in template_id:
        return "cdn"
    if "_direct" in template_id:
        return "direct"
    raise ValueError(f"Cannot infer connection mode for {template_id}")


def tls_mode(security: str) -> str:
    return "tls" if security == "tls" else "plain"


# Xray-core warnings (log of 2026-10-14). Deprecated features still work, but Xray asks for migration.
DEPRECATED_TRANSPORTS = {
    "ws": "XHTTP (H2 and H3); the XHTTP templates use the same connection mode",
    "grpc": "XHTTP stream-up (H2)",
    "httpupgrade": "XHTTP (H2 and H3)",
}
DEPRECATED_PROTOCOLS = {
    "vmess": "VLESS with encryption (ML-KEM); see the VLESS XHTTP templates and the encryption key step",
    "trojan": "VLESS with Flow and Seed; see the VLESS TCP TLS Vision template",
}


def deprecation_for(protocol, network):
    if network in DEPRECATED_TRANSPORTS:
        return {"reason": f"{network} transport is deprecated in Xray-core", "replace": DEPRECATED_TRANSPORTS[network]}
    if protocol in DEPRECATED_PROTOCOLS:
        return {"reason": f"{protocol} is deprecated in Xray-core", "replace": DEPRECATED_PROTOCOLS[protocol]}
    return None


def convert(entry: dict) -> dict:
    tid = entry["id"]
    content = json.loads(json.dumps(entry["content"]))  # deep copy

    # Remove fields the panel assigns. The source "id" conflicts across templates.
    source_id = content.pop("id", None)
    for key in ("up", "down", "total", "lastTrafficResetTime", "clientStats", "userId"):
        content.pop(key, None)

    # TCP header obfuscation uses a request path of its own, not the WebSocket one.
    if content.get("streamSettings", {}).get("network") == "tcp":
        text = json.dumps(content).replace("{{PATH_WS}}", "{{PATH_TCP}}")
        content = json.loads(text)

    # Port is never fixed in the library: it must be supplied per inbound.
    source_port = content.get("port")
    content.setdefault("enable", True)  # new inbounds start enabled
    content["port"] = "{{PORT}}"
    udp = (content.get("streamSettings", {}).get("network") == "hysteria"
           or content.get("protocol") in ("tuic", "amneziawg"))
    content["tag"] = "in-{{PORT}}-udp" if udp else "in-{{PORT}}-tcp"

    protocol = content["protocol"]
    if protocol not in ALLOWED_PROTOCOLS:
        raise ValueError(f"{tid}: unexpected protocol {protocol!r}")

    stream = content.get("streamSettings", {})
    native_security = NATIVE_PROTOCOLS.get(content.get("protocol"))

    # Legacy streamSettings.externalProxy is not converted to hosts on API add.
    # Move it out of the inbound and keep it as host entries (mapping taken from
    # externalProxyEntryToHost in db.go at v3.9.0 and v3.10.0).
    external_proxies = []
    for index, ep in enumerate(stream.pop("externalProxy", []) or []):
        forced = ep.get("forceTls", "same")
        remark = (ep.get("remark") or "").strip() or f"imported {index + 1}"
        external_proxies.append({
            "remark": remark[:256],
            "address": ep.get("dest", ""),
            "port": ep.get("port", 0),
            "security": forced if forced in ("same", "tls", "none") else "same",
            "sni": ep.get("sni", ""),
            "alpn": [a for a in ep.get("alpn", []) if a],
            "sortOrder": index,
        })

    placeholders = sorted(set(PLACEHOLDER.findall(json.dumps(content) + json.dumps(external_proxies))))
    required = sorted(set(placeholders) | {"PORT"})  # PORT is always required

    number_match = re.match(r"\s*(\d+)\.", entry["name"])
    if not number_match:
        raise ValueError(f"{tid}: name must start with a number")

    return {
        "template_id": tid,
        "number": int(number_match.group(1)),
        "client_flow": entry.get("client_flow", ""),
        "deprecated": deprecation_for(content.get("protocol"), content.get("streamSettings", {}).get("network")),
        "name": entry["name"],
        "template_version": TEMPLATE_VERSION,
        "source": {
            "repo": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "file": SOURCE_FILE,
            "source_content_id": source_id,
            "source_port": source_port,
        },
        "connection_mode": connection_mode(tid),
        "protocol": protocol,
        "transport": stream.get("network") or (content.get("protocol") if native_security else None),
        "security": native_security if native_security else (
            "reality" if stream.get("security") == "reality" else tls_mode(stream.get("security", "none"))),
        "port": {
            "default": None,
            "reserved": sorted(RESERVED_PORTS),
            "note": "Port must be supplied when creating the inbound. The source default is not used.",
        },
        "required_inputs": required,
        "placeholders": placeholders,
        "naming": {
            "remark_default": content.get("remark"),
            "tag_pattern": "in-{PORT}-tcp",
        },
        "validation": {
            "port_range": [1, 65535],
            "reserved_ports": sorted(RESERVED_PORTS),
            "protocol_allowed": sorted(ALLOWED_PROTOCOLS),
        },
        "external_proxies": external_proxies,
        "content": content,
    }


def main() -> int:
    with open(SOURCE_JSON, encoding="utf-8") as fh:
        entries = json.load(fh)
    if os.path.exists(EXTRA_TEMPLATES):
        with open(EXTRA_TEMPLATES, encoding="utf-8") as fh:
            entries = entries + json.load(fh)

    seen = set()
    os.makedirs(OUT_DIR, exist_ok=True)
    for entry in entries:
        tid = entry["id"]
        if "_cdn" in tid:
            continue  # CDN templates are written by tools/build_cdn_templates.py
        if tid in seen:
            print(f"Duplicate template id: {tid}", file=sys.stderr)
            return 1
        seen.add(tid)
        doc = convert(entry)
        path = os.path.join(OUT_DIR, f"{tid}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"wrote {os.path.relpath(path, ROOT)}")
    print(f"{len(seen)} templates written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
