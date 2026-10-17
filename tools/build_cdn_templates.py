"""Build the five CDN inbound templates (TLS only, fixed Cloudflare ports, ALPN http/1.1).

Each CDN template is derived from the matching TLS direct template in inbounds/, so the
transport settings stay identical. Run from the project root:

    python3 tools/build_cdn_templates.py

Only the files listed in CDN_SPECS are written. Older CDN files are removed first.
"""

import copy
import glob
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(ROOT, "inbounds")
CDN_TEMPLATE_VERSION = "1.2.0"
SOURCE_COMMIT = "46439c4"

# template_id, number, label, direct template it is derived from, fixed Cloudflare port
CDN_SPECS = [
    ("tls_ws_cdn_vless", 10, "VLESS WS TLS CDN", "tls_ws_direct", 8443),
    ("tls_httpupgrade_cdn_vless", 11, "VLESS HTTPUpgrade TLS CDN", "tls_vless_httpupgrade_direct", 2053),
    ("tls_xhttp_cdn_vless", 12, "VLESS xHTTP TLS CDN", "tls_xhttp_direct", 2083),
    ("tls_grpc_cdn_vless", 13, "VLESS gRPC TLS CDN", "tls_vless_grpc_direct", 2087),
    ("tls_ws_cdn_vmess", 14, "VMess WS TLS CDN", "tls_vmess_ws_direct", 2096),
    ("tls_xhttp_su_cdn_vless", 15, "VLESS xHTTP stream-up TLS CDN", "tls_xhttp_direct", 44300),
]

# Fixed ports that are not Cloudflare ports: the origin listens there and a Cloudflare origin rule maps to it.
ORIGIN_PORT_TEMPLATES = {"tls_xhttp_su_cdn_vless"}

# Every option of the panel's Cipher Suites picker (frontend schemas/primitives/options.ts, TLS_CIPHER_OPTION).
# The panel stores the selection as one colon-joined string.
ALL_CIPHER_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]

# Per-template changes on top of the common CDN settings.
TLS_OVERRIDES = {
    "tls_httpupgrade_cdn_vless": {"rejectUnknownSni": False},
    "tls_grpc_cdn_vless": {"rejectUnknownSni": False, "alpn": ["h2"]},
    "tls_ws_cdn_vmess": {"rejectUnknownSni": False},
    # xHTTP behind Cloudflare works with ALPN h2 only (hand tests: http/1.1 alone never worked).
    "tls_xhttp_cdn_vless": {"alpn": ["h2"]},
    "tls_xhttp_su_cdn_vless": {"alpn": ["h2"]},
}

# xHTTP behind Cloudflare: packet-up is the most compatible mode through CDNs (Xray-core discussion 4113).
# The server then accepts only packet-up, and share links carry the same mode. More buffered POSTs are kept
# per session so out-of-order POSTs through a CDN do not drop the session.
XHTTP_OVERRIDES = {
    "tls_xhttp_cdn_vless": {"mode": "packet-up", "scMaxBufferedPosts": 100},  # most compatible
    "tls_xhttp_su_cdn_vless": {"mode": "stream-up"},  # faster upload, less compatible, origin port 44300
}

PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
PLACEHOLDER_MAP = {"CERT_DIRECT": "CERT_CDN", "KEY_DIRECT": "KEY_CDN", "SUBDOMAIN_DIRECT": "SUBDOMAIN_CDN"}
ECH_FREE_ALPN = ["http/1.1"]


def _load_deprecation():
    spec = importlib.util.spec_from_file_location("build_templates", os.path.join(HERE, "build_templates.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.deprecation_for


def build_one(template_id, number, label, source_id, fixed_port, deprecation_for):
    with open(os.path.join(OUT_DIR, f"{source_id}.json"), encoding="utf-8") as fh:
        source = json.load(fh)
    text = json.dumps(source["content"], ensure_ascii=False)
    for old, new in PLACEHOLDER_MAP.items():
        text = text.replace("{{" + old + "}}", "{{" + new + "}}")
    content = json.loads(text)
    content["remark"] = f"{number}. {label}"
    content["port"] = "{{PORT}}"
    content["tag"] = "in-{{PORT}}-tcp"
    stream = content["streamSettings"]
    if stream.get("security") != "tls":
        raise ValueError(f"{source_id}: CDN templates must be TLS")
    tls = stream["tlsSettings"]
    tls["alpn"] = list(ECH_FREE_ALPN)  # http/1.1 for compatibility, as requested
    tls["cipherSuites"] = ":".join(ALL_CIPHER_SUITES)  # all suites ticked
    tls.update(copy.deepcopy(TLS_OVERRIDES.get(template_id, {})))
    if template_id in XHTTP_OVERRIDES:
        stream["xhttpSettings"].update(XHTTP_OVERRIDES[template_id])
        stream["xhttpSettings"]["noSSEHeader"] = False  # noSSEHeader broke xHTTP behind Cloudflare in hand tests
    tls.setdefault("settings", {})
    tls["settings"].setdefault("echConfigList", "")  # filled at runtime only when the user asks for ECH
    # Behind Cloudflare the transport Host header is the CDN domain (gRPC has no host field).
    for key in ("wsSettings", "httpupgradeSettings", "xhttpSettings"):
        if key in stream and not stream[key].get("host"):
            stream[key]["host"] = "{{SUBDOMAIN_CDN}}"
    stream.pop("finalmask", None)  # filled at runtime only when the user asks for finalmask
    placeholders = sorted(set(PLACEHOLDER.findall(json.dumps(content))))
    required = sorted(set(placeholders) | {"PORT"})
    protocol = content["protocol"]
    transport = stream["network"]
    network = transport
    template = {
        "template_id": template_id,
        "number": number,
        "client_flow": "",
        "deprecated": deprecation_for(protocol, network),
        "name": f"{number}. {label}",
        "template_version": CDN_TEMPLATE_VERSION,
        "source": {
            "repo": "https://github.com/URT19/3x-ui-generator",
            "commit": SOURCE_COMMIT,
            "derived_from": source_id,
        },
        "connection_mode": "cdn",
        "protocol": protocol,
        "transport": transport,
        "security": "tls",
        "fixed_port": fixed_port,
        "origin_port": template_id in ORIGIN_PORT_TEMPLATES,
        "port": {
            "default": None,
            "reserved": [80, 443],
            "note": "Port is fixed by fixed_port. It is a Cloudflare HTTPS port unless origin_port is true.",
        },
        "required_inputs": required,
        "placeholders": placeholders,
        "naming": {"remark_default": f"{number}. {label}", "tag_pattern": "in-{PORT}-tcp"},
        "validation": {
            "port_range": [1, 65535],
            "reserved_ports": [80, 443],
            "protocol_allowed": ["vless", "vmess"],
        },
        "external_proxies": [],
        "content": content,
    }
    return template


def main() -> int:
    for path in glob.glob(os.path.join(OUT_DIR, "*_cdn*.json")):
        os.remove(path)
    deprecation_for = _load_deprecation()
    for template_id, number, label, source_id, fixed_port in CDN_SPECS:
        doc = build_one(template_id, number, label, source_id, fixed_port, deprecation_for)
        out = os.path.join(OUT_DIR, f"{template_id}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"wrote {os.path.relpath(out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
