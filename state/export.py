"""Export the inbounds on the panel, merged with local records, to JSON and YAML files.

The export has no secrets: no API token, no private key content. Certificate file paths
are included because they are needed to use the inbounds. Each entry says whether the
inbound was created by this tool (managed) or only exists on the panel.
"""

import json
import os
import time
from typing import Dict, List, Optional

from config.version import APP_VERSION

SCHEMA_VERSION = 1
FIELDS = (
    "id", "name", "port", "protocol", "connection_mode", "transport", "security",
    "address", "domain", "path", "template_id", "template_version", "ssl_enabled",
    "cert_fullchain", "cert_privkey", "fingerprint", "created_at", "managed", "panel_enabled",
)


def _match(record: Dict, row: Dict) -> bool:
    return record.get("inbound_id") == row.get("id") and record.get("name") == row.get("remark")


def build_inventory(panel_rows: List[Dict], local: Dict[str, List[Dict]], now: Optional[float] = None) -> Dict:
    records = [(kind, r) for kind, items in local.items() for r in items]
    entries = []
    for row in panel_rows:
        kind, record = next(((k, r) for k, r in records if _match(r, row)), (None, None))
        record = record or {}
        entry = {
            "id": row.get("id"),
            "name": row.get("remark"),
            "port": row.get("port"),
            "protocol": row.get("protocol"),
            "connection_mode": kind,
            "transport": record.get("transport"),
            "security": record.get("security"),
            "address": record.get("address"),
            "domain": record.get("domain"),
            "path": record.get("path"),
            "template_id": record.get("template_id"),
            "template_version": record.get("template_version"),
            "ssl_enabled": (record.get("security") == "tls") if record else None,
            "cert_fullchain": record.get("cert_fullchain"),
            "cert_privkey": record.get("cert_privkey"),
            "fingerprint": record.get("fingerprint"),
            "created_at": record.get("created_at"),
            "managed": bool(record),
            "panel_enabled": row.get("enable"),
        }
        entries.append({field: entry.get(field) for field in FIELDS})
    return {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "count": len(entries),
        "managed_count": sum(1 for e in entries if e["managed"]),
        "inbounds": entries,
    }


def _scalar(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value)
    return json.dumps(str(value), ensure_ascii=False)  # JSON strings are valid YAML double-quoted strings


def _yaml_lines(value, indent: int = 0) -> List[str]:
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            return [pad + "{}"]
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.extend(_yaml_lines(item, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_scalar(item) if not isinstance(item, (dict, list)) else ('{}' if isinstance(item, dict) else '[]')}")
        return lines
    if isinstance(value, list):
        if not value:
            return [pad + "[]"]
        lines = []
        for item in value:
            if isinstance(item, dict) and item:
                inner = _yaml_lines(item, indent + 1)
                lines.append(f"{pad}- " + inner[0].lstrip())
                lines.extend(inner[1:])
            else:
                lines.append(f"{pad}- {_scalar(item)}")
        return lines
    return [pad + _scalar(value)]


def to_yaml(data: Dict) -> str:
    return "\n".join(_yaml_lines(data)) + "\n"


def export_inventory(out_dir: str, data: Dict, stamp: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"inbounds-{stamp}")
    json_path, yaml_path = base + ".json", base + ".yaml"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    with open(yaml_path, "w", encoding="utf-8") as fh:
        fh.write(to_yaml(data))
    return {"json": json_path, "yaml": yaml_path}
