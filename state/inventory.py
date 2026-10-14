"""Read-only comparison of local records with the live panel inbound list.

Nothing here changes local files or the panel. Results are a report only.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Inventory:
    matched: List[Dict] = field(default_factory=list)
    missing_on_panel: List[Dict] = field(default_factory=list)
    unknown_on_panel: List[Dict] = field(default_factory=list)
    port_conflicts: List[int] = field(default_factory=list)


def compare(local: Dict[str, List[Dict]], panel_rows: List[Dict]) -> Inventory:
    inv = Inventory()
    panel_by_id = {row.get("id"): row for row in panel_rows}
    known_ids = set()

    for connection_type, records in local.items():
        for record in records:
            rid = record.get("inbound_id")
            known_ids.add(rid)
            row = panel_by_id.get(rid)
            entry = {"type": connection_type, "id": rid, "name": record.get("name"),
                     "port": record.get("port")}
            if row is not None and row.get("remark") == record.get("name"):
                inv.matched.append(entry)
            else:
                inv.missing_on_panel.append(entry)

    for row in panel_rows:
        if row.get("id") not in known_ids:
            inv.unknown_on_panel.append({"id": row.get("id"), "name": row.get("remark"),
                                         "port": row.get("port")})

    ports = Counter(row.get("port") for row in panel_rows if isinstance(row.get("port"), int))
    inv.port_conflicts = sorted(port for port, count in ports.items() if count > 1)
    return inv
