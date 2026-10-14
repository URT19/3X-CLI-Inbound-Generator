"""Summaries for menu 13. Read-only: built from the panel list and local records."""

from collections import Counter
from typing import Dict, List, Optional

from state.inventory import compare


def summarize(panel_rows: Optional[List[Dict]], local: Dict[str, List[Dict]]) -> Dict:
    report: Dict = {"source": "panel and local records" if panel_rows is not None else "local records only"}
    records = [(kind, r) for kind, items in local.items() for r in items]
    report["local_total"] = len(records)
    report["local_by_connection"] = dict(Counter(kind for kind, _ in records))
    report["local_by_transport"] = dict(Counter(r.get("transport") or "unknown" for _, r in records))
    report["local_by_security"] = dict(Counter(r.get("security") or "unknown" for _, r in records))
    report["local_templates"] = dict(Counter(r.get("template_id") or "unknown" for _, r in records))
    if panel_rows is not None:
        inv = compare(local, panel_rows)
        report["panel_total"] = len(panel_rows)
        report["panel_enabled"] = sum(1 for r in panel_rows if r.get("enable"))
        report["panel_by_protocol"] = dict(Counter(r.get("protocol") or "unknown" for r in panel_rows))
        report["matched"] = len(inv.matched)
        report["missing_on_panel"] = len(inv.missing_on_panel)
        report["unmanaged_on_panel"] = len(inv.unknown_on_panel)
        report["port_conflicts"] = inv.port_conflicts
    return report
