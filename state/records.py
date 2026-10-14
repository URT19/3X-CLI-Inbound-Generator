"""Local records of inbounds created by this tool, kept per connection type.

Files: <state_dir>/direct.json and <state_dir>/cdn.json. They are separate from the
panel and from the templates. Panel data is never copied back here automatically.
"""

import json
import os
import tempfile
from typing import Dict, List

RECORD_TYPES = ("direct", "cdn", "relay")


class RecordError(RuntimeError):
    """A record file cannot be read or written."""


def _path(state_dir: str, connection_type: str) -> str:
    if connection_type not in RECORD_TYPES:
        raise RecordError(f"No records are kept for connection type {connection_type!r}")
    return os.path.join(state_dir, f"{connection_type}.json")


def load_records(state_dir: str, connection_type: str) -> List[Dict]:
    path = _path(state_dir, connection_type)
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RecordError(f"Cannot read {path}; it was not changed") from exc
    if not isinstance(data, list):
        raise RecordError(f"{path} must contain a JSON list; it was not changed")
    return data


def append_record(state_dir: str, connection_type: str, record: Dict) -> None:
    records = load_records(state_dir, connection_type)
    records.append(record)
    os.makedirs(state_dir, exist_ok=True)
    path = _path(state_dir, connection_type)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=f".{connection_type}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
