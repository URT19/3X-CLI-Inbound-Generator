"""Protocol support catalog (config/protocols.json). Data only, updated when the panel changes."""

import json
import os
from typing import List

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protocols.json")
with open(_PATH, encoding="utf-8") as _fh:
    _DATA = json.load(_fh)
PROTOCOL_TAG = _DATA["panel_source_tag"]


def load_protocol_catalog() -> List[dict]:
    return list(_DATA["protocols"])
