"""Load inbound templates from inbounds/ and render them into panel payloads.

Templates are plain JSON files. Adding or editing one never requires a code change.
Rendering is pure: it never talks to the panel.
"""

import copy
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from panel.errors import PanelError
from utils.naming import NamingError, build_name

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")
REQUIRED_KEYS = {
    "template_id", "name", "template_version", "connection_mode",
    "protocol", "security", "required_inputs", "validation", "content",
    "number", "transport",
}
RESERVED_PORTS = {80, 443}


class TemplateError(PanelError):
    """A template file is missing, malformed, or cannot be rendered."""


@dataclass
class Template:
    template_id: str
    number: int
    transport: str
    name: str
    template_version: str
    connection_mode: str
    protocol: str
    security: str
    required_inputs: List[str]
    content: Dict[str, Any]
    external_proxies: List[Dict[str, Any]] = field(default_factory=list)
    deprecated: Optional[Dict[str, Any]] = None
    client_flow: str = ""
    source_file: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


def _validate(doc: Dict[str, Any], path: str) -> Template:
    missing = REQUIRED_KEYS - set(doc)
    if missing:
        raise TemplateError(f"{path}: missing keys {sorted(missing)}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(doc["template_version"])):
        raise TemplateError(f"{path}: template_version must look like 1.0.0")
    if doc["connection_mode"] not in ("direct", "cdn", "relay", "local"):
        raise TemplateError(f"{path}: unknown connection_mode {doc['connection_mode']!r}")
    if os.path.splitext(os.path.basename(path))[0] != doc["template_id"]:
        raise TemplateError(f"{path}: file name must equal template_id")
    if not isinstance(doc["content"], dict):
        raise TemplateError(f"{path}: content must be an object")
    if not isinstance(doc["number"], int) or doc["number"] < 1:
        raise TemplateError(f"{path}: number must be a positive integer")
    return Template(
        template_id=doc["template_id"],
        number=doc["number"],
        transport=doc["transport"],
        name=doc["name"],
        template_version=doc["template_version"],
        connection_mode=doc["connection_mode"],
        protocol=doc["protocol"],
        security=doc["security"],
        required_inputs=list(doc["required_inputs"]),
        content=doc["content"],
        external_proxies=list(doc.get("external_proxies", [])),
        deprecated=doc.get("deprecated"),
        client_flow=doc.get("client_flow", ""),
        source_file=path,
    )


def load_library(directory: str) -> Dict[str, Template]:
    """Return {template_id: Template}. Broken files raise TemplateError."""
    if not os.path.isdir(directory):
        raise TemplateError(f"Template directory not found: {directory}")
    library: Dict[str, Template] = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except json.JSONDecodeError as exc:
            raise TemplateError(f"{path}: invalid JSON ({exc.msg})") from exc
        template = _validate(doc, path)
        if template.template_id in library:
            raise TemplateError(f"Duplicate template_id {template.template_id!r}")
        library[template.template_id] = template
    return library


def _fill(node: Any, values: Dict[str, str]) -> Any:
    if isinstance(node, dict):
        return {k: _fill(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill(v, values) for v in node]
    if isinstance(node, str):
        whole = re.fullmatch(r"\{\{([A-Z_]+)\}\}", node)
        if whole:
            return values[whole.group(1)]
        def sub(match):
            return values[match.group(1)]
        return PLACEHOLDER.sub(sub, node)
    return node


def _check_inputs(template: Template, values: Dict[str, Any]) -> int:
    missing = [k for k in template.required_inputs if k not in values or values[k] in (None, "")]
    if missing:
        raise TemplateError(f"Missing inputs for {template.template_id}: {', '.join(missing)}")
    try:
        port = int(values["PORT"])
    except (TypeError, ValueError) as exc:
        raise TemplateError("PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise TemplateError("PORT must be between 1 and 65535")
    if port in RESERVED_PORTS:
        raise TemplateError(f"PORT {port} is reserved and cannot be used for an inbound")
    return port


def render_hosts(template: Template, values: Dict[str, Any], inbound_id: int) -> List[Dict[str, Any]]:
    """Host payloads for the template's external proxies, bound to an inbound id."""
    _check_inputs(template, values)
    text_values = {k: str(v) for k, v in values.items()}
    text_values["PORT"] = str(int(values["PORT"]))
    hosts = []
    for entry in template.external_proxies:
        host = _fill(copy.deepcopy(entry), text_values)
        host["port"] = int(host["port"])
        host["inboundId"] = inbound_id
        hosts.append(host)
    return hosts


def render(template: Template, values: Dict[str, Any], remark: Optional[str] = None) -> Dict[str, Any]:
    """Build the add/update payload. Raises TemplateError on missing or bad input.

    remark is the final inbound name. When omitted, the default name is built
    without checking the panel, so callers that talk to a panel should pass it.
    """
    missing = [k for k in template.required_inputs if k not in values or values[k] in (None, "")]
    if missing:
        raise TemplateError(f"Missing inputs for {template.template_id}: {', '.join(missing)}")

    port_raw = values["PORT"]
    try:
        port = int(port_raw)
    except (TypeError, ValueError) as exc:
        raise TemplateError("PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise TemplateError("PORT must be between 1 and 65535")
    if port in RESERVED_PORTS:
        raise TemplateError(f"PORT {port} is reserved and cannot be used for an inbound")

    text_values = {k: str(v) for k, v in values.items()}
    text_values["PORT"] = str(port)
    payload = _fill(copy.deepcopy(template.content), text_values)
    payload["port"] = port
    payload.setdefault("enable", True)
    if remark is None:
        try:
            remark = build_name(template, existing=[])
        except NamingError as exc:
            raise TemplateError(str(exc)) from exc
    payload["remark"] = remark
    return payload
