"""XHTTP test matrix for CDN debugging.

Builds many variants of the CDN xHTTP template (mode x ALPN, plus a few extras) so each one can be put
behind Cloudflare by hand and tested. Variants are ordinary templates in memory only; nothing is written
to inbounds/. Names carry a short code, for example 51-VLESS-XHTTP-XT-PU-H1-TLS.
"""

import copy
import dataclasses
from typing import Any, Dict, List

from templates.loader import Template

BASE_ID = "tls_xhttp_cdn_vless"
FIRST_NUMBER = 50
NAME_PREFIX = "XT"

MODES = (("AU", "auto"), ("PU", "packet-up"), ("SU", "stream-up"), ("SO", "stream-one"))
ALPNS = (("H1", ["http/1.1"]), ("H2", ["h2"]), ("H12", ["h2", "http/1.1"]))


class MatrixError(ValueError):
    """The base template cannot be used for the matrix."""


def _specs() -> List[Dict[str, Any]]:
    specs = []
    for mode_code, mode in MODES:
        for alpn_code, alpn in ALPNS:
            specs.append({"code": f"{mode_code}-{alpn_code}", "mode": mode, "alpn": alpn,
                          "note": f"mode {mode}, ALPN {','.join(alpn)}"})
    for alpn_code, alpn in ALPNS[:2]:
        specs.append({"code": f"PU-{alpn_code}-NS", "mode": "packet-up", "alpn": alpn, "no_sse": True,
                      "note": f"mode packet-up, ALPN {','.join(alpn)}, noSSEHeader on"})
    specs.append({"code": "MIN", "mode": "auto", "alpn": ["h2", "http/1.1"], "minimal": True,
                  "note": "only path, host and mode auto; ALPN h2,http/1.1 (Xray defaults for the rest)"})
    return specs


def build_variants(base: Template) -> List[Template]:
    if base.transport != "xhttp" or base.security != "tls":
        raise MatrixError("The matrix needs a TLS xHTTP template")
    variants: List[Template] = []
    for index, spec in enumerate(_specs()):
        content = copy.deepcopy(base.content)
        stream = content["streamSettings"]
        xhttp = stream["xhttpSettings"]
        if spec.get("minimal"):
            xhttp = {"path": xhttp["path"], "host": xhttp.get("host", ""), "mode": spec["mode"]}
            stream["xhttpSettings"] = xhttp
        else:
            xhttp["mode"] = spec["mode"]
            if spec.get("no_sse"):
                xhttp["noSSEHeader"] = True
        stream["tlsSettings"]["alpn"] = list(spec["alpn"])
        number = FIRST_NUMBER + index
        variants.append(dataclasses.replace(
            base,
            template_id=f"{base.template_id}_t{index + 1:02d}",
            number=number,
            name=f"{number}. XHTTP test {spec['code']}",
            fixed_port=None,
            content=content,
            external_proxies=[],
            deprecated=None,
            extra={"name_label": f"{NAME_PREFIX}-{spec['code']}", "note": spec["note"], "code": spec["code"]},
        ))
    return variants
