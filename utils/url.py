"""URL helpers shared by the panel client."""

from urllib.parse import urlsplit, urlunsplit

HTTPS_DEFAULT_PORT = 443


def normalize_base_url(raw: str) -> str:
    """Return a full base URL with scheme, without a trailing slash.

    Rules (from the exHEManager API guide):
      - If no scheme is given, use https:// for port 443 and http:// otherwise.
      - Keep an optional web base path (e.g. /mysecret) as-is.
    """
    value = (raw or "").strip()
    if not value:
        raise ValueError("Panel address is empty")

    if "://" not in value:
        host_part = value.split("/", 1)[0]
        port = None
        if host_part.startswith("["):  # IPv6 literal such as [::1]:443
            if "]:" in host_part:
                port = host_part.rsplit("]:", 1)[1]
        elif ":" in host_part:
            port = host_part.rsplit(":", 1)[1]
        scheme = "https" if port == str(HTTPS_DEFAULT_PORT) else "http"
        value = f"{scheme}://{value}"

    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("Panel address has no host")

    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
