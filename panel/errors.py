"""Exception types raised by the panel client."""


class PanelError(Exception):
    """Base class for all panel client errors."""


class PanelUnreachable(PanelError):
    """The panel could not be reached (network, DNS, TLS handshake)."""


class PanelAuthError(PanelError):
    """The token or credentials were rejected, or the token scope is too narrow."""


class PanelNotFound(PanelError):
    """HTTP 404: usually a wrong web base path or a missing resource."""


class PanelResponseError(PanelError):
    """The panel answered, but the response is not a valid success envelope."""
