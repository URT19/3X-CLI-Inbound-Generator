"""ANSI styling and screen helpers. Colors are off when output is not a terminal
or when the NO_COLOR environment variable is set."""

import os

CLEAR_SCREEN = "\033[2J\033[H"

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


class Style:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def paint(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        prefix = "".join(_CODES[name] for name in names)
        return f"{prefix}{text}{_CODES['reset']}"

    def heading(self, text: str) -> str:
        return self.paint(text, "bold", "cyan")

    def accent(self, text: str) -> str:
        return self.paint(text, "bold", "magenta")

    def ok(self, text: str) -> str:
        return self.paint(text, "green")

    def warn(self, text: str) -> str:
        return self.paint(text, "yellow")

    def error(self, text: str) -> str:
        return self.paint(text, "bold", "red")

    def muted(self, text: str) -> str:
        return self.paint(text, "dim")


def style_for(stream) -> Style:
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    return Style(enabled=is_tty and "NO_COLOR" not in os.environ)
