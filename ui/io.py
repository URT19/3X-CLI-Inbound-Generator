"""Input that does not crash on bytes that are not valid UTF-8 (for example keys typed on a
non-English keyboard layout in some terminals). Invalid bytes become replacement characters, so
the answer is simply not a valid option and the user is asked again."""

import sys


def safe_input(prompt: str = "") -> str:
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    raw = sys.stdin.buffer.readline()
    if not raw:
        raise EOFError
    return raw.decode("utf-8", errors="replace").rstrip("\r\n")
