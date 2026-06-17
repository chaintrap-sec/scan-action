"""Sanitize user-derived strings for GitHub Actions logs and PR markdown."""

from __future__ import annotations

import re

_MARKER = "<!-- chaintrap-sca -->"


def sanitize_gha_field(value: str, *, max_len: int = 500) -> str:
    """Strip characters that break GitHub Actions workflow commands."""
    s = str(value or "")
    s = s.replace("\r", " ").replace("\n", " ")
    s = s.replace("%", "%25")
    # Prevent nested workflow command injection.
    s = s.replace("::", ": :")
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def escape_markdown_inline(value: str, *, max_len: int = 500) -> str:
    """Escape text embedded in markdown backticks or table cells."""
    s = str(value or "")
    s = s.replace("\r", " ").replace("\n", " ")
    s = s.replace("`", "'")
    s = s.replace("|", "\\|")
    if _MARKER in s:
        s = s.replace(_MARKER, "(chaintrap-marker)")
    if "</details>" in s.lower():
        s = re.sub(r"</details>", "(details)", s, flags=re.IGNORECASE)
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def escape_markdown_cell(value: str, *, max_len: int = 400) -> str:
    """Plain table cell (no backticks)."""
    return escape_markdown_inline(value, max_len=max_len).replace("\\|", "|").replace("|", "∣")
