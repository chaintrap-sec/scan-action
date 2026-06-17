"""Conservative shell-line splitting for ephemeral install commands."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Iterator

from chaintrap_guard.parse_ephemeral import parse_ephemeral_command, specs_from_parsed

_SKIP_TOKENS = frozenset({"sudo", "env", "time", "command", "exec"})

_NPM_MANAGERS = frozenset({"npx", "pnpx", "pnpm", "yarn", "bunx", "bun"})
_PYPI_MANAGERS = frozenset({"pip", "pip3", "uv", "uvx", "pipx", "python", "python3"})

_CHAIN_SPLITTERS = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


def split_shell_line(line: str) -> list[str]:
    """Split a compound shell line into individual command segments."""
    text = (line or "").strip()
    if not text or text.startswith("#"):
        return []
    parts: list[str] = []
    for segment in _CHAIN_SPLITTERS.split(text):
        seg = segment.strip()
        if seg and not seg.startswith("#"):
            parts.append(seg)
    return parts


def _tokenize(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _strip_leading_noise(tokens: list[str]) -> list[str]:
    out = list(tokens)
    while out and out[0].lower() in _SKIP_TOKENS:
        out = out[1:]
        if out and out[0].startswith("-"):
            out = out[1:]
    return out


def _detect_manager(tokens: list[str]) -> tuple[str, list[str]] | None:
    if not tokens:
        return None
    t0 = tokens[0].lower()
    if t0 in _NPM_MANAGERS or t0 in _PYPI_MANAGERS:
        return t0, tokens[1:]

    if len(tokens) >= 3 and t0 in ("python", "python3") and tokens[1] == "-m":
        mod = tokens[2].lower()
        if mod == "pip":
            return "pip", tokens[3:]
        return None

    if t0 == "uv" and len(tokens) >= 2:
        sub = tokens[1].lower()
        if sub in ("x", "tool", "pip"):
            return "uv", tokens[1:]

    if t0 == "bun" and len(tokens) >= 2 and tokens[1].lower() == "x":
        return "bunx", tokens[2:]

    return None


def _skip_non_registry(tokens: list[str]) -> bool:
  joined = " ".join(tokens).lower()
  if "git+" in joined or "://" in joined:
      return True
  if any(tok in (".", "-e", "--editable") for tok in tokens):
      return True
  if " install ." in f" {' '.join(tokens)} " or joined.strip().endswith(" ."):
      return True
  return False


def extract_specs_from_command(
    command: str,
    *,
    cwd: Path | None = None,
    ecosystems: set[str] | None = None,
) -> list[dict]:
    """Return ephemeral package specs discovered from one command string."""
    wanted = ecosystems or {"npm", "pypi"}
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for segment in split_shell_line(command):
        tokens = _strip_leading_noise(_tokenize(segment))
        detected = _detect_manager(tokens)
        if not detected:
            continue
        manager, argv = detected
        if _skip_non_registry(argv):
            continue

        parsed = parse_ephemeral_command(manager, argv, cwd=cwd)
        for spec in specs_from_parsed(parsed):
            eco = str(spec.ecosystem or "").lower()
            if eco not in wanted:
                continue
            pkg_spec = f"{spec.name}@{spec.version or 'unknown'}"
            key = (eco, pkg_spec.lower())
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "ecosystem": eco,
                    "package_spec": pkg_spec,
                    "name": spec.name,
                    "version": spec.version or "unknown",
                    "unpinned": not (spec.version or "").strip(),
                }
            )
    return results


def iter_command_lines_from_run_block(block: str) -> Iterator[str]:
    for raw in block.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            yield line
