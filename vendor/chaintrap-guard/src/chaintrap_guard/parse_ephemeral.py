"""Route ephemeral install command argv to the appropriate guard parser."""

from __future__ import annotations

from pathlib import Path

from chaintrap_guard.models import PackageSpec, ParsedCommand
from chaintrap_guard.parse_dlx import parse_bunx, parse_pnpm_dlx, parse_yarn_dlx
from chaintrap_guard.parse_npx import parse_npx
from chaintrap_guard.parse_pip import parse_pip, parse_uv
from chaintrap_guard.parse_pipx import parse_pipx
from chaintrap_guard.parse_uvx import parse_uv_tool_run, parse_uvx


def parse_ephemeral_command(
    manager: str,
    argv: list[str],
    *,
    cwd: Path | None = None,
) -> ParsedCommand:
    m = (manager or "").strip().lower()
    if m in ("npx", "pnpx"):
        return parse_npx(argv, cwd=cwd)
    if m == "pnpm":
        return parse_pnpm_dlx(argv, cwd=cwd)
    if m == "yarn":
        return parse_yarn_dlx(argv, cwd=cwd)
    if m in ("bunx", "bun"):
        return parse_bunx(argv if m == "bunx" else argv[1:] if argv and argv[0] == "x" else argv, cwd=cwd)
    if m in ("pip", "pip3"):
        return parse_pip(argv, cwd=cwd)
    if m == "uv":
        if argv and argv[0].lower() in ("tool", "x"):
            if argv[0].lower() == "x":
                return parse_uvx(argv[1:], cwd=cwd)
            return parse_uv_tool_run(argv, cwd=cwd)
        if argv and argv[0].lower() == "pip":
            return parse_uv(argv, cwd=cwd)
        return parse_uv(argv, cwd=cwd)
    if m == "uvx":
        return parse_uvx(argv, cwd=cwd)
    if m == "pipx":
        return parse_pipx(argv, cwd=cwd)
    return ParsedCommand(manager=m, subcommand="", passthrough=True, raw_argv=argv)


def specs_from_parsed(cmd: ParsedCommand) -> list[PackageSpec]:
    if cmd.passthrough or not cmd.targets:
        return []
    return list(cmd.targets)


def package_spec_string(spec: PackageSpec) -> str:
    ver = (spec.version or "").strip() or "unknown"
    return f"{spec.name}@{ver}"
