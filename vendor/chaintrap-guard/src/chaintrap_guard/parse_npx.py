from __future__ import annotations

from pathlib import Path

from chaintrap_guard.models import PackageSpec, ParsedCommand
from chaintrap_guard.parse_npm import _parse_spec

_NPX_FLAGS_WITH_VALUE = frozenset(
    {"-p", "--package", "-c", "--call", "--shell", "--node-arg", "--npm"}
)
_NPX_KNOWN_COMMANDS = frozenset(
    {
        "run",
        "exec",
        "install",
        "ci",
        "init",
        "create",
        "publish",
        "uninstall",
        "link",
        "unlink",
        "cache",
        "config",
        "help",
        "test",
        "start",
        "stop",
        "restart",
        "version",
    }
)


def parse_npx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    """
    npx <pkg>[@version] [cmd...] — treat first package-like token as install target.
    npx --package=foo / -p foo also supported.
    """
    _ = cwd
    args = list(argv)
    if not args:
        return ParsedCommand(manager="npx", subcommand="", passthrough=True, raw_argv=argv)

    targets: list[PackageSpec] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-"):
            if tok in ("-p", "--package") and i + 1 < len(args):
                spec = _parse_spec(args[i + 1])
                if spec:
                    targets.append(spec)
                i += 2
                continue
            if "=" in tok and tok.split("=", 1)[0] in ("-p", "--package"):
                spec = _parse_spec(tok.split("=", 1)[1])
                if spec:
                    targets.append(spec)
                i += 1
                continue
            if tok in _NPX_FLAGS_WITH_VALUE and i + 1 < len(args):
                i += 2
                continue
            i += 1
            continue

        low = tok.lower()
        if low in _NPX_KNOWN_COMMANDS:
            return ParsedCommand(
                manager="npx",
                subcommand=low,
                passthrough=True,
                raw_argv=argv,
            )

        spec = _parse_spec(tok)
        if spec:
            targets.append(spec)
            break
        i += 1

    if not targets:
        return ParsedCommand(manager="npx", subcommand="", passthrough=True, raw_argv=argv)

    return ParsedCommand(
        manager="npx",
        subcommand="exec",
        targets=targets,
        raw_argv=argv,
    )
