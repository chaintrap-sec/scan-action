from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PackageSpec:
    name: str
    version: str = ""
    ecosystem: str = "npm"


@dataclass
class ParsedCommand:
    manager: str
    subcommand: str
    targets: list[PackageSpec] = field(default_factory=list)
    passthrough: bool = False
    manifest_only: bool = False
    raw_argv: list[str] = field(default_factory=list)
