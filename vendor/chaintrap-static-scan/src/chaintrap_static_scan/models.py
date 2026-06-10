from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Ecosystem = Literal["npm", "pypi"]


@dataclass(frozen=True, order=True)
class PackageKey:
    """One resolved package on one host (inventory row granularity)."""

    host: str
    ecosystem: Ecosystem
    name: str
    version: str


@dataclass
class OsvFinding:
    """Classified OSV advisory ids for one package version (same for all hosts sharing that version)."""

    malicious_ids: list[str] = field(default_factory=list)
    vulnerable_ids: list[str] = field(default_factory=list)
    query_error: str | None = None
