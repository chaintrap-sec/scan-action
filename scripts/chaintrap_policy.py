"""Load optional .chaintrap.yml repo policy overrides."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


@dataclass
class ChaintrapPolicy:
    minimum_release_age_days: int = 7
    block_install_scripts: bool = False
    block_typosquat: bool = False
    block_fresh_releases: bool = False
    fail_on_cve: str = "none"
    fail_on_mal: bool = True
    fail_on_ioc: str = "block"
    ignored_packages: set[str] = field(default_factory=set)
    ignored_rules: set[str] = field(default_factory=set)
    audit_workflows: bool = True
    fail_on_error: bool = False
    content_scan: bool = True
    # Egress policy (wired to CTW-016)
    egress_allow: list[str] = field(default_factory=list)
    egress_block_unlisted: bool = False


def _as_set(raw: Any) -> set[str]:
    if not raw:
        return set()
    if isinstance(raw, list):
        return {str(x).strip().lower() for x in raw if str(x).strip()}
    return set()


def _as_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip().lower() for x in raw if str(x).strip()]
    return []


def load_policy(workspace: Path) -> ChaintrapPolicy:
    path = workspace / ".chaintrap.yml"
    if not path.is_file():
        return ChaintrapPolicy()
    if yaml is None:
        return ChaintrapPolicy()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return ChaintrapPolicy()
    if not isinstance(raw, dict):
        return ChaintrapPolicy()

    gates = raw.get("gates") if isinstance(raw.get("gates"), dict) else {}
    ignore = raw.get("ignore") if isinstance(raw.get("ignore"), dict) else {}
    egress = raw.get("egress") if isinstance(raw.get("egress"), dict) else {}

    return ChaintrapPolicy(
        minimum_release_age_days=int(
            raw.get("minimum_release_age_days", gates.get("minimum_release_age_days", 7))
        ),
        block_install_scripts=bool(
            raw.get("block_install_scripts", gates.get("block_install_scripts", False))
        ),
        block_typosquat=bool(raw.get("block_typosquat", gates.get("block_typosquat", False))),
        block_fresh_releases=bool(
            raw.get("block_fresh_releases", gates.get("block_fresh_releases", False))
        ),
        fail_on_cve=str(raw.get("fail_on_cve", gates.get("fail_on_cve", "none"))),
        fail_on_mal=bool(raw.get("fail_on_mal", gates.get("fail_on_mal", True))),
        fail_on_ioc=str(raw.get("fail_on_ioc", gates.get("fail_on_ioc", "block"))),
        ignored_packages=_as_set(ignore.get("packages")),
        ignored_rules=_as_set(ignore.get("rules")),
        audit_workflows=bool(raw.get("audit_workflows", True)),
        fail_on_error=bool(raw.get("fail_on_error", gates.get("fail_on_error", False))),
        content_scan=bool(raw.get("content_scan", gates.get("content_scan", True))),
        egress_allow=_as_list(egress.get("allow")),
        egress_block_unlisted=bool(egress.get("block_unlisted", False)),
    )
