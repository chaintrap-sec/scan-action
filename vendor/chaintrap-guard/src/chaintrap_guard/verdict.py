from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from chaintrap_static_scan.models import OsvFinding, PackageKey
from chaintrap_static_scan.pipeline import scan_packages
from chaintrap_static_scan.sqlite_store import ensure_schema, upsert_findings

from chaintrap_guard.config import GuardConfig, TrustedPackage
from chaintrap_guard.models import PackageSpec
from chaintrap_guard.registry import resolve_version


class VerdictAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class PackageVerdict:
    spec: PackageSpec
    action: VerdictAction
    malicious_ids: list[str]
    vulnerable_ids: list[str]
    label: str
    reference_urls: list[str]


@dataclass
class GuardResult:
    verdicts: list[PackageVerdict]
    analyzed_count: int
    blocked: list[PackageVerdict]
    warned: list[PackageVerdict]

    @property
    def should_block(self) -> bool:
        return bool(self.blocked)

    @property
    def exit_code(self) -> int:
        if self.blocked:
            return 1
        return 0


def osv_reference_url(vuln_id: str) -> str:
    from urllib.parse import quote

    return f"https://osv.dev/vulnerability/{quote((vuln_id or '').strip())}"


def _derive_label(mal: list[str], vuln: list[str]) -> str:
    if mal:
        return "Block"
    if vuln:
        return "Vulnerable"
    return "Low Risk"


def _is_trusted(spec: PackageSpec, trusted: list[TrustedPackage]) -> bool:
    for t in trusted:
        if t.ecosystem != spec.ecosystem:
            continue
        if t.name.lower() != spec.name.lower():
            continue
        if t.version in ("*", "", "any"):
            return True
        if t.version == spec.version:
            return True
    return False


def _lookup_sqlite(db_path: Path, host: str, spec: PackageSpec) -> OsvFinding | None:
    if not db_path.is_file():
        return None
    eco = spec.ecosystem.strip().lower()
    try:
        ensure_schema(db_path)
    except OSError:
        return None
    try:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.execute(
                """
                SELECT malicious_ids_json, vulnerable_ids_json, query_error
                FROM osv_package_scan
                WHERE ecosystem = ? AND lower(package_name) = lower(?) AND package_version = ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (eco, spec.name.strip(), spec.version.strip()),
            )
            row = cur.fetchone()
            if not row:
                return None
            return OsvFinding(
                malicious_ids=json.loads(row[0] or "[]"),
                vulnerable_ids=json.loads(row[1] or "[]"),
                query_error=row[2],
            )
    except sqlite3.OperationalError:
        return None


def _action_for_finding(
    mal: list[str],
    vuln: list[str],
    *,
    cfg: GuardConfig,
) -> VerdictAction:
    if mal:
        return VerdictAction.BLOCK
    if vuln and (cfg.paranoid or cfg.strict):
        return VerdictAction.BLOCK
    if vuln:
        return VerdictAction.WARN
    return VerdictAction.ALLOW


def analyze_targets(specs: list[PackageSpec], cfg: GuardConfig) -> GuardResult:
    resolved: list[PackageSpec] = []
    for s in specs:
        if _is_trusted(s, cfg.trusted_packages):
            continue
        ver = resolve_version(
            s.ecosystem,
            s.name,
            s.version,
            enabled=cfg.resolve_latest,
        )
        if not ver:
            continue
        resolved.append(PackageSpec(name=s.name, version=ver, ecosystem=s.ecosystem))

    if not resolved:
        return GuardResult(verdicts=[], analyzed_count=0, blocked=[], warned=[])

    db_path = cfg.osv_db()
    findings: dict[PackageKey, OsvFinding] = {}
    need_live: list[PackageSpec] = []

    for spec in resolved:
        cached = _lookup_sqlite(db_path, cfg.host, spec)
        pk = PackageKey(host=cfg.host, ecosystem=spec.ecosystem, name=spec.name, version=spec.version)
        if cached is not None:
            findings[pk] = cached
        else:
            need_live.append(spec)

    if need_live:
        keys = [
            PackageKey(host=cfg.host, ecosystem=s.ecosystem, name=s.name, version=s.version)
            for s in need_live
        ]
        live = scan_packages(keys)
        findings.update(live)
        try:
            ensure_schema(db_path)
            upsert_findings(db_path, {k: v for k, v in live.items() if v})
        except OSError:
            pass

    verdicts: list[PackageVerdict] = []
    blocked: list[PackageVerdict] = []
    warned: list[PackageVerdict] = []

    for spec in resolved:
        pk = PackageKey(host=cfg.host, ecosystem=spec.ecosystem, name=spec.name, version=spec.version)
        fd = findings.get(pk) or OsvFinding()
        mal = list(fd.malicious_ids or [])
        vuln = list(fd.vulnerable_ids or [])
        action = _action_for_finding(mal, vuln, cfg=cfg)
        refs = [osv_reference_url(i) for i in mal + vuln]
        pv = PackageVerdict(
            spec=spec,
            action=action,
            malicious_ids=mal,
            vulnerable_ids=vuln,
            label=_derive_label(mal, vuln),
            reference_urls=refs,
        )
        verdicts.append(pv)
        if action == VerdictAction.BLOCK:
            blocked.append(pv)
        elif action == VerdictAction.WARN:
            warned.append(pv)

    return GuardResult(
        verdicts=verdicts,
        analyzed_count=len(resolved),
        blocked=blocked,
        warned=warned,
    )


def format_block_message(result: GuardResult) -> str:
    lines: list[str] = []
    if result.blocked:
        lines.append("\u2717 Malicious or blocked package(s)")
        for pv in result.blocked:
            spec = pv.spec
            lines.append(f"\n  - {spec.name}@{spec.version}")
            for vid in pv.malicious_ids + pv.vulnerable_ids:
                lines.append(f"    Reference: {osv_reference_url(vid)}")
    lines.append(
        f"\n\u2717 Chaintrap Guard: {result.analyzed_count} package(s) analyzed, "
        f"{len(result.blocked)} blocked"
    )
    return "\n".join(lines)
