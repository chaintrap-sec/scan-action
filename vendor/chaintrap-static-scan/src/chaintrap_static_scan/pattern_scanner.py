"""Line-oriented malware pattern scanner for extracted package trees."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from chaintrap_static_scan.npm_malware_rules import (
    NPM_DROPPER_FILENAMES,
    NPM_INSTALL_HOOKS,
    NPM_MALWARE_RULES,
    NpmMalwareRule,
)
from chaintrap_static_scan.pypi_malware_rules import (
    PYPI_MALWARE_RULES,
    SETUP_PY_INSTALL_HOOK_RULE,
    PyPIMalwareRule,
)


class _RuleProto(Protocol):
    pattern: str
    rule_id: str
    severity: str
    category: str
    description: str


@dataclass(frozen=True)
class PatternHit:
    rule_id: str
    severity: str
    category: str
    message: str
    file: str
    line: int
    snippet: str


def _compile_rules(rules: tuple[_RuleProto, ...]) -> list[tuple[re.Pattern[str], _RuleProto]]:
    return [(re.compile(rule.pattern, re.IGNORECASE), rule) for rule in rules]


_SKIP_PATH_SEGMENTS = frozenset(
    {"tests", "test", "__tests__", "testing", "spec", "specs", "fixtures", "benchmark"}
)


def _skip_scan_path(rel: str) -> bool:
    """Skip vendor test trees and minified bundles to reduce benign noise."""
    norm = rel.replace("\\", "/").lower()
    if norm.endswith(".min.js") or norm.endswith(".min.mjs"):
        return True
    parts = norm.split("/")
    return any(seg in _SKIP_PATH_SEGMENTS for seg in parts)


def _append_hit(
    findings: list[PatternHit],
    rule: _RuleProto,
    rel: str,
    line_no: int,
    line: str,
) -> None:
    findings.append(
        PatternHit(
            rule_id=rule.rule_id,
            severity=str(rule.severity).upper(),
            category=rule.category,
            message=rule.description,
            file=rel,
            line=line_no,
            snippet=line.strip()[:240],
        )
    )


def _scan_npm_package_json(path: Path, rel: str, compiled) -> list[PatternHit]:
    """Inspect package.json install-hook command strings (Shai-Hulud preinstall dropper)."""
    findings: list[PatternHit] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return findings
    if not isinstance(doc, dict):
        return findings
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return findings
    for hook in NPM_INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        for cre, rule in compiled:
            if cre.search(cmd):
                _append_hit(findings, rule, rel, 1, f"{hook}: {cmd}")
    return findings


def scan_tree(
    extract_root: Path,
    ecosystem: str,
    *,
    max_file_bytes: int = 400_000,
) -> list[PatternHit]:
    eco = ecosystem.strip().lower()
    if eco == "npm":
        rules: tuple[_RuleProto, ...] = NPM_MALWARE_RULES
        suffixes = {".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx"}
        skip_names = {"package.json"}
    elif eco == "pypi":
        rules = PYPI_MALWARE_RULES
        suffixes = {".py", ".pyw", ".toml", ".cfg", ".ini", ".txt", ".sh", ".yaml", ".yml", ".json"}
        skip_names = set()
    else:
        return []

    compiled = _compile_rules(rules)
    setup_exec_eval = re.compile(r"\b(?:exec|eval)\s*\(", re.IGNORECASE)
    root = extract_root.resolve()
    findings: list[PatternHit] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_early = str(path.relative_to(root)).replace("\\", "/")
        # Dropper filename is itself a high-signal IOC, even if oversized/obfuscated.
        if eco == "npm" and path.name in NPM_DROPPER_FILENAMES and not _skip_scan_path(rel_early):
            findings.append(
                PatternHit(
                    rule_id="CTC-TTP002",
                    severity="CRITICAL",
                    category="DROPPER",
                    message=f"Shai-Hulud dropper filename present: {path.name}",
                    file=rel_early,
                    line=1,
                    snippet=path.name,
                )
            )
        # package.json: inspect install-hook command strings rather than skipping.
        if eco == "npm" and path.name == "package.json" and not _skip_scan_path(rel_early):
            findings.extend(_scan_npm_package_json(path, rel_early, compiled))
        if path.name in skip_names:
            continue
        if path.suffix.lower() not in suffixes:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _skip_scan_path(rel):
            continue
        is_setup_py = eco == "pypi" and (rel == "setup.py" or rel.endswith("/setup.py"))
        for i, line in enumerate(text.splitlines(), start=1):
            matched: list[_RuleProto] = []
            for cre, rule in compiled:
                if cre.search(line):
                    matched.append(rule)
            if is_setup_py and setup_exec_eval.search(line):
                matched = [r for r in matched if r.rule_id not in ("exec_call", "eval_call")]
                matched.append(SETUP_PY_INSTALL_HOOK_RULE)
            for rule in matched:
                _append_hit(findings, rule, rel, i, line)
    return findings


def hits_to_dicts(hits: list[PatternHit]) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": h.rule_id,
            "severity": h.severity,
            "category": h.category,
            "message": h.message,
            "file": h.file,
            "line": h.line,
            "snippet": h.snippet,
        }
        for h in hits
    ]
