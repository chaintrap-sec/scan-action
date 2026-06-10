"""Line-oriented malware pattern scanner for extracted package trees."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from chaintrap_static_scan.npm_malware_rules import NPM_MALWARE_RULES, NpmMalwareRule
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
