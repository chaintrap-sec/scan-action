"""Line-oriented malware pattern scanner for extracted package trees."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from chaintrap_static_scan.npm_malware_rules import (
    NPM_DROPPER_FILENAMES,
    NPM_INSTALL_HOOKS,
    NPM_MALWARE_RULES,
    NPM_OVERSIZE_CATEGORIES,
    NpmMalwareRule,
)
from chaintrap_static_scan.pypi_malware_rules import (
    PYPI_MALWARE_RULES,
    SETUP_PY_INSTALL_HOOK_RULE,
    PyPIMalwareRule,
)

_OVERSIZE_PREFIX_BYTES = 524_288  # 512 KB prefix for large droppers
_ENTROPY_MIN_SIZE = 50_000
_ENTROPY_THRESHOLD = 5.2


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

_BINDING_GYP_SHELL = re.compile(
    r"\b(?:curl|wget|powershell|cmd\.exe|bash|sh)\b|execSync|spawnSync",
    re.IGNORECASE,
)


def _skip_scan_path(rel: str) -> bool:
    norm = rel.replace("\\", "/").lower()
    if norm.endswith(".min.js") or norm.endswith(".min.mjs"):
        return True
    parts = norm.split("/")
    return any(seg in _SKIP_PATH_SEGMENTS for seg in parts)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


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


def _scan_lines(
    text: str,
    rel: str,
    compiled: list[tuple[re.Pattern[str], _RuleProto]],
    *,
    categories: frozenset[str] | None = None,
    is_setup_py: bool = False,
    setup_exec_eval: re.Pattern[str] | None = None,
) -> list[PatternHit]:
    findings: list[PatternHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        matched: list[_RuleProto] = []
        for cre, rule in compiled:
            if categories is not None and rule.category not in categories:
                continue
            if cre.search(line):
                matched.append(rule)
        if is_setup_py and setup_exec_eval and setup_exec_eval.search(line):
            matched = [r for r in matched if r.rule_id not in ("exec_call", "eval_call")]
            matched.append(SETUP_PY_INSTALL_HOOK_RULE)
        for rule in matched:
            _append_hit(findings, rule, rel, i, line)
    return findings


def _scan_npm_package_json(path: Path, rel: str, compiled) -> list[PatternHit]:
    findings: list[PatternHit] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return findings
    if not isinstance(doc, dict):
        return findings
    scripts = doc.get("scripts")
    if isinstance(scripts, dict):
        for hook in NPM_INSTALL_HOOKS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            findings.extend(_scan_lines(f"{hook}: {cmd}", rel, compiled))
    if doc.get("gypfile") is True:
        for hook in NPM_INSTALL_HOOKS:
            cmd = (scripts or {}).get(hook) if isinstance(scripts, dict) else None
            if isinstance(cmd, str) and _BINDING_GYP_SHELL.search(cmd):
                findings.append(
                    PatternHit(
                        rule_id="CTC-TTP010",
                        severity="CRITICAL",
                        category="INSTALL_HOOK",
                        message="package.json gypfile:true with risky install script (Phantom Gyp pattern)",
                        file=rel,
                        line=1,
                        snippet=f"gypfile + {hook}: {cmd[:120]}",
                    )
                )
                break
    return findings


def _scan_binding_gyp(path: Path, rel: str, compiled) -> list[PatternHit]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if not _BINDING_GYP_SHELL.search(text):
        return []
    findings = _scan_lines(text, rel, compiled)
    findings.append(
        PatternHit(
            rule_id="CTC-TTP010",
            severity="CRITICAL",
            category="INSTALL_HOOK",
            message="binding.gyp contains shell/download/exec (Phantom Gyp install hook)",
            file=rel,
            line=1,
            snippet=text.strip()[:240],
        )
    )
    return findings


def _entropy_hit(rel: str, size: int, entropy: float) -> PatternHit:
    return PatternHit(
        rule_id="CTC-OBF020",
        severity="HIGH",
        category="OBFUSCATION",
        message=f"Large JS file with high Shannon entropy ({entropy:.2f}) — likely obfuscated dropper",
        file=rel,
        line=1,
        snippet=f"size={size} entropy={entropy:.2f}",
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
        extra_names = {"binding.gyp"}
        skip_names = {"package.json"}
    elif eco == "pypi":
        rules = PYPI_MALWARE_RULES
        suffixes = {".py", ".pyw", ".toml", ".cfg", ".ini", ".txt", ".sh", ".yaml", ".yml", ".json"}
        extra_names = set()
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

        if eco == "npm" and path.name == "package.json" and not _skip_scan_path(rel_early):
            findings.extend(_scan_npm_package_json(path, rel_early, compiled))

        if eco == "npm" and path.name == "binding.gyp" and not _skip_scan_path(rel_early):
            findings.extend(_scan_binding_gyp(path, rel_early, compiled))

        if path.name in skip_names:
            continue
        if path.name not in extra_names and path.suffix.lower() not in suffixes:
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue

        if size > max_file_bytes:
            if eco == "npm" and path.suffix.lower() in (".js", ".cjs", ".mjs") and not _skip_scan_path(rel_early):
                try:
                    with path.open("rb") as fh:
                        prefix = fh.read(_OVERSIZE_PREFIX_BYTES)
                    prefix_text = prefix.decode("utf-8", errors="ignore")
                    findings.extend(
                        _scan_lines(
                            prefix_text,
                            rel_early,
                            compiled,
                            categories=NPM_OVERSIZE_CATEGORIES,
                        )
                    )
                    if size >= _ENTROPY_MIN_SIZE:
                        ent = _shannon_entropy(prefix)
                        if ent >= _ENTROPY_THRESHOLD:
                            findings.append(_entropy_hit(rel_early, size, ent))
                except OSError:
                    pass
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _skip_scan_path(rel):
            continue
        is_setup_py = eco == "pypi" and (rel == "setup.py" or rel.endswith("/setup.py"))
        findings.extend(
            _scan_lines(
                text,
                rel,
                compiled,
                is_setup_py=is_setup_py,
                setup_exec_eval=setup_exec_eval,
            )
        )
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
