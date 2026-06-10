"""GitHub Actions workflow hardening audit (CTW-* rules)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_TAG_OR_BRANCH = re.compile(r"@[^/]+/[^@]+@(?:v\d|main|master|develop|latest|release)")

# Actions known to have been compromised in supply-chain incidents.
# Pinning to the fixed commit SHA is the mitigation; flagging by name regardless
# of ref so reviewers re-verify the pin against the post-incident safe commit.
_KNOWN_COMPROMISED_ACTIONS: dict[str, str] = {
    "tj-actions/changed-files": "CVE-2025-30066 — repo compromised Mar 2025; verify pin is a post-fix SHA",
    "reviewdog/action-setup": "Implicated in the tj-actions compromise (Mar 2025); verify pin",
    "tj-actions/eslint-changed-files": "Same maintainer as the tj-actions compromise; verify pin",
}


def _load_yaml(path: Path) -> Any:
    if yaml is None:
        raise RuntimeError("PyYAML required for workflow audit (pip install pyyaml)")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _line_for_pattern(text: str, pattern: str) -> int:
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern in line:
            return idx
    return 1


def _audit_file(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    rel = path.as_posix()

    if "pull_request_target" in text:
        if re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            findings.append(
                {
                    "rule_id": "CTW-001",
                    "severity": "CRITICAL",
                    "message": "pull_request_target checks out PR head ref (Pwn Request risk)",
                    "file": rel,
                    "line": _line_for_pattern(text, "pull_request_target"),
                }
            )
        elif "pull_request_target" in text:
            findings.append(
                {
                    "rule_id": "CTW-001",
                    "severity": "HIGH",
                    "message": "pull_request_target workflow present — review fork trust boundary",
                    "file": rel,
                    "line": _line_for_pattern(text, "pull_request_target"),
                }
            )

    for match in re.finditer(r"uses:\s*([^\s]+)", text):
        ref = match.group(1).strip()
        if "@" not in ref:
            continue
        _, _, pin = ref.rpartition("@")
        if not _SHA40.match(pin):
            line = text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "CTW-002",
                    "severity": "HIGH",
                    "message": f"Action not pinned to commit SHA: {ref}",
                    "file": rel,
                    "line": line,
                }
            )

    if yaml is not None:
        try:
            doc = _load_yaml(path)
        except Exception:
            doc = None
        if isinstance(doc, dict):
            perms = doc.get("permissions")
            if perms is None:
                findings.append(
                    {
                        "rule_id": "CTW-003",
                        "severity": "MEDIUM",
                        "message": "Workflow missing explicit permissions: block (defaults to write-capable token)",
                        "file": rel,
                        "line": 1,
                    }
                )
            elif isinstance(perms, str) and perms.strip().lower() in ("write-all", "all"):
                findings.append(
                    {
                        "rule_id": "CTW-003",
                        "severity": "HIGH",
                        "message": f"Workflow permissions too broad: {perms}",
                        "file": rel,
                        "line": _line_for_pattern(text, "permissions:"),
                    }
                )
            if isinstance(doc.get("permissions"), dict):
                if doc["permissions"].get("contents") == "write" and "pull_request_target" in text:
                    findings.append(
                        {
                            "rule_id": "CTW-003",
                            "severity": "HIGH",
                            "message": "contents:write with pull_request_target increases fork attack surface",
                            "file": rel,
                            "line": _line_for_pattern(text, "permissions:"),
                        }
                    )
            if doc.get("permissions") == "write-all" or (
                isinstance(doc.get("permissions"), dict)
                and doc["permissions"].get("id-token") == "write"
                and "jobs" not in doc
            ):
                pass
            if isinstance(doc.get("permissions"), dict) and doc["permissions"].get("id-token") == "write":
                if "on:" in text and "workflow_dispatch" not in text:
                    findings.append(
                        {
                            "rule_id": "CTW-004",
                            "severity": "MEDIUM",
                            "message": "id-token: write at workflow level — prefer job-scoped OIDC",
                            "file": rel,
                            "line": _line_for_pattern(text, "id-token"),
                        }
                    )

    for match in re.finditer(r"run:\s*\|?\s*\n([\s\S]*?)(?=\n\s{2}\w|\Z)", text):
        block = match.group(1)
        if re.search(r"\$\{\{\s*secrets\.", block):
            line = text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "CTW-005",
                    "severity": "HIGH",
                    "message": "Secret interpolated into run script (injection risk)",
                    "file": rel,
                    "line": line,
                }
            )

    if "pull_request" in text and re.search(r"actions/cache@v", text):
        if "pull_request_target" not in text:
            findings.append(
                {
                    "rule_id": "CTW-006",
                    "severity": "LOW",
                    "message": "Cache action on PR workflows — verify cache key isolation from forks",
                    "file": rel,
                    "line": _line_for_pattern(text, "actions/cache"),
                }
            )

    # CTW-007: persistence vectors (Shai-Hulud injected discussion.yaml + self-hosted runner)
    if re.search(r"^\s*on:.*\bdiscussion\b", text, re.MULTILINE) or re.search(
        r"^\s*discussion(?:_comment)?\s*:", text, re.MULTILINE
    ):
        findings.append(
            {
                "rule_id": "CTW-007",
                "severity": "HIGH",
                "message": "Workflow triggers on discussion events — uncommon; Shai-Hulud persistence vector",
                "file": rel,
                "line": _line_for_pattern(text, "discussion"),
            }
        )
    if re.search(r"actions-runner/config\.sh|RUNNER_ALLOW_RUNASROOT|--runnergroup\b", text):
        findings.append(
            {
                "rule_id": "CTW-007",
                "severity": "CRITICAL",
                "message": "Workflow registers a self-hosted runner — backdoor persistence pattern",
                "file": rel,
                "line": _line_for_pattern(text, "config.sh"),
            }
        )

    # CTW-008: secret exfiltration via outbound HTTP in a run step (GhostAction)
    for match in re.finditer(r"run:\s*\|?\s*\n([\s\S]*?)(?=\n\s{2}\w|\Z)", text):
        block = match.group(1)
        has_net = re.search(r"\b(curl|wget|Invoke-WebRequest|nc)\b", block)
        has_secret = re.search(
            r"\$\{\{\s*secrets\.|\bGITHUB_TOKEN\b|printenv|\benv\s*\|", block
        )
        has_external = re.search(r"https?://(?!(?:[^\s/]*\.)?github\.com)", block)
        if has_net and has_secret and has_external:
            line = text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "CTW-008",
                    "severity": "CRITICAL",
                    "message": "Run step posts secrets/env to an external host (exfiltration pattern)",
                    "file": rel,
                    "line": line,
                }
            )

    # CTW-009: known-compromised third-party actions
    for match in re.finditer(r"uses:\s*([^\s@]+)@?\S*", text):
        action = match.group(1).strip()
        note = _KNOWN_COMPROMISED_ACTIONS.get(action)
        if note:
            line = text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "CTW-009",
                    "severity": "HIGH",
                    "message": f"Known-compromised action '{action}': {note}",
                    "file": rel,
                    "line": line,
                }
            )

    return findings


def audit_workflows(workspace: Path) -> list[dict[str, Any]]:
    root = workspace.resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    findings: list[dict[str, Any]] = []
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        if path.is_file():
            findings.extend(_audit_file(path))
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        pass
    return findings


def workflow_findings_to_rollup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "workflow_audit": True,
        "finding_count": len(findings),
        "findings": findings,
    }
