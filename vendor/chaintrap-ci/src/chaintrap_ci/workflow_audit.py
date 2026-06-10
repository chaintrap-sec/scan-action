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


def _iter_run_blocks(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for match in re.finditer(r"run:\s*\|?\s*\n([\s\S]*?)(?=\n\s{2}\w|\Z)", text):
        line = text[: match.start()].count("\n") + 1
        out.append((line, match.group(1)))
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.search(r"run:\s*([^\n#]+)$", line)
        if not m:
            continue
        cmd = m.group(1).strip()
        if cmd and cmd != "|" and not cmd.startswith("${{"):
            out.append((i, cmd))
    return out


def audit_workflow_file(path: Path) -> list[dict[str, Any]]:
    """Audit a single workflow YAML file."""
    return _audit_file(path)


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

    doc: dict[str, Any] | None = None
    if yaml is not None:
        try:
            loaded = _load_yaml(path)
            doc = loaded if isinstance(loaded, dict) else None
        except Exception:
            doc = None
        if doc is not None:
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

    for line, block in _iter_run_blocks(text):
        if re.search(r"\$\{\{\s*secrets\.", block):
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

    if re.search(r"^\s*on:.*\bdiscussion\b", text, re.MULTILINE) or re.search(
        r"^\s*discussion(?:_comment)?\s*:", text, re.MULTILINE
    ):
        findings.append(
            {
                "rule_id": "CTW-007",
                "severity": "HIGH",
                    "message": "Workflow triggers on discussion events, which can execute untrusted user input paths",
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

    for line, block in _iter_run_blocks(text):
        has_net = re.search(r"\b(curl|wget|Invoke-WebRequest|nc)\b", block)
        has_secret = re.search(
            r"\$\{\{\s*secrets\.|\bGITHUB_TOKEN\b|printenv|\benv\s*\|", block
        )
        has_external = re.search(r"https?://(?!(?:[^\s/]*\.)?github\.com)", block)
        if has_net and has_secret and has_external:
            findings.append(
                {
                    "rule_id": "CTW-008",
                    "severity": "CRITICAL",
                    "message": "Run step posts secrets/env to an external host (exfiltration pattern)",
                    "file": rel,
                    "line": line,
                }
            )

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

    # CTW-010: behavioral remote payload execution patterns in workflows
    perms = doc.get("permissions") if isinstance(doc, dict) else None
    id_write = isinstance(perms, dict) and perms.get("id-token") == "write"
    actions_read = isinstance(perms, dict) and perms.get("actions") == "read"
    for line, block in _iter_run_blocks(text):
        has_shell_pipe = bool(
            re.search(r"\b(?:curl|wget)\b[^\n|&;]*\|\s*(?:ba)?sh\b", block, re.I)
            or (
                re.search(r"base64\s+-d", block, re.I)
                and re.search(r"\|\s*(?:ba)?sh\b", block, re.I)
            )
        )
        has_raw_ip_target = bool(re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", block))
        has_secrets = bool(re.search(r"\$\{\{\s*secrets\.|\bGITHUB_TOKEN\b|printenv|\benv\s*\|", block))
        if has_shell_pipe:
            findings.append(
                {
                    "rule_id": "CTW-010",
                    "severity": "CRITICAL",
                    "message": "Workflow downloads or decodes remote content and pipes it directly into a shell",
                    "file": rel,
                    "line": line,
                }
            )
        elif has_raw_ip_target and (has_secrets or id_write or actions_read):
            findings.append(
                {
                    "rule_id": "CTW-010",
                    "severity": "HIGH",
                    "message": "Workflow sends network traffic to raw IP destinations while handling credentials or elevated token scopes",
                    "file": rel,
                    "line": line,
                }
            )

    # CTW-011: OIDC publish abuse (Megalodon + Miasma SLSA publish)
    if doc is not None:
        perms = doc.get("permissions")
        if isinstance(perms, dict):
            id_write = perms.get("id-token") == "write"
            actions_read = perms.get("actions") == "read"
            has_trigger = bool(
                re.search(r"^\s*on:\s*\[?\s*push", text, re.MULTILINE)
                or re.search(r"workflow_dispatch", text)
            )
            npm_publish = "npm publish" in text or "npm ci" in text and "registry.npmjs.org" in text
            if id_write and (actions_read or npm_publish) and has_trigger:
                findings.append(
                    {
                        "rule_id": "CTW-011",
                        "severity": "HIGH",
                        "message": "OIDC token (id-token: write) with actions:read or npm publish — supply-chain publish abuse pattern",
                        "file": rel,
                        "line": _line_for_pattern(text, "id-token"),
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
    return findings


def audit_bundled_workflows(extract_root: Path) -> list[dict[str, Any]]:
    """
    Find and audit workflow files shipped inside a dependency tarball.
    Maps CTW-* rule ids to CTC-WF-* for content-scan findings.
    """
    root = extract_root.resolve()
    findings: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/").lower()
        if "/.github/workflows/" not in f"/{rel}/" and not rel.startswith(".github/workflows/"):
            continue
        if path.suffix.lower() not in (".yml", ".yaml"):
            continue
        for wf in _audit_file(path):
            mapped = dict(wf)
            rid = str(wf.get("rule_id") or "CTW-000")
            mapped["rule_id"] = rid.replace("CTW-", "CTC-WF-", 1)
            mapped["category"] = "BUNDLED_WORKFLOW"
            mapped["message"] = f"Bundled workflow: {wf.get('message', '')}"
            findings.append(mapped)
    return findings


def workflow_findings_to_rollup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "workflow_audit": True,
        "finding_count": len(findings),
        "findings": findings,
    }


def workflow_findings_to_content_hits(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert workflow audit findings to content-scan hit dicts."""
    out: list[dict[str, Any]] = []
    for f in findings:
        out.append(
            {
                "rule_id": str(f.get("rule_id") or "CTC-WF-000"),
                "severity": str(f.get("severity") or "HIGH").upper(),
                "category": str(f.get("category") or "BUNDLED_WORKFLOW"),
                "message": str(f.get("message") or ""),
                "file": str(f.get("file") or ""),
                "line": int(f.get("line") or 1),
                "snippet": str(f.get("message") or "")[:240],
            }
        )
    return out
