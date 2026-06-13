"""GitHub Actions workflow hardening audit (CTW-* rules)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from chaintrap_ci.run_script_parser import (
    egress_hosts,
    has_artifact_download,
    has_artifact_exec_after_download,
    has_cloud_cred_path,
    has_decode_exec,
    has_env_dump,
    has_expression_injection,
    has_external_egress,
    has_file_write,
    has_git_commit,
    has_git_push,
    has_network_tool,
    has_pkg_manager_hijack,
    has_proc_mem_read,
    has_raw_ip,
    has_repo_mutation,
    has_reverse_shell,
    has_secret_ref,
    has_sensitive_file_write,
    has_shell_pipe,
    has_token_grep,
    has_workflow_file_write,
    is_exfil_sink,
    load_exfil_sinks,
    over_privileged_scopes,
)

_SHA40 = re.compile(r"^[a-f0-9]{40}$")

# ---------------------------------------------------------------------------
# Compromised / high-risk action list — loaded from data/compromised_actions.json
# when available, with inline fallback.
# ---------------------------------------------------------------------------

_INLINE_COMPROMISED_ACTIONS: dict[str, str] = {
    "tj-actions/changed-files": "CVE-2025-30066 — repo compromised Mar 2025; verify pin is a post-fix SHA",
    "reviewdog/action-setup": "Implicated in the tj-actions compromise (Mar 2025); verify pin",
    "tj-actions/eslint-changed-files": "Same maintainer as the tj-actions compromise; verify pin",
}


def _load_compromised_actions(data_dir: Path | None) -> dict[str, str]:
    if data_dir is not None:
        p = data_dir / "compromised_actions.json"
        if p.is_file():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return {str(k): str(v) for k, v in raw.items()}
            except Exception:
                pass
    return dict(_INLINE_COMPROMISED_ACTIONS)


# Mutable tags that should not be used in place of a commit SHA.
_MUTABLE_TAG_RE = re.compile(r"@(?:main|master|v\d+\s*$)", re.I)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _finding(rule_id: str, severity: str, message: str, file: str, line: int) -> dict[str, Any]:
    return {"rule_id": rule_id, "severity": severity, "message": message, "file": file, "line": line}


# ---------------------------------------------------------------------------
# Core audit function
# ---------------------------------------------------------------------------


def audit_workflow_file(path: Path) -> list[dict[str, Any]]:
    """Audit a single workflow YAML file."""
    return _audit_file(path)


def _audit_file(
    path: Path,
    *,
    data_dir: Path | None = None,
    egress_allow: frozenset[str] | None = None,
    egress_block_unlisted: bool = False,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    rel = path.as_posix()
    run_blocks = _iter_run_blocks(text)
    exfil_sinks = load_exfil_sinks(
        (data_dir / "exfil_sinks.txt") if data_dir else None
    )
    compromised_actions = _load_compromised_actions(data_dir)

    # ------------------------------------------------------------------
    # CTW-001: pull_request_target — Pwn Request
    # ------------------------------------------------------------------
    if "pull_request_target" in text:
        if re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            findings.append(
                _finding(
                    "CTW-001", "CRITICAL",
                    "pull_request_target checks out PR head ref (Pwn Request risk)",
                    rel, _line_for_pattern(text, "pull_request_target"),
                )
            )
        else:
            findings.append(
                _finding(
                    "CTW-001", "HIGH",
                    "pull_request_target workflow present — review fork trust boundary",
                    rel, _line_for_pattern(text, "pull_request_target"),
                )
            )

    # ------------------------------------------------------------------
    # CTW-002: unpinned actions + mutable tags
    # ------------------------------------------------------------------
    for match in re.finditer(r"uses:\s*([^\s]+)", text):
        ref = match.group(1).strip()
        if "@" not in ref:
            continue
        _, _, pin = ref.rpartition("@")
        line = text[: match.start()].count("\n") + 1
        if not _SHA40.match(pin):
            if _MUTABLE_TAG_RE.match("@" + pin):
                findings.append(
                    _finding(
                        "CTW-002", "HIGH",
                        f"Action pinned to a mutable tag — use a full commit SHA: {ref}",
                        rel, line,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "CTW-002", "HIGH",
                        f"Action not pinned to commit SHA: {ref}",
                        rel, line,
                    )
                )

    # ------------------------------------------------------------------
    # CTW-003: missing / overly-broad permissions
    # ------------------------------------------------------------------
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
                _finding(
                    "CTW-003", "MEDIUM",
                    "Workflow missing explicit permissions: block (defaults to write-capable token)",
                    rel, 1,
                )
            )
        elif isinstance(perms, str) and perms.strip().lower() in ("write-all", "all"):
            findings.append(
                _finding(
                    "CTW-003", "HIGH",
                    f"Workflow permissions too broad: {perms}",
                    rel, _line_for_pattern(text, "permissions:"),
                )
            )
        if isinstance(perms, dict):
            if perms.get("contents") == "write" and "pull_request_target" in text:
                findings.append(
                    _finding(
                        "CTW-003", "HIGH",
                        "contents:write with pull_request_target increases fork attack surface",
                        rel, _line_for_pattern(text, "permissions:"),
                    )
                )

    # ------------------------------------------------------------------
    # CTW-004: workflow-level id-token: write (prefer job-scoped)
    # ------------------------------------------------------------------
    if isinstance(doc, dict) and isinstance(doc.get("permissions"), dict):
        if doc["permissions"].get("id-token") == "write":
            if "on:" in text and "workflow_dispatch" not in text:
                findings.append(
                    _finding(
                        "CTW-004", "MEDIUM",
                        "id-token: write at workflow level — prefer job-scoped OIDC",
                        rel, _line_for_pattern(text, "id-token"),
                    )
                )

    # ------------------------------------------------------------------
    # CTW-005: secrets interpolated directly into run scripts
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_secret_ref(block):
            findings.append(
                _finding(
                    "CTW-005", "HIGH",
                    "Secret interpolated into run script (injection risk)",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-006: cache action on PR (fork cache poisoning risk)
    # ------------------------------------------------------------------
    if "pull_request" in text and re.search(r"actions/cache@v", text):
        if "pull_request_target" not in text:
            findings.append(
                _finding(
                    "CTW-006", "LOW",
                    "Cache action on PR workflows — verify cache key isolation from forks",
                    rel, _line_for_pattern(text, "actions/cache"),
                )
            )

    # ------------------------------------------------------------------
    # CTW-007: discussion triggers / self-hosted runner registration
    # ------------------------------------------------------------------
    if re.search(r"^\s*on:.*\bdiscussion\b", text, re.MULTILINE) or re.search(
        r"^\s*discussion(?:_comment)?\s*:", text, re.MULTILINE
    ):
        findings.append(
            _finding(
                "CTW-007", "HIGH",
                "Workflow triggers on discussion events, which can execute untrusted user input paths",
                rel, _line_for_pattern(text, "discussion"),
            )
        )
    if re.search(r"actions-runner/config\.sh|RUNNER_ALLOW_RUNASROOT|--runnergroup\b", text):
        findings.append(
            _finding(
                "CTW-007", "CRITICAL",
                "Workflow registers a self-hosted runner — backdoor persistence pattern",
                rel, _line_for_pattern(text, "config.sh"),
            )
        )

    # ------------------------------------------------------------------
    # CTW-008: exfiltration — secrets/env POSTed to external host
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if (
            has_network_tool(block)
            and has_secret_ref(block)
            and has_external_egress(block, egress_allow)
        ):
            findings.append(
                _finding(
                    "CTW-008", "CRITICAL",
                    "Run step posts secrets/env to an external host (exfiltration pattern)",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-009: known-compromised or high-risk actions
    # ------------------------------------------------------------------
    for match in re.finditer(r"uses:\s*([^\s@]+)@?\S*", text):
        action = match.group(1).strip()
        note = compromised_actions.get(action)
        if note:
            line = text[: match.start()].count("\n") + 1
            findings.append(
                _finding(
                    "CTW-009", "HIGH",
                    f"Known-compromised action '{action}': {note}",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-010: shell-pipe or raw-IP download + credentials
    # ------------------------------------------------------------------
    perms = doc.get("permissions") if isinstance(doc, dict) else None
    id_write = isinstance(perms, dict) and perms.get("id-token") == "write"
    actions_read = isinstance(perms, dict) and perms.get("actions") == "read"

    for line, block in run_blocks:
        if has_shell_pipe(block):
            findings.append(
                _finding(
                    "CTW-010", "CRITICAL",
                    "Workflow downloads or decodes remote content and pipes it directly into a shell",
                    rel, line,
                )
            )
        elif has_raw_ip(block) and (has_secret_ref(block) or id_write or actions_read):
            findings.append(
                _finding(
                    "CTW-010", "HIGH",
                    "Workflow sends network traffic to raw IP destinations while handling credentials or elevated token scopes",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-011: OIDC publish abuse
    # ------------------------------------------------------------------
    if isinstance(doc, dict) and isinstance(perms, dict):
        id_write_011 = perms.get("id-token") == "write"
        actions_read_011 = perms.get("actions") == "read"
        has_trigger = bool(
            re.search(r"^\s*on:\s*\[?\s*push", text, re.MULTILINE)
            or re.search(r"workflow_dispatch", text)
        )
        npm_publish = "npm publish" in text or (
            "npm ci" in text and "registry.npmjs.org" in text
        )
        if id_write_011 and (actions_read_011 or npm_publish) and has_trigger:
            findings.append(
                _finding(
                    "CTW-011", "HIGH",
                    "OIDC token (id-token: write) with actions:read or npm publish — supply-chain publish abuse pattern",
                    rel, _line_for_pattern(text, "id-token"),
                )
            )

    # ------------------------------------------------------------------
    # CTW-012: credential / env harvesting + token-pattern scraping
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_env_dump(block):
            findings.append(
                _finding(
                    "CTW-012", "HIGH",
                    "Workflow dumps environment variables — common first step in credential harvesting",
                    rel, line,
                )
            )
        elif has_token_grep(block):
            findings.append(
                _finding(
                    "CTW-012", "HIGH",
                    "Workflow searches for secret or token patterns in the environment or filesystem",
                    rel, line,
                )
            )
        elif has_proc_mem_read(block):
            findings.append(
                _finding(
                    "CTW-012", "CRITICAL",
                    "Workflow reads process memory paths (/proc/*/environ or /proc/*/mem) to scrape live secrets",
                    rel, line,
                )
            )
        elif has_cloud_cred_path(block):
            findings.append(
                _finding(
                    "CTW-012", "HIGH",
                    "Workflow accesses credential or key material files (.aws/credentials, .npmrc, keystores, etc.)",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-013: secrets / harvested data staged to file, artifact, or output
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_file_write(block) and (has_secret_ref(block) or has_env_dump(block)):
            findings.append(
                _finding(
                    "CTW-013", "HIGH",
                    "Workflow writes secrets or environment data to a file, artifact, or step output — staging for exfiltration",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-014: repo self-mutation (git commit + push from CI)
    # ------------------------------------------------------------------
    has_push_perm = isinstance(perms, dict) and perms.get("contents") == "write"
    is_pr_target = "pull_request_target" in text
    for line, block in run_blocks:
        if has_git_push(block):
            sev = "CRITICAL" if (has_push_perm or is_pr_target) else "HIGH"
            findings.append(
                _finding(
                    "CTW-014", sev,
                    "Workflow pushes commits back to the repository — could silently alter source or inject backdoors",
                    rel, line,
                )
            )
        elif has_repo_mutation(block):
            findings.append(
                _finding(
                    "CTW-014", "HIGH",
                    "Workflow modifies repository state (PR create/merge or git commit) from a triggered context",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-015: CI/config file tampering
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_workflow_file_write(block):
            findings.append(
                _finding(
                    "CTW-015", "CRITICAL",
                    "Workflow writes to .github/workflows/ or .git/hooks/ during execution — persistent pipeline backdoor pattern",
                    rel, line,
                )
            )
        elif has_sensitive_file_write(block):
            findings.append(
                _finding(
                    "CTW-015", "HIGH",
                    "Workflow modifies shell startup or system configuration files (/etc/sudoers, /etc/hosts, ~/.bashrc)",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-016: egress to known exfil sinks or unlisted hosts
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if not has_network_tool(block):
            continue
        hosts = egress_hosts(block, egress_allow)
        sinks = [h for h in hosts if is_exfil_sink(h, exfil_sinks)]
        if sinks:
            findings.append(
                _finding(
                    "CTW-016", "CRITICAL",
                    f"Workflow makes outbound connection to known data-exfiltration endpoint: {', '.join(sinks)}",
                    rel, line,
                )
            )
        elif hosts and egress_block_unlisted:
            findings.append(
                _finding(
                    "CTW-016", "HIGH",
                    f"Workflow makes outbound connection to unlisted host not in egress allowlist: {', '.join(hosts[:3])}",
                    rel, line,
                )
            )
        elif has_raw_ip(block):
            findings.append(
                _finding(
                    "CTW-016", "HIGH",
                    "Workflow makes outbound connection to a raw IP address — bypasses DNS-based egress filtering",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-017: reverse / interactive shell
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_reverse_shell(block):
            findings.append(
                _finding(
                    "CTW-017", "CRITICAL",
                    "Workflow contains reverse shell or interactive shell-back pattern (/dev/tcp, nc -e, socat EXEC, mkfifo)",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-018: obfuscated / dynamic command construction
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_decode_exec(block):
            findings.append(
                _finding(
                    "CTW-018", "HIGH",
                    "Workflow constructs or evaluates commands at runtime (base64 decode, eval, IEX, inline interpreter) — payload obfuscation pattern",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-019: package manager / runtime hijack
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_pkg_manager_hijack(block):
            findings.append(
                _finding(
                    "CTW-019", "HIGH",
                    "Workflow overrides package registry, preloads a library (LD_PRELOAD), or installs packages with elevated privileges — supply-chain hijack vector",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-020: dangerous trigger + untrusted code execution
    # ------------------------------------------------------------------
    dangerous_triggers = re.search(
        r"\b(workflow_run|issue_comment|issue|push)\b", text
    )
    if dangerous_triggers:
        for line, block in run_blocks:
            if re.search(r"\$\{\{\s*github\.event\.(comment|issue|head_commit)\.", block):
                findings.append(
                    _finding(
                        "CTW-020", "HIGH",
                        "Workflow triggered by an untrusted event type uses event payload data in a run step — script injection risk",
                        rel, line,
                    )
                )

    # ------------------------------------------------------------------
    # CTW-021: GITHUB_TOKEN over-privilege advisory (informational)
    # ------------------------------------------------------------------
    if isinstance(perms, dict):
        over_broad = over_privileged_scopes(perms)
        if len(over_broad) >= 2:
            findings.append(
                _finding(
                    "CTW-021", "LOW",
                    f"Workflow grants write access to {len(over_broad)} token scopes ({', '.join(over_broad)}) — apply least-privilege permissions",
                    rel, _line_for_pattern(text, "permissions:"),
                )
            )

    # ------------------------------------------------------------------
    # CTW-022: expression / script injection via untrusted github.event.*
    # ------------------------------------------------------------------
    for line, block in run_blocks:
        if has_expression_injection(block):
            sev = "CRITICAL" if is_pr_target else "HIGH"
            findings.append(
                _finding(
                    "CTW-022", sev,
                    "Untrusted github.event.* expression interpolated directly into a run step — use an intermediate env variable to prevent shell injection",
                    rel, line,
                )
            )

    # ------------------------------------------------------------------
    # CTW-023: artifact poisoning (workflow_run + download + execute)
    # ------------------------------------------------------------------
    is_workflow_run_trigger = bool(re.search(r"\bworkflow_run\b", text))
    if is_workflow_run_trigger and has_artifact_download(text):
        if has_artifact_exec_after_download(run_blocks):
            findings.append(
                _finding(
                    "CTW-023", "HIGH",
                    "Privileged workflow_run trigger downloads and executes artifacts from an untrusted workflow — verify artifact integrity before execution",
                    rel, _line_for_pattern(text, "download-artifact"),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def audit_workflows(
    workspace: Path,
    *,
    data_dir: Path | None = None,
    egress_allow: frozenset[str] | None = None,
    egress_block_unlisted: bool = False,
) -> list[dict[str, Any]]:
    root = workspace.resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    findings: list[dict[str, Any]] = []
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        if path.is_file():
            findings.extend(
                _audit_file(
                    path,
                    data_dir=data_dir,
                    egress_allow=egress_allow,
                    egress_block_unlisted=egress_block_unlisted,
                )
            )
    return findings


def audit_bundled_workflows(extract_root: Path, **kwargs: Any) -> list[dict[str, Any]]:
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
        for wf in _audit_file(path, **kwargs):
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
