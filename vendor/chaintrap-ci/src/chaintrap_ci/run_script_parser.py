"""Shared predicates for extracting security-relevant signals from workflow run-blocks."""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Network egress patterns
# ---------------------------------------------------------------------------

_EGRESS_URL_RE = re.compile(
    r"https?://([a-zA-Z0-9_.\-]+(?::\d+)?)",
    re.I,
)
_RAW_IP_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I)
_NETWORK_TOOL_RE = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|scp|rsync|nc|ncat|socat|ssh|sftp)\b",
    re.I,
)

# Domains that are considered safe egress (GitHub infra, registries, CDNs).
_SAFE_EGRESS_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "github.githubassets.com",
        "registry.npmjs.org",
        "npmjs.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry-1.docker.io",
        "docker.io",
        "index.docker.io",
        "gcr.io",
        "ghcr.io",
        "pkg.dev",
        "azure.com",
        "windows.net",
        "amazonaws.com",
        "actions.githubusercontent.com",
        "releases.ubuntu.com",
        "packages.microsoft.com",
        "download.docker.com",
    }
)


def egress_hosts(block: str, extra_allow: frozenset[str] | None = None) -> list[str]:
    """Return non-safe external hostnames found in a run block."""
    allow = _SAFE_EGRESS_DOMAINS | (extra_allow or frozenset())
    hosts = []
    for m in _EGRESS_URL_RE.finditer(block):
        host = m.group(1).lower().split(":")[0]
        if any(host == d or host.endswith("." + d) for d in allow):
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts


def has_external_egress(block: str, extra_allow: frozenset[str] | None = None) -> bool:
    return bool(egress_hosts(block, extra_allow))


def has_raw_ip(block: str) -> bool:
    return bool(_RAW_IP_RE.search(block))


def has_network_tool(block: str) -> bool:
    return bool(_NETWORK_TOOL_RE.search(block))


# ---------------------------------------------------------------------------
# Credential / secret reference patterns
# ---------------------------------------------------------------------------

_SECRET_REF_RE = re.compile(
    r"\$\{\{\s*secrets\.|"
    r"\bGITHUB_TOKEN\b|"
    r"\bACTIONS_RUNTIME_TOKEN\b|"
    r"\bACTIONS_ID_TOKEN_REQUEST_TOKEN\b",
    re.I,
)
_ENV_DUMP_RE = re.compile(
    r"\b(printenv|env\b|export\s+-p|Get-ChildItem\s+Env:|"
    r"Get-ChildItem\s+env:|dir\s+env:)\b",
    re.I,
)
_TOKEN_GREP_RE = re.compile(
    r"\b(grep|rg|ripgrep|Select-String)\b[^\n]*\b(ghp_|gho_|ghu_|ghs_|ghr_|"
    r"GITHUB_TOKEN|token|secret|password|passwd|credential)",
    re.I,
)
_PROC_MEM_RE = re.compile(r"/proc/\d+/(?:environ|mem|maps|cmdline)", re.I)
_CLOUD_CRED_PATH_RE = re.compile(
    r"\.aws/credentials|\.npmrc|\.docker/config\.json|"
    r"\$GITHUB_ENV\b|GITHUB_ENV\b|"
    r"\.netrc|\.pgpass|id_rsa|id_ed25519|"
    r"wallet\.dat|keystore\.json|"
    r"\bCookies\b[^\n]*(?:Chrome|Firefox|Edge|Safari)",
    re.I,
)


def has_secret_ref(block: str) -> bool:
    return bool(_SECRET_REF_RE.search(block))


def has_env_dump(block: str) -> bool:
    return bool(_ENV_DUMP_RE.search(block))


def has_token_grep(block: str) -> bool:
    return bool(_TOKEN_GREP_RE.search(block))


def has_proc_mem_read(block: str) -> bool:
    return bool(_PROC_MEM_RE.search(block))


def has_cloud_cred_path(block: str) -> bool:
    return bool(_CLOUD_CRED_PATH_RE.search(block))


# ---------------------------------------------------------------------------
# File write / staging patterns
# ---------------------------------------------------------------------------

_FILE_WRITE_RE = re.compile(
    r"(?:>>?\s*\S+|"                          # shell redirect
    r"\btee\b[^\n]+|"                         # tee command
    r"cat\s*>+\s*\S+|"                        # cat > file (heredoc target)
    r"echo\s+[^\n]*>+\s*\S+|"               # echo >
    r"Set-Content\b|"                         # PowerShell
    r"Out-File\b|"
    r"\$GITHUB_OUTPUT\b|"                     # Actions output staging
    r"\$GITHUB_STEP_SUMMARY\b|"
    r"actions/upload-artifact)",              # artifact upload step
    re.I,
)
_GITHUB_WORKFLOWS_WRITE_RE = re.compile(
    r"\.github/workflows/|\.git/hooks/",
    re.I,
)
_SENSITIVE_FILE_WRITE_RE = re.compile(
    r"(?:>>?\s*)(?:~|\$HOME)/\.(?:bashrc|zshrc|profile|bash_profile)|"
    r"(?:>>?\s*)/etc/(?:sudoers|hosts|crontab|profile|environment)",
    re.I,
)


def has_file_write(block: str) -> bool:
    return bool(_FILE_WRITE_RE.search(block))


def has_workflow_file_write(block: str) -> bool:
    return bool(_GITHUB_WORKFLOWS_WRITE_RE.search(block))


def has_sensitive_file_write(block: str) -> bool:
    return bool(_SENSITIVE_FILE_WRITE_RE.search(block))


def has_artifact_upload(step_uses: str) -> bool:
    return "upload-artifact" in step_uses.lower()


# ---------------------------------------------------------------------------
# Git / repo mutation patterns
# ---------------------------------------------------------------------------

_GIT_PUSH_RE = re.compile(r"\bgit\b[^\n]*\bpush\b", re.I)
_GIT_COMMIT_RE = re.compile(r"\bgit\b[^\n]*\bcommit\b", re.I)
_GH_PR_CREATE_RE = re.compile(r"\bgh\s+pr\s+(?:create|merge|close)\b", re.I)
_GH_RELEASE_RE = re.compile(r"\bgh\s+release\b", re.I)


def has_git_push(block: str) -> bool:
    return bool(_GIT_PUSH_RE.search(block))


def has_git_commit(block: str) -> bool:
    return bool(_GIT_COMMIT_RE.search(block))


def has_repo_mutation(block: str) -> bool:
    return has_git_push(block) or has_git_commit(block) or bool(_GH_PR_CREATE_RE.search(block))


# ---------------------------------------------------------------------------
# Dynamic / decode-exec patterns
# ---------------------------------------------------------------------------

_DECODE_EXEC_RE = re.compile(
    r"\bbase64\b[^\n|]*-d[^\n|]*\|[^\n]*(?:ba)?sh\b|"    # base64 -d | sh
    r"\bbase64\b[^\n|]*--decode[^\n|]*\|[^\n]*(?:ba)?sh\b|"
    r"\beval\b\s*['\"`]\$\(|"                              # eval "$(..."
    r"\beval\b\s*\$\(|"
    r"\bIEX\b|\bInvoke-Expression\b|"                     # PowerShell
    r"\bnode\s+-e\b|\bpython\s+-c\b|"                     # inline interpreters
    r"\bpython3\s+-c\b|"
    r"\bperl\s+-e\b|"
    r"\bruby\s+-e\b",
    re.I,
)
_SHELL_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|&;]*\|\s*(?:ba)?sh\b",
    re.I,
)


def has_decode_exec(block: str) -> bool:
    return bool(_DECODE_EXEC_RE.search(block))


def has_shell_pipe(block: str) -> bool:
    return bool(_SHELL_PIPE_RE.search(block))


# ---------------------------------------------------------------------------
# Reverse shell patterns
# ---------------------------------------------------------------------------

_REVERSE_SHELL_RE = re.compile(
    r"/dev/tcp/|"
    r"\bnc\b[^\n]*\s-e\s+|"
    r"\bsocat\b[^\n]*EXEC:|"
    r"\bmkfifo\b[^\n]*\|\s*(?:nc|ncat)\b",
    re.I,
)


def has_reverse_shell(block: str) -> bool:
    return bool(_REVERSE_SHELL_RE.search(block))


# ---------------------------------------------------------------------------
# Package manager / runtime hijack
# ---------------------------------------------------------------------------

_PKG_HIJACK_RE = re.compile(
    r"npm\s+config\s+set\s+registry|"
    r"pip\s+config\s+set\s+global\.index-url|"
    r"\bLD_PRELOAD\b|"
    r"sudo\s+(?:npm|pip|gem|composer)\b",
    re.I,
)
_NPMRC_WRITE_RE = re.compile(r"\.npmrc|pip\.conf|\.pypirc", re.I)


def has_pkg_manager_hijack(block: str) -> bool:
    return bool(_PKG_HIJACK_RE.search(block))


# ---------------------------------------------------------------------------
# Expression / script injection patterns (untrusted GHA context into run:)
# ---------------------------------------------------------------------------

_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"issue\.title|issue\.body|"
    r"comment\.body|review\.body|"
    r"pull_request\.title|pull_request\.body|"
    r"pull_request\.head\.ref|"
    r"pages\.\*\.page_name|"
    r"head_commit\.message|"
    r"head_commit\.author\.name|"
    r"head_commit\.committer\.name|"
    r"discussion\.title|discussion\.body|"
    r"label\.name|milestone\.title"
    r")\s*\}\}",
    re.I,
)


def has_expression_injection(block: str) -> bool:
    """Return True if an untrusted github.event.* expression is interpolated directly into shell."""
    return bool(_UNTRUSTED_EXPR_RE.search(block))


# ---------------------------------------------------------------------------
# Artifact poisoning helpers (YAML-level, not run-block)
# ---------------------------------------------------------------------------

def has_artifact_download(text: str) -> bool:
    return bool(re.search(r"actions/download-artifact", text, re.I))


def has_artifact_exec_after_download(blocks: list[tuple[int, str]]) -> bool:
    """Heuristic: if a workflow downloads an artifact and a run-block executes files."""
    exec_re = re.compile(
        r"\b(?:chmod\s*\+x|bash|sh|python|node|make|npm\s+(?:install|ci|run))\b",
        re.I,
    )
    for _, block in blocks:
        if exec_re.search(block):
            return True
    return False


# ---------------------------------------------------------------------------
# Known exfil sink list loader
# ---------------------------------------------------------------------------

_BUILTIN_EXFIL_SINKS: frozenset[str] = frozenset(
    {
        "webhook.site",
        "requestbin.com",
        "requestcatcher.com",
        "canarytokens.com",
        "pipedream.net",
        "ngrok.io",
        "ngrok.app",
        "serveo.net",
        "transfer.sh",
        "0x0.st",
        "pastie.org",
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "controlc.com",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "hooks.slack.com",
        "api.telegram.org",
        "notify.run",
        "ntfy.sh",
        "burpcollaborator.net",
        "interact.sh",
        "oastify.com",
    }
)


def load_exfil_sinks(data_path: Any | None = None) -> frozenset[str]:
    """Load known exfil sinks from data file, falling back to builtins."""
    from pathlib import Path

    if data_path is not None:
        p = Path(data_path)
        if p.is_file():
            lines = {
                ln.strip().lower()
                for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")
            }
            return frozenset(lines) | _BUILTIN_EXFIL_SINKS
    return _BUILTIN_EXFIL_SINKS


def is_exfil_sink(host: str, sinks: frozenset[str]) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in sinks)


# ---------------------------------------------------------------------------
# GITHUB_TOKEN scope recommendation helper
# ---------------------------------------------------------------------------

_WRITE_SCOPES: frozenset[str] = frozenset(
    {"contents", "packages", "deployments", "issues", "pull-requests", "id-token", "pages"}
)


def over_privileged_scopes(perms: dict[str, Any]) -> list[str]:
    return [k for k, v in perms.items() if v == "write" and k in _WRITE_SCOPES]
