"""Obfuscation and oversized dropper detection tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "chaintrap-static-scan" / "src"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

from chaintrap_static_scan.pattern_scanner import scan_tree  # noqa: E402


def test_oversized_obfuscated_dropper_detected(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    header = (
        "eval(function(p,a,c,k,e,d){return p.replace(/[a-zA-Z]/g,function(c){"
        "return String.fromCharCode(c.charCodeAt(0)+13)});})('Miasma: The Spreading Blight');\n"
        "var _0xdeadbeef=['trufflehog'];\n"
    )
    pad = "\\x41" * 20
    body = (pad * 25_000) + "\n"
    (pkg / "index.js").write_text(header + body, encoding="utf-8")
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-OBF011" in rules
    assert any(r.startswith("CTC-OBF") for r in rules)


def test_benign_small_file_no_entropy_fp(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "index.js").write_text("module.exports = { ok: true };\n", encoding="utf-8")
    rules = {h.rule_id for h in scan_tree(pkg, "npm")}
    assert "CTC-OBF020" not in rules
