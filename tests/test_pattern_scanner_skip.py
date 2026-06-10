"""Tests for content-scan path filtering."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor" / "chaintrap-static-scan" / "src"))

from chaintrap_static_scan.pattern_scanner import scan_tree  # noqa: E402


def test_scan_tree_skips_tests_directory(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    tests = pkg / "tests"
    tests.mkdir(parents=True)
    (pkg / "evil.py").write_text("eval(base64.b64decode('x'))\n", encoding="utf-8")
    (tests / "test_evil.py").write_text("eval(base64.b64decode('x'))\n", encoding="utf-8")

    hits = scan_tree(pkg, "pypi")
    files = {h.file for h in hits}

    assert any("evil.py" in f for f in files)
    assert not any("tests/" in f for f in files)
