"""SQLite cache must not crash guard when schema is missing."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from chaintrap_guard.config import GuardConfig
from chaintrap_guard.models import PackageSpec
from chaintrap_guard.verdict import analyze_targets


def test_analyze_targets_empty_sqlite_file(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "osv_static_scan.sqlite"
    db.write_bytes(b"")
    monkeypatch.setenv("OSV_STATIC_SCAN_DB", str(db))
    monkeypatch.setenv("CHAINTRAP_WATCH_DATA_DIR", str(tmp_path))
    cfg = GuardConfig.load()
    result = analyze_targets(
        [PackageSpec(name="telnyx", version="4.87.2", ecosystem="pypi")],
        cfg,
    )
    assert result.analyzed_count >= 1
    assert result.should_block
