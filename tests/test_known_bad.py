"""Tests for OSV-independent known-bad denylist."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "chaintrap-static-scan" / "src"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

from chaintrap_static_scan.known_bad import clear_known_bad_cache, match  # noqa: E402


def test_known_bad_blocks_miasma_version():
    clear_known_bad_cache()
    hit = match("npm", "@redhat-cloud-services/types", "3.6.1", data_dir=ROOT / "data")
    assert hit is not None
    assert hit["rule_id"] == "CTC-KB001"
    assert "Miasma" in hit.get("campaign", "") or "known-bad" in hit["message"].lower()


def test_known_bad_blocks_nx_compromised():
    clear_known_bad_cache()
    hit = match("npm", "nx", "20.9.0", data_dir=ROOT / "data")
    assert hit is not None


def test_known_bad_allows_clean_version():
    clear_known_bad_cache()
    hit = match("npm", "lodash", "4.17.21", data_dir=ROOT / "data")
    assert hit is None
