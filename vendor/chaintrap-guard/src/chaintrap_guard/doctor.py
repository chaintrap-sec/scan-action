from __future__ import annotations

import sys
from pathlib import Path

from chaintrap_guard.config import GuardConfig, default_config_path
from chaintrap_guard.verdict import analyze_targets
from chaintrap_guard.models import PackageSpec


def run_doctor() -> int:
    cfg = GuardConfig.load()
    cfg_path = default_config_path()
    db = cfg.osv_db()

    print("Chaintrap Guard doctor")
    print(f"  config:     {cfg_path} ({'ok' if cfg_path.is_file() else 'missing — run setup install'})")
    print(f"  osv_db:     {db} ({'ok' if db.is_file() else 'missing — will use live OSV only'})")
    print(f"  host:       {cfg.host}")
    print(f"  paranoid:   {cfg.paranoid}")
    print(f"  strict:     {cfg.strict}")
    print(f"  resolve_latest: {cfg.resolve_latest}")

    probes = [
        ("npm", PackageSpec(name="lodash", version="4.17.21", ecosystem="npm"), False),
        ("npm-mal", PackageSpec(name="ts-logger-pack", version="1.1.3", ecosystem="npm"), True),
        ("pypi", PackageSpec(name="requests", version="2.31.0", ecosystem="pypi"), False),
        ("pypi-mal", PackageSpec(name="telnyx", version="4.87.2", ecosystem="pypi"), True),
    ]

    print("\nOSV probes:")
    ok = True
    for label, spec, expect_block in probes:
        result = analyze_targets([spec], cfg)
        blocked = result.should_block
        status = "BLOCK" if blocked else "allow"
        expect = "BLOCK" if expect_block else "allow"
        match = blocked == expect_block
        if not match:
            ok = False
        flag = "ok" if match else "UNEXPECTED"
        ids = []
        if result.verdicts:
            v = result.verdicts[0]
            ids = v.malicious_ids + v.vulnerable_ids
        print(f"  [{flag}] {label}: {spec.name}@{spec.version} -> {status} (expected {expect}) ids={ids[:3]}")

    if ok:
        print("\nDoctor: all probes behaved as expected.")
        return 0
    print("\nDoctor: some probes failed — check network or OSV data.", file=sys.stderr)
    return 1
