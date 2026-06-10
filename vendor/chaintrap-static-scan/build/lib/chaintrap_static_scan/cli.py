from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from chaintrap_static_scan.models import PackageKey
from chaintrap_static_scan.pipeline import scan_packages

_log = logging.getLogger(__name__)


def _load_source_files(path: Path) -> list[tuple[str, dict[str, Any]]]:
    raw_text = path.read_text(encoding="utf-8-sig")
    root = json.loads(raw_text)
    if isinstance(root, list):
        return [(path.name, item) for item in root if isinstance(item, dict)]
    if isinstance(root, dict) and "source_files" in root:
        out: list[tuple[str, dict[str, Any]]] = []
        for sf in root.get("source_files") or []:
            if not isinstance(sf, dict):
                continue
            fn = str(sf.get("file_name") or sf.get("fileName") or path.name)
            pl = sf.get("payload")
            if isinstance(pl, dict):
                out.append((fn, pl))
        return out or [(path.name, root)]
    if isinstance(root, dict):
        return [(path.name, root)]
    return []


def _run(args: argparse.Namespace) -> int:
    from chaintrap_static_scan.normalize import normalize_source_payloads

    input_path = Path(args.input)
    sqlite_path = Path(args.sqlite)

    pairs = _load_source_files(input_path)
    normalized = normalize_source_payloads(pairs)
    keys: list[PackageKey] = []
    for n in normalized:
        if n.artifact_type not in ("npm", "pypi"):
            continue
        keys.append(
            PackageKey(
                host=n.host_name,
                ecosystem=n.artifact_type,  # type: ignore[arg-type]
                name=n.name,
                version=n.version,
            )
        )
    dedup: dict[tuple[str, str, str, str], PackageKey] = {}
    for k in keys:
        dedup[(k.host, k.ecosystem, k.name.lower(), k.version)] = k
    keys = list(dedup.values())
    total_after_dedupe = len(keys)
    if getattr(args, "max_packages", None) is not None and int(args.max_packages) > 0:
        keys = keys[: int(args.max_packages)]
        _log.info("Scanning %s of %s unique npm/pypi rows (--max-packages)", len(keys), total_after_dedupe)

    if not keys:
        _log.warning("No npm/pypi packages found in input.")
        findings: dict[PackageKey, Any] = {}
    else:
        findings = scan_packages(keys)

    from chaintrap_static_scan.sqlite_store import ensure_schema, upsert_findings

    ensure_schema(sqlite_path)
    n_upsert = upsert_findings(sqlite_path, findings)
    print(
        json.dumps(
            {
                "upserted": n_upsert,
                "packages_scanned": len(keys),
                "unique_packages_before_cap": total_after_dedupe,
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="chaintrap-static-scan")
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="Normalize JSON, query OSV, write SQLite")
    run.add_argument("--input", required=True, help="JSON file (agent-style payload or source_files wrapper)")
    run.add_argument("--sqlite", required=True, help="Path to osv_static_scan.sqlite")
    run.add_argument(
        "--max-packages",
        type=int,
        default=None,
        metavar="N",
        help="Scan at most N unique npm/pypi rows (after dedupe); for large telemetry files",
    )
    run.set_defaults(func=_run)
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
