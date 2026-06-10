from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from chaintrap_static_scan.models import OsvFinding, PackageKey

_DB_LOCK = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS osv_package_scan (
  host TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  scanned_at TEXT NOT NULL,
  malicious_ids_json TEXT NOT NULL DEFAULT '[]',
  vulnerable_ids_json TEXT NOT NULL DEFAULT '[]',
  query_error TEXT,
  PRIMARY KEY (host, ecosystem, package_name, package_version)
);
"""


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    try:
        _configure_connection(conn)
        yield conn
    finally:
        conn.close()


def ensure_schema(db_path: Path) -> None:
    with _DB_LOCK:
        with _connect(db_path) as conn:
            conn.executescript(_SCHEMA)
            conn.commit()


def upsert_findings(db_path: Path, findings: dict) -> int:
    """Persist pipeline results. `findings` maps PackageKey -> OsvFinding."""
    if not findings:
        return 0
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rows: list[tuple] = []
    for pk, fd in findings.items():
        rows.append(
            (
                pk.host,
                pk.ecosystem,
                pk.name,
                pk.version,
                now,
                json.dumps(fd.malicious_ids),
                json.dumps(fd.vulnerable_ids),
                fd.query_error,
            )
        )
    with _DB_LOCK:
        with _connect(db_path) as conn:
            conn.executemany(
                """
                INSERT INTO osv_package_scan (
                  host, ecosystem, package_name, package_version, scanned_at,
                  malicious_ids_json, vulnerable_ids_json, query_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host, ecosystem, package_name, package_version) DO UPDATE SET
                  scanned_at = excluded.scanned_at,
                  malicious_ids_json = excluded.malicious_ids_json,
                  vulnerable_ids_json = excluded.vulnerable_ids_json,
                  query_error = excluded.query_error
                """,
                rows,
            )
            conn.commit()
    return len(rows)


def fetch_for_host_ecosystem(db_path: Path, host: str, ecosystem: str) -> dict[tuple[str, str], dict]:
    """
    Return map (package_name_lower, package_version) -> row dict with
    malicious_ids, vulnerable_ids, query_error, scanned_at.
    """
    if not db_path.is_file():
        return {}
    eco = ecosystem.strip().lower()
    with _DB_LOCK:
        with _connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT package_name, package_version, malicious_ids_json, vulnerable_ids_json,
                       query_error, scanned_at
                FROM osv_package_scan
                WHERE host = ? AND ecosystem = ?
                """,
                (host, eco),
            )
            out: dict[tuple[str, str], dict] = {}
            for r in cur.fetchall():
                key = (str(r["package_name"]).lower(), str(r["package_version"]))
                out[key] = {
                    "malicious_ids": json.loads(r["malicious_ids_json"] or "[]"),
                    "vulnerable_ids": json.loads(r["vulnerable_ids_json"] or "[]"),
                    "query_error": r["query_error"],
                    "scanned_at": r["scanned_at"],
                }
            return out


def fetch_rows_for_host_ecosystem(db_path: Path, host: str, ecosystem: str) -> list[dict]:
    """
    All OSV rows for one host + ecosystem (original package_name casing preserved).
    Used when telemetry CSV has no rows for that host but ingest used another hostname.
    """
    if not db_path.is_file():
        return []
    eco = ecosystem.strip().lower()
    with _DB_LOCK:
        with _connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT package_name, package_version, malicious_ids_json, vulnerable_ids_json,
                       query_error, scanned_at
                FROM osv_package_scan
                WHERE host = ? AND ecosystem = ?
                ORDER BY package_name, package_version
                """,
                (host, eco),
            )
            out: list[dict] = []
            for r in cur.fetchall():
                out.append(
                    {
                        "package_name": str(r["package_name"]),
                        "package_version": str(r["package_version"]),
                        "malicious_ids": json.loads(r["malicious_ids_json"] or "[]"),
                        "vulnerable_ids": json.loads(r["vulnerable_ids_json"] or "[]"),
                        "query_error": r["query_error"],
                        "scanned_at": r["scanned_at"],
                    }
                )
            return out


def distinct_hosts_in_db(db_path: Path) -> list[str]:
    """Distinct host values present in osv_package_scan (npm/pypi rows)."""
    if not db_path.is_file():
        return []
    with _DB_LOCK:
        with _connect(db_path) as conn:
            cur = conn.execute(
                """
                SELECT DISTINCT host FROM osv_package_scan
                WHERE ecosystem IN ('npm', 'pypi') AND host != ''
                ORDER BY host
                """
            )
            return [str(row[0]) for row in cur.fetchall() if row[0]]
