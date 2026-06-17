from __future__ import annotations

import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def _debounce_path() -> Path:
    override = (os.environ.get("CHAINTRAP_GUARD_REFRESH_DEBOUNCE_FILE") or "").strip()
    if override:
        return Path(override).expanduser()
    temp = (os.environ.get("TEMP") or os.environ.get("TMP") or "").strip()
    base = Path(temp) if temp else Path.home()
    return base / "chaintrap-guard-watch-refresh.ts"


def notify_watch_refresh(url: str | None = None, debounce_seconds: int = 90) -> None:
    """Best-effort ping to Chaintrap Watch so inventory/OSV refresh after package installs."""
    flag = (os.environ.get("CHAINTRAP_GUARD_NOTIFY_REFRESH") or "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return

    target = (
        url
        or (os.environ.get("CHAINTRAP_WATCH_REFRESH_URL") or "").strip()
        or "http://127.0.0.1:8765/api/dashboard/refresh"
    )
    try:
        debounce_seconds = max(0, int(os.environ.get("CHAINTRAP_GUARD_REFRESH_DEBOUNCE_SEC") or debounce_seconds))
    except ValueError:
        pass

    stamp_path = _debounce_path()
    now = time.time()
    try:
        if stamp_path.is_file() and now - float(stamp_path.read_text(encoding="utf-8").strip()) < debounce_seconds:
            return
    except (OSError, ValueError):
        pass

    try:
        req = urllib.request.Request(target, method="GET")
        with urllib.request.urlopen(req, timeout=5):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        return

    try:
        stamp_path.parent.mkdir(parents=True, exist_ok=True)
        stamp_path.write_text(str(now), encoding="utf-8")
    except OSError:
        pass
