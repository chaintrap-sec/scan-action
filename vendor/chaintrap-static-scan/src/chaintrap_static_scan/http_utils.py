"""Shared HTTP helpers with retry/backoff for registry and OSV calls."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

_log = logging.getLogger(__name__)

_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF = 0.5
_DEFAULT_TIMEOUT = 20.0
_MAX_READ = 4_000_000


def http_get_json(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    retries: int = _DEFAULT_RETRIES,
    backoff: float = _DEFAULT_BACKOFF,
    headers: dict[str, str] | None = None,
    max_read: int = _MAX_READ,
    method: str = "GET",
    data: bytes | None = None,
) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
    """
    GET/POST JSON with retries. Returns (parsed_json, error_message).
    error_message is set only when all attempts fail.
    """
    hdrs = {
        "Accept": "application/json",
        "User-Agent": "chaintrap-static-scan/0.2",
    }
    if headers:
        hdrs.update(headers)
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")

    last_err = "unknown error"
    for attempt in range(max(1, retries)):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(max_read)
            parsed = json.loads(raw.decode("utf-8"))
            return parsed, None
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code}: {exc.reason}"
            if exc.code in (429, 500, 502, 503, 504) and attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
            return None, last_err
        except (
            urllib.error.URLError,
            json.JSONDecodeError,
            TimeoutError,
            OSError,
        ) as exc:
            last_err = str(exc)
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
    _log.warning("http_get_json failed for %s after %s attempts: %s", url, retries, last_err)
    return None, last_err


def http_get_bytes(
    url: str,
    *,
    timeout: float = 60.0,
    retries: int = _DEFAULT_RETRIES,
    backoff: float = _DEFAULT_BACKOFF,
    max_bytes: int = 10_485_760,
) -> tuple[bytes | None, str | None]:
    """Download raw bytes with size cap and retries."""
    last_err = "unknown error"
    for attempt in range(max(1, retries)):
        req = urllib.request.Request(url, headers={"User-Agent": "chaintrap-static-scan/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                return None, f"response exceeds {max_bytes} bytes"
            return data, None
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code}: {exc.reason}"
            if exc.code in (429, 500, 502, 503, 504) and attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
            return None, last_err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = str(exc)
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
    return None, last_err
