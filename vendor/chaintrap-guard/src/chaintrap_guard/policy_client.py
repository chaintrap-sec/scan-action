"""Optional backend policy check for install-time guard (contract v1)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def check_backend_policy(
    *,
    api_base: str,
    api_key: str,
    org_id: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    user_id: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any] | None:
    """
    POST supply-chain analyze with org_id to probe policy.
    Returns denial envelope on block when dry_run=False; None if allowed or unreachable.
    """
    url = api_base.rstrip("/") + "/api/v1/supply-chain/analyze"
    body = json.dumps(
        {
            "ecosystem": ecosystem,
            "package_name": package_name,
            "package_version": package_version,
            "org_id": org_id,
            "user_id": user_id,
            "force_refresh": False,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status == 200:
                return None
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", {})
            if not dry_run:
                return detail
    except Exception:
        pass
    return None


def policy_block_from_env() -> bool:
    return os.getenv("CHAINTRAP_POLICY_ENFORCE", "").strip().lower() in ("1", "true", "yes")
