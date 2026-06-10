"""Tests for Supabase IOC PostgREST client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from chaintrap_ci.ioc_client import fetch_org_iocs


@patch("chaintrap_ci.ioc_client.urllib.request.urlopen")
def test_fetch_org_iocs_parses_rows(mock_urlopen):
    payload = [
        {
            "ecosystem": "npm",
            "package_name": "evil",
            "package_version": "1.0.0",
            "severity": "CRITICAL",
            "source": "manual",
            "ioc_key": "npm:evil@1.0.0",
        }
    ]
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = resp

    out = fetch_org_iocs("https://proj.supabase.co", "secret-key", "org-acme")
    assert ("npm", "evil", "1.0.0") in out
    assert out[("npm", "evil", "1.0.0")]["source"] == "manual"


def test_fetch_org_iocs_missing_creds_returns_empty():
    assert fetch_org_iocs("", "", "") == {}
