from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[4]


def _default_watch_data_dir() -> Path | None:
    raw = (os.environ.get("CHAINTRAP_WATCH_DATA_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser()
    la = (os.environ.get("LOCALAPPDATA") or "").strip()
    if la:
        return Path(la) / "ChaintrapWatchApp"
    return None


def default_config_dir() -> Path:
    override = (os.environ.get("CHAINTRAP_GUARD_CONFIG_DIR") or "").strip()
    if override:
        return Path(override).expanduser()
    xdg = (os.environ.get("XDG_CONFIG_HOME") or "").strip()
    if xdg:
        return Path(xdg).expanduser() / "chaintrap-guard"
    return Path.home() / ".config" / "chaintrap-guard"


def default_config_path() -> Path:
    explicit = (os.environ.get("CHAINTRAP_GUARD_CONFIG") or "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return default_config_dir() / "config.yml"


def default_osv_db_path() -> Path:
    raw = (os.environ.get("OSV_STATIC_SCAN_DB") or "").strip()
    if raw:
        return Path(raw).expanduser()
    wd = _default_watch_data_dir()
    if wd is not None:
        return wd / "osv_static_scan.sqlite"
    return _REPO_ROOT / "data" / "osv_static_scan.sqlite"


def _bundled_template_text() -> str:
    try:
        return (
            resources.files("chaintrap_guard")
            .joinpath("config.template.yml")
            .read_text(encoding="utf-8")
        )
    except Exception:
        pass
    legacy = _REPO_ROOT / "config" / "chaintrap-guard.template.yml"
    if legacy.is_file():
        return legacy.read_text(encoding="utf-8")
    return "paranoid: false\nstrict: false\ntrusted_packages: []\n"


@dataclass
class TrustedPackage:
    ecosystem: str
    name: str
    version: str = "*"


@dataclass
class GuardConfig:
    paranoid: bool = False
    strict: bool = False
    trusted_packages: list[TrustedPackage] = field(default_factory=list)
    host: str = "local"
    osv_db_path: Path | None = None
    resolve_latest: bool = True
    passthrough_unknown: bool = True
    dry_run: bool = False
    watch_refresh_url: str = ""
    org_id: str = ""
    api_base: str = ""
    api_key: str = ""
    policy_enforce: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> GuardConfig:
        cfg_path = path or default_config_path()
        data: dict[str, Any] = {}
        if cfg_path.is_file():
            with cfg_path.open(encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded

        trusted: list[TrustedPackage] = []
        for item in data.get("trusted_packages") or []:
            if not isinstance(item, dict):
                continue
            trusted.append(
                TrustedPackage(
                    ecosystem=str(item.get("ecosystem") or "npm").strip().lower(),
                    name=str(item.get("name") or "").strip(),
                    version=str(item.get("version") or "*").strip(),
                )
            )

        host = str(data.get("host") or "").strip() or socket.gethostname() or "local"
        db_raw = data.get("osv_db_path")
        db_path = Path(str(db_raw)).expanduser() if db_raw else None

        watch_url = str(data.get("watch_refresh_url") or "").strip()
        if not watch_url:
            watch_url = (os.environ.get("CHAINTRAP_WATCH_REFRESH_URL") or "").strip()

        org_id = str(data.get("org_id") or os.environ.get("CHAINTRAP_ORG_ID") or "").strip()
        api_base = str(data.get("api_base") or os.environ.get("CHAINTRAP_API_BASE") or "").strip()
        api_key = str(data.get("api_key") or os.environ.get("CHAINTRAP_API_KEY") or "").strip()
        policy_enforce = bool(data.get("policy_enforce", False)) or (
            os.environ.get("CHAINTRAP_POLICY_ENFORCE", "").strip().lower() in ("1", "true", "yes")
        )

        return cls(
            paranoid=bool(data.get("paranoid", False)),
            strict=bool(data.get("strict", False)),
            trusted_packages=trusted,
            host=host,
            osv_db_path=db_path,
            resolve_latest=bool(data.get("resolve_latest", True)),
            passthrough_unknown=bool(data.get("passthrough_unknown", True)),
            dry_run=bool(data.get("dry_run", False)),
            watch_refresh_url=watch_url,
            org_id=org_id,
            api_base=api_base,
            api_key=api_key,
            policy_enforce=policy_enforce,
        )

    def osv_db(self) -> Path:
        return self.osv_db_path or default_osv_db_path()

    def write_template(self, dest: Path | None = None) -> Path:
        dest = dest or default_config_path()
        dest.parent.mkdir(parents=True, exist_ok=True)
        text = _bundled_template_text()
        wd = _default_watch_data_dir()
        if wd is not None and "osv_db_path:" not in text:
            osv = (wd / "osv_static_scan.sqlite").as_posix()
            text = text.rstrip() + f"\nosv_db_path: {osv}\n"
        dest.write_text(text, encoding="utf-8")
        return dest
