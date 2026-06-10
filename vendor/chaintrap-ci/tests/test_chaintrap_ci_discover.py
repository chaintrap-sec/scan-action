"""Tests for lockfile discovery."""

from __future__ import annotations

from pathlib import Path

from chaintrap_ci.discover import discover_packages


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_discover_package_lock_npm(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "package-lock.json",
        """{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/@scope/pkg": { "version": "2.0.0" }
  }
}""",
    )

    items = discover_packages(tmp_path, {"npm"})
    specs = {item["package_spec"] for item in items}

    assert items[0]["ecosystem"] == "npm"
    assert "lodash@4.17.21" in specs
    assert "@scope/pkg@2.0.0" in specs


def test_discover_uv_lock_pypi(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "uv.lock",
        """version = 1

[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "urllib3"
version = "2.2.2"
""",
    )

    items = discover_packages(tmp_path, {"pypi"})
    specs = {item["package_spec"] for item in items}

    assert all(item["ecosystem"] == "pypi" for item in items)
    assert "requests@2.32.3" in specs
    assert "urllib3@2.2.2" in specs


def test_discover_requirements_txt_pinned_only(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        """requests==2.32.3
django>=4.0
celery[redis]==5.4.0
# comment
""",
    )

    items = discover_packages(tmp_path, {"pypi"})
    specs = {item["package_spec"] for item in items}

    assert specs == {"requests@2.32.3", "celery@5.4.0"}


def test_discover_poetry_lock(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "poetry.lock",
        """[[package]]
name = "click"
version = "8.1.7"
python-versions = ">=3.7"

[[package]]
name = "rich"
version = "13.7.1"
python-versions = ">=3.7.0"
""",
    )

    items = discover_packages(tmp_path, {"pypi"})
    specs = {item["package_spec"] for item in items}

    assert "click@8.1.7" in specs
    assert "rich@13.7.1" in specs


def test_discover_pnpm_lock_packages_section(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pnpm-lock.yaml",
        """lockfileVersion: '9.0'

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc}
  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-def}
  /left-pad/1.3.0:
    resolution: {integrity: sha512-ghi}
""",
    )

    items = discover_packages(tmp_path, {"npm"})
    specs = {item["package_spec"] for item in items}

    assert "lodash@4.17.21" in specs
    assert "@scope/pkg@2.0.0" in specs
    assert "left-pad@1.3.0" in specs


def test_discover_nested_lockfiles_with_paths_dot(tmp_path: Path) -> None:
    _write(tmp_path, "apps/web/package-lock.json", _minimal_package_lock("axios", "1.7.2"))
    _write(tmp_path, "services/api/uv.lock", _minimal_uv_lock("fastapi", "0.115.0"))

    items = discover_packages(tmp_path, {"npm", "pypi"}, paths=".")
    specs = {item["package_spec"] for item in items}

    assert "axios@1.7.2" in specs
    assert "fastapi@0.115.0" in specs


def test_discover_comma_separated_subpaths(tmp_path: Path) -> None:
    _write(tmp_path, "apps/web/package-lock.json", _minimal_package_lock("axios", "1.7.2"))
    _write(tmp_path, "services/api/uv.lock", _minimal_uv_lock("fastapi", "0.115.0"))
    _write(tmp_path, "other/uv.lock", _minimal_uv_lock("ignored", "9.9.9"))

    items = discover_packages(
        tmp_path,
        {"npm", "pypi"},
        paths="apps/web,services/api",
    )
    specs = {item["package_spec"] for item in items}

    assert specs == {"axios@1.7.2", "fastapi@0.115.0"}


def test_discover_dedupes_and_caps_max_items(tmp_path: Path) -> None:
    _write(tmp_path, "a/package-lock.json", _minimal_package_lock("dup", "1.0.0"))
    _write(tmp_path, "b/package-lock.json", _minimal_package_lock("dup", "1.0.0"))

    lines = "\n".join(f"pkg{i}==1.0.{i}" for i in range(90))
    _write(tmp_path, "requirements.txt", lines)

    items = discover_packages(tmp_path, {"npm", "pypi"}, max_items=80)
    specs = [item["package_spec"] for item in items]

    assert len(items) == 80
    assert specs.count("dup@1.0.0") == 1


def test_discover_ecosystem_filter(tmp_path: Path) -> None:
    _write(tmp_path, "package-lock.json", _minimal_package_lock("axios", "1.7.2"))
    _write(tmp_path, "uv.lock", _minimal_uv_lock("fastapi", "0.115.0"))

    npm_only = discover_packages(tmp_path, {"npm"})
    pypi_only = discover_packages(tmp_path, {"pypi"})

    assert {item["package_spec"] for item in npm_only} == {"axios@1.7.2"}
    assert {item["package_spec"] for item in pypi_only} == {"fastapi@0.115.0"}


def _minimal_package_lock(name: str, version: str) -> str:
    return f"""{{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "name": "demo", "version": "1.0.0" }},
    "node_modules/{name}": {{ "version": "{version}" }}
  }}
}}"""


def _minimal_uv_lock(name: str, version: str) -> str:
    return f"""version = 1

[[package]]
name = "{name}"
version = "{version}"
"""
