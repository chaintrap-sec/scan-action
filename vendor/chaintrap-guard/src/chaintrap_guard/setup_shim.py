from __future__ import annotations

import os
import platform
import stat
import sys
from pathlib import Path

from chaintrap_guard.config import default_config_dir, default_config_path

_MARKER_BEGIN = "# >>> chaintrap-guard >>>"
_MARKER_END = "# <<< chaintrap-guard <<<"

_MANAGERS = ("npm", "npx", "pip", "pip3", "uv", "pnpm", "yarn", "bun", "pnpx")


def _shell_rc_candidates() -> list[Path]:
    home = Path.home()
    shell = (os.environ.get("SHELL") or "").lower()
    out: list[Path] = []
    if "zsh" in shell:
        out.append(home / ".zshrc")
    elif "fish" in shell:
        out.append(home / ".config" / "fish" / "config.fish")
    else:
        out.append(home / ".bashrc")
        out.append(home / ".bash_profile")
    for p in (home / ".zshrc", home / ".bashrc", home / ".profile"):
        if p not in out:
            out.append(p)
    return out


def _alias_block() -> str:
    lines = [_MARKER_BEGIN, "# Chaintrap Guard — transparent package manager wrappers"]
    for mgr in _MANAGERS:
        lines.append(f"alias {mgr}='chaintrap-guard {mgr}'")
    lines.append(_MARKER_END)
    return "\n".join(lines) + "\n"


def _fish_block() -> str:
    lines = [_MARKER_BEGIN, "# Chaintrap Guard"]
    for mgr in _MANAGERS:
        lines.append(f"alias {mgr} 'chaintrap-guard {mgr}'")
    lines.append(_MARKER_END)
    return "\n".join(lines) + "\n"


def _shim_dir() -> Path:
    return default_config_dir() / "shims"


def _windows_shim_line(mgr: str) -> str:
    py = sys.executable
    return f'@echo off\r\n"{py}" -m chaintrap_guard {mgr} %*\r\n'


def _write_shims() -> Path:
    bindir = _shim_dir()
    bindir.mkdir(parents=True, exist_ok=True)
    for mgr in _MANAGERS:
        path = bindir / mgr
        if platform.system() == "Windows":
            path = bindir / f"{mgr}.cmd"
            content = _windows_shim_line(mgr)
        else:
            content = f"#!/bin/sh\nexec chaintrap-guard {mgr} \"$@\"\n"
        path.write_text(content, encoding="utf-8")
        if platform.system() != "Windows":
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _patch_rc(path: Path, block: str) -> bool:
    if not path.parent.exists():
        return False
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if _MARKER_BEGIN in text:
        before, _, after = text.partition(_MARKER_BEGIN)
        _, _, after = after.partition(_MARKER_END)
        text = before + after
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n\n" + block, encoding="utf-8")
    return True


def _unpatch_rc(path: Path) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if _MARKER_BEGIN not in text:
        return False
    before, _, rest = text.partition(_MARKER_BEGIN)
    _, _, after = rest.partition(_MARKER_END)
    path.write_text((before + after).rstrip() + "\n", encoding="utf-8")
    return True


_WIN_PS_PROFILE_BEGIN = "# >>> chaintrap-guard PATH"
_WIN_PS_PROFILE_END = "# <<< chaintrap-guard PATH"
_WIN_PS_PROFILE_BLOCK = """\
# >>> chaintrap-guard PATH (Machine PATH can precede User on Windows)
$__ctgShim = "$env:USERPROFILE\\.config\\chaintrap-guard\\shims"
if (Test-Path $__ctgShim) {
    $parts = $env:Path -split ';' | Where-Object { $_ -and ($_ -ne $__ctgShim) }
    $env:Path = "$__ctgShim;" + ($parts -join ';')
}
# <<< chaintrap-guard PATH
"""


def _install_windows_powershell_profile() -> list[Path]:
    updated: list[Path] = []
    home = Path.home()
    for sub in ("Documents/PowerShell", "Documents/WindowsPowerShell"):
        profile_dir = home / sub.replace("/", os.sep)
        profile_dir.mkdir(parents=True, exist_ok=True)
        profile = profile_dir / "Microsoft.PowerShell_profile.ps1"
        text = profile.read_text(encoding="utf-8") if profile.is_file() else ""
        if _WIN_PS_PROFILE_BEGIN in text:
            before, _, rest = text.partition(_WIN_PS_PROFILE_BEGIN)
            _, _, after = rest.partition(_WIN_PS_PROFILE_END)
            text = before + after
        profile.write_text(text.rstrip() + "\n\n" + _WIN_PS_PROFILE_BLOCK, encoding="utf-8")
        updated.append(profile)
    return updated


def _windows_path_snippet(shim_dir: Path) -> str:
    return (
        "\nWindows PATH (recommended — User Environment Variables):\n"
        f"  1. Add to PATH (prepend): {shim_dir}\n"
        "  2. Run enable-guard-path.ps1 (also patches PowerShell profile).\n"
        "  3. Open a NEW PowerShell window.\n"
        "  4. Verify: where.exe npm   (shims first)\n"
        "\nAlternative (current cmd session only):\n"
        '  doskey npm=chaintrap-guard npm $*\n'
        '  doskey pip=chaintrap-guard pip $*\n'
        '  doskey uv=chaintrap-guard uv $*\n'
    )


def setup_install(*, write_config: bool = True) -> int:
    bindir = _write_shims()
    if platform.system() == "Windows":
        print("Chaintrap Guard: Windows setup")
        print(_windows_path_snippet(bindir))
        ps1 = default_config_dir() / "enable-guard-path.ps1"
        ps1.parent.mkdir(parents=True, exist_ok=True)
        shim_esc = str(bindir).replace("\\", "\\\\")
        ps1.write_text(
            f'$shim = "{bindir}"\n'
            f'$userPath = [Environment]::GetEnvironmentVariable("Path", "User")\n'
            f'$parts = $userPath -split ";" | Where-Object {{ $_ -and ($_ -ne $shim) }}\n'
            f'[Environment]::SetEnvironmentVariable("Path", "$shim;" + ($parts -join ";"), "User")\n'
            f'Write-Host "User PATH: shim prepended."\n'
            f'$profiles = @(\n'
            f'  "$env:USERPROFILE\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",\n'
            f'  "$env:USERPROFILE\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1"\n'
            f')\n'
            f'$block = @\'\n{_WIN_PS_PROFILE_BLOCK}\'@\n'
            f'foreach ($profile in $profiles) {{\n'
            f'  $dir = Split-Path $profile\n'
            f'  if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n'
            f'  $text = if (Test-Path $profile) {{ Get-Content $profile -Raw }} else {{ "" }}\n'
            f'  if ($text -notlike "*{_WIN_PS_PROFILE_BEGIN}*") {{\n'
            f'    Set-Content -Path $profile -Value ($text.TrimEnd() + "`n`n" + $block) -Encoding UTF8\n'
            f'    Write-Host "Updated $profile"\n'
            f'  }}\n'
            f'}}\n'
            f'Write-Host "Open a NEW PowerShell window, then: where.exe npm"\n',
            encoding="utf-8",
        )
        for p in _install_windows_powershell_profile():
            print(f"PowerShell profile: {p}")
        print(f"  Or run once: powershell -ExecutionPolicy Bypass -File \"{ps1}\"")
        if write_config:
            from chaintrap_guard.config import GuardConfig

            p = GuardConfig.load().write_template()
            print(f"Config written: {p}")
        return 0

    shell = (os.environ.get("SHELL") or "").lower()
    block = _fish_block() if "fish" in shell else _alias_block()
    patched = False
    for rc in _shell_rc_candidates():
        if rc.name == "config.fish" and "fish" not in shell:
            continue
        if rc.name != "config.fish" and "fish" in shell:
            continue
        if _patch_rc(rc, block):
            print(f"Updated {rc}")
            patched = True
            break

    path_hint = f'export PATH="{bindir}:$PATH"'
    if not patched:
        print("Could not find a shell rc file; append this to your profile:", file=sys.stderr)
        print(path_hint, file=sys.stderr)
    else:
        print(f"Optional PATH shims: {path_hint}")

    if write_config:
        from chaintrap_guard.config import GuardConfig

        cfg_path = GuardConfig.load().write_template()
        print(f"Config: {cfg_path}")

    print("Restart your terminal, then run: chaintrap-guard doctor")
    return 0


def setup_remove(*, remove_config: bool = False) -> int:
    for rc in _shell_rc_candidates():
        _unpatch_rc(rc)
    shim = _shim_dir()
    if shim.is_dir():
        for child in shim.iterdir():
            child.unlink(missing_ok=True)
        shim.rmdir()
    if remove_config:
        default_config_path().unlink(missing_ok=True)
    print("Chaintrap Guard shell integration removed.")
    return 0
