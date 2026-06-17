from __future__ import annotations

import sys
from pathlib import Path

from chaintrap_guard.config import GuardConfig
from chaintrap_guard.exec_pm import run_package_manager
from chaintrap_guard.doctor import run_doctor
from chaintrap_guard.parse_npm import parse_npm
from chaintrap_guard.parse_npx import parse_npx
from chaintrap_guard.parse_pip import parse_pip, parse_uv
from chaintrap_guard.setup_shim import setup_install, setup_remove
from chaintrap_guard.verdict import analyze_targets, format_block_message


def _parse_for_manager(manager: str, argv: list[str]) -> "ParsedCommand":
    from chaintrap_guard.models import ParsedCommand

    cwd = Path.cwd()
    if manager in ("npx", "pnpx"):
        return parse_npx(argv, cwd=cwd)
    if manager in ("npm", "pnpm", "yarn", "bun"):
        return parse_npm(argv, cwd=cwd)
    if manager in ("pip", "pip3"):
        return parse_pip(argv, cwd=cwd)
    if manager == "uv":
        return parse_uv(argv, cwd=cwd)
    return ParsedCommand(manager=manager, subcommand="", passthrough=True, raw_argv=argv)


def _check_cloud_policy(cfg: GuardConfig, targets) -> dict | None:
    if not cfg.policy_enforce or not cfg.org_id or not cfg.api_base or not cfg.api_key:
        return None
    from chaintrap_guard.policy_client import check_backend_policy

    for spec in targets:
        eco = str(getattr(spec, "ecosystem", "") or "").strip().lower()
        if eco not in ("npm", "pypi"):
            continue
        denial = check_backend_policy(
            api_base=cfg.api_base,
            api_key=cfg.api_key,
            org_id=cfg.org_id,
            ecosystem=eco,
            package_name=spec.name,
            package_version=spec.version or "",
            dry_run=False,
        )
        if denial:
            return denial
    return None


def run_guard(manager: str, argv: list[str], cfg: GuardConfig) -> int:
    parsed = _parse_for_manager(manager, argv)

    if parsed.passthrough:
        if not cfg.passthrough_unknown:
            print(
                f"chaintrap-guard: unsupported {manager} subcommand '{parsed.subcommand}' "
                "(passthrough_unknown=false)",
                file=sys.stderr,
            )
            return 2
        return run_package_manager(manager, argv)

    if not parsed.targets:
        return run_package_manager(manager, argv)

    result = analyze_targets(parsed.targets, cfg)

    policy_denial = _check_cloud_policy(cfg, parsed.targets)
    if policy_denial:
        msg = policy_denial.get("reason_message") or policy_denial.get("reason_code") or "policy_denied"
        print(f"chaintrap-guard: blocked by org policy — {msg}", file=sys.stderr)
        return 1

    for pv in result.warned:
        print(
            f"chaintrap-guard: warning — {pv.spec.name}@{pv.spec.version} "
            f"({pv.label}): {', '.join(pv.vulnerable_ids) or 'advisories present'}",
            file=sys.stderr,
        )

    if result.should_block:
        print(format_block_message(result), file=sys.stderr)
        return 1

    if cfg.dry_run:
        print(
            f"chaintrap-guard: dry-run — would allow {result.analyzed_count} package(s)",
            file=sys.stderr,
        )
        return 0

    rc = run_package_manager(manager, argv)
    if rc == 0 and parsed.subcommand in ("install", "add", "i"):
        try:
            from chaintrap_guard.refresh_notify import notify_watch_refresh

            notify_watch_refresh(cfg.watch_refresh_url)
        except Exception:
            pass
    return rc


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in ("-h", "--help", "help"):
        print(
            "Usage: chaintrap-guard <setup|doctor|npm|pip|uv|npx|...> [args...]\n"
            "  setup install | setup remove [--config-file]\n"
            "  doctor  — config, OSV DB, npm+PyPI probes\n"
            "  chaintrap-guard npm|pip install <pkg>  — OSV scan then real PM\n"
        )
        return 0 if args and args[0] == "help" else (0 if not args else 0)

    if args[0] == "doctor":
        return run_doctor()

    if args[0] == "setup":
        sub = args[1] if len(args) > 1 else ""
        if sub == "install":
            return setup_install()
        if sub == "remove":
            remove_cfg = "--config-file" in args[2:]
            return setup_remove(remove_config=remove_cfg)
        print("Usage: chaintrap-guard setup install|remove", file=sys.stderr)
        return 2

    manager = args[0]
    pm_argv = args[1:]
    cfg = GuardConfig.load()

    if manager == "chaintrap-guard":
        return main(pm_argv)

    return run_guard(manager, pm_argv, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
