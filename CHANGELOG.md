# Changelog

All notable changes to [chaintrap-sec/scan-action](https://github.com/chaintrap-sec/scan-action).

## [1.4.1] - 2026-06-18

### Added

- **Branch-tiered inventory reporting** — CI reports send `branch_tier` (`default` vs `pr_preview`), `default_branch`, and `pr_number` so PR scans no longer overwrite live default-branch package inventory on the Chaintrap dashboard
- Lockfile **inventory payload** on optional API report (`inventory`, `package_count`, per-package OSV fields)
- Action env: `GITHUB_PR_NUMBER`, `CHAINTRAP_DEFAULT_BRANCH` (wired from `github.event.pull_request.number` and repo default branch)

### Changed

- Default-branch (`push` to `main`) scans update **live** inventory only; `pull_request` scans land under **PR previews**

## [1.4.0] - 2026-06-17

### Added

- **Ephemeral dependency discovery** — scan npm/PyPI installs in workflows, `package.json` scripts, Dockerfiles, and shell/Makefiles (`npx`, `pnpm dlx`, `pip install`, `uvx`, `pipx run`, and more)
- Vendored **chaintrap-guard** parsers (`uvx`, `pipx`, `dlx`, `bunx`)
- PR diff mode for ephemeral surfaces; **bootstrap full scan** on first Chaintrap PR
- PR summary section: *Ephemeral dependencies (not in lockfile)*
- Action input `ephemeral-scan` (default `true`) and `.chaintrap.yml` gate `gates.ephemeral_scan`
- `tests/test_ephemeral_discover.py`, fixtures under `test_fixtures/ephemeral_deps/`, CI job `dogfood-ephemeral`
- Architecture doc: [docs/EPHEMERAL_DEPS_V1.4.md](docs/EPHEMERAL_DEPS_V1.4.md)

### Changed

- Lockfile packages consume `max-packages` budget first; ephemeral fills the remainder
- Ephemeral duplicates already in lockfile are hidden
- Known-bad denylist blocks even when OSV lookup returns no result
- Content scan runs on PR ephemeral packages (HIGH/CRITICAL block); unpinned ephemeral warns only

## [1.3.0] - 2026-06-17

### Security

- **`paths` input** cannot escape the workspace root
- **PR summary / CI annotations** sanitize user-derived text (markdown and workflow commands)
- **Tarball downloads** restricted to registry CDN hosts (npm/PyPI)
- **Supabase IOC URL** must be a `*.supabase.co` / `*.supabase.in` host
- **Optional API reporting** restricted to `*.chaintrap.com` (override via `CHAINTRAP_API_ALLOW_HOSTS`)
- Blocked link-local and private IP targets for outbound HTTPS

### Added

- `tests/test_security_abuse.py` and CI jobs `security-abuse`, `dogfood-security-abuse`
- [SECURITY.md](SECURITY.md) and [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md)
- Dependabot config for GitHub Actions

### Changed

- Examples and self-test workflows pin third-party actions to commit SHAs

## [1.2.1] - 2026-06-17

### Changed

- Market-ready README with value prop, example PR output, pinning guide
- `examples/minimal-workflow.yml` and `examples/README.md`
- Marketplace action description updated

## [1.2.0] - 2026-06-17

### Added

- **Defanged IOC artifacts** on content-scan findings in PR summaries and SARIF
  - URLs → `hxxps://host[.]com/path`
  - Domains → `evil[.]com`
  - IPs → `203[.]0[.]113[.]55`
  - Suspicious commands surfaced as sub-bullets under Evidence
- `ioc_extract.py` module in vendored static scanner
- Tests for extraction, defanging, and summary rendering

### Changed

- Evidence section shows actionable artifacts instead of generic rule labels alone
- SARIF `message.text` and `properties.artifacts` include primary IOC when present

## [1.0.0] - prior

- Runner-local npm/PyPI lockfile scanning (OSV MAL-*, CVE warnings)
- PR diff mode with optional content scan
- Workflow hardening audit (CTW-* rules)
- Unpinned manifest compile (`resolve-manifests: auto`) via uv + npm lock-only
- SARIF + PR summary markdown outputs
- Optional Supabase tenant IOC layer

[1.4.0]: https://github.com/chaintrap-sec/scan-action/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/chaintrap-sec/scan-action/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/chaintrap-sec/scan-action/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/chaintrap-sec/scan-action/compare/v1...v1.2.0
