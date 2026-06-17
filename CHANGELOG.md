# Changelog

All notable changes to [chaintrap-sec/scan-action](https://github.com/chaintrap-sec/scan-action).

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

[1.2.0]: https://github.com/chaintrap-sec/scan-action/compare/v1...v1.2.0
