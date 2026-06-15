# Chaintrap Scan Action

> **Install once. Every PR/commit scans dependencies for malware and flags risky CI workflows.**

Runner-local supply chain security for **npm** and **PyPI** lockfiles. No source code leaves the GitHub runner.

## 60-second install

Add `.github/workflows/chaintrap.yml`:

```yaml
name: Chaintrap
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: chaintrap-sec/scan-action@v1
        id: chaintrap

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        continue-on-error: true
        with:
          sarif_file: ${{ steps.chaintrap.outputs.sarif-file }}
          category: chaintrap

      - uses: actions/github-script@v7
        if: github.event_name == 'pull_request' && always()
        with:
          script: |
            const fs = require('fs');
            const path = require('path');
            const summaryPath = '${{ steps.chaintrap.outputs.summary-file }}';
            if (!fs.existsSync(summaryPath)) return;
            const body = fs.readFileSync(summaryPath, 'utf8');
            const marker = '<!-- chaintrap-sca -->';
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            const existing = comments.find(c => c.body && c.body.includes(marker));
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: existing.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body,
              });
            }
```

**Pin by commit SHA for production** (recommended):

```yaml
- uses: chaintrap-sec/scan-action@<full-commit-sha>
```

## What gets blocked vs warned

| Signal | Default |
|--------|---------|
| Known malicious packages | **Block** |
| Private threat indicators (optional) | **Block** |
| Known vulnerabilities (CVE/GHSA) | Warn |
| Fresh release (<7 days) | Warn |
| npm install lifecycle scripts | Warn |
| Typosquat similarity | Warn |
| Malware patterns inside package code (PR-added packages) | **Block** (CRITICAL/HIGH) |
| Scan errors | Warn (set `fail-on-error: "true"` to block) |
| Risky CI workflow configuration (`pull_request_target`, unpinned actions) | **Block** (CRITICAL/HIGH) |

## Zero-config by default

Works with **no secrets and no setup** — known malicious npm/PyPI packages are blocked out of the box.

Optional private threat-intel feed: [docs/IOC_PARTNER_ONBOARDING.md](docs/IOC_PARTNER_ONBOARDING.md).

## Repo policy (`.chaintrap.yml`)

```yaml
minimum_release_age_days: 7
audit_workflows: true
gates:
  block_fresh_releases: false
  block_install_scripts: false
  fail_on_error: false
  content_scan: true
ignore:
  packages:
    - left-pad@1.0.0
  rules:
    - CTH-003
```

## Privacy

- Scans run **entirely on the GitHub runner**
- Only package names and versions are checked against public vulnerability databases and registries
- On PRs, newly added packages may be downloaded to the runner for local static analysis — nothing is uploaded
- Source code never leaves the runner

See [docs/PRIVACY.md](docs/PRIVACY.md).

## Lockfiles supported

`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` (pinned `==` or compiled ranges)

## Scope & limits

- Packages are matched by **exact name and version** after discovery — unpinned `requirements.txt` lines (ranges, bare names) and `package.json` semver ranges are **compiled on the runner** when `resolve-manifests` is enabled (default `auto`)
- Compile uses **uv** (`uv pip compile`) for PyPI and `npm install --package-lock-only` for npm; expect roughly **5–45 seconds per changed manifest** on cold cache, often **2–8s** with a warm `~/.cache/uv` Actions cache
- For faster, deterministic CI, commit **`uv.lock`** / **`package-lock.json`** instead of relying on compile
- Transitive dependencies from compile are included in the resolved set (same as a real install resolve)
- Deep code analysis of package contents runs on **packages newly added in a PR**, not the whole existing tree
- Floating versions with **no manifest file change** (e.g. `latest`) are only caught on scheduled full scans, not PR diff
- A clean scan reduces risk; it is not a guarantee a package is safe

## Docs

- [Privacy](docs/PRIVACY.md)
- [Private threat intel](docs/IOC_PARTNER_ONBOARDING.md)
