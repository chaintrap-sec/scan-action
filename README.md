# Chaintrap Scan Action

> **Install once. Every PR/commit scans dependencies for malware and flags risky CI workflows.**

Runner-local supply chain security for **npm** and **PyPI** lockfiles. No source code leaves your GitHub runner.

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
| Your organization's private threat indicators (optional) | **Block** |
| Known vulnerabilities (CVE/GHSA) | Warn |
| Fresh release (<7 days) | Warn |
| npm install lifecycle scripts | Warn |
| Typosquat similarity | Warn |
| Malware patterns inside package code (PR-added packages) | **Block** (CRITICAL/HIGH) |
| Scan errors | Warn (set `fail-on-error: "true"` to block) |
| Risky CI workflow configuration (`pull_request_target`, unpinned actions) | **Block** (CRITICAL/HIGH) |

## Zero-config by default

Works with **no secrets and no setup** — known malicious npm/PyPI packages are blocked out of the box.

Teams with a private threat-intelligence feed can connect it via action inputs — see [docs/IOC_PARTNER_ONBOARDING.md](docs/IOC_PARTNER_ONBOARDING.md).

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

- Scans run **entirely on your GitHub runner**
- Only package names and versions are checked against public vulnerability databases and registries
- On PRs, newly added packages may be downloaded to the runner for local static analysis — nothing is uploaded
- Your source code never leaves the runner

See [docs/PRIVACY.md](docs/PRIVACY.md).

## Lockfiles supported

`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` (pinned `==` only)

## Docs

- [Onboarding guide](docs/DESIGN_PARTNER_ONBOARDING.md)
- [Private threat intel setup](docs/IOC_PARTNER_ONBOARDING.md)
