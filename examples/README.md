# Examples

Copy one of these to your repo as `.github/workflows/chaintrap.yml`.

| File | Use when |
| --- | --- |
| [consumer-workflow.yml](consumer-workflow.yml) | **Recommended** — full scan, GitHub Security tab, and PR comment with blocked-package details |
| [minimal-workflow.yml](minimal-workflow.yml) | Scan only — findings in GitHub Security tab and job summary (no PR comment) |

Pin `@v1.2.1`, `@v1`, or a full commit SHA from [releases](https://github.com/chaintrap-sec/scan-action/releases).
