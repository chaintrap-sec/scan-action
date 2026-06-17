# Examples

Copy one of these to your repo as `.github/workflows/chaintrap.yml`.

| File | Use when |
| --- | --- |
| [consumer-workflow.yml](consumer-workflow.yml) | **Recommended** — scan, SARIF upload, and sticky PR comment with risk cards + defanged IOC evidence |
| [minimal-workflow.yml](minimal-workflow.yml) | Scan + SARIF only; findings appear in GitHub Security tab and job summary |

Pin `@v1.2.0` or a full commit SHA from [releases](https://github.com/chaintrap-sec/scan-action/releases).
