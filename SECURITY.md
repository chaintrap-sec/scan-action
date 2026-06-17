# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `v1.x` (latest tag) | Yes |
| `< v1.0` | No |

## Reporting a vulnerability

If you find a security issue in [chaintrap-sec/scan-action](https://github.com/chaintrap-sec/scan-action):

1. **Do not** open a public GitHub issue for exploitable findings.
2. Email **security@chaintrap.com** with:
   - Description and impact
   - Steps to reproduce
   - Affected version / commit SHA
3. We aim to acknowledge within **3 business days** and provide a fix timeline within **10 business days** for confirmed issues.

## Scope

In scope:

- The composite GitHub Action (`action.yml`, `scripts/`, vendored scanners)
- Abuse via workflow inputs (`paths`, optional API/IOC URLs, content scan)
- PR summary / CI annotation injection from crafted dependency metadata
- Supply-chain integrity of releases and tags in this repository

Out of scope:

- Vulnerabilities in consumer application code scanned by the action
- Misconfigured consumer workflows that intentionally pass secrets to untrusted URLs (documented as operator error)
- Issues in third-party GitHub Actions pinned by consumer repos (see [examples/](examples/) for pinning guidance)

## Trust model

- **Repo owners** control `.chaintrap.yml`, workflow inputs, and optional secrets.
- The action runs with permissions granted by the consumer workflow (`contents: read` minimum).
- Fork pull requests using standard `pull_request` cannot change base-branch policy without merge.
- Avoid `pull_request_target` with checkout of untrusted head SHAs alongside this action.

## Security testing

See [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md) for how we run abuse tests locally and in CI.
