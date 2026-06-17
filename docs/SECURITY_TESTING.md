# Security testing

How Chaintrap scan-action is tested against abuse (path escape, log/comment injection, SSRF).

## Run locally

```bash
cd chaintrap-scan-action
pip install pytest pyyaml -e vendor/chaintrap-static-scan -e vendor/chaintrap-ci
pytest tests/test_security_abuse.py -q
pytest tests/ -q -k "not integration"
python sandbox/run_sandbox.py
```

## Abuse test coverage

| Area | Test file | What it checks |
| --- | --- | --- |
| Path scope | `test_security_abuse.py` | `paths` input cannot escape workspace |
| CI log injection | `test_security_abuse.py` | GHA `::error` / `::warning` sanitization |
| PR markdown | `test_security_abuse.py` | Table/marker injection in summary |
| API reporting SSRF | `test_security_abuse.py` | HTTPS-only, blocked metadata/private hosts |
| Supabase IOC | `test_security_abuse.py` | Host must match Supabase domain policy |
| Tarball download | `test_security_abuse.py` | Registry CDN host allowlist |
| Fixtures | `test_fixtures/security_abuse/` | Injection strings in lockfile package names |

## CI

Job `security-abuse` in [.github/workflows/self-test.yml](../.github/workflows/self-test.yml) runs on every push/PR to `main`.

Job `dogfood-security-abuse` runs the action against `test_fixtures/security_abuse/` and verifies the PR summary marker appears exactly once.

## Branch protection

Required checks on `main`: `unit`, `integration`, `security-abuse`, `sandbox`. Config: [.github/branch-protection.json](../.github/branch-protection.json).

## Manual checklist (release gate)

- [ ] `pytest tests/test_security_abuse.py` green
- [ ] No unpinned third-party actions in `action.yml` runtime steps
- [ ] Examples/README recommend SHA pins for consumer workflows
- [ ] Changelog documents security-relevant behavior changes

## Reporting

See [SECURITY.md](../SECURITY.md).
