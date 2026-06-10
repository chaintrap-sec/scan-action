# Privacy

Chaintrap Scan Action is **runner-local**:

- Lockfiles are parsed on the GitHub Actions runner
- OSV queries go to `https://api.osv.dev` (with retries; transient failures warn by default)
- Optional npm/PyPI registry metadata for heuristics uses public registry APIs
- On **pull requests**, diff-added packages may be downloaded from npm/PyPI registries (size-capped tarballs/wheels) and scanned locally for malware patterns — artifacts are extracted to a temp directory on the runner and deleted after the job
- Optional Supabase IOC reads tenant-scoped indicator rows only

**Not sent to Chaintrap cloud:**

- Application source code
- Downloaded package tarballs or scan findings
- Private repository contents (beyond lockfile paths read locally)
- Secrets or environment variables

**Network egress (runner only):**

| Destination | When | Data sent |
|-------------|------|-----------|
| `api.osv.dev` | Every scan | Package name + version |
| `registry.npmjs.org` | Heuristics + PR content scan | Package name + version |
| `pypi.org` | Heuristics + PR content scan | Package name + version |
| Your Supabase | If IOC configured | IOC lookup keys only |

Design partners who enable Supabase IOC provide their own project URL and read-only key scoped via RLS.
