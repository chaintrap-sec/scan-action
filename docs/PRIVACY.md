# Privacy

Chaintrap Scan Action v1 is **runner-local**:

- Lockfiles are parsed on the GitHub Actions runner
- OSV queries go to `https://api.osv.dev`
- Optional npm/PyPI registry metadata for heuristics uses public registry APIs
- Optional Supabase IOC reads tenant-scoped indicator rows only

**Not sent to Chaintrap cloud:**

- Application source code
- Private repository contents (beyond lockfile paths read locally)
- Secrets or environment variables

Design partners who enable Supabase IOC provide their own project URL and read-only key scoped via RLS.
