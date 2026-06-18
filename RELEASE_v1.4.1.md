## Branch-tiered dashboard inventory (v1.4.1)

Fixes PR scans polluting **live** package inventory when a feature branch adds packages not on `main`.

### Highlights
- Reports `branch_tier`, `default_branch`, `pr_number` to Chaintrap API
- Sends full lockfile `inventory` payload for dashboard snapshots
- `pull_request` → `pr_preview`; default-branch push → `default` (live)

### Upgrade
```yaml
- uses: chaintrap-sec/scan-action@v1.4.1
# or
- uses: chaintrap-sec/scan-action@v1
```

Requires Chaintrap API with migration **018** (`branch_tier` on CI inventory).
