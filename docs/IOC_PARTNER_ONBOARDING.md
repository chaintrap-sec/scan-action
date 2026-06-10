# Supabase IOC partner provisioning

## Table

`package_ioc_indicators` columns used by the action:

- `org_id` — tenant filter
- `ecosystem` — `npm` | `pypi`
- `package_name`, `package_version` — exact match
- `severity`, `source`, `ioc_key`, `active`

## RLS policies (read-only partner key)

```sql
-- Enable RLS
ALTER TABLE package_ioc_indicators ENABLE ROW LEVEL SECURITY;

-- Partner read: own org rows only
CREATE POLICY partner_ioc_read ON package_ioc_indicators
  FOR SELECT
  TO authenticated, anon
  USING (
    active = true
    AND org_id = current_setting('request.jwt.claims', true)::json->>'org_id'
  );

-- Service role manages writes (not exposed to partners)
```

For anon key + `org-id` action input (simpler v1):

```sql
CREATE POLICY partner_ioc_read_by_org ON package_ioc_indicators
  FOR SELECT
  TO anon
  USING (active = true AND org_id = coalesce(current_setting('app.org_id', true), ''));
```

Set `app.org_id` via PostgREST header or use filtered view per partner.

## Community IOC (optional)

Shared read-only rows with `org_id = 'org-community'` for keyless OSV+community tier.

## Request volume

- OSV: one batched query per job
- IOC store: one GET per job; cached on the runner within the job only
- Registry heuristics: per added package in diff mode
