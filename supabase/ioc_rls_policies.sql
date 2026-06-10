-- Supabase RLS for partner IOC read access
-- Apply in Supabase SQL editor for design partner provisioning

ALTER TABLE package_ioc_indicators ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS partner_ioc_read ON package_ioc_indicators;

CREATE POLICY partner_ioc_read ON package_ioc_indicators
  FOR SELECT
  USING (active = true);

-- Tighten in production: AND org_id = '<partner-org-id>'
-- Grant anon/authenticated SELECT only via scoped API key
