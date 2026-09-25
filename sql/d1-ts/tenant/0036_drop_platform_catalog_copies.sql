-- Platform definitions live in CONTROL_DATA and PLATFORM_CONFIG KV.
-- Keep tenant overrides, including old edits whose writer left platform_seed
-- on the offering. Edited parents and parents used by custom offerings survive.
CREATE TABLE IF NOT EXISTS retired_platform_catalog_rows (
    kind TEXT NOT NULL, tenant_id TEXT NOT NULL, id TEXT NOT NULL,
    PRIMARY KEY (kind, tenant_id, id)
);
INSERT OR IGNORE INTO retired_platform_catalog_rows
SELECT 'model', tenant_id, model_id FROM catalog_model_offerings WHERE source = 'platform_seed';
INSERT OR IGNORE INTO retired_platform_catalog_rows
SELECT 'provider', tenant_id, provider_id FROM catalog_model_offerings WHERE source = 'platform_seed';
-- The old graph seed also copied channels/models with no offerings.
INSERT OR IGNORE INTO retired_platform_catalog_rows
SELECT 'model', m.tenant_id, m.id FROM catalog_models m
JOIN tenant_provisioning_marks s ON s.tenant_id = m.tenant_id
WHERE s.mark = 'model_catalog_seed' AND m.created_at_unix = s.applied_at_unix;
INSERT OR IGNORE INTO retired_platform_catalog_rows
SELECT 'provider', p.tenant_id, p.id FROM provider_channels p
JOIN tenant_provisioning_marks s ON s.tenant_id = p.tenant_id
WHERE s.mark = 'model_catalog_seed' AND p.created_at_unix = s.applied_at_unix;

UPDATE catalog_model_offerings SET source = 'admin'
WHERE source = 'platform_seed' AND (
    updated_at_unix <> created_at_unix
    OR EXISTS (SELECT 1 FROM catalog_models m
        WHERE m.tenant_id = catalog_model_offerings.tenant_id AND m.id = catalog_model_offerings.model_id
          AND m.updated_at_unix <> m.created_at_unix)
    OR EXISTS (SELECT 1 FROM provider_channels p
        WHERE p.tenant_id = catalog_model_offerings.tenant_id AND p.id = catalog_model_offerings.provider_id
          AND p.updated_at_unix <> p.created_at_unix)
);
DELETE FROM catalog_model_offerings WHERE source = 'platform_seed';
DELETE FROM catalog_models
WHERE updated_at_unix = created_at_unix
  AND EXISTS (SELECT 1 FROM retired_platform_catalog_rows r
      WHERE r.kind = 'model' AND r.tenant_id = catalog_models.tenant_id AND r.id = catalog_models.id)
  AND NOT EXISTS (SELECT 1 FROM catalog_model_offerings o
      WHERE o.tenant_id = catalog_models.tenant_id AND o.model_id = catalog_models.id);
DELETE FROM provider_channels
WHERE updated_at_unix = created_at_unix
  AND EXISTS (SELECT 1 FROM retired_platform_catalog_rows r
      WHERE r.kind = 'provider' AND r.tenant_id = provider_channels.tenant_id AND r.id = provider_channels.id)
  AND NOT EXISTS (SELECT 1 FROM catalog_model_offerings o
      WHERE o.tenant_id = provider_channels.tenant_id AND o.provider_id = provider_channels.id);
DROP TABLE retired_platform_catalog_rows;
DELETE FROM tenant_provisioning_marks WHERE mark = 'model_catalog_seed';
UPDATE catalog_revisions SET revision = revision + 1;
DROP TABLE IF EXISTS tenant_role_catalog;
