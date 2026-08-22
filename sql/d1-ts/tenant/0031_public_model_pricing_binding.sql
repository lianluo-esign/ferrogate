-- Tenant routes retain a reference to the platform public-price catalog. The
-- selected price remains platform-owned and is resolved by the gateway, so a
-- catalog source switch does not require rewriting every tenant database.
ALTER TABLE provider_channels
    ADD COLUMN cost_multiplier REAL NOT NULL DEFAULT 1 CHECK (cost_multiplier >= 0);

ALTER TABLE catalog_model_offerings ADD COLUMN pricing_model_id TEXT;

CREATE INDEX IF NOT EXISTS idx_catalog_model_offerings_pricing_model
    ON catalog_model_offerings (tenant_id, pricing_model_id);
