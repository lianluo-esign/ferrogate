-- Business provider family projected from the platform billing group.
-- Nullable only for legacy, unbound groups that could not be inferred during
-- the control migration; new groups always carry a validated type id.

ALTER TABLE shared_billing_groups ADD COLUMN provider_type_id TEXT;

CREATE INDEX IF NOT EXISTS idx_shared_billing_groups_type
    ON shared_billing_groups (provider_type_id, enabled);
