-- ===========================================================================
-- Billing groups with per-group price multipliers (#942, epic #941)
--
-- A one-api-style billing layer over the platform model catalog (#889/#810):
-- an operator groups upstream providers, sets ONE price multiplier per group,
-- and binds API keys to a group. The consumed price of a served request is the
-- provider's official offering price (`platform_catalog_offerings`) times the
-- group's `multiplier`.
--
-- Scope is PLATFORM, like the model catalog it sits over: these tables live in
-- the CONTROL database, which has exactly one occupant, so there is no
-- `tenant_id` column and the names are `platform_`-prefixed so
-- `packages/storage/test/d1/schema.test.ts` can keep proving the control and
-- tenant table families never overlap.
--
-- A group ↔ provider is MANY-TO-MANY: one group binds several providers, and a
-- provider may sit in several groups (and therefore carry a different effective
-- price per group). The binding lives in its own edge table. The single-row
-- revision stamp mirrors `platform_catalog_revisions`: one monotone counter the
-- gateway's cached multiplier source compares to invalidate its memo.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS platform_billing_groups (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- The post-price scalar. `>= 0` because a zero multiplier is a legitimate
    -- "comp this group" setting; a negative price is not. 1.0 is the identity
    -- so a group created without one bills at the provider's official price.
    multiplier      REAL NOT NULL DEFAULT 1.0 CHECK (multiplier >= 0),
    description     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One human-facing name per group: the admin surface and a key's stored
-- `billing_group_id` both address a group by id, but an operator picks it by
-- name, so a duplicate name is a mistake, not a second group.
CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_billing_groups_name
    ON platform_billing_groups (name);

CREATE TABLE IF NOT EXISTS platform_billing_group_providers (
    group_id        TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (group_id, provider_id),
    -- Deleting a group drops its bindings; deleting a provider drops the
    -- bindings that named it (the group survives, minus that provider).
    FOREIGN KEY (group_id) REFERENCES platform_billing_groups (id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES platform_provider_channels (id) ON DELETE CASCADE
);

-- The reverse lookup: "which groups bind this provider?" — used when a
-- provider is edited or removed, and by the console's provider view.
CREATE INDEX IF NOT EXISTS ix_platform_billing_group_providers_provider
    ON platform_billing_group_providers (provider_id);

-- The single-row revision stamp. One billing-group registry, one monotone
-- revision: the gateway's `PlatformBillingGroupSource` compares it to decide
-- whether its cached multipliers are stale.
CREATE TABLE IF NOT EXISTS platform_billing_group_revisions (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    revision        INTEGER NOT NULL DEFAULT 1,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);
