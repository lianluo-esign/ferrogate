-- ===========================================================================
-- Platform announcements (公告) — operator-authored notices shared to tenants
-- (#948, shared-config channel).
--
-- An operator writes a notice once, on the control database, on the Vega admin
-- surface. It is PLATFORM scope, like the billing groups and model catalog it
-- sits beside: these tables live in the CONTROL database, which has exactly one
-- occupant, so there is no tenant_id column and the names are platform_-prefixed
-- so packages/storage/test/d1/schema.test.ts keeps proving the control and
-- tenant table families never overlap.
--
-- An announcement is READ-ONLY to a tenant. It reaches each tenant's own Durable
-- Object through the one-way shared-config push (the shared_announcements mirror
-- in the tenant schema), so a tenant renders notices from its own object with no
-- control-plane hop. The single-row revision stamp mirrors
-- platform_billing_group_revisions: one monotone counter the shared-config
-- fan-out compares to skip an unchanged fleet.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS platform_announcements (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    -- Display severity the tenant UI maps to a colour/icon. Free text with an
    -- 'info' default so an announcement created without one renders as neutral;
    -- an unknown value falls to the neutral treatment client-side.
    level           TEXT NOT NULL DEFAULT 'info',
    -- 0/1 published flag. A disabled announcement is retained (draft/history)
    -- but excluded from the tenant-facing render.
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- Optional display window, unix seconds. NULL means unbounded on that end.
    starts_at_unix  INTEGER,
    ends_at_unix    INTEGER,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Enabled-window lookup for the tenant-facing list the mirror serves.
CREATE INDEX IF NOT EXISTS ix_platform_announcements_enabled
    ON platform_announcements (enabled);

-- The single-row revision stamp. One announcement registry, one monotone
-- revision: the shared-config fan-out compares it to decide whether the fleet
-- push can be skipped.
CREATE TABLE IF NOT EXISTS platform_announcement_revisions (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    revision        INTEGER NOT NULL DEFAULT 1,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);
