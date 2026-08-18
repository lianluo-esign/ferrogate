-- ===========================================================================
-- Announcements (公告), MIRRORED read-only into the tenant DO (#948)
--
-- The second domain on the shared-config channel, after billing groups
-- (0027_shared_config_mirror). The control plane owns platform_announcements
-- and pushes a snapshot into this table through the privileged tenant-write RPC
-- at tenant creation and on the cron cadence. After that a tenant renders
-- notices from THIS local table with no control-plane hop.
--
-- READ-ONLY inside the tenant. The privileged push RPC is the only writer, so
-- ordinary tenant query/batch traffic is refused against it by
-- PRIVILEGED_WRITE_TABLES in packages/storage/src/tenant-data-object.ts, the
-- same gate that protects the billing-group mirror and the role-binding
-- projection.
--
-- The per-domain sync cursor lives in shared_config_cursor (created by 0027)
-- under the 'announcements' domain, so this migration adds only the data table
-- plus its enabled-window lookup index. Column parity with the source
-- (title, body, level, enabled, starts_at_unix, ends_at_unix) plus
-- config_revision, which stamps the push that wrote the row.
--
-- DIALECT: no cross-database FK (the source rows live in the CONTROL database),
-- BOOLEAN -> INTEGER 0/1, timestamps unix seconds.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS shared_announcements (
    id                TEXT PRIMARY KEY,
    title             TEXT NOT NULL,
    body              TEXT NOT NULL,
    level             TEXT NOT NULL DEFAULT 'info',
    enabled           INTEGER NOT NULL DEFAULT 1,
    starts_at_unix    INTEGER,
    ends_at_unix      INTEGER,
    config_revision   INTEGER NOT NULL DEFAULT 0,
    synced_at_unix    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Enabled-notice lookup for the tenant-facing render once a tenant reads its
-- own mirror.
CREATE INDEX IF NOT EXISTS idx_shared_announcements_enabled
    ON shared_announcements(enabled);
