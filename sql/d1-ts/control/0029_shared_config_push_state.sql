-- ===========================================================================
-- Shared-config push watermark: what the fleet has already been sent (#948)
--
-- The shared-config async channel pushes platform config (billing groups today,
-- plans/announcements next) DOWN into every tenant Durable Object's read-only
-- mirror (`sql/d1-ts/tenant/0027_shared_config_mirror.sql`). The cron pass that
-- drives it must answer one question cheaply, once per tick, for the WHOLE
-- fleet: "has anything changed since the last time I fanned out?" — because the
-- alternative, re-pushing to every tenant on every cadence, wakes every idle
-- tenant object for nothing, which is the exact per-tenant load this
-- architecture exists to shed.
--
-- This single-row-per-domain watermark is that answer. The pass reads the
-- domain's SOURCE revision (e.g. `platform_billing_group_revisions.revision`)
-- and compares it to `last_pushed_revision` here: equal -> skip the fan-out
-- entirely; greater -> push the full snapshot to every provisioned tenant, then
-- advance this row. It lives in the CONTROL database (one occupant, no
-- `tenant_id`), like the source revisions it tracks.
--
-- ## Why control-side and not per-tenant
--
-- Each tenant ALSO records its own applied revision in its `shared_config_cursor`
-- (so a push is idempotent and a lagging tenant self-corrects). But asking every
-- tenant "are you current?" is itself a per-tenant round trip. This watermark
-- lets the pass make the fleet-wide skip decision from ONE control read, and
-- only touches tenants when there is genuinely new config to deliver. The first
-- pass after this ships (watermark 0 < any real source revision) back-fills the
-- existing fleet exactly once.
--
-- `last_pushed_revision` starts at 0 so the first real revision always triggers
-- a back-fill; `tenants_pushed` is observability for the last fan-out.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS shared_config_push_state (
    domain               TEXT PRIMARY KEY,
    last_pushed_revision INTEGER NOT NULL DEFAULT 0,
    tenants_pushed       INTEGER NOT NULL DEFAULT 0,
    updated_at_unix      INTEGER NOT NULL DEFAULT (unixepoch())
);
