-- ---------------------------------------------------------------------------
-- `siem_export_cursors` — how far each customer sink has been fed  (#683)
--
-- `request_logs` (#664) and the hash-chained `audit_events` (#684) are the
-- authoritative evidence this platform keeps, and until this table there was
-- nowhere to record what had already left. That gap is not a missing feature,
-- it is an UNDETECTABLE one: a pump with no durable position either re-sends
-- everything on every tick or skips whatever happened while it was down, and
-- the second failure is invisible in the destination — a customer's Splunk
-- index does not say "rows 400..600 never arrived".
--
-- ## Why a (timestamp, id) pair and not an offset
--
-- The row is a KEYSET cursor: the last (ordering timestamp, primary id) pair
-- successfully ACKNOWLEDGED by the sink. `OFFSET` cannot be resumed safely on
-- an append-heavy table — rows inserted between two ticks shift the window and
-- silently drop a row from it — and the id tiebreaker is load-bearing for the
-- same reason `admin_request_log.ts` gives: these timestamps are whole SECONDS
-- and a busy gateway puts thousands of rows in one of them.
--
-- ## `replay_epoch` — the replay is idempotent
--
-- An operator replays a window by naming a NEW epoch plus a `from_unix` in the
-- sink's configuration. The epoch APPLIED is stored here, so the rewind happens
-- exactly once no matter how many ticks see the same configuration; without it
-- the pump would rewind on every tick and the sink would never converge.
--
-- ## Advancement rule
--
-- The cursor moves only AFTER a batch is acknowledged, and only FORWARD (the
-- `WHERE` on the UPDATE in `src/siem/cursor.ts`). Both halves are the
-- at-least-once guarantee: a crash between "sink received it" and "cursor
-- advanced" re-sends that batch, which is a duplicate the destination can
-- de-duplicate on `id` — never a hole it cannot see.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem_export_cursors (
    -- The sink id from `SIEM_EXPORT_SINKS`, and the stream within it. One row
    -- per (sink, stream): a sink that carries both request logs and audit
    -- events advances through them independently, because they are different
    -- tables with different clocks and one being behind must not hold the
    -- other back.
    sink_id TEXT NOT NULL,
    stream TEXT NOT NULL,
    -- The tenant this sink is fenced to, COPIED here rather than only living in
    -- configuration. It is what makes a mis-edited config visible after the
    -- fact: the delivered rows and the tenant they were fenced to are recorded
    -- in the same row an auditor reads.
    tenant TEXT NOT NULL,
    -- The acknowledged position: `started_at_unix` / `occurred_at_unix` and the
    -- row id that broke the tie.
    last_ts INTEGER NOT NULL,
    last_id TEXT NOT NULL,
    -- Cumulative acknowledged rows, so "the pump is running but delivering
    -- nothing" is distinguishable from "the pump has never run".
    delivered INTEGER NOT NULL DEFAULT 0,
    replay_epoch INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (sink_id, stream)
);

-- An operator asking "which of this tenant's sinks is behind" reads by tenant.
CREATE INDEX IF NOT EXISTS idx_siem_export_cursors_tenant
    ON siem_export_cursors(tenant);
