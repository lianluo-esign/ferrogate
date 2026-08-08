-- ===========================================================================
-- Batch EXECUTION state (#698, slice 2/3)
--
-- 0022 created the API/state surface; nothing ever advanced a row past
-- `validating` because the table had nowhere to record HOW FAR a job had got.
-- This migration adds that, plus the durable per-line results the finalizer
-- assembles the output JSONL from.
--
-- ## Why a lease and not "the queue message owns the job"
--
-- Cloudflare Queues are at-least-once and the 1-minute Cron is a second,
-- independent trigger, so the same batch WILL be picked up twice — a redelivery
-- racing a sweep is the normal case, not the pathological one. A batch line is
-- a PAID provider call, so "both workers run it" is money, not a duplicate row.
-- `lease_owner` + `lease_expires_at_unix` make the claim a single guarded
-- UPDATE: exactly one invocation wins, and an invocation that dies mid-tick
-- releases the job when its lease expires rather than stranding it forever.
--
-- ## Why per-line results live in a TABLE and not in a staging file
--
-- The alternative was appending each tick's output to a staging `/v1/files`
-- object. Assets are immutable and versioned, so "append" is really
-- read-rewrite-republish: O(n^2) bytes, a new file id every tick, and a pile of
-- orphaned objects for the retention sweep. A row keyed `(batch_id,
-- line_index)` is instead IDEMPOTENT under Queue redelivery — a re-executed
-- line overwrites its own row instead of doubling the output — and lets the
-- finalizer stream the JSONL out in line order in one query.
--
-- ## Why the creating credential is recorded on the batch
--
-- The executor runs with no request, so it cannot re-read an `AuthContext`.
-- Budget and wallet enforcement are per-credential and per-project, not merely
-- per-tenant, so the scope chain that admitted the CREATE is persisted here and
-- re-applied to every line. Without it the executor could only enforce a
-- tenant-wide cap and a project budget would silently not apply to batch spend.
-- ===========================================================================

ALTER TABLE batches ADD COLUMN api_key_id TEXT;
ALTER TABLE batches ADD COLUMN project_id TEXT;
ALTER TABLE batches ADD COLUMN next_line_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE batches ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE batches ADD COLUMN lease_owner TEXT;
ALTER TABLE batches ADD COLUMN lease_expires_at_unix INTEGER;
ALTER TABLE batches ADD COLUMN failure_code TEXT;
ALTER TABLE batches ADD COLUMN failure_message TEXT;

-- Slice 3: which execution strategy this job settled on, and the upstream's own
-- handle when it is running on the provider's native batch endpoint.
ALTER TABLE batches ADD COLUMN execution_mode TEXT;
ALTER TABLE batches ADD COLUMN provider TEXT;
ALTER TABLE batches ADD COLUMN provider_batch_id TEXT;

-- The claim scan: non-terminal rows whose lease is free or expired, oldest
-- first. `status` leads because the sweep always filters on it.
CREATE INDEX IF NOT EXISTS idx_tenant_batches_lease
    ON batches(status, lease_expires_at_unix ASC, created_at_unix ASC);

CREATE TABLE IF NOT EXISTS batch_request_results (
    batch_id TEXT NOT NULL,
    -- Zero-based position in the input JSONL. Part of the primary key, which
    -- is what makes a redelivered line an overwrite instead of a duplicate.
    line_index INTEGER NOT NULL,
    -- The caller's `custom_id`, echoed on the output line exactly as OpenAI
    -- does. Empty string when the input line carried none.
    custom_id TEXT NOT NULL DEFAULT '',
    -- 1 = the line produced a response, 0 = it produced an error. Drives which
    -- of the two output files the line is written to.
    succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
    -- The whole OpenAI batch output line, already shaped:
    -- `{id, custom_id, response: {...} | null, error: {...} | null}`.
    body_json TEXT NOT NULL CHECK (json_valid(body_json) = 1),
    created_at_unix INTEGER NOT NULL,
    PRIMARY KEY (batch_id, line_index)
);

CREATE INDEX IF NOT EXISTS idx_batch_request_results_batch
    ON batch_request_results(batch_id, succeeded, line_index ASC);
