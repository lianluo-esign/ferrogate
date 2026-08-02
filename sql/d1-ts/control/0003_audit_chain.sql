-- #684: the hash-chain columns on `audit_events`.
--
-- `audit_events` was append-only by CONVENTION: the writer only ever inserts,
-- but nothing about a STORED row committed to any other row, so an
-- `UPDATE audit_events SET audit_json = ...` or a `DELETE` by anyone holding
-- database credentials left no trace at all. These four columns make each row
-- commit to its predecessor, so an alteration is detectable from an export
-- alone — see `packages/storage/src/audit-chain.ts` for the algorithm and
-- `docs/audit-tamper-evidence.md` for the verification procedure.
--
-- ALL FOUR ARE NULLABLE, deliberately, for two reasons that are both real:
--
--   1. rows written BEFORE this migration cannot be retro-chained (there is no
--      honest hash to invent for them), and
--   2. `audit_events` has a SECOND writer — the gateway's asset audit sink
--      (`apps/gateway/src/assets/d1.ts`) — which is not chained yet.
--
-- Unchained rows are not silently tolerated: the verifier COUNTS and REPORTS
-- them (`unchained_rows`) and downgrades its verdict to `inconclusive`, because
-- ignoring them would let an attacker append a forged row simply by leaving
-- these columns NULL.
ALTER TABLE audit_events ADD COLUMN chain_key TEXT;
ALTER TABLE audit_events ADD COLUMN seq INTEGER;
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN row_hash TEXT;

-- THE SERIALIZATION POINT for concurrent appends, not merely an index.
--
-- D1 has no interactive transactions, so the writer reads the chain head,
-- computes the new row's hash in the isolate, and inserts. Two isolates that
-- read the same head would otherwise both write `seq = n+1` and produce two
-- rows claiming the same position — a fork, which verification cannot resolve
-- and which would let a writer overwrite another writer's link. This UNIQUE
-- index turns that race into a constraint violation the writer RETRIES against
-- the new head (`apps/control-plane/src/store/d1.ts::#audit`).
--
-- SQLite treats NULLs as distinct in a UNIQUE index, so the unchained rows
-- described above do not collide with each other.
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_chain_seq
    ON audit_events(chain_key, seq);

-- The chain-head read (`ORDER BY seq DESC LIMIT 1` within one chain) runs on
-- every audited mutation, so it gets the covering index rather than a scan of
-- the whole append-only table.
CREATE INDEX IF NOT EXISTS idx_audit_events_chain_head
    ON audit_events(chain_key, seq DESC);
