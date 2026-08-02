-- ---------------------------------------------------------------------------
-- Agent identity with a verifiable delegation chain  (#691)
--
-- Two things land here, and they are two halves of one control:
--
--   1. `delegation_revocations` — the list the GATEWAY reads on every
--      delegated request, so revoking a link breaks every chain through it
--      without waiting for expiry;
--   2. `request_logs.delegation_chain` / `.delegation_root` — the audit and
--      chargeback columns, so an evidence row names the whole chain rather
--      than the last credential to touch the request.
--
-- ## Why the chain columns live on `request_logs` rather than in a new table
--
-- Because #677 built per-request cost attribution on `request_logs` joined to
-- the metering aggregate, and its query groups by tenant / project / key /
-- model / tag / agent_run. A chain recorded in a table beside that join would
-- be a second attribution shape: the audit row would name a chain the cost
-- query could not group by, which is half a feature. Two columns on the row the
-- cost query already reads make `?delegation_root=user:u_1` one more `AND`
-- predicate on a statement that already exists.
--
-- `delegation_chain` holds the whole rendered path
-- (`user:u_1>agent:planner>agent:writer`) because an auditor's question is
-- "who was involved", and `delegation_root` is split out as its own column
-- because finance's question is "whose spend is this" — a `LIKE 'user:u_1>%'`
-- over the path would answer the second question with a scan and would answer
-- it wrongly for any principal that is a prefix of another.
--
-- The DEPTH is deliberately not a column: it is `length(path)` derivable, no
-- query needs to group by it, and a column nothing filters on is a promise the
-- schema does not have to keep.
--
-- ## The revocation table's shape
--
-- One `subject` column holds EITHER a link's `jti` (surgical: this grant is
-- dead) OR a principal (`agent:planner` — blast radius: this agent is
-- compromised, kill everything it was given and everything it granted). They
-- share a column because the verifier asks one batched question of both on the
-- same walk, and two tables would be two chances to forget one of them.
--
-- `(tenant, subject)` is the PRIMARY KEY and therefore also the lookup index.
-- The `tenant` half is the fence: without it one tenant could revoke a `jti`
-- and break another tenant's chain, which is a cross-tenant denial of service
-- through a control surface.
--
-- `expires_at_unix` exists so a revocation can be swept once every chain it
-- could break has expired anyway — an unbounded revocation list is read on
-- every delegated request forever. NULL means "never sweep", which is the safe
-- default; the sweep is a later slice and its absence costs only storage.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS delegation_revocations (
    tenant           TEXT    NOT NULL,
    -- A link `jti`, or a `{kind}:{id}` principal. See the note above.
    subject          TEXT    NOT NULL,
    reason           TEXT,
    revoked_by       TEXT,
    revoked_at_unix  INTEGER NOT NULL,
    expires_at_unix  INTEGER,
    PRIMARY KEY (tenant, subject)
);

-- The sweep's access path. The lookup itself rides the primary key.
CREATE INDEX IF NOT EXISTS idx_delegation_revocations_expiry
    ON delegation_revocations(expires_at_unix);

ALTER TABLE request_logs ADD COLUMN delegation_chain TEXT;
ALTER TABLE request_logs ADD COLUMN delegation_root TEXT;

-- `GET /admin/v1/cost-records?delegation_root=…` and its CSV/Parquet export,
-- fenced and ordered exactly as the un-filtered read already is. Without the
-- `tenant` leading column the predicate would be answered by a scan of an
-- append-heavy table on the one report finance runs over a whole month.
CREATE INDEX IF NOT EXISTS idx_request_logs_delegation_root
    ON request_logs(tenant, delegation_root, started_at_unix DESC);
