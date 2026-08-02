-- Issue #695: the response cache stops being a deploy-time var.
--
-- Until this table existed the whole `[cache]` section reached the gateway as
-- Worker `[vars]` (`GATEWAY_CACHE_MODE`, `GATEWAY_CACHE_SEMANTIC_THRESHOLD`,
-- …). Those are DEPLOYMENT-wide and only `wrangler deploy` can change them, so
-- a tenant could not enable semantic caching, tune its similarity threshold,
-- narrow it to a model set, or throw away what it already held. This is the
-- durable half: one row per governed scope, written by
-- `/admin/v1/semantic-cache-policies/**` and read on the gateway's request path
-- by `apps/gateway/src/cache/governance.ts`.
--
-- ## Every override column is NULLABLE, and that is the whole design
--
-- NULL means INHERIT the deployment's var value; a non-NULL value overrides it.
-- A three-valued column is what lets "this tenant has a row because it pinned
-- one field" coexist with "everything else still follows the deployment
-- default" — a NOT NULL DEFAULT would silently freeze every other field at the
-- value the schema happened to pick on the day the row was created.
--
-- `enabled` is INTEGER rather than BOOLEAN for the same reason D1 has no
-- boolean: 0 / 1 / NULL is exactly the tri-state.
--
-- ## `invalidation_epoch` is the explicit-invalidation mechanism
--
-- It is mixed into the cache key (`cache/key.ts`'s `governance_fingerprint`),
-- so bumping it makes every digest computed under the old value unreachable —
-- both the exact Cache API entries and the semantic scope buckets — WITHOUT
-- enumerating or deleting anything. Enumeration is not available to us: the
-- Cloudflare Cache API cannot list keys, and the semantic store is per-isolate.
-- A monotonic counter inside the hash is the only invalidation primitive that
-- works for both stores and is instantly consistent with the read path.
--
-- ## `generation` is the CAS token
--
-- Same shape as `guardrail_policy_bindings`: D1 is SQLite, a Worker cannot hold
-- a transaction open across an await, so every mutation is a
-- read-then-guarded-write and an empty `RETURNING` set is a lost update.
CREATE TABLE IF NOT EXISTS semantic_cache_policies (
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    enabled INTEGER,
    mode TEXT,
    similarity_threshold REAL,
    ttl_seconds INTEGER,
    -- JSON array of logical model names. Empty/NULL = every model this
    -- deployment serves; non-empty = ONLY these, which is the "scope it" lever.
    scoped_models TEXT,
    invalidation_epoch INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    updated_by TEXT,
    generation INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_type, scope_id)
);

-- The gateway reads by `(scope_type, scope_id)` on the request path; the PK
-- already covers that. This index is for the admin LIST leg, which orders by
-- scope so a console page is stable across requests.
CREATE INDEX IF NOT EXISTS idx_semantic_cache_policies_scope
    ON semantic_cache_policies (scope_type, scope_id);
