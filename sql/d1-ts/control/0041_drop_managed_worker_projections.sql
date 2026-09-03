-- ===========================================================================
-- Drop the managed-worker family control projections (Track A red-line)
--
-- `agent_worker_instances`, `managed_worker_sessions`,
-- `managed_worker_lifecycle_events`, `managed_worker_isolation_policies`,
-- `managed_worker_isolation_selections` and `managed_worker_templates` (all
-- 0001_init_control) are the remaining control-side projection *mirrors* of the
-- managed (gateway-hosted) agent-worker plane. They are the direct siblings of
-- `managed_worker_isolation_evidence`, which 0036 already dropped from control:
-- their authoritative home is the per-tenant TenantDataObject, and every live
-- producer and reader targets that tenant object, so the control copies have no
-- remaining writer or reader.
--
--   * WRITE — `agent-runtime/runs/evidence.ts` upserts every one of these rows
--     into the tenant's OWN object (`tenantDatabase(env, tenantId)` →
--     `DurableObjectD1Database`) and states so explicitly: "write durable
--     evidence into the tenant's TenantDataObject — the ONLY copy". There is no
--     control-facade mirror write; there never was one for this family (the
--     managed evidence was "never mirrored either").
--   * READ  — `control-plane/store/tenant-worker.ts`
--     (`listTenantManagedWorkers` / `listTenantManagedWorkerSessions`) reads the
--     tenant object via `openTenantWorkerRepository` → `tenantDatabaseFor`, and
--     the admin surface `routes/admin_managed_worker.ts` fans out over every
--     provisioned tenant object (`provisionedTenantPage` /
--     `deps.tenantDatabases`). "The tenant object now owns the managed-worker
--     rows." That reader switch shipped long before this DROP (commit b0a78086)
--     and is already live in production, so no isolate still reads the mirror.
--
-- No historical backfill is required. The control copies were populated ONLY by
-- the one-time D1→control lift-and-shift; the SAME source rows were lift-and-
-- shifted into the tenant objects (this family is in the tenant-backfill
-- manifest too), and every write since has been tenant-only. Each tenant object
-- is therefore a superset of its dead control mirror — unlike a projection that
-- kept accumulating control-only rows after the cut (which is why the
-- experiment/eval family needs its gated backfill and this one does not).
--
-- Keeping the empty mirrors implies a second source of truth and lets a future
-- writer accidentally bypass tenant isolation — the exact red line this program
-- eliminates. `IF EXISTS` keeps this idempotent for fresh and already-migrated
-- control databases (0013 / 0036 / 0037 / 0038 / 0039 / 0040 precedent). None of
-- the six is referenced by an inbound foreign key, so drop order is free; each
-- table's index (`idx_agent_worker_instances_started`,
-- `idx_managed_worker_sessions_requested`,
-- `idx_managed_worker_lifecycle_events_occurred`,
-- `idx_managed_worker_isolation_selections_selected`) drops with its table.
--
-- Deploy order: this is a pure DROP of an already-dead mirror (like 0036), with
-- no companion reader/writer switch — the reader moved to the tenant object in a
-- prior deploy — so there is no CP→gateway ordering constraint. The gateway
-- bundle that defines the ControlDataObject carries this migration; an old
-- isolate that somehow still hit the mirror during rollout skew would see
-- `no such table`, but no such reader exists.
-- ===========================================================================

DROP TABLE IF EXISTS agent_worker_instances;
DROP TABLE IF EXISTS managed_worker_sessions;
DROP TABLE IF EXISTS managed_worker_lifecycle_events;
DROP TABLE IF EXISTS managed_worker_isolation_policies;
DROP TABLE IF EXISTS managed_worker_isolation_selections;
DROP TABLE IF EXISTS managed_worker_templates;
