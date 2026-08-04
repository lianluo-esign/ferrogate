-- ===========================================================================
-- FerroGate TS/CF rewrite — PER-TENANT database schema (migration 0001)
--
-- Applied ONCE PER TENANT, to that tenant's OWN D1 database. The account-global
-- half is `../control/0001_init_control.sql`; read its header for the full
-- split rule. The short version: this file holds a tenant's own MONEY, USAGE,
-- ASSETS, SCHEDULES and PRESENCE — everything whose reads always carry a
-- routing tenant id, and everything whose leakage across tenants would be a
-- security incident rather than a bug.
--
-- ---------------------------------------------------------------------------
-- WHY PHYSICAL ISOLATION CHANGES WHAT THE SCHEMA MUST DO
-- ---------------------------------------------------------------------------
-- On Postgres, cross-tenant isolation came from RLS predicates over a shared
-- table plus `current_setting('ferrogate.tenant_id')`. There is no RLS here and
-- no GUC: the database boundary IS the isolation. Two consequences are load-
-- bearing and are the reason the `tenant_id` columns below are RETAINED even
-- though every row in this database belongs to one tenant:
--
--   1. `tenant_id` stays as a COMPOSITE STORAGE KEY. Deterministic ids
--      (`{tenant}:{asset_type}:{name}:{version}`, `{scope_type}:{scope_id}`)
--      embed it, the Rust `Stored*` structs carry it, and the UNIQUE
--      constraints below are stated over it. Dropping the column would rename
--      the parity surface and break every deterministic id — a silent break.
--   2. `tenant_id` is a MIS-ROUTING TRIPWIRE, not a filter. A router bug that
--      opens tenant B's database for tenant A writes a row whose `tenant_id`
--      disagrees with the database it landed in. Application code asserts on
--      that mismatch; without the column the corruption would be invisible.
--
-- Because there is no cross-database FK, NOTHING here references `tenants`,
-- `plans`, `roles`, or `quota_policies` — those rows live in the control
-- database. Referential integrity is enforced in application code.
--
-- ---------------------------------------------------------------------------
-- WHAT IS *NOT* HERE, AND WHY (so the absence is deliberate, not forgotten)
-- ---------------------------------------------------------------------------
--   * `tenants`, `plans`, RBAC, admin users, SSO, `quota_policies`,
--     `site_domains`, the control-plane registry, `api_key_directory`,
--     `static_api_keys` -> CONTROL (split rules (a)/(b)/(c)).
--   * observability, billing ledger/outbox/events, guardrail policies, managed
--     and self-hosted worker stores -> CONTROL (split rule (d): whole-table
--     cross-tenant analytics reads).
--   * PORT-TODO(inventory-data-billing §4 "x402"): the `payment_attempts` table
--     backing `packages/storage/src/payment-attempt.ts` (the #396/#352
--     generation-guarded CAS) is NOT created here. Per the standing user
--     directive x402/Solana payment slices are deprioritized, and the Rust D1
--     file never defined the table either. The in-memory port stays; the DDL
--     and its CAS land with the x402 slice. The one wallet-side consequence IS
--     honored below: `wallet_reservations` keeps `settlement_id`, and the
--     payment-attempt hold-protection guard (`sweepExpiredWalletReservations`
--     never sweeping an owned hold) is enforced in application code until the
--     owning table exists.
--
-- DIALECT: identical to the control file (JSONB->TEXT, BIGINT->INTEGER,
-- BOOLEAN->INTEGER 0/1, DOUBLE PRECISION->REAL, no cross-table FKs, no RLS,
-- descriptive-enum CHECKs dropped). COLUMN NAMES ARE PARITY with
-- `sql/d1/001_init_d1.sql`.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ---------------------------------------------------------------------------
-- Hierarchy below the tenant: Project -> Workspace
--
-- Tenant-routed exactly as the Rust D1 backend routed them
-- (`control_plane_store_d1/core_entities.rs`: writes route on `tenant_id`).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant
    ON projects(tenant_id);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (project_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_project
    ON workspaces(project_id);

CREATE INDEX IF NOT EXISTS idx_workspaces_tenant
    ON workspaces(tenant_id);

-- ---------------------------------------------------------------------------
-- Virtual (native) API keys — the AUTHORITATIVE row
--
-- Column-for-column from the Rust D1 file. The control database holds only the
-- narrow `api_key_directory` lookup index (hash -> tenant + the two lifecycle
-- bits); EVERYTHING that describes what a key may DO — scopes, model and
-- provider allowlists, per-key token budget, per-key RPM — is tenant data and
-- stays physically isolated here.
--
-- `key_hash` is the hash, never the credential. `last4`/`key_prefix` exist for
-- console display only.
--
-- The dual-write ordering rule that keeps the two copies fail-closed is stated
-- in the control migration's `api_key_directory` header. Read it before
-- writing either table.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last4 TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    allowed_models_json TEXT NOT NULL DEFAULT '[]',
    allowed_providers_json TEXT NOT NULL DEFAULT '[]',
    monthly_token_budget INTEGER,
    request_limit_per_minute INTEGER,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    rotated_at_unix INTEGER,
    expires_at_unix INTEGER,
    revoked_at_unix INTEGER
);

CREATE INDEX IF NOT EXISTS idx_api_keys_workspace
    ON api_keys(workspace_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_project
    ON api_keys(tenant_id, project_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
    ON api_keys(key_prefix);

-- NEW (this rewrite): the hash lookup within the tenant database, so the second
-- leg of authentication (directory -> tenant DB -> full key row) is a point
-- lookup rather than a scan. UNIQUE because a hash identifies exactly one key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash
    ON api_keys(key_hash);

-- ===========================================================================
-- WALLETS + RESERVATIONS + SETTLEMENTS  (#169/#281, inventory §1.5.1/§1.5.2)
--
-- Prepaid-credit FINANCIAL state. Balances are INTEGER CREDITS — never REAL —
-- so no float drift can create or destroy money. (`credits_per_usd` is
-- 1_000_000, i.e. 1 credit = 1 micro-USD; the conversion happens in
-- `@ferrogate/billing`, and only the integer lands here.)
--
-- These tables are ported column-for-column rather than as `*_json` documents
-- specifically because the no-oversell guard does REAL SQL ARITHMETIC on
-- `balance_credits` and `SUM(amount_credits)`. A document row could not serve
-- that guard: SQLite would have to materialize and re-parse JSON per row inside
-- the guard's subquery, and the atomicity would be lost.
--
-- THE KEYSTONE PROOF (`D1WalletStore.reserveWalletCredits`): ONE `batch()` of
-- three statements —
--   S0  idempotency probe by hold id;
--   S1  guarded `INSERT ... SELECT ... FROM wallets w WHERE w.tenant_id = ?
--         AND ? <= w.balance_credits - COALESCE((SELECT SUM(r.amount_credits)
--         FROM wallet_reservations r WHERE r.tenant_id = ? AND r.status =
--         'active' AND r.expires_at_unix > ?), 0)
--         ON CONFLICT (id) DO NOTHING RETURNING id`  -- empty = not admitted;
--   S2  wallet-state read that splits `no_wallet` from `insufficient`.
-- D1 has no `SELECT ... FOR UPDATE`, but a `batch()` is ONE implicit
-- transaction and SQLite serializes writers per database, so the guard is
-- re-evaluated against committed state inside the same transaction as the
-- insert. N parallel reserves against a balance affording N-1 admit exactly
-- N-1.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS wallets (
    -- Deterministic: equal to `tenant_id` (a tenant has at most one wallet).
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL UNIQUE,
    balance_credits INTEGER NOT NULL DEFAULT 0,
    auto_recharge_threshold_credits INTEGER,
    auto_recharge_amount_credits INTEGER,
    dunning INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

-- One durable row per hold. `settlement_id` (equal to the hold id) is set when
-- the hold captures, linking the ledger charge back to its originating hold.
-- The active, unexpired holds are summed against `balance_credits` to compute
-- AVAILABLE balance for the no-oversell guard.
--
-- `status` is 'active' | 'settled' | 'released'. No CHECK (descriptive enum,
-- validated before the write) — but note the guard SQL depends on the exact
-- literal 'active'; the constant lives in `packages/storage/src/wallet.ts`
-- (`WALLET_RESERVATION_ACTIVE`) and the D1 statements interpolate nothing.
CREATE TABLE IF NOT EXISTS wallet_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount_credits INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at_unix INTEGER NOT NULL,
    settlement_id TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wallet_reservations_tenant_status
    ON wallet_reservations(tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_wallet_reservations_active_expiry
    ON wallet_reservations(expires_at_unix);

-- NEW (this rewrite): the exact shape of the no-oversell guard's SUM subquery
-- (`tenant_id`, `status`, `expires_at_unix`). The Rust file's two separate
-- indexes cover the prefix but leave the expiry predicate to a row check; this
-- covering index lets the hottest statement in the money path stay index-only.
-- Additive: no column renamed, no constraint changed.
CREATE INDEX IF NOT EXISTS idx_wallet_reservations_live_holds
    ON wallet_reservations(tenant_id, status, expires_at_unix, amount_credits);

-- One durable row per settled debit/credit. Claiming this id and moving the
-- balance commit together in ONE batch, so a replay returns the first outcome
-- instead of debiting twice — idempotency is the PRIMARY KEY, not a flag.
CREATE TABLE IF NOT EXISTS wallet_settlements (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    delta_credits INTEGER NOT NULL,
    balance_after_credits INTEGER,
    created_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wallet_settlements_tenant_time
    ON wallet_settlements(tenant_id, created_at_unix DESC);

-- Payment methods (#169). Provider customer/payment-method ids only — no PAN,
-- no token secret. Deterministic id `{tenant}:{provider}:{provider_pm_id}`.
CREATE TABLE IF NOT EXISTS payment_methods (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_customer_id TEXT NOT NULL,
    provider_payment_method_id TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    UNIQUE (tenant_id, provider, provider_payment_method_id)
);

CREATE INDEX IF NOT EXISTS idx_payment_methods_tenant
    ON payment_methods(tenant_id);

-- ===========================================================================
-- USAGE / METERING ROLLUPS  (#171/#226, inventory §1.5.6)
--
-- The read side of "current month cumulative cost for scope X" that monthly
-- budget enforcement and the usage/cost report API both consume. Tenant-scoped:
-- a tenant's rollups across EVERY scope level it owns live here.
--
-- The `usage_monthly_rollups.scope_type` CHECK is the SECOND deliberate
-- exception to "enumeration CHECKs are dropped" (the first is the membership
-- `role` tier in the control file). It is kept verbatim from BOTH the Rust
-- Postgres and D1 files because this column is the JOIN KEY of the
-- quota-resolution chain: a typo'd scope silently creates a parallel rollup
-- that no budget check ever reads, and the spend becomes invisible.
-- ===========================================================================

-- The tenant/project/api-key identity a usage aggregate is attributed to.
-- Referenced by `usage_aggregate_rollups.tenant_context_id` BY VALUE (the
-- Postgres FK is dropped for physical isolation).
--
-- NOTE `organization_id` is the BILLING/attribution identity and is a DIFFERENT
-- column from the routing `tenant_id` used elsewhere. Do not conflate them.
CREATE TABLE IF NOT EXISTS tenant_contexts (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    team_id TEXT,
    project_id TEXT,
    workspace_id TEXT,
    user_id TEXT,
    api_key_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_tenant_contexts_org_project
    ON tenant_contexts(organization_id, project_id);

CREATE INDEX IF NOT EXISTS idx_tenant_contexts_api_key
    ON tenant_contexts(api_key_id);

-- Per-(tenant_context, model, provider) cumulative token totals. Written
-- together with its `tenant_contexts` row as ONE atomic batch
-- (`persist_usage_aggregate`), so a rollup can never reference a context row
-- that does not exist.
CREATE TABLE IF NOT EXISTS usage_aggregate_rollups (
    id TEXT PRIMARY KEY,
    tenant_context_id TEXT NOT NULL,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_usage_rollups_tenant_model_provider
    ON usage_aggregate_rollups(tenant_context_id, logical_model, provider);

-- One row per (period_month, scope_type, scope_id); incremented on every
-- settled request. Deterministic id `{period_month}:{scope_type}:{scope_id}`
-- (`usageMonthlyRollupId`), so the accumulate is an idempotent-by-tuple upsert
-- with no lookup-then-insert step.
CREATE TABLE IF NOT EXISTS usage_monthly_rollups (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'project', 'workspace', 'key')),
    scope_id TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (period_month, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_usage_monthly_rollups_scope
    ON usage_monthly_rollups(scope_type, scope_id, period_month);

CREATE INDEX IF NOT EXISTS idx_usage_monthly_rollups_period
    ON usage_monthly_rollups(period_month);

-- Per-calendar-month usage/cost rollup keyed by an arbitrary caller-supplied
-- metadata key/value pair, scoped to the originating organization (#171/#226).
-- `organization_id` defaults to '' (not NULL) so the deterministic id
-- `{period}:{org}:{key}:{value}` is total — a NULL would make two different
-- rows collide on the same id.
CREATE TABLE IF NOT EXISTS usage_metadata_rollups (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    organization_id TEXT NOT NULL DEFAULT '',
    metadata_key TEXT NOT NULL,
    metadata_value TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_usage_metadata_rollups_org_key
    ON usage_metadata_rollups(organization_id, metadata_key, period_month);

-- ===========================================================================
-- HOSTED ASSETS + CHANNELS + RETENTION  (#176/#260/#263/#366/#371)
-- ===========================================================================

-- The Rust D1 file stored inline bytes in a base64 TEXT `content` column
-- because the D1 HTTP proxy binds every param as TEXT. This rewrite runs INSIDE
-- a Worker with R2 available, and inventory §1.7 is explicit that inline BYTEA
-- should move to R2 — so `content` is DROPPED and `storage_uri` (the R2 object
-- key, derived from `content_hash`) is the only body pointer.
--
-- This is a deliberate DIVERGENCE, not an omission, and it is the one place
-- this file does not keep a Rust column. Recorded here so it is auditable:
--   * removed : `content TEXT NOT NULL`  (base64 inline body, <= 10 MiB)
--   * kept    : `content_hash` (sha256) and `size_bytes`, which is everything
--               the quota-admission guard reads — that guard never touched the
--               bytes.
--   * kept    : `storage_uri`, now REQUIRED in practice rather than optional.
-- PORT-TODO(inventory-request-path §1.6 "Object storage"): the asset handlers
-- must write the R2 object BEFORE this row and delete-on-rollback, since there
-- is no transaction spanning R2 and D1. Until that ordering lands in
-- `apps/gateway/src/assets/`, `storage_uri` stays nullable so an in-flight
-- upload is representable.
CREATE TABLE IF NOT EXISTS stored_assets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    storage_uri TEXT,
    variant TEXT NOT NULL DEFAULT '',
    yanked INTEGER NOT NULL DEFAULT 0,
    visibility TEXT NOT NULL DEFAULT 'visible',
    UNIQUE (tenant_id, asset_type, name, version, variant)
);

-- Leftmost-prefix index covering "list everything for a tenant", "list one
-- asset_type for a tenant", and the ORDER BY name, version listing.
CREATE INDEX IF NOT EXISTS idx_stored_assets_tenant_type_name
    ON stored_assets(tenant_id, asset_type, name, version);

-- NEW (this rewrite): the cumulative asset-storage quota guard sums
-- `size_bytes` per tenant on every push (`assetQuotaAdmission`). Covering index
-- so the admission check is index-only instead of a table scan that grows with
-- the tenant's asset count.
CREATE INDEX IF NOT EXISTS idx_stored_assets_tenant_size
    ON stored_assets(tenant_id, size_bytes);

-- Mutable channel pointers (latest/stable/canary + free-form tags) resolved to
-- a concrete version at pull time (#260). The deterministic id equals
-- `{tenant}:{asset_type}:{name}:{channel}`, so the id PK and the composite
-- UNIQUE encode the SAME logical channel; a move is an upsert by id.
CREATE TABLE IF NOT EXISTS asset_channels (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (tenant_id, asset_type, name, channel)
);

CREATE INDEX IF NOT EXISTS idx_asset_channels_lookup
    ON asset_channels(tenant_id, asset_type, name);

-- Generalizable retention rules (#263): keep the newest `keep_last_n` and/or
-- anything younger than `max_age_secs`, NEVER touching anything younger than
-- `min_age_secs` (the safety grace window). All-NULL size/age dimensions is a
-- pure no-op — the fail-safe default, so a half-configured policy deletes
-- nothing rather than everything.
CREATE TABLE IF NOT EXISTS retention_policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '*',
    keep_last_n INTEGER,
    max_age_secs INTEGER,
    min_age_secs INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_retention_policies_tenant_resource
    ON retention_policies(tenant_id, resource_type);

-- ===========================================================================
-- WORKFLOW-RUN EXECUTION BUDGETS  (#279, inventory §1.5.3)
--
-- One row per (workflow_id@workflow_version, run_id) that each step debits.
-- A NULL cap means that dimension is UNBOUNDED; the `spent_*` columns
-- accumulate monotonically per dimension; a debit breaching ANY capped
-- dimension is rejected FAIL-CLOSED WITHOUT applying spend and flips `status`
-- to 'exhausted'; a top-up raises the caps and flips it back to 'active'.
--
-- D1/SQLite has NO `SELECT ... FOR UPDATE`, so the debit cannot serialize
-- concurrent steps on a row lock. It uses an OPTIMISTIC CAS instead: read the
-- counters, then a guarded
--   `UPDATE ... WHERE id = ? AND status = 'active'
--      AND spent_credits = ? AND spent_tokens = ? AND spent_tool_calls = ?
--      AND <the four caps are IS-identical to the read> RETURNING ...`
-- An empty RETURNING set means a concurrent debit or top-up committed between
-- the read and the write -> bounded re-read + retry
-- (`WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS`). Because the write only lands when the
-- guard still matches the read, and `spent_* = spent_* + delta` runs inside
-- SQLite's per-database serialized writer, N concurrent steps against a
-- tool-call budget of K let exactly K through — the same no-overspend property
-- the Postgres row lock gave, with ZERO change to the debit contract.
--
-- The caps are part of the guard (not just the counters) precisely so a
-- concurrent TOP-UP invalidates an in-flight debit's decision: the debit
-- decided `exceeded` against the old cap, and must re-decide against the new
-- one instead of writing a stale verdict.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS workflow_run_budgets (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    workflow_version INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    cost_budget_credits INTEGER,
    token_budget INTEGER,
    tool_call_budget INTEGER,
    wall_clock_deadline_unix INTEGER,
    spent_credits INTEGER NOT NULL DEFAULT 0,
    spent_tokens INTEGER NOT NULL DEFAULT 0,
    spent_tool_calls INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

-- The admin per-tenant budget listing filters by tenant_id; the run lookup
-- (open/debit/topup/get) is by primary key, so no separate run_id index.
CREATE INDEX IF NOT EXISTS idx_workflow_run_budgets_tenant
    ON workflow_run_budgets(tenant_id);

-- ===========================================================================
-- AGENT SCHEDULES + FIRE HISTORY  (#246)
--
-- The Postgres fire-log `ON DELETE CASCADE` onto `agent_schedules` is dropped
-- (no cross-table FK in this dialect), so `deleteAgentSchedule` must cascade
-- the fire rows ITSELF as one atomic `batch()`. That is not a nicety: without
-- it, deleting and recreating a schedule with the same id would inherit the old
-- fire ledger and silently suppress the new schedule's first fires.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS agent_schedules (
    schedule_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    spec_kind TEXT NOT NULL,
    cron_expr TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    interval_secs INTEGER,
    target_kind TEXT NOT NULL,
    target_json TEXT NOT NULL DEFAULT '{}',
    overlap_policy TEXT NOT NULL DEFAULT 'skip',
    catchup_policy TEXT NOT NULL DEFAULT 'skip_missed',
    jitter_secs INTEGER NOT NULL DEFAULT 0,
    next_fire_at_unix INTEGER,
    last_fire_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
);

-- Due-schedule scan: enabled rows whose next_fire_at has arrived, cheapest
-- first. The partial index keeps the hot path off disabled/unscheduled rows.
CREATE INDEX IF NOT EXISTS idx_agent_schedules_due
    ON agent_schedules(next_fire_at_unix ASC)
    WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_schedules_tenant
    ON agent_schedules(tenant_id, workspace_id, name);

-- Durable fire history + idempotency ledger. One row per (schedule, slot); the
-- UNIQUE plus `ON CONFLICT DO NOTHING` makes a slot fire AT MOST ONCE across
-- every gateway isolate racing the same tenant database. This is the whole
-- at-most-once gate — there is no lock anywhere else in the schedule path.
CREATE TABLE IF NOT EXISTS agent_schedule_fires (
    fire_id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL,
    scheduled_fire_at_unix INTEGER NOT NULL,
    fired_at_unix INTEGER NOT NULL,
    node_id TEXT,
    outcome TEXT NOT NULL,
    dispatch_id TEXT,
    run_id TEXT,
    detail TEXT,
    UNIQUE (schedule_id, scheduled_fire_at_unix)
);

CREATE INDEX IF NOT EXISTS idx_agent_schedule_fires_history
    ON agent_schedule_fires(schedule_id, scheduled_fire_at_unix DESC);

-- ===========================================================================
-- OBSERVED-AGENT PRESENCE  (#357, inventory §1.5.6 monotonic upserts)
--
-- ONE short conditional upsert per (tenant_id, api_key_id) recording the MAX
-- last-seen timestamp and a COALESCED request count, so a burst of touches for
-- one virtual key never grows the table.
--
-- The upsert uses SQLite's SCALAR `max(x, y)` / `min(x, y)` — SQLite has NO
-- GREATEST/LEAST, and the two-argument `max`/`min` are scalar functions, not
-- the aggregates of the same name. That keeps last-seen monotonic and
-- first-seen minimal even under a DELAYED touch that arrives out of order:
-- without it, a retried/queued touch carrying an older timestamp would move
-- `last_seen_at_unix` BACKWARDS and the presence window would lose the agent.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS observed_agent_presence (
    tenant_id TEXT NOT NULL,
    api_key_id TEXT NOT NULL,
    first_seen_at_unix INTEGER NOT NULL,
    last_seen_at_unix INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, api_key_id)
);

-- Tenant-scoped window read (recent presence, newest first) served straight
-- from the index; also the target of the coalescing upsert.
CREATE INDEX IF NOT EXISTS idx_observed_agent_presence_tenant_last_seen
    ON observed_agent_presence(tenant_id, last_seen_at_unix DESC);

-- Platform-operator cross-tenant window read (per database; the operator view
-- fans out over tenant databases and merge-sorts).
CREATE INDEX IF NOT EXISTS idx_observed_agent_presence_last_seen
    ON observed_agent_presence(last_seen_at_unix DESC);

-- ===========================================================================
-- AGENT COST BURN  (#428)
--
-- Durable per-agent cost accumulation: one row per (tenant_id, agent_key,
-- period), bumped by an atomic upsert so a per-agent budget survives a restart.
-- `accumulated_usd` is REAL (money in USD here, NOT credits) mirroring
-- `quota_policies.agent_cost_budget_usd`, which is the value it is compared
-- against — keeping both REAL is what makes the comparison exact.
-- `first_seen_unix` is min()-folded for the same out-of-order reason as
-- presence above.
-- ===========================================================================
CREATE TABLE IF NOT EXISTS agent_cost_burn (
    tenant_id TEXT NOT NULL,
    agent_key TEXT NOT NULL,
    period TEXT NOT NULL,
    accumulated_usd REAL NOT NULL DEFAULT 0,
    first_seen_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, agent_key, period)
);

-- ---------------------------------------------------------------------------
-- Record the migration LAST.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '0001_init_tenant');
