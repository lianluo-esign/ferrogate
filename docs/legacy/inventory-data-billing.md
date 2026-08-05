# Legacy Inventory — DATA & BILLING cluster

> **Historical inventory, superseded 2026-08-05 for tenant storage.** The
> D1-per-tenant and proxy material below records the Rust-era reference design.
> Current FerroGate uses one CONTROL D1 database and one SQLite Durable Object
> per tenant; see
> [`per-tenant-durable-object-storage-2026-08.md`](../design/per-tenant-durable-object-storage-2026-08.md).
> This inventory is retained without rewriting its original evidence.

Rust → TypeScript (Cloudflare Workers: Bun + Hono + Zod + full CF suite) 1:1 rewrite.
Cluster crates: `ferrogate-storage`, `ferrogate-billing`, `ferrogate-payments`, `ferrogate-observability`.

Source of truth for this doc: crate sources under `crates/ferrogate-*/src`, the DDL under
`sql/001_init_postgres.sql` (Postgres, **schema version 59**), `sql/d1/001_init_d1.sql`
(the already-drafted Cloudflare D1 / SQLite target), and `sql/clickhouse/001_init_analytics.sql`.

> Big-picture: the Rust codebase **already contains a partial Cloudflare port**. There is a
> `StorageProviderKind::CloudflareD1` backend (`control_plane_store_d1/`), a hand-written D1 SQLite
> schema (`sql/d1/001_init_d1.sql`), a **database-per-tenant** topology, and a **`d1-proxy` Worker**
> (`workers/d1-proxy/`) that exposes native D1 `batch()`/`RETURNING` over HTTP because the D1 REST
> query API cannot do transactions. The TS rewrite should treat the D1 backend as the reference
> design, not invent a new mapping. Many of the hard decisions (RLS removal, FK removal, JSONB→TEXT,
> `FOR UPDATE`→optimistic CAS) are already made and documented in `docs/cloudflare-d1-backend.md`.

---

## 0. Cluster dependency graph and shared types

```
ferrogate-payments   (leaf: no FerroGate deps; base64/serde/serde_json/sha2)
      ▲        ▲
      │        │
ferrogate-billing ── depends on ferrogate-core, ferrogate-payments
      ▲
      │
ferrogate-storage ── depends on ferrogate-core, ferrogate-billing, ferrogate-payments,
                     ferrogate-cloudflare (D1/R2 clients), deadpool-postgres,
                     tokio-postgres, native-tls, croner, chrono/chrono-tz
ferrogate-observability  (leaf-ish: only serde_json + tracing; NO storage/network I/O)
```

Acyclic by design. `ferrogate-payments` deliberately declares **no FerroGate dependency** so
`ferrogate-storage` can depend on it for the x402 payment-attempt state alphabet without a cycle.
`ferrogate-billing` is storage-free: the durable `LedgerSink`/`BillingEventRepository` live in
`ferrogate-storage`, which already depends on billing.

Shared core type: `ferrogate_core::TenantContext` — `{ organization_id, team_id, project_id,
workspace_id, user_id, api_key_id }` (all `Option<String>`). This is the attribution tuple threaded
through every billing event, ledger entry, and metering row.

---

# 1. `ferrogate-storage`

## 1.1 Purpose
Repository/persistence boundary for the entire FerroGate control plane and its high-write
append/analytics stores. Owns the SQL schema, three interchangeable backends (in-memory, Postgres/
Supabase, Cloudflare D1), schema migration + validation, and every concurrency-critical transaction
(wallet holds, workflow budgets, payment-attempt CAS, guardrail-binding CAS). This is by far the
largest and hardest crate to port (`src/lib.rs` alone is ~18.4k lines).

## 1.2 Public API surface

**Backend selection / lifecycle**
- `enum StorageProviderKind { Memory, Supabase, TursoLibsql, Postgres, Mysql, CloudflareD1 }` —
  `.as_str()`, `.is_durable()`, `.implemented()` (implemented set = Memory, Supabase, Postgres,
  CloudflareD1; Turso/MySQL are declared but not implemented).
- `struct PostgresStorageConfig { dsn, pool_size, pool_acquire_timeout_millis, tls_mode,
  tls_ca_cert_path, connect_timeout_secs, statement_timeout_millis, schema, search_path }`.
- `enum PostgresTlsMode { Disable, Prefer, Require, VerifyCa, VerifyFull }`.
- `struct RuntimeStorageOptions`, `struct RuntimeStorageBackend`, `struct RuntimeStorageRepositories`
  (the top-level object the gateway holds; ~1500-line impl of every repo method dispatching to the
  active backend), `struct RuntimeControlPlaneState` (the in-memory document store).
- `struct StorageBackendEvidence`, `struct StorageSchemaEvidence` (engine/version/name/checksum/
  validated), `PostgresPoolMetricsSnapshot`.
- `enum StorageError` — the crate-wide error type (`NotFound`, `Conflict`, `AlreadyExists`,
  `Serialization`, `Postgres(String)`, `Runtime(String)`, `OperationDeadlineExceeded{operation,stage,
  commit_started}`, …). All Postgres error strings pass through `sanitize_storage_error` (DSN/secret
  scrubbing).
- `struct StorageOperation` / `enum StorageOperationCancelOutcome` — the async-storage commit-fence
  primitive that lets a cancelled/timed-out op distinguish "never committed" from "outcome unknown".

**Repository traits** (thin marker traits over generic `Repository<T>` / `AppendRepository<T>`):
`ApiKeyRepository`, `TenantRepository`, `PolicyRepository`, `RequestLogRepository`,
`AuditLogRepository`, `BillingEventRepository`, `UsageAggregateRepository`, `AgentRunRepository`,
`AgentRunEventRepository`, `ManagedWorkerTemplateRepository`, `AgentWorkerInstanceRepository`,
`ManagedWorkerSessionRepository`, `ManagedWorkerLifecycleEventRepository`, self-hosted-worker
repositories (registration/heartbeat/telemetry/artifact/checkpoint/dispatch),
`GuardrailPolicyRepository`, `SnapshotReplayFloorRepository`.

**The central engine trait** `pub(crate) trait ControlPlaneStore` (in `control_plane_store.rs`, ~880
lines of method signatures) — the async abstraction every backend implements. One trait, three impls
(`MemoryControlPlaneStore`, `PostgresControlPlaneStore`, `D1ControlPlaneStore`), dispatched via
`RuntimeControlPlaneBackend::store() -> &dyn ControlPlaneStore`. Covers: api-keys, admin users +
memberships + refresh tokens, SSO config + pending flows, tenant accounts, projects, workspaces,
quota policies, plans, assets + channels + retention, usage rollups, billing ledger + report outbox +
metering events, guardrail revisions/bindings CAS, replay floors, request/audit logs, agent runs +
events, managed + self-hosted worker stores, site domains + DNS verification, per-metadata usage
rollups, observed-agent presence, agent cost burn, budget-alert idempotency, workflow-run budgets,
RBAC (permissions/roles/bindings), agent schedules + fires, wallets + reservations + payment methods,
payment attempts + the single CAS transition seam.

**~120 `Stored*` DTO structs** (row shapes): `StoredApiKey`, `StoredTenant`, `StoredTenantAccount`,
`StoredPlan`, `StoredAsset` (+ `AssetVisibility`, `AssetQuotaAdmission`, `StoredAssetChannel`,
`AssetPromotionTarget`, `AssetVisibilityPromotionOutcome`), `StoredProject`, `StoredWorkspace`,
`StoredAdminUser` + membership + refresh token, `StoredSsoProviderConfig`, `StoredSsoPendingFlow`,
`StoredQuotaPolicy` (+ `QuotaScopeKind`, `validate_quota_policy`), `StoredUsageMonthlyRollup`,
`StoredUsageMetadataRollup`, `StoredWallet`, `StoredWalletReservation`, `StoredWalletSettlement`,
`StoredPaymentMethod`, `StoredPaymentAttempt` (+ query/page/links/transition types),
`StoredWorkflowRunBudget` (+ `WorkflowRunBudgetCaps`, `WorkflowBudgetDebit`), `StoredAgentSchedule` +
`StoredAgentScheduleFire`, `StoredSiteDomain` + `StoredSiteDomainVerification`,
`StoredObservedAgentPresence`, `StoredAgentCostBurn`, `StoredBudgetAlertNotification`,
`StoredPermission`/`StoredRole`/`StoredTenantRoleBinding`, `StoredGuardrailPolicyRevision`/`Binding`,
`StoredRequestLog`, `StoredAuditEvent`, `StoredUsageAggregate`, `StoredAgentRun`/`Event`, all the
managed/self-hosted worker rows, `ControlPlaneOverviewAggregate` + `OverviewUsageTotals` +
`QuotaPressureScope` + `PolicyGovernanceCounts` (the #339 overview endpoint aggregate).
- Deterministic id helpers: `stored_asset_id`, `stored_asset_variant_id`, `asset_channel_id`,
  `quota_policy_id`, `usage_monthly_rollup_id`, `usage_metadata_rollup_id`, `agent_cost_burn_key`,
  `budget_alert_notification_id`, `tenant_role_binding_id`, `guardrail_policy_revision_id`,
  `period_month_from_unix` (`YYYY-MM` UTC), `sha256_hex`.

## 1.3 Backends and topology

Three `ControlPlaneStore` implementations behind one enum:

1. **`MemoryControlPlaneStore`** — `Mutex<RuntimeControlPlaneState>` plus a set of bounded in-memory
   append repositories (`InMemoryRepository`, `InMemoryAppendRepository`,
   `InMemoryAgentRunEventRepository`, `InMemoryWorkerScopedRepository`). Store of record for tests and
   ephemeral deploys; also the read-modify-write baseline mirror on durable backends. All append
   stores are **bounded** with oldest-eviction (issue #231 — heartbeats/telemetry come from untrusted
   self-hosted workers, so an uncapped store is a DoS vector).

2. **`PostgresControlPlaneStore`** — Supabase/Postgres over `deadpool-postgres` + `tokio-postgres` +
   `native-tls`. `control_plane_store_postgres.rs` (~2090 lines) + a large chunk of `lib.rs` inherent
   methods + `postgres_row_mappers.rs`. This is the **production** backend today.

3. **`D1ControlPlaneStore`** — Cloudflare D1 (SQLite). `control_plane_store_d1/` (mod.rs ~2486 lines +
   14 submodules: agent_schedule, assets, auth_quota, billing, client, client_config,
   config_documents, core_entities, guardrail, observability, observed_presence, provisioning,
   rbac_site_domain, rows, usage, wallet, worker_stores, workflow_budget). **This is the CF target
   reference implementation.**

### D1 topology (the model the TS port should adopt)
- **Database-per-tenant + one control database.** Physical isolation replaces row-level tenant
  fencing. `tenants` and account-global config (admin users, SSO, quota policies, plans, RBAC, site
  domains, budget alerts, all observability/billing/worker analytics families) live **only in the
  control database**. Each tenant's financial + usage + asset + schedule state lives in **that
  tenant's own D1 database**.
- **Routing** (`control_plane_store_d1/client.rs`): `control_database_id()`,
  `database_for_tenant(tenant_id)` (empty tenant → control DB), `tenant_proxy_binding(tenant_id)` →
  a Worker binding NAME (there is **no runtime select-DB-by-id**; the binding must be declared in
  wrangler config and redeployed per tenant), `fan_out_database_ids()` (control DB first then every
  tenant DB, for id-only reads and unfiltered lists), `provisioned_tenant_bindings()`.
- **Two transports:**
  - `D1Client` (REST, `crates/ferrogate-cloudflare/src/d1.rs`) — the public D1 HTTP query API. Used
    for the **non-atomic** surface: provisioning, schema migration, CRUD, config documents. **No
    multi-statement-with-params transaction, no `RETURNING`.**
  - `D1ProxyClient` (`d1_proxy.rs`) — a thin Rust client over the deployed **`d1-proxy` Worker**
    (`workers/d1-proxy/`), which holds a **native D1 binding** and can run `prepare().bind()`,
    `batch()` (atomic), and `RETURNING`, exposed as a bearer-authed HTTP API. Used for the **atomic
    hot path** (`D1ProxyStatement{sql, params}`, `.batch()/.batch_on(binding)`,
    `.query()/.query_on(binding)`). Params bind as **strings** (SQLite affinity coerces; booleans are
    `"1"`/`"0"`; SQL NULL via `NULLIF(?, '')` + empty-string bind).
- **Fan-out for id-only ops.** `settle`/`release` reservations, `debit`/`topup`/`get` workflow
  budgets, `get`/`delete` asset, schedule get/delete/fire — the trait signature carries only an entity
  id, so the impl fans out over provisioned tenant bindings to find the holding DB, then runs the
  guarded transition on it. Operator cross-tenant lists fan out + re-sort in process to match the
  Postgres `ORDER BY`.
- **Deferred on D1 (still return typed `unimplemented-backend-surface`):**
  `sweep_expired_wallet_reservations` (its money-safety guard reads `payment_attempts.hold_id`),
  payment methods + `transition_payment_attempt` (x402 — deprioritized), and MCP identity. Everything
  else is implemented.

## 1.4 FULL SCHEMA (Postgres v59 → D1/SQLite)

Complete DDL: `sql/001_init_postgres.sql` (2684 lines, 59 migrations) and `sql/d1/001_init_d1.sql`
(D1/SQLite core). Below is the complete table roster grouped by domain. All timestamps are
`*_at_unix BIGINT` epoch seconds (SQLite `INTEGER`, default `unixepoch()`; Postgres default
`EXTRACT(EPOCH FROM NOW())::BIGINT`). All `*_json` columns are Postgres `JSONB` → SQLite `TEXT`.

### 1.4.1 Universal dialect divergences (Postgres → D1/SQLite)
| Postgres | D1/SQLite | Notes |
|---|---|---|
| `JSONB` (+ GIN index, `jsonb_build_object`, `->>`) | `TEXT` (parse in app; **no JSON index**) | `control_plane_resources.document_json` loses its GIN index; any JSONB query operator must move to app code or a projection column. |
| `BIGINT` | `INTEGER` (64-bit) | fine. |
| `DOUBLE PRECISION` | `REAL` | money columns (`cost_usd`, `monthly_budget_usd`, `accumulated_usd`). |
| `BOOLEAN` | `INTEGER` 0/1 | decode `!= 0`. |
| `BYTEA` (asset `content`, MCP token ciphertext/nonce) | `TEXT` base64 | inline asset bytes ride a base64 TEXT column; large blobs must move to **R2**. |
| cross-table `FOREIGN KEY` (+ `ON DELETE CASCADE`) | **dropped** | referential integrity enforced in app; cascades done manually as one `/d1/batch` (e.g. `delete_agent_schedule` cascades its fires). |
| `CHECK (x IN (...))` enum constraints | **mostly dropped** (validated in Rust) | **exceptions kept**: `admin_user_tenant_memberships.role`, `usage_monthly_rollups.scope_type`. |
| Row-Level Security (`ENABLE RLS` + policies) | **dropped** | replaced by physical DB-per-tenant isolation. |
| `SELECT ... FOR UPDATE` | **no equivalent** | replaced by atomic `/d1/batch` + optimistic guarded `UPDATE ... RETURNING` CAS. |
| `INSERT ... RETURNING`, `GREATEST`/`LEAST` | proxy-Worker only; `max(x,y)`/`min(x,y)` scalars | REST API has no `RETURNING`; SQLite has no `GREATEST`/`LEAST`. |
| `EXTRACT(EPOCH FROM NOW())` | `unixepoch()` | default timestamps. |
| partial indexes `WHERE ...` | supported by SQLite | mostly port unchanged. |
| `SMALLINT` | `INTEGER` | `budget_alert_notifications.threshold_pct`. |

### 1.4.2 Multi-tenant hierarchy & identity (control DB)
- **`tenants`** — `id PK, name, slug UNIQUE, status DEFAULT 'active', plan_id NOT NULL DEFAULT 'free'
  → plans(id), created/updated_at_unix`.
- **`projects`** — `id PK, tenant_id → tenants ON DELETE CASCADE, name, slug, status,
  UNIQUE(tenant_id, slug)`. idx: `projects(tenant_id)`.
- **`workspaces`** — `id PK, project_id → projects CASCADE, tenant_id → tenants CASCADE, name, slug,
  environment DEFAULT 'default', status, UNIQUE(project_id, slug)`. idx on project, tenant.
- **`api_keys`** — `id PK, workspace_id/tenant_id/project_id (all → CASCADE), name, key_prefix,
  key_hash, last4, enabled BOOL, scopes_json, allowed_models_json, allowed_providers_json,
  monthly_token_budget BIGINT?, request_limit_per_minute BIGINT?, rotated/expires/revoked_at_unix?`.
  idx: workspace; (tenant,project); key_prefix.
- **`admin_users`** — `id PK, email UNIQUE, password_hash, display_name, superadmin BOOL,
  last_login/disabled_at_unix?`.
- **`admin_user_tenant_memberships`** — `id PK, user_id → admin_users CASCADE, tenant_id → tenants
  CASCADE, role CHECK IN (owner,admin,member,viewer), UNIQUE(user_id, tenant_id)`. **CHECK kept in
  D1** (privilege tier). idx user, tenant.
- **`admin_user_refresh_tokens`** — `id PK, user_id → CASCADE, token_hash UNIQUE, tenant_id?, role?,
  expires_at_unix, revoked_at_unix?`. Stored hashed. idx user, hash, (user,tenant).
- **`sso_provider_configs`** — `tenant_id PK → tenants CASCADE, provider_kind CHECK IN (oidc,saml),
  default_role, group_role_mapping_json, oidc_* fields (client secret is a `secret_ref` URI, never
  plaintext), saml_* fields`.
- **`sso_pending_flows`** — `state PK, tenant_id, provider_kind, code_verifier?, request_id?,
  expires_at_unix`. idx expiry.
- **`permissions`** — `id PK, key UNIQUE, name, description`.
- **`roles`** — `id PK, name, slug UNIQUE, description, permission_keys_json`.
- **`tenant_role_bindings`** — `id PK, tenant_id → tenants, role_id → roles, UNIQUE(tenant_id,
  role_id)`. idx tenant.

### 1.4.3 Quota / plans / budget-alerts (control DB)
- **`quota_policies`** — `id PK, scope_type CHECK IN (tenant,project,workspace,key), scope_id,
  model_allowlist_json, rpm_limit?, tpm_limit?, monthly_budget_usd DOUBLE?, enabled BOOL,
  alert_threshold_pcts_json, asset_storage_quota_bytes? (tenant-only CHECK),
  monthly_egress_bytes_budget?, download_rpm_limit?, asset_max_object_bytes? (tenant-only),
  agent_cost_budget_usd DOUBLE? (any scope), UNIQUE(scope_type, scope_id)`. **Effective-quota merge
  (key→workspace→project→plan): nearest value overrides but may not EXCEED an ancestor cap; allowlist
  = intersection; costs min-across-chain.**
- **`plans`** — `id PK, name, slug UNIQUE, mcp_enabled/self_hosted_workers_enabled/asset_hosting_
  enabled/extension_tools_enabled BOOL, admin_console_seats?, default_model_allowlist_json,
  default_rpm/tpm_limit?, default_monthly_budget_usd?, default_asset_storage_quota_bytes?,
  default_monthly_egress_bytes_budget?, default_download_rpm_limit?, default_asset_max_object_bytes?,
  default_agent_cost_budget_usd?`. Seeds a `'free'` plan (both dialects).
- **`budget_alert_notifications`** — `id PK, scope_type, scope_id, period_month, threshold_pct
  SMALLINT, notified_at_unix, UNIQUE(scope_type,scope_id,period_month,threshold_pct)`. Idempotency
  ledger: a threshold fires its webhook once per billing period (#170).

### 1.4.4 Billing / metering / usage (Postgres: normalized global tables; D1: control DB, JSON-doc)
- **`billing_metering_events`** — `request_id PK, trace_id?, agent_run_id?, workflow_*?, cluster/node_
  id?, tenant NOT NULL, logical_model, provider, provider_model?, prompt/completion/total_tokens BIGINT,
  usage_source, status_code?, occurred_at_unix, event_json`. idx tenant/time, model/provider/time,
  provider/model/time, trace.
- **`metering_events`** + **`metering_event_routes`** + **`metering_event_usage`** — normalized settled
  metering, PK re-keyed to `billing_event_id` in migration 30 (one logical request → many billable
  provider attempts). `metering_events`: `+ tenant_context_id → tenant_contexts, cost_usd DOUBLE?,
  latency_ms?, provider_attempt_id, provider_attempt_index, metadata_json, event_json (full immutable
  settlement payload built via jsonb_build_object)`. Route/usage children FK to billing_event_id
  CASCADE. **On D1 these three collapse into a single `billing_events(billing_event_id PK, request_id,
  provider_attempt_index, occurred_at_unix, event_json)` document table.**
- **`tenant_contexts`** — `id PK, organization_id?, team_id?, project_id?, workspace_id?, user_id?,
  api_key_id?`. (Tenant-scoped on D1.) idx (org,project), (api_key).
- **`usage_aggregates`** — `id PK, organization_id?, project_id?, api_key_id?, tenant?, logical_model,
  provider, prompt/completion/total_tokens, usage_json`. Process-local read-of-record.
- **`usage_aggregate_rollups`** — `id PK, tenant_context_id → tenant_contexts, logical_model, provider,
  prompt/completion/total_tokens`. REPLACE-upserted by `persist_usage_aggregate` (tenant DB on D1, one
  atomic `/d1/batch` with the tenant_contexts upsert).
- **`usage_monthly_rollups`** — `id PK, period_month, scope_type CHECK IN (tenant,project,workspace,
  key) (KEPT in D1), scope_id, prompt/completion/total_tokens, cost_usd DOUBLE, request_count,
  error_count, UNIQUE(period_month,scope_type,scope_id)`. **One settled request fans out into up to 4
  rows (one per scope level).** The read side of "current-month cumulative cost for scope X".
- **`usage_metadata_rollups`** — `id PK, period_month, organization_id DEFAULT '', metadata_key,
  metadata_value, tokens/cost/request/error counts`. Per arbitrary caller metadata pair (#171/#226);
  N metadata pairs → N incremented rows.
- **`billing_ledger`** — `id PK (idempotency key), request_id, trace_id?, organization/project/
  workspace/api_key_id?, logical_model, provider, provider_model, tokens, usage_source, status_code,
  input/output/total_cost DOUBLE, currency DEFAULT 'USD', credits DOUBLE, entry_json,
  provider_attempt_id/index, occurred_at_unix?`. Append-only, idempotent on `id`. **D1: reduced to
  `id, organization_id, project_id, api_key_id, created_at_unix, entry_json`.**
- **`billing_report_outbox`** — `id PK (= ledger entry id), event_json, attempts, next_attempt_unix,
  dead_lettered_at_unix?`. Durable gateway→billing-service delivery queue; sweeper drains, dead-letters
  after `MAX_BILLING_OUTBOX_ATTEMPTS`. idx due, dead_lettered (partial).
- **`agent_cost_burn`** — `PK(tenant_id, agent_key, period), accumulated_usd DOUBLE, first_seen_unix,
  updated_at_unix`. Atomic `INSERT ... ON CONFLICT DO UPDATE SET accumulated_usd = existing +
  EXCLUDED RETURNING accumulated_usd`. (Tenant-scoped; on D1 the accumulate is defined but not yet
  routed onto the tenant binding.)

### 1.4.5 Wallets / reservations / payment attempts (tenant DB on D1)
- **`wallets`** — `id PK, tenant_id UNIQUE → tenants CASCADE, balance_credits BIGINT (integer credits,
  no float drift; 1 USD = 1_000_000 credits), auto_recharge_threshold_credits?,
  auto_recharge_amount_credits?, dunning BOOL`.
- **`wallet_reservations`** — `id PK, tenant_id, amount_credits BIGINT, status DEFAULT 'active'
  ('active'|'settled'|'released'), expires_at_unix, settlement_id? (= reservation id on capture)`. idx
  (tenant,status), partial (expires_at_unix WHERE status='active').
- **`wallet_settlements`** — `id PK, tenant_id, delta_credits BIGINT, balance_after_credits?,
  created_at_unix`. One durable row per settlement; claiming the id + moving balance is one txn →
  idempotent replay.
- **`payment_methods`** — `id PK, tenant_id → CASCADE, provider, provider_customer_id,
  provider_payment_method_id, is_default BOOL`. Opaque provider refs; **never raw card data**.
- **`payment_attempts`** (x402, migration 52 — **deprioritized**) — `id PK, tenant_id → CASCADE,
  project/workspace/run/worker/request/trace_id?, method, resource_url, request_body_hash?,
  challenge_hash, x402_version BIGINT, scheme, network_caip2, mint, atomic_amount TEXT (u64 exceeds
  i64; CHECK `~ '^[0-9]{1,20}$'`), recipient, credits_amount BIGINT? (CHECK ≥0), conversion_version?,
  policy_revision BIGINT, decision, reason_code, hold_id? (→ wallet_reservations.id, no FK),
  state CHECK IN (challenged,authorized,submitted,settled,denied,released,failed,outcome_unknown),
  generation BIGINT (operation token surviving async reread), submitted_at_unix?,
  transaction_signature? (partial UNIQUE index — one on-chain sig captures at most one hold),
  settled_atomic_amount? (CHECK canonical u64), settlement_response?, failure_code?`. idx (tenant,
  time), partial (hold), partial (updated_at WHERE state IN submitted/outcome_unknown — the reconciler
  due-query).

### 1.4.6 Assets / channels / retention / site domains (tenant DB on D1)
- **`stored_assets`** — `id PK, tenant_id → tenants, project_id?, asset_type, name, version,
  content_type, content_hash, size_bytes BIGINT (CHECK 0 ≤ size ≤ 10 MiB OR storage_uri IS NOT NULL),
  content BYTEA (inline; base64 TEXT on D1), storage_uri? (S3/R2 object key when bucket-backed),
  variant DEFAULT '', yanked BOOL, visibility DEFAULT 'visible' (visible|pending_scan|quarantined),
  UNIQUE(tenant_id, asset_type, name, version, variant)`. idx (tenant,type,name,version).
- **`asset_channels`** — `id PK (= {tenant}:{type}:{name}:{channel}), tenant_id, asset_type, name,
  channel, version, UNIQUE(tenant_id,asset_type,name,channel)`. Mutable latest/stable/canary + tag
  pointers resolved to a concrete version at pull time.
- **`retention_policies`** — `id PK, tenant_id, resource_type, scope DEFAULT '*', keep_last_n?,
  max_age_secs?, min_age_secs DEFAULT 0`. Generalizable "keep newest N and/or younger than max_age,
  never touch younger than min_age" GC rule; fail-safe = KEEP.
- **`site_domains`** — `hostname PK, tenant_id, site`. One hostname → one `{tenant}/{site}`. idx tenant.
- **`site_domain_verifications`** — `PK(tenant_id, hostname), site, state (pending_verification|
  verified|expired|grandfathered), challenge_token, issued/token_expires/verified/verification_expires/
  last_checked_at_unix?, last_failure_reason?, attempt_count`. DNS-TXT ownership proof; keyed on
  (tenant,hostname) so several tenants may hold a pending challenge for one hostname (anti-squat).
  `try_begin_site_domain_verification_attempt` is a rate-limit CAS before any outbound DNS (#576).

### 1.4.7 Workflow budgets, schedules, presence (tenant DB on D1)
- **`workflow_run_budgets`** — `id PK, workflow_id, workflow_version BIGINT, run_id, tenant_id,
  cost_budget_credits?, token_budget?, tool_call_budget?, wall_clock_deadline_unix?, spent_credits/
  tokens/tool_calls BIGINT DEFAULT 0, status DEFAULT 'active' (active|exhausted)`. idx tenant. NULL
  cap = unbounded; spent_* accumulate monotonically; a debit breaching ANY capped dimension is
  rejected fail-closed WITHOUT applying spend and flips status to 'exhausted'; top-up raises caps,
  flips back to 'active'.
- **`agent_schedules`** — `schedule_id PK, tenant_id, workspace_id, name, enabled BOOL, spec_kind
  (cron|interval), cron_expr?, timezone DEFAULT 'UTC' (IANA), interval_secs?, target_kind
  (self_hosted_dispatch|agent_run), target_json, overlap_policy (skip|allow), catchup_policy
  (skip_missed|fire_once), jitter_secs, next/last_fire_at_unix?, revision`. Partial idx (next_fire_at
  WHERE enabled AND next_fire_at NOT NULL); idx (tenant,workspace,name). **Cron parsing via `croner`
  crate + `chrono-tz` timezones.**
- **`agent_schedule_fires`** — `fire_id PK, schedule_id → agent_schedules CASCADE (dropped on D1),
  scheduled_fire_at_unix, fired_at_unix, node_id?, outcome (dispatched|skipped_overlap|skipped_
  disabled|error), dispatch_id?, run_id?, detail?, UNIQUE(schedule_id, scheduled_fire_at_unix)`.
  **At-most-once fire gate**: UNIQUE + `ON CONFLICT DO NOTHING`.
- **`observed_agent_presence`** — `PK(tenant_id, api_key_id), first/last_seen_at_unix, request_count`.
  Coalesced presence: one conditional upsert bumping `last_seen = GREATEST(...)` /
  `first_seen = LEAST(...)`, `request_count += 1`. **SQLite uses scalar `max(x,y)`/`min(x,y)`** (no
  GREATEST/LEAST).

### 1.4.8 Observability / worker / audit families (control DB; Postgres normalized, D1 JSON-doc)
- **`control_plane_resources`** — `PK(resource_kind, resource_id), document_json JSONB (+GIN),
  revision, created/updated_at_unix`. The generic kind-keyed config-document store (policy /
  gateway_config / agent_workflow / skill_package / prompt_template / plugin_registration / mcp_server
  / agent_upstream / tool_approval / api_key / tenant). **GIN index lost on D1.**
- **`agent_runs`** / **`agent_run_events`** — full record as `run_json`/`event_json`; Postgres carries
  projection columns (request_id, trace_id, tenant, turn, kind, target, outcome, action_fingerprint,
  decision, decision_reason, output_disposition); D1 keeps only the columns the read SQL needs.
- **`request_logs`** — `request_id PK, trace/agent_run/workflow/cluster/node_id?, tenant?, route?,
  provider?, logical/provider_model?, gateway_config_id/revision?, status_code?, error_code?,
  cache_status?, started/completed_at_unix, request_json`. Many idx (tenant/time, model/provider/time,
  trace, agent_run, status).
- **`audit_events`** — `id PK, request/trace/agent_run/workflow/cluster/node_id?, actor_api_key_id?,
  tenant?, action, target?, outcome, action_fingerprint/decision/decision_reason/output_disposition?,
  audit_json`.
- **`guardrail_policy_revisions`** — `PK(policy_id, revision CHECK>0), immutable_id UNIQUE, created_by,
  policy_json`. Immutable content.
- **`guardrail_policy_bindings`** — `policy_id PK, active_revision? (deferrable FK to revisions),
  archived_revisions_json, updated_by, generation BIGINT CHECK≥0`. Mutable active pointer;
  generation-guarded CAS.
- **`guardrail_evaluations`** / **`guardrail_check_evaluations`** — sanitized evidence (verdict/action/
  enforcement/stage/mode, no prompt or matched text). **Postgres RLS-scoped by
  `current_setting('ferrogate.tenant_id')`** — dropped on D1.
- **Managed worker stores** — `managed_worker_templates`, `agent_worker_instances`,
  `managed_worker_sessions`, `managed_worker_lifecycle_events`, `managed_worker_isolation_selections`,
  `managed_worker_isolation_policies`, `managed_worker_isolation_evidence` (Postgres richly normalized
  w/ FKs + CASCADE; D1 → single `*_json` doc + one ORDER BY projection column each).
- **Self-hosted worker stores** — `self_hosted_worker_registrations` (+ `token_secret`, identity
  fingerprint/expiry), `self_hosted_worker_heartbeats`, `self_hosted_worker_telemetry_events`,
  `self_hosted_worker_artifacts`, `self_hosted_worker_checkpoints`, `self_hosted_run_dispatches` (+
  the `self_hosted_run_dispatch_capabilities` side table — folded into the dispatch document on D1).
- **`mcp_oauth_authorization_states`** / **`mcp_oauth_flows`** / **`mcp_oauth_credentials`** —
  per-user MCP OAuth. PKCE verifiers + access/refresh tokens stored as `BYTEA` ciphertext+nonce
  (encrypted with a deployment key before reaching storage). **RLS-scoped on Postgres.** (Not yet on
  D1 — MCP identity is a deferred surface.)
- **`control_plane_replay_floors`** — `PK(tenant_id, deployment_id), last_accepted_revision`.
  Signed-snapshot bounded-rollback floor; writers only ever raise it (GREATEST upsert; D1 uses `max()`
  + follow-up SELECT because no RETURNING on REST).
- **`storage_schema_migrations`** — `version PK, name, checksum, applied_at_unix`. Migration ledger.

## 1.5 Concurrency algorithms (the load-bearing correctness proofs)

These are the transactions that MUST survive the port. On Postgres they use `SELECT ... FOR UPDATE`
row locks; on D1/SQLite (no row lock) they use an atomic `/d1/batch` or a guarded `UPDATE ...
RETURNING` optimistic CAS. SQLite serializes writers per database, so a guarded write only lands when
the guard still matches the read → the same no-oversell / no-lost-update property.

1. **Wallet reserve — no oversell** (`wallet.rs` / `control_plane_store_d1/wallet.rs`).
   Postgres: `SELECT balance_credits FROM wallets WHERE tenant_id=$1 FOR UPDATE`, sum live holds,
   conditional insert. D1: one 3-statement `/d1/batch`:
   - S0 idempotency probe by hold id;
   - S1 guarded `INSERT INTO wallet_reservations ... SELECT ... FROM wallets w WHERE w.tenant_id=?
     AND CAST(? AS INTEGER) <= w.balance_credits - COALESCE((SELECT SUM(r.amount_credits) FROM
     wallet_reservations r WHERE r.tenant_id=? AND r.status='active' AND r.expires_at_unix>?),0)
     ON CONFLICT (id) DO NOTHING RETURNING id` — empty RETURNING = not admitted;
   - S2 wallet-state read to split `NoWallet` vs `Insufficient`.
   N parallel reserves against a balance affording N−1 admit exactly N−1.
2. **Wallet settle/release** — `settle` captures a hold into a wallet debit + `wallet_settlements`
   row + `active→settled` flip as one atomic batch (idempotent by settlement id = hold id). `release`
   is a single `UPDATE ... WHERE status='active' RETURNING` CAS. Both fan out over tenant bindings
   (signature carries only the reservation id).
3. **Workflow-run budget debit** (`workflow_budget.rs`) — Postgres `SELECT ... FOR UPDATE` RMW. D1:
   read counters → `dimension_exceeded_by` arithmetic decides `Applied`/`Exceeded` → guarded
   `UPDATE ... WHERE <status + spent_* + caps unchanged since read> RETURNING`; empty RETURNING =
   concurrent debit landed → bounded re-read + retry. `WorkflowBudgetDebit` contract stays
   `{Applied, Exceeded}` (no new Conflict variant). Every bound numeric param wrapped `CAST(? AS
   INTEGER)`.
4. **Payment-attempt CAS** (`payment_attempt.rs`, x402 — deprioritized) — the single
   `transition_payment_attempt(op_name, id, allowed_from[], to_state, evidence, now)` seam; a short
   conditional CAS gated on current state + `generation` operation token.
5. **Guardrail binding CAS** — `activate`/`archive`/`restore` are generation-guarded compare-and-swaps
   on the single mutable `guardrail_policy_bindings` row (`UPDATE/INSERT/DELETE ... WHERE generation=?
   ... RETURNING policy_id`; empty = lost-update → typed CAS `Conflict`). SQL constants:
   `GUARDRAIL_POLICY_BINDING_{INSERT,UPDATE,DELETE}_CAS_SQL` in `lib.rs`.
6. **Monotonic upserts** — replay floors and observed-presence use `GREATEST/LEAST` (Postgres) /
   `max()/min()` (SQLite) so a delayed/out-of-order write never regresses the row.
7. **Reference-guarded deletes** — `delete_project_if_unreferenced` / `delete_workspace_if_unreferenced`
   / `delete_asset_variant_if_unreferenced` take `SELECT ... FOR UPDATE` on the parent to close the
   TOCTOU window; D1 mirrors with a guard+write in one batch.
8. **Billing outbox atomic enqueue** — `append_billing_event_with_outbox_enqueue` writes the metering
   event and the outbox row in one transaction (D1: one `/d1/batch` on the control DB via the proxy).

## 1.6 Connection pooling & external I/O (the pooler cap)
- `async_postgres.rs`: `deadpool-postgres` `Pool` with `RecyclingMethod::Verified`.
  `Pool::builder(manager).max_size(config.pool_size)`. **Default `pool_size = 4`**
  (`default_postgres_pool_size()` in `ferrogate-config`).
- Acquire path: `acquire(operation, caller_timeout)` uses `min(pool_acquire_timeout, caller_timeout)`
  (default acquire timeout **1000 ms**); records `acquire_total`, `acquire_timeout_total`,
  `acquire_wait_micros_total`; a deadline maps to `StorageError::OperationDeadlineExceeded`.
- TLS via `native-tls` + `postgres-native-tls` (`PostgresTlsMode` disable/prefer/require/verify_ca/
  verify_full).
- **External pooler cap:** Supabase's transaction pooler (Supavisor) caps at ~16 connections for the
  deployment. Every gateway instance draws from this shared cap, so `pool_size` × instance count must
  stay under it. This is the single biggest reason the CF port moves off Postgres — a Worker cannot
  hold a warm connection pool at all.
- Schema init/validation: `schema_migrations.rs` derives `POSTGRES_SCHEMA_VERSION` (=59) and
  `POSTGRES_SCHEMA_NAME` from the SQL file at const-eval; `StorageSchemaEvidence` carries an
  FNV-1a-64 checksum of the DDL. Startup validates every table/index/FK exists in the configured
  `search_path` schema (`validate_postgres_schema`, incl. the `PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_
  QUERY` against `pg_constraint`).

## 1.7 Proposed CF/TS mapping (storage)
The D1 backend is the reference; the TS port re-implements it natively in the Worker.

| Concern | CF primitive | Notes |
|---|---|---|
| Account-global control-plane config (tenants, admin users, SSO, quota_policies, plans, RBAC, site domains, budget alerts, config documents, guardrail revisions/bindings, replay floors) | **D1 (control database)** | one control DB; the `d1-proxy` pattern becomes a native binding in-Worker — no proxy Worker needed once everything runs *inside* a Worker. |
| Observability/worker/audit analytics families (agent runs/events, request/audit logs, billing events, managed + self-hosted worker stores) | **D1 control DB (JSON-doc rows)** OR **Analytics Engine** for the high-cardinality append streams | request/audit logs and metering are append-heavy and time-ordered → strong candidates for **Analytics Engine** (write via `writeDataPoint`, read via SQL API) or **Logpush**, keeping D1 for the queryable control-plane slice. The ClickHouse warehouse (`sql/clickhouse/`) is the analytics model to mirror in Analytics Engine. |
| Per-tenant financial/usage/asset/schedule state (wallets, reservations, settlements, usage rollups, stored_assets, channels, retention, workflow budgets, agent schedules + fires, observed presence, agent cost burn) | **D1 (one database per tenant)** | already the design. Atomic ops run natively in-Worker (`env.TENANT_DB.batch([...])`, `RETURNING`) — the whole `d1-proxy` HTTP hop disappears. **Open constraint: per-tenant D1 bindings are declared at deploy time in wrangler config; there is no runtime bind-by-id.** A large tenant count forces either dynamic dispatch via a routing Worker/DO, or D1's newer programmatic-binding APIs — evaluate `D1 Sessions`/`getByName` maturity. |
| Inline asset bytes (`stored_assets.content`, ≤10 MiB) and bucket-backed assets (`storage_uri`) | **R2** | move all inline BYTEA to R2; keep only metadata + object key in D1. `content_hash` (sha256) → R2 object key. |
| MCP OAuth token ciphertext (`BYTEA`) | **D1 TEXT (base64)** + **CF Secrets Store** for the deployment key | encryption key is a per-deployment secret. |
| Per-request no-oversell wallet holds / workflow-budget debits | **D1 atomic batch + optimistic guarded UPDATE...RETURNING** | already ported; SQLite per-DB writer serialization gives the invariant. Consider a **Durable Object per tenant wallet** if contention or cross-DB coordination is needed (single-threaded DO gives a natural lock). |
| Connection pool | **none needed** | D1/R2/KV are stateless HTTP bindings; the ~16-conn pooler cap simply evaporates. |
| Schema migration + validation | D1 migrations (`wrangler d1 migrations`) | keep the checksum/version evidence idea; drop the `pg_constraint` introspection (SQLite `PRAGMA`/`sqlite_master` instead). |

**No clean CF equivalent (flag):** (a) Postgres **RLS** — gone, replaced by physical DB-per-tenant
(fine, but any code that relied on `current_setting('ferrogate.tenant_id')` must move the tenant
predicate into app code / routing); (b) **cross-table FKs + CASCADE** — D1 supports FKs but the
DB-per-tenant split breaks cross-DB references; cascades are manual batches; (c) **`SELECT ... FOR
UPDATE`** — no row locks; replaced by optimistic CAS (works, but every such site needs the retry
loop); (d) **JSONB GIN indexes / JSONB operators** — no indexed JSON query; add projection columns or
move filters to app code; (e) **`RETURNING` over the D1 REST API** — needs the native binding (in a
Worker you have it; a pure-REST/external caller does not); (f) **per-tenant D1 binding at runtime** —
the deploy-time binding constraint is the biggest architectural open question for tenant scale.

TS libs: `zod` for the `Stored*`/DTO validation that Rust got from serde + type system; a thin D1
query helper (the `D1ProxyStatement`/`with_params` shape maps to `env.DB.prepare(sql).bind(...)`);
`@cloudflare/workers-types`.

---

# 2. `ferrogate-billing`

## 2.1 Purpose
Token-usage metering + the standalone billing microservice (issue #129): a `PriceBook` rate card, a
pure `charge()` that turns a `BillingEvent` into a priced `LedgerEntry`, a `LedgerSink` persistence
seam, an HTTP `serve()` entrypoint, and (issue #356) the inbound (merchant-side) fixed-price x402
monetization loop. Storage-free.

## 2.2 Public API surface
- Types: `TokenUsage {prompt,completion,total_tokens}` (`.reconcile_split()`, `.estimate_missing_
  total()`), `ModelPrice {input_price_per_1m, output_price_per_1m, currency}` (`.estimate(usage) ->
  CostEstimate`), `CostEstimate {input_cost, output_cost, total_cost, currency}`,
  `enum BillingUsageSource {ProviderUsage, GatewayEstimate}`, `struct ProviderAttempt
  {provider_attempt_id, provider_attempt_index}` (`.for_request(request_id, idx)`, `.is_legacy()`),
  `struct BillingEvent` (the wire event: request/trace/attempt ids, workflow/cluster/node ids,
  `TenantContext`, model/provider, `TokenUsage`, usage_source, status_code, occurred_at_unix,
  `cost_usd?`, `latency_ms?`, `metadata: BTreeMap`, `wallet_delta_credits?`,
  `wallet_balance_after_credits?`), `struct BillingError {code, message}`.
- `pricing`: `PriceBook {entries: Vec<PriceEntry>, credits_per_usd, egress_price_per_gb?}`,
  `PriceEntry {provider, model, price}`. Constants: `DEFAULT_CREDITS_PER_USD = 1_000_000.0`
  (1 credit = 1 micro-USD), `BYTES_PER_BILLED_GB = 1e9` (decimal GB), `DEFAULT_EGRESS_PRICE_PER_GB =
  0.09`. `egress_cost_usd(price_per_gb, bytes)`. `PriceBook::with_default_rate_card()` seeds
  per-1M-token prices for gpt-5.5/5/4o/4o-mini, claude-sonnet-4/opus-4, gemini-2.5-pro/flash, grok-4,
  deepseek-chat/reasoner.
- `ledger`: `charge(book, event) -> Result<LedgerEntry, BillingError>`, `LedgerEntry`,
  `enum CostSource {GatewaySettled, BillingPriceBook}`, `same_provider_attempt_settlement`,
  `ledger_entry_id(event)`, `trait LedgerSink {record, list(filter,offset,limit), get(id)}`,
  `LedgerListFilter {organization_id?, project_id?, api_key_id?}`, `LedgerTotals`, `InMemoryLedgerSink`.
- `service`: `serve(BillingServiceConfig)`, `BillingServiceConfig {listen, price_book, sink:
  Arc<dyn LedgerSink>, token: Option<String>}`, `billing_error_http_status(err) -> u16`.
- `lib`: `trait BillingEventSink {record, list}`, `InMemoryBillingEventSink` (bounded VecDeque),
  `validate_request_metadata(map)` — `MAX_METADATA_ENTRIES = 8`, `MAX_METADATA_KEY_LEN = 64`,
  `MAX_METADATA_VALUE_LEN = 256`.
- `x402_inbound`: `InboundX402Endpoint`/`ValidatedInboundX402Endpoint`, `settle_inbound_payment`,
  `InboundX402RevenueRecord`, `RevenueSink`/`InMemoryRevenueSink`, `RevenueSource::X402Inbound`,
  `PAYMENT_REQUIRED_STATUS = 402` (**x402 — deprioritized; §4 below**).

## 2.3 Billing/metering algorithms (precise)
- **`TokenUsage::reconcile_split()`** (issue #140): if `total == 0` → `total = prompt + completion`
  (saturating); else if `completion == 0 && total > prompt` → `completion = total − prompt`; and if
  `prompt == 0 && total > completion` → `prompt = total − completion`. Prevents billing a
  provider-omitted side at $0 (e.g. Gemini reporting only prompt+total).
- **`ModelPrice::estimate(usage)`** → `input_cost = prompt * input_price_per_1m / 1e6`,
  `output_cost = completion * output_price_per_1m / 1e6`, `total = input + output`.
- **`PriceBook::price_for(provider, model)`** — precedence, most specific first: exact `(provider,
  model)` → `(provider, "*")` → `("*", model)` → `("*", "*")`. Returns `None` (fail-closed) when
  nothing matches. `credits_for_usd(usd) = usd * credits_per_usd`.
- **`charge(book, event)`** — the source-of-truth rule (issue #135): if the event carries a finite,
  ≥0 `cost_usd` (gateway-settled), **that figure is authoritative** — the gateway already priced +
  enforced budget against it, so the ledger records the same number; `settled_breakdown()` splits it
  into input/output by the rate card's ratio (or by token counts if no price). Divergence beyond a
  5% relative tolerance (absolute floor $0.0001) is **logged, never overridden** (issue #152). If the
  event has no settled cost, price from the rate card; **fail closed with `price_not_found` (HTTP 422)
  when no rule matches** — never bill zero. `credits = credits_for_usd(cost.total_cost)`.
- **Idempotency** — `ledger_entry_id(event)`: new events → `ferrogate:provider-attempt:{attempt_id}`;
  legacy events → `ferrogate:{trace_id}:{request_id}` or `ferrogate:{request_id}`. `LedgerSink::record`
  is idempotent: a replay with byte-equal settlement is a no-op (`Ok(false)`); a replay with different
  data → `billing_idempotency_conflict` (HTTP 409). `billing_error_http_status`: `price_not_found` →
  422, `billing_idempotency_conflict` → 409, else 500.
- **Egress metering** (issue #262): `egress_cost_usd(price_per_gb, bytes) = bytes / 1e9 * price_per_gb`;
  `None` when unpriced (fail-open — no fabricated cost).

## 2.4 The billing microservice (`service.rs`)
Standalone process. Hand-rolled blocking HTTP/1.1 (`TcpListener` + thread-per-connection, no async
runtime, no framework — mirrors `ferrogate-auth-service`). Routes: `GET /healthz|/v1/healthz`,
`POST /v1/billing/charge` (`charge_and_record`), `GET /v1/billing/ledger` (paginated, tenant-filtered
via query `organization_id`/`project_id`/`api_key_id` pushed into the sink query, issue #149),
`GET /v1/billing/ledger/{id}`. Guards: optional `Authorization: Bearer <token>` (constant-time
compare; `/healthz` stays open, issue #136), `MAX_REQUEST_BYTES = 1 MiB`, `CONNECTION_TIMEOUT = 15s`
(slowloris), `MAX_CONCURRENT_CONNECTIONS = 512` (load-shed), page limit clamp 1..1000 (default 100).

## 2.5 CF/TS mapping (billing)
- **`charge()` / `PriceBook` / `TokenUsage`** — pure functions; port verbatim to TS. The `f64` money
  math is fine in JS `number` **except** the integer-credit domain (`DEFAULT_CREDITS_PER_USD = 1e6`,
  wallet `balance_credits BIGINT`) — keep credits as **`bigint`** in TS to preserve the no-drift
  property; only USD is `number`. Validate with Zod.
- **The standalone HTTP service** → a **Hono route group** (`POST /v1/billing/charge`,
  `GET /v1/billing/ledger[/:id]`) inside the gateway Worker (or its own Worker). Drop the hand-rolled
  HTTP parser entirely — Hono handles routing/limits; use `crypto.subtle`/`timingSafeEqual`-style
  bearer check.
- **`LedgerSink`** → D1 `billing_ledger` (control DB), idempotent `INSERT ... ON CONFLICT(id) DO
  NOTHING` + reload-compare on conflict (already the D1 impl).
- **`billing_report_outbox`** durable delivery queue → **Cloudflare Queues** is the natural fit
  (replace the DB-polled sweeper with a Queue consumer + dead-letter queue), or keep the D1 outbox
  table + a Cron Trigger sweeper if you want the exact current semantics.
- **Rate card config** → KV or a config document in D1; `PriceBook::from_json_slice` maps to a Zod
  schema.

---

# 3. `ferrogate-payments`  *(x402 / Solana — DEPRIORITIZED)*

## 3.1 Purpose
A narrow, protocol-neutral **client-side** boundary for agent payments: x402 v2, HTTP transport,
Solana SVM networks, `exact` scheme. Pure types + wire parsing only — no network I/O, no wallet, no
keys. Per project memory + module docs, **all x402/Solana payment work is deprioritized**; capture the
shape, do not port yet.

## 3.2 Public API surface (for reference)
- `attempt_state`: `enum PaymentAttemptState {Challenged, Authorized, Submitted, Settled, Denied,
  Released, Failed, OutcomeUnknown}` with `.as_str()`/`.parse()`, `.is_terminal()`,
  `.is_pre_submission()`, `.is_reconcilable()`, `.is_initial()`, `.retains_hold_when_unresolved()`.
  **Key invariant: `OutcomeUnknown` is NON-terminal and RETAINS the wallet hold** (post-submission
  ambiguity is not proof the money didn't move — releasing could spend stablecoin without charging the
  wallet). `is_pre_submission` (TTL sweeper may release) and `is_reconcilable` (settlement reconciler)
  are disjoint. This is the alphabet the storage `payment_attempts.state` CHECK constraint uses.
- `wire`: `parse_payment_required(header)`, `select_requirement(req, filter) -> SelectedPayment`
  (deterministic challenge hash), `parse_payment_response`, `validate_solana_address`,
  `base58_decode`, `parse_atomic_amount`, `SolanaNetwork` (CAIP-2 devnet/mainnet), `SettlementEvidence
  {success, network, transaction_signature?, settled_amount?, payer?, error_reason?}`. Constants:
  `X402_VERSION`, `SCHEME_EXACT`, `HEADER_PAYMENT_{REQUIRED,SIGNATURE,RESPONSE}`, `MAX_MEMO_BYTES`,
  `MAX_TIMEOUT_SECONDS`, `MAX_ACCEPTS_ENTRIES`, `MAX_HEADER_BYTES`, `MAX_SVM_TRANSACTION_BYTES`,
  `CHALLENGE_HASH_DOMAIN`.
- `intent`: `PaymentIntent`/`Draft`/`Identity`, `RequestBodyHash`, `PAYMENT_INTENT_HASH_DOMAIN`.
- `proof`: `build_payment_signature(...)`, `SvmTransferSigner` trait (all signing injected),
  `SecretBytes`, `SvmTransferIntent`.
- `sdk` (feature-gated `sdk-solana-pay-kit`, NOT compiled): a machine-readable qualification record.
  `solana-pay-kit 0.2.0` is **not usable** on MSRV 1.88 (its deps need rustc ≥1.89). Wire parsing is
  hand-rolled with golden fixtures + a negative corpus.

## 3.3 CF/TS mapping
Deferred. If/when revived: pure TS module (base58 + sha256 via `@noble/*`); the `SvmTransferSigner`
seam maps to a WebCrypto/Solana-web3.js signer. Flag: no MSRV constraint in JS, so `@solana/web3.js`
is available, but this remains out of scope.

---

# 4. `ferrogate-observability`

## 4.1 Purpose
Logging/metrics/tracing **boundary** types and OTLP request builders. I/O-free by design (only
`serde_json` + `tracing`): backends **build** HTTP requests, they never send them (the transport lives
in `ferrogate-cli`'s `dispatch_otlp_request`), so every backend is unit-testable with no network.

## 4.2 Public API surface
- `metrics`: `GatewayMetricsSnapshot` — a large flat counter struct: request_log/error totals,
  per-status totals, cache hits/misses (+ semantic cache hits, #273), guardrail counters
  (match/denial/redaction/detector_error/evaluation/fail/error/shadow/evidence-persistence-failure/
  cas-conflict), billing_event_total + billing_report_enqueue_failure_total, tool_call/latency,
  MCP identity counters, `postgres_pool_acquire_*` (surfaced from `PostgresPoolMetricsSnapshot`),
  evidence-writer enqueued/written/dropped (#309), token totals, per-model/provider totals,
  per-MCP-method totals (#277), network-access denied/rate-limited (#166), asset-lifecycle scanned/
  pruned/failed (#263), asset-presign issued/rejected/bucket-rejected/staging-missing/commit-rejected/
  aborted/abort-reclaim-failed (#368), `UnjoinableActionMetricTotal` (#522). Sub-structs:
  `RequestStatusMetric`, `TokenMetricTotals`, `ModelProviderMetricTotal`, `McpMethodMetricTotal`.
- `spans`: `GatewaySpanKind` + `GatewaySpanTemplate` + 6 canonical templates (`GATEWAY_REQUEST_SPAN`,
  `AUTH_SPAN`, `POLICY_SPAN`, `MODEL_ROUTE_SPAN`, `PROVIDER_DISPATCH_SPAN`, `BILLING_WRITE_SPAN` =
  `ferrogate.metering.write`), `default_span_templates()`.
- `config`: `ObservabilityConfig`, `ObservabilitySignal {Trace, Metric, Log}`,
  `ObservabilityExporterKind {Stdout, Otlp, Prometheus, File, Cloudflare}`,
  `ObservabilityExporterConfig` (+ constructors `stdout_logs`, `otlp`, `cloudflare`,
  `prometheus_metrics`, `file_logs`), `trait ObservabilityPlugin`, `ObservabilityPipelineConfig`,
  `enum ObservabilityConfigError` (missing name/signals/endpoint/path, invalid http path/endpoint,
  unsupported signal, missing/invalid credential, insecure endpoint).
- `backend`: `trait TelemetryBackend {name, supports(signal), metrics_request, traces_request,
  logs_request, validate}`, `ALL_SIGNALS`, `OtlpBackend` (plain OTLP/HTTP+JSON), and `CloudflareBackend`
  (§4.4). Each `*_request` returns `Ok(None)` when nothing to send.
- `otlp`: `OtlpHttpRequest {method, url, content_type, body, headers}`, `OtlpAttribute`,
  `OtlpSpanRecord {trace_id, span_id, parent_span_id?, name, start/end_time_unix_nano, attributes}`,
  `OtlpLogRecord {trace_id?, span_id?, severity_text, body, time_unix_nano, attributes}`,
  `build_otlp_{metrics,traces,logs}_request` — emit OTLP/JSON (`resourceMetrics`/`resourceSpans`/
  `resourceLogs` envelopes). **OTLP/JSON, not protobuf** (matches CF's native Workers OTLP export).
- `prometheus`: the Prometheus text-exposition renderer for `GatewayMetricsSnapshot` (586 lines).

## 4.3 What's emitted where
Metrics → OTLP `/v1/metrics` JSON or Prometheus text. Traces → OTLP `/v1/traces`. Logs → OTLP
`/v1/logs`, stdout, or file. Spans follow the 6 canonical gateway templates. The Postgres pool metrics
flow into the snapshot so pool saturation is observable.

## 4.4 The Cloudflare telemetry path (already designed — issue #520)
`CloudflareBackend` ships OTLP/HTTP+JSON to a **`telemetry-collector` Worker** (`workers/telemetry-
collector/`) with a bearer token + `x-ferrogate-tenant` fallback-tenant header. **Why a Worker:**
Cloudflare exposes **no observability ingest endpoint** — no OTLP receiver, no Workers Logs write API;
Analytics Engine's `writeDataPoint()` is a **Worker binding**, not an HTTP API. So a Rust process in a
container cannot write telemetry to CF directly; the collector Worker is the ingest endpoint we deploy,
and it fans out to **Analytics Engine + Workers Logs** over bindings. Credential guard: bearer over
plaintext is refused except to loopback (`endpoint_protects_credentials`), and CR/LF in headers is
rejected at config time.

The ClickHouse warehouse schema (`sql/clickhouse/001_init_analytics.sql`) is the analytics data model:
`ferrogate_request_logs` (MergeTree, partition YYYYMM, order tenant/time/request_id),
`ferrogate_trace_spans`, `ferrogate_usage_metrics` (**SummingMergeTree** — aggregates
tokens/cost/request/error counts), `ferrogate_billing_metering_events`, `ferrogate_audit_timeline`.
Retention TTLs in `002_retention_ttl.sql`.

## 4.5 CF/TS mapping (observability)
The port runs **inside** a Worker, so the whole "build request, don't send" split and the collector
Worker hop can collapse — the gateway Worker holds the Analytics Engine binding directly.

| Signal | CF primitive | Notes |
|---|---|---|
| Metrics / usage aggregates (`GatewayMetricsSnapshot`, `ferrogate_usage_metrics`) | **Workers Analytics Engine** (`env.AE.writeDataPoint({indexes, blobs, doubles})`) | one `index` per data point (the collector already uses tenant as index); SummingMergeTree behavior → AE's aggregation + SQL API reads. |
| Request/audit logs, trace spans | **Workers Logs / Logpush** and/or **Tail Workers** | structured JSON logs; Logpush to R2/external sink for retention; a Tail Worker can post-process/forward. Keep OTLP/JSON shape for interop with CF's native Worker OTLP export so trace ids line up. |
| Prometheus scrape endpoint | a Hono `GET /metrics` route rendering AE-read or in-memory counters | the 586-line Prometheus renderer ports to a TS text builder; but in-Worker there is no long-lived process to accumulate counters — counters must live in **Durable Objects** or be reconstructed from AE SQL. |
| Config/exporter validation | Zod schemas | port `ObservabilityConfigError` variants to a discriminated union. |

**Flag — the in-memory counter problem:** `GatewayMetricsSnapshot` assumes a long-lived process that
accumulates counters between scrapes. Workers are stateless per request. Either (a) write every event
to **Analytics Engine** and compute snapshots via its SQL API on read, or (b) hold counters in a
**Durable Object** (single-threaded, durable) and sample them. This is the main observability
re-architecture, not a 1:1 port.

---

# 5. Top 3 hardest things to port

1. **Postgres → D1 migration of the per-tenant financial/atomic core (the whole point).**
   Not the DDL (already drafted in `sql/d1/001_init_d1.sql`) but the *transaction semantics*: every
   `SELECT ... FOR UPDATE` wallet-hold, workflow-budget debit, guarded delete, and CAS must be
   re-expressed as an atomic D1 `batch()` or an optimistic `UPDATE ... WHERE <unchanged> RETURNING`
   with a bounded retry loop, relying on SQLite's per-database writer serialization for the
   no-oversell / no-lost-update invariants. Losing RLS, cross-table FKs+CASCADE, `GREATEST/LEAST`,
   JSONB/GIN, and `RETURNING`-over-REST each forces a concrete code change. The reference D1 impl
   exists but several surfaces are still `unimplemented-backend-surface` (payment attempts,
   reservation sweep, MCP identity), and the whole thing was built against an external `d1-proxy`
   Worker that the in-Worker TS port can and should eliminate.

2. **Per-tenant D1 database routing without runtime bind-by-id.** The database-per-tenant topology has
   no CF primitive for "open tenant X's database by id at runtime" — bindings are declared in wrangler
   config and require a redeploy per tenant. The Rust backend sidesteps this with per-tenant proxy
   bindings + fan-out, which does not scale to many tenants. The TS port must solve this (routing
   Worker/Durable Object per tenant, D1 Sessions/`getByName` if mature enough, or a different
   isolation model) — this is the single biggest architectural unknown.

3. **The observability accumulator + the "CF has no telemetry ingest" gap.** `GatewayMetricsSnapshot`
   is a process-lifetime counter bag with no home in a stateless Worker; it must move to Analytics
   Engine (write-on-event, aggregate-on-read via SQL) and/or a Durable Object, and the Prometheus/OTLP
   surfaces re-derived from that. The current design already routes through a bespoke
   `telemetry-collector` Worker precisely because Analytics Engine / Workers Logs are binding-only, not
   HTTP — the in-Worker port inherits that constraint and must re-plumb metrics, logs, and traces onto
   AE + Logpush + Tail Workers rather than an OTLP HTTP exporter.

*(Honorable mentions: keeping wallet credits as integer `bigint` end-to-end in JS to preserve the
no-float-drift money invariant; replacing the deadpool-postgres connection pool + the ~16-conn Supabase
pooler cap with stateless D1/R2/KV bindings — a simplification, but every pool-metric and
deadline-exceeded path disappears and must be re-thought; and the durable billing outbox → Cloudflare
Queues migration.)*
