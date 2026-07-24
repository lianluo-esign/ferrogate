# Cloudflare D1 control-plane backend (per-tenant databases)

Status: first slice landed (issue #420); auth/quota entity families + the
storage-side config-driven construction route + `list_databases` pagination
landed (issue #440); the ferrogate-cli construction hook (config fields +
`state.rs` branch) + the RBAC / site-domain / budget-alert-ledger entity
families landed (issue #445); the observability append/analytics families
(agent runs/events, request/audit logs) + snapshot replay floors landed (issue
#447); and the billing ledger/outbox/events, guardrail policy
revisions/bindings, and managed + self-hosted worker stores landed (issue #449).
Builds on the shared Cloudflare client (#405), the `ControlPlaneStore` trait
extraction (#419), and the #425 dispatch consolidation.

FerroGate's third control-plane storage backend persists control-plane
entities in **per-tenant Cloudflare D1 databases** driven over the D1 REST
API — physical database-per-tenant isolation instead of shared-Postgres
row-level isolation (`tenant_id` columns + RLS).

## Where the code lives

| Piece | Location |
| --- | --- |
| D1 REST endpoint wrapper (lifecycle + query) | `crates/ferrogate-cloudflare/src/d1.rs` |
| Backend (`D1ControlPlaneStore`, registry, provisioning) | `crates/ferrogate-storage/src/control_plane_store_d1.rs` |
| SQLite-dialect core schema | `sql/d1/001_init_d1.sql` |
| Mocked-transport tests + portability matrix | `crates/ferrogate-storage/src/control_plane_store_d1_test.rs`, `crates/ferrogate-cloudflare/src/d1_test.rs` |

### Transport placement decision

The D1 endpoint wrapper lives in `ferrogate-cloudflare` (a self-contained
`d1` module), NOT in `ferrogate-storage`, because auth, `{account_id}`
templating, envelope decoding, typed error mapping, and the deterministic
retry/backoff loop are already written once in the shared `CloudflareClient`
(#405) with injectable transport/clock seams. `ferrogate-storage` now depends
on `ferrogate-cloudflare` (a leaf client crate — no dependency cycle) and
contributes only the entity → SQL mapping. The alternative — a storage-side
HTTP module — was rejected because it would duplicate the retry/envelope
stack or force a second transport trait that mirrors what `HttpTransport`
already provides.

## Topology

- **Control database** (`ferrogate-control`): the `tenants` table, the
  generic kind-keyed `control_plane_resources` config-document table, the
  tenant→database registry document, and every **account-global** family
  (issue #440): `admin_users`, `admin_user_tenant_memberships`,
  `admin_user_refresh_tokens`, `sso_provider_configs`, `sso_pending_flows`,
  `quota_policies`, and `plans`; plus the issue #445 admin/config families:
  `permissions`, `roles`, `tenant_role_bindings` (RBAC), `site_domains`, and
  `budget_alert_notifications` (the alert idempotency ledger). These are
  account-scoped configuration, not per-request tenant data — admin identities
  span tenants, quota lookups carry no tenant context, and site-domain lookups
  resolve by hostname with no tenant context — so they are never fanned out over
  tenant databases. It also holds the issue #447 observability tables
  (`agent_runs`, `agent_run_events`, `request_logs`, `audit_events`,
  `control_plane_replay_floors`) and the issue #449 billing
  (`billing_ledger`, `billing_report_outbox`, `billing_events`), guardrail
  (`guardrail_policy_revisions`, `guardrail_policy_bindings`), and managed /
  self-hosted worker-store tables — all whole-table cross-tenant reads whose
  `tenant` column is a composite storage key, not a routing id, so a single
  control-database mirror is cleaner than a lossy per-tenant fan-out. Each of
  those stores the full record as a `*_json` document plus projection columns
  for its filter/order/paginate SQL.
- **Tenant databases** (`ferrogate-tenant-<tenant_id>`, one per tenant):
  that tenant's `projects`, `workspaces`, and `api_keys` rows.
- Writes route on the entity's `tenant_id`. An empty `tenant_id` routes to
  the control database (pre-multi-tenant records). Id-only reads and
  unfiltered lists fan out over control + all registered tenant databases,
  which is acceptable on this admin/low-volume path (see rate limits).

### Tenant→database registry

`D1TenantDatabaseRegistry` (tenant_id → database uuid, plus the control
database uuid) is persisted through the **existing config-document surface**
— kind `d1_tenant_database`, id `registry` — rather than any new storage
primitive. On this backend the document lives in the control database's
`control_plane_resources` table; a deployment whose admin store is Postgres
can persist the identical document there because the Postgres backend's
kind-keyed table accepts arbitrary kinds. Provisioning
(`provision_control_database` / `provision_tenant_database` /
`deprovision_tenant_database`) creates/deletes databases via REST, applies
`sql/d1/001_init_d1.sql` as one multi-statement batch, and re-persists the
registry document. Provisioning is idempotent per tenant.

## Schema dialect (`sql/d1/001_init_d1.sql`)

Ported from the core tables of `sql/001_init_postgres.sql`
(`control_plane_resources`, `tenants`, `projects`, `workspaces`,
`api_keys`, `storage_schema_migrations`). Intentional divergences:

- **No RLS / GUC tenant fencing** — isolation is physical
  (database-per-tenant), so row-level fencing is redundant.
- **No cross-table FOREIGN KEYs** — a tenant database's `tenants` row lives
  in the control database, so intra-database FKs to `tenants` cannot
  resolve; referential integrity is enforced at the application layer (the
  reject-if-referenced deletes are single guarded `DELETE ... AND NOT
  EXISTS(...)` statements, atomic within a database).
- **Type mapping** — `JSONB` → `TEXT`, `BIGINT` → `INTEGER` (SQLite ints are
  64-bit), `BOOLEAN` → `INTEGER` 0/1, `EXTRACT(EPOCH FROM NOW())` →
  `unixepoch()`.

A portability test matrix
(`control_plane_store_d1_test.rs::portability`) parses BOTH migration files
and asserts the core tables expose identical column sets, that the D1
dialect carries no RLS/`current_setting` scaffolding and no `REFERENCES`
clauses, and (via mocked-transport round-trip tests) that the row shape a D1
write produces decodes back into the same `Stored*` struct the Postgres row
decoders produce.

### Parameter typing

Cloudflare documents query `params` as an array of **strings**. The backend
stays inside that contract: numbers bind as decimal strings (SQLite column
type affinity converts on insert), booleans as `"1"`/`"0"`, and SQL `NULL`
is expressed as `NULLIF(?, '')` with an empty-string bind rather than a JSON
`null` param.

## Rate-limit strategy: admin HTTP vs proxy-Worker binding

The public Cloudflare REST API is limited to ~1,200 requests / 5 min / user,
and every query is a cross-network round trip. The strategy split is:

- **Raw HTTP (this slice)** — admin/low-volume operations only: database
  provisioning, schema migration, entity CRUD, config documents. The shared
  client's deterministic backoff (#405) absorbs incidental 429s.
- **Proxy Worker with a D1 binding (follow-up)** — the hot path. A Worker
  holding the tenant database binding serves request logs, usage
  aggregates, billing events, and any per-request reads. See
  [`cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md)
  §bindings (`outboundByHost` shim) and
  [`cloudflare-integration.md`](cloudflare-integration.md) §6. This is
  exactly why the high-write trait surface is typed unimplemented below
  instead of being routed over raw HTTP.

Other D1 limits that shaped the design: 100 KB/statement, 100 params,
2 MB/row, 30 s/query, single-threaded per database, 10 GB/database,
50k databases/account (comfortably above any tenant-count target).

## Implemented vs erroring trait surface (first slice)

Implemented against D1:

- **API keys**: `upsert_api_key_record`, `get_api_key_record`,
  `list_api_key_records`, `find_api_key_records_by_prefix`.
- **Tenant accounts**: `upsert_tenant_account`, `get_tenant_account`,
  `list_tenant_accounts`.
- **Projects**: `upsert_project`, `get_project`, `list_projects`,
  `delete_project`, `delete_project_if_unreferenced`.
- **Workspaces**: `upsert_workspace`, `get_workspace`, `list_workspaces`,
  `delete_workspace`, `delete_workspace_if_unreferenced`,
  `resolve_workspace_scope`.
- **Admin users / memberships / refresh tokens** (issue #440, control
  database): `upsert_admin_user`, `get_admin_user_by_id`,
  `get_admin_user_by_email`, `upsert_admin_user_membership`,
  `list_admin_user_memberships_by_user`,
  `list_admin_user_memberships_by_tenant`, `delete_admin_user_membership`,
  `upsert_admin_user_refresh_token`, `get_admin_user_refresh_token_by_hash`,
  `revoke_all_admin_user_refresh_tokens`,
  `revoke_admin_user_refresh_tokens_for_tenant`.
- **SSO** (issue #440, control database): `upsert_sso_provider_config`,
  `get_sso_provider_config`, `delete_sso_provider_config`,
  `insert_sso_pending_flow`, `take_sso_pending_flow`. The D1 HTTP query API
  has no `DELETE ... RETURNING`, so `take_sso_pending_flow` reads the row and
  then deletes it (plus prunes expired rows) in a follow-up statement.
- **Quota policies + plans** (issue #440, control database):
  `upsert_quota_policy`, `get_quota_policy`, `list_quota_policies`,
  `delete_quota_policy`, `upsert_plan`, `get_plan`, `list_plans`. The
  migration seeds the default `free` plan (`INSERT OR IGNORE`), mirroring the
  Postgres migration and the in-memory `default_free_plan()`.
- **RBAC** (issue #445, control database): `upsert_permission`,
  `get_permission`, `list_permissions`, `delete_permission`, `upsert_role`,
  `get_role`, `list_roles`, `delete_role`, `bind_tenant_role`,
  `list_tenant_role_bindings`, `unbind_tenant_role`. Permissions/roles are
  shared/global (like plans); the `tenant_role_bindings` FKs to `tenants`/
  `roles` are dropped (physical isolation) and `unbind` deletes by the natural
  `(tenant_id, role_id)` key.
- **Site domains** (issue #445, control database): `upsert_site_domain`,
  `get_site_domain`, `list_site_domains`, `delete_site_domain`. `hostname` is
  the natural key and serve-path lookups carry no tenant context, so this
  family lives in the control database like `quota_policies`.
- **Budget alert idempotency ledger** (issue #445, control database):
  `record_budget_alert_notification`, `budget_alert_already_notified`,
  `list_budget_alert_notifications`. The Postgres `CHECK` on `scope_type` is
  dropped (validated in Rust); `record` is `INSERT ... ON CONFLICT (id) DO
  NOTHING` for once-per-period-per-tier idempotency.
- **Observability append/analytics** (issue #447, control database): agent
  runs (`upsert_agent_run`, `agent_run`, `agent_runs`, `agent_runs_by_ids`),
  agent run events (`append_agent_run_event`, `agent_run_events`,
  `agent_run_events_for_runs`), request logs (`append_request_log`,
  `request_logs`, `request_logs_page`, `delete_request_logs`,
  `request_logs_for_agent_runs`), audit events (`append_audit_event`,
  `audit_events`, `audit_events_page`, `delete_audit_events`,
  `audit_events_for_agent_runs`), and the cross-family
  `agent_run_summary_seed_ids`. Each row stores the FULL record as a `*_json`
  TEXT document (deserialized on read, mirroring the Postgres `*_json::text`
  selects) plus the projection columns the filter/order/paginate SQL needs.
  **Routing note:** unlike per-tenant entity data, these route to the CONTROL
  database, not a tenant database. Their analytics reads are cross-tenant
  whole-table scans (time-ordered, `count(*) OVER()`-paginated, and a four-way
  `UNION ALL` seed) and the `tenant` column is a composite storage key, not a
  routing tenant id — so a single-query control-database mirror of the Postgres
  single-table semantics is cleaner and lossless versus a per-tenant fan-out
  merge-sort with fetch-all-then-slice pagination. Postgres `= ANY($1)`
  predicates become SQLite `IN (?, …)` lists; the `()`/`Vec`/`Option`-returning
  surfaces swallow-with-warn on error like the Postgres backend, the
  `Result`-returning ones surface it.
- **Snapshot replay floors** (issue #206/#447, control database):
  `get_snapshot_replay_floor`, `advance_snapshot_replay_floor`. Account-global
  control-plane snapshot-replay state keyed by `(tenant_id, deployment_id)`.
  The Postgres `GREATEST(...) ... RETURNING` upsert becomes a SQLite `max()`
  upsert plus a follow-up `SELECT` (the HTTP query API has no `RETURNING`, as
  with `take_sso_pending_flow`); `max()` keeps the stored floor monotonic.
- **Billing ledger + report outbox + billing events** (issue #449, control
  database): the ledger (`append_billing_ledger_entry` — idempotent
  `INSERT ... DO NOTHING` plus a reload/settlement-compare on conflict —
  `list_billing_ledger_entries`, `billing_ledger_entry`), the report outbox
  (`enqueue_billing_report`, `list_due_billing_reports`,
  `reschedule_billing_report`, `dead_letter_billing_report`,
  `list_dead_lettered_billing_reports`, `replay_dead_lettered_billing_report` —
  a guarded `UPDATE` plus a follow-up `SELECT` for the terminal state, no
  `RETURNING` — `get_billing_report_outbox_entry`, `delete_billing_report`), and
  settled metering events (`append_billing_event`, `billing_events`,
  `billing_events_page`). Billing is account-global cross-tenant metering with
  whole-table reads, so it routes to the CONTROL database like the #447
  observability families; each row stores the full record as a `*_json`
  document plus the filter/order/paginate projection columns, with the outbox
  attempt/schedule state kept as columns so reschedule/dead-letter/replay stay
  single-statement `UPDATE`s. `append_billing_event_with_outbox_enqueue` (the
  two-table atomic enqueue, issue #150) stays erroring.
- **Guardrail policy revisions + bindings** (issue #449, control database):
  `insert_guardrail_policy_revision` (idempotent on `(policy_id, revision)`,
  typed `Conflict` on replay), `get_guardrail_policy_revision`,
  `list_guardrail_policy_revisions`, `get_guardrail_policy_binding`,
  `list_guardrail_policy_bindings`. Account-global guardrail configuration
  (like plans/RBAC). The generation-guarded `activate`/`archive`/`restore` CAS
  transitions stay erroring (they need the compare-and-swap transaction the D1
  HTTP query API lacks).
- **Managed worker stores** (issue #449, control database): templates, agent
  worker instances, sessions, lifecycle events, and the isolation
  selection/policy/evidence trio — each an `upsert`/`append` of the full record
  as a `*_json` document plus an ORDER BY projection column, and a whole-table
  list.
- **Self-hosted worker stores** (issue #449, control database): registrations
  (+ single-get), heartbeats (+ `latest_self_hosted_worker_heartbeat`),
  telemetry events (+ per-run newest-window and per-worker filtered reads),
  artifacts (+ single-get), checkpoints (+ single-get), run dispatches (the
  Postgres capability side-table folds into the dispatch document), and
  `self_hosted_worker_activity_stats` (count/max subselects in one query).
- **Config documents** (generic kind-keyed, control database):
  `upsert_config_document`, `delete_config_document`,
  `get_config_document`, `list_config_documents`,
  `list_config_resource_documents`, `replace_config_documents`,
  `control_plane_snapshot`, `config_documents`.
- **Process-local semantics** (identical on every backend):
  `set_retention_limits` (no-op like Postgres), `next_audit_event_id`,
  `upsert_usage_aggregate_local`, `store_usage_aggregate_local`,
  `usage_aggregates` (process-local view), `sum_api_key_committed_tokens`
  (process-local view).

Everything else — the atomic-transition families that need the transaction
semantics the D1 HTTP query API lacks (wallets + reservations, payment
methods/attempts, workflow run budgets, `append_billing_event_with_outbox_enqueue`,
and the guardrail activate/archive/restore CAS transitions);
assets/channels/retention (deferred as a whole family — its move/yank/variant
coordination ops are atomic `FOR UPDATE` cross-table transitions, the same
transaction gap that blocks wallets, plus inline BYTEA content the document
pattern serves poorly); usage monthly + metadata rollups +
`persist_usage_aggregate` (the durable half — the rollups are maintained by the
`append_billing_event` settlement transaction's read-modify-write increments,
which have no single-statement equivalent, and the usage-aggregate
store-of-record here is still the process-local mirror); and the remaining
pre-#425 per-entity dispatch surfaces (agent schedules, observed agent presence,
guardrail evidence, MCP identity) — returns the **typed
`unimplemented-backend-surface` error** (`is_unimplemented_backend_surface`
matches it) wherever the signature carries a `Result`, and logs a warning +
returns an empty/default value where it cannot. Nothing fails silently; tests
pin the contract. (RBAC, site domains, and the budget-alert ledger from that
group are now implemented — issue #445; request/audit logs, agent runs/events,
and snapshot replay floors — issue #447; billing ledger/outbox/events, guardrail
revisions/bindings, and the managed + self-hosted worker stores — issue #449,
all above.)

## Config-driven construction (issue #440)

`StorageProviderKind::CloudflareD1` (`storage.provider = "cloudflare_d1"`)
selects the backend; absent config selects nothing (opt-in).
`RuntimeStorageRepositories::cloudflare_d1_from_client(client, options)` is the
storage half: it seeds the tenant→database registry from
`CloudflareD1StorageOptions { control_database_id, tenant_databases,
audit_event_retention_records }` and wraps the store. The caller owns the
transport (it builds the `CloudflareClient`/`D1Client` from the `[cloudflare]`
block), so `ferrogate-storage` stays transport-free and unit-testable against a
scripted transport.

## CLI construction hook (issue #445)

`crates/ferrogate-cli` now constructs the D1 backend from config.
`runtime_storage_repositories` (`crates/ferrogate-cli/src/state.rs`) branches on
`storage.provider = "cloudflare_d1"` before the in-memory fallback: it reads the
`[cloudflare]` block (erroring if absent — also caught by config validation),
builds a `CloudflareClient` (`CloudflareClient::new` + `EnvTokenResolver`) and
wraps it in a `D1Client`, then assembles `CloudflareD1StorageOptions` from two
new `[storage]` config fields and hands it to
`RuntimeStorageRepositories::cloudflare_d1_from_client`:

- **`storage.d1_control_database_id`** (optional string) → the control-database
  uuid. Absent/empty means "not provisioned yet"; the backend rejects
  control-plane access until `provision_control_database` seeds it.
- **`storage.d1_tenant_databases`** (optional `{ tenant_id = "db-uuid" }` map) →
  pre-seeds the tenant→database registry for a deployment resuming against
  already-provisioned tenant databases.

`audit_event_retention_records` is threaded from `[analytics]` exactly as for
the other backends. Registry bootstrap (provisioning the control database on
first run) stays an explicit admin step via
`D1ControlPlaneStore::provision_control_database`, not a startup side effect.
Absent config selects nothing — the backend is opt-in (`storage.provider`
defaults to `memory`).

## Remaining scope (follow-ups)

1. **Proxy-Worker D1 binding path** for the high-write surface (request logs,
   audit events, billing events, usage aggregates) and per-request reads.
   Deferred — this is the `prepare().bind()` / `batch()` / `withSession()`
   binding path, which belongs in a Worker (`workers/**`, out of scope) rather
   than the raw REST client, exactly as the rate-limit split dictates. Issue
   #447 lands the durable D1 SQL translation for the request/audit-log and
   agent-run/event families over the admin HTTP path (routed to the control
   database, above); the proxy-Worker binding is the separate hot-path
   transport for the same tables and remains the follow-up.
2. Remaining entity families still erroring: assets/channels/retention and the
   usage monthly/metadata rollups + `persist_usage_aggregate` durable half
   (deferred as families — see above); the atomic-transition families blocked on
   the proxy-Worker binding (wallets + reservations, payment methods/attempts,
   workflow budgets, `append_billing_event_with_outbox_enqueue`, guardrail
   activate/archive/restore); and the per-entity surfaces agent schedules,
   observed agent presence, MCP identity. (Issue #449 landed the billing
   ledger/outbox/events, guardrail revisions/bindings, and managed +
   self-hosted worker stores over the admin HTTP path, routed to the control
   database — above.)
4. `/raw` query variant and `batch` request shape if bulk import ever needs
   them. (Entity `SELECT`s already return their full result set in one query
   response; `list_databases` now follows REST pagination past 1,000 rows.)
5. Live-Cloudflare integration test (gated on account credentials), mirror
   of `supabase_roundtrip.rs`.
