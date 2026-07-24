# Cloudflare D1 control-plane backend (per-tenant databases)

Status: first slice landed (issue #420). Builds on the shared Cloudflare
client (#405), the `ControlPlaneStore` trait extraction (#419), and the #425
dispatch consolidation.

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
  generic kind-keyed `control_plane_resources` config-document table, and the
  tenant→database registry document.
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

Everything else — admin users, SSO, refresh tokens, quota policies, plans,
assets/channels/retention, usage monthly rollups, billing ledger/outbox,
guardrail policy revisions/bindings, snapshot replay floors, request/audit
logs, billing events, `persist_usage_aggregate` (the durable half), agent
runs/events, managed/self-hosted worker stores, and the pre-#425 per-entity
dispatch surfaces (wallets, payment attempts, RBAC, agent schedules, site
domains, budget alerts, workflow budgets, observed agent presence, usage
metadata rollups, guardrail evidence, MCP identity) — returns the **typed
`unimplemented-backend-surface` error** (`is_unimplemented_backend_surface`
matches it) wherever the signature carries a `Result`, and logs a warning +
returns an empty/default value where it cannot (the append/analytics
getters). Nothing fails silently; tests pin the contract.

## Remaining scope (follow-ups)

1. Proxy-Worker D1 binding path for the high-write surface (request logs,
   audit events, billing events, usage aggregates) and per-request reads.
2. Remaining entity families on the trait (admin users/SSO first — they are
   plain CRUD; then quota policies/plans, assets).
3. Wiring a config/CLI construction path (`RuntimeStorageRepositories::
   cloudflare_d1` exists; a `storage.provider = cloudflare_d1` config route
   and registry bootstrap/preflight do not yet).
4. D1 list pagination beyond the first 1,000 databases; `/raw` query variant
   and `batch` request shape if bulk import ever needs them.
5. Live-Cloudflare integration test (gated on account credentials), mirror
   of `supabase_roundtrip.rs`.
