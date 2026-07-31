# Cloudflare D1 control-plane backend (per-tenant databases)

Status: first slice landed (issue #420); auth/quota entity families + the
storage-side config-driven construction route + `list_databases` pagination
landed (issue #440); the ferrogate-cli construction hook (config fields +
`state.rs` branch) + the RBAC / site-domain / budget-alert-ledger entity
families landed (issue #445); the observability append/analytics families
(agent runs/events, request/audit logs) + snapshot replay floors landed (issue
#447); and the billing ledger/outbox/events, guardrail policy
revisions/bindings, and managed + self-hosted worker stores landed (issue #449).
The **proxy-Worker D1 binding** (`workers/d1-proxy/`) + its Rust client
(`ferrogate_cloudflare::d1_proxy`) + the FIRST atomic-transition op routed
through it (`append_billing_event_with_outbox_enqueue`) landed as the keystone
slice (issue #450); the guardrail binding CAS transitions
(`activate`/`archive`/`restore`) were wired through the same proxy `/d1/query`
binding next (issue #454); and the FIRST **tenant-scoped** atomic family —
prepaid-credit wallets (`reserve`/`settle`/`release` + wallet CRUD) — landed over
**per-tenant proxy bindings** (issue #455). Builds on the shared Cloudflare client
(#405), the `ControlPlaneStore` trait extraction (#419), and the #425 dispatch
consolidation.

FerroGate's third control-plane storage backend persists control-plane
entities in **per-tenant Cloudflare D1 databases** driven over the D1 REST
API — physical database-per-tenant isolation instead of shared-Postgres
row-level isolation (`tenant_id` columns + RLS).

## Where the code lives

| Piece | Location |
| --- | --- |
| D1 REST endpoint wrapper (lifecycle + query) | `crates/ferrogate-cloudflare/src/d1.rs` |
| **Proxy-Worker client (atomic `/d1/batch` + `/d1/query`)** | `crates/ferrogate-cloudflare/src/d1_proxy.rs` |
| **Proxy Worker (native D1 binding, bearer HTTP API)** | `workers/d1-proxy/` (`src/index.ts`, `src/auth.ts`, `wrangler.toml`) |
| Backend (`D1ControlPlaneStore`, registry, provisioning) | `crates/ferrogate-storage/src/control_plane_store_d1/` |
| Atomic op wired through the proxy (`append_billing_event_with_outbox_enqueue`) | `crates/ferrogate-storage/src/control_plane_store_d1/billing.rs` |
| Guardrail binding CAS wired through the proxy (`activate`/`archive`/`restore`, #454) | `crates/ferrogate-storage/src/control_plane_store_d1/guardrail.rs` |
| Tenant-scoped wallets/reservations over per-tenant proxy bindings (#455) | `crates/ferrogate-storage/src/control_plane_store_d1/wallet.rs` |
| SQLite-dialect core schema | `sql/d1/001_init_d1.sql` |
| Mocked-transport tests + portability matrix | `crates/ferrogate-storage/src/control_plane_store_d1_test.rs`, `crates/ferrogate-cloudflare/src/d1_test.rs`, `crates/ferrogate-cloudflare/src/d1_proxy_test.rs` |

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

- **Enumeration `CHECK`s dropped** — validated in Rust before the write.
  **One exception (issue #517):**
  `admin_user_tenant_memberships.role` keeps its
  `CHECK (role IN ('owner','admin','member','viewer'))`, because that column
  is a privilege tier (it selects the scopes a console session's gateway API
  key is minted with), not a descriptive enum. `MembershipRole::parse`
  (`crates/ferrogate-auth-service/src/membership_role.rs`) is the enforcement that
  covers both backends and already-provisioned databases — SQLite cannot add
  a `CHECK` to an existing table, so the constraint only binds newly
  provisioned D1 databases and is a second layer, not the primary one.

A portability test matrix
(`control_plane_store_d1_test.rs::portability`) parses BOTH migration files
and asserts the core tables expose identical column sets, that the membership
`role` domain is identical in both dialects, that the D1
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
- **Proxy Worker with a D1 binding (issue #450, landed for the atomic path)** —
  a Worker (`workers/d1-proxy/`) holding a native D1 binding (`env.DB`) exposes a
  bearer-authenticated HTTP API. It runs `prepare().bind()` / `batch()` (atomic)
  / `RETURNING` — the exact three primitives the REST HTTP query API lacks — for
  the **atomic-transition hot path**. See
  [`cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md)
  §bindings (`outboundByHost` shim) and
  [`cloudflare-integration.md`](cloudflare-integration.md) §6. This is exactly
  why the atomic trait surface was typed unimplemented instead of being routed
  over raw HTTP.

Other D1 limits that shaped the design: 100 KB/statement, 100 params,
2 MB/row, 30 s/query, single-threaded per database, 10 GB/database,
50k databases/account (comfortably above any tenant-count target).

## Proxy-Worker D1 binding: the atomic hot path (issue #450)

The D1 **REST** HTTP query API has no multi-statement-with-params transaction
and no `RETURNING`. That blocks every **atomic-transition** family — the ones
whose correctness needs two-or-more writes to commit together, or a
compare-and-swap that reads back the row it just changed: wallets + reservations,
payment methods/attempts, workflow run budgets,
`append_billing_event_with_outbox_enqueue` (the metering write + report-outbox
enqueue of issue #150), and the guardrail activate/archive/restore CAS
transitions. No amount of empty-string-sentinel SQL over REST expresses an atomic
batch, so these cannot ride the REST client.

The fix is a small proxy Worker that holds a **native D1 binding** and exposes
exactly the primitives REST lacks.

### The proxy Worker (`workers/d1-proxy/`)

A TypeScript Worker (typed against `@cloudflare/workers-types`) with a
`[[d1_databases]]` binding (`env.DB: D1Database`). A DIY bearer gate — a verbatim
copy of the agent-gateway house pattern (`requireBearer` + constant-time compare,
its own copy under `workers/d1-proxy/src/auth.ts`; worker dirs never import
across each other) — fronts two data routes, both POST-only and fail-closed
(401 missing / 403 invalid / 500 unconfigured token):

| Route | D1 binding call | Purpose |
| --- | --- | --- |
| `POST /d1/batch` | `env.DB.batch([prepare().bind(...), ...])` | **Atomic** multi-statement batch. All statements commit together or the whole batch rolls back. Returns one result per statement, each carrying its `RETURNING` rows. |
| `POST /d1/query` | `prepare().bind(...).all()` | Single statement with `RETURNING`, for CAS ops expressible as one `UPDATE ... RETURNING` / `INSERT ... RETURNING`. |
| `GET /healthz` | — | Unauthenticated liveness probe (exposes no secret, touches no data). |

Request bodies: `/d1/batch` takes `{ "statements": [ { "sql", "params": [...] }, ... ] }`;
`/d1/query` takes one `{ "sql", "params": [...] }`. Params are `string | number |
boolean | null`; the Rust client sends the **all-strings** form (SQLite affinity
converts on insert), identical to the REST contract. Responses are the same
Cloudflare-style envelope the REST API uses (`{ success, errors, messages,
result }`), and each statement result is the same `{ results, success, meta }`
shape the REST query endpoint returns per statement — so the Rust side reuses one
decoder (`D1QueryResult`) across both transports. D1 execution failures answer a
`5001` error code (deliberately NOT a Cloudflare auth/scope/rate-limit code, so a
rolled-back batch is never misclassified as an auth failure). The Worker also
guards the documented limits up front (≤100 params/statement, a defensive
statements/batch cap).

The Worker's `env.DB` binding is fixed at deploy time to the FerroGate **control
database** — the atomic family wired in this slice (billing metering + report
outbox) is account-global control-plane data that routes to the control database,
exactly like the #447/#449 REST families. Issue #455 later added the optional
`database` selector on both request bodies, so the same deployed Worker also
serves one binding per tenant database (absent selector = `env.DB`); see the
per-tenant binding section below. Every binding is still declared at deploy time
— there is no runtime select-by-database-id.

### The Rust client (`ferrogate_cloudflare::d1_proxy`)

`D1ProxyClient` is a thin, self-contained client mirroring the `d1.rs` REST
wrapper's style. It is deliberately **not** built on `CloudflareClient` (which
templates `{account_id}`, targets the Cloudflare REST base URL, and uses the
account API token): the proxy Worker lives at its own deployed origin and
authenticates with its **own** bearer secret. Instead it reuses the lower-level
shared seams directly — `HttpTransport` (Bearer request/response, injectable +
mockable with the same scripted transport the REST tests use), `TokenResolver`
(the `env://`/inline/`cf://` credential seam), and `CloudflareEnvelope` (the wire
shape). Its surface:

- `batch(&[D1ProxyStatement]) -> Result<Vec<D1QueryResult>, CloudflareError>` —
  one result per statement, in order.
- `query(&D1ProxyStatement) -> Result<D1QueryResult, CloudflareError>`.

`D1ProxyStatement { sql, params: Vec<String> }` is the typed request statement.
Proxy failures surface through the SAME `CloudflareError` mapping as REST
failures, so callers handle one error model.

### Atomic-vs-REST routing split

- **REST (`D1Client`)** stays the transport for the **non-atomic / admin**
  surface: provisioning, schema migration, entity CRUD, config documents, and
  every append/analytics family already landed over REST (billing ledger/outbox
  reads, observability, etc.).
- **Proxy (`D1ProxyClient`)** serves the **atomic** hot path only.
  `D1ControlPlaneStore` holds an `Option<D1ProxyClient>` (builder:
  `with_proxy_client`). When it is absent (a REST-only deployment) the atomic
  families **fail closed** with the typed `unimplemented-backend-surface` error
  — the same typed error the deferred surfaces return, never a silent or partial
  write. This is a deployment-time condition, not a deferred family: the same
  method succeeds once a proxy is bound.

### Wired atomic op: `append_billing_event_with_outbox_enqueue`

The keystone proof (in `control_plane_store_d1/billing.rs`). It routes a
**two-statement atomic batch** through `/d1/batch`:

1. The metering insert — `INSERT INTO billing_events ... ON CONFLICT
   (billing_event_id) DO NOTHING RETURNING billing_event_id`. The `RETURNING` row
   is present **iff** the event was newly recorded; a REST-only backend cannot
   learn this in the same round trip.
2. The report-outbox enqueue — `INSERT INTO billing_report_outbox ... ON CONFLICT
   (id) DO NOTHING` (idempotent on the caller's `outbox_id`).

Both statements' SQL mirror the standalone `append_billing_event` /
`enqueue_billing_report` writes verbatim (only `RETURNING` is added), so the
atomic path stays row-for-row consistent with the non-atomic REST writes. `batch`
commits them as one unit: if either fails, D1 rolls the whole batch back — the
issue #150 guarantee that a metering write never lands without its outbox
enqueue, so there is no partial-success case (`enqueue_error` stays `None`, like
Postgres). On an idempotent replay (metering row already present → no `RETURNING`
row) the stored event's settlement is re-verified over the REST reload path
(`billing_event_by_id`, a non-atomic single read), mirroring
`append_billing_event`; a divergent replay is a typed `Conflict`.

### Wired atomic op: guardrail binding CAS (`activate` / `archive` / `restore`, issue #454)

The generation-guarded compare-and-swaps on the single mutable
`guardrail_policy_bindings` row (in `control_plane_store_d1/guardrail.rs`). Each is
one **single-statement** CAS through `/d1/query` — the companion to the billing
keystone's `/d1/batch`:

- `activate` / `archive`: read the current binding (a non-atomic REST point read),
  compute the next binding with the SAME pure planners the Postgres backend uses
  (`next_guardrail_activation_binding` / `next_guardrail_archive_binding`), then a
  guarded write. When a prior binding exists it is an `UPDATE guardrail_policy_bindings
  SET ... WHERE policy_id = ? AND generation = ? RETURNING policy_id` (the CAS guards
  on the previous generation); the first write is an `INSERT ... ON CONFLICT (policy_id)
  DO NOTHING RETURNING policy_id`. `activate`/`archive` also first verify the target
  revision exists over REST (typed `NotFound` otherwise).
- `restore` (rollback, issue #388): re-establish a captured binding under its expected
  generation (the same guarded `UPDATE`), or `DELETE ... WHERE generation = ? RETURNING
  policy_id` back to "no binding".

In every case an **empty `RETURNING` set is the lost-update signal** — the guard did
not match (a concurrent writer moved the generation, or raced the first insert) — which
the REST query API cannot surface, and which maps to the typed CAS
`Conflict` (`is_guardrail_policy_binding_cas_conflict`). The full binding is persisted as
the `binding_json` document the read path deserializes, with
`active_revision`/`updated_at_unix`/`generation` mirrored into the projection columns the
guard and reads use. Guardrail configuration is **account-global** (like plans/RBAC), so
the proxy's control-DB binding serves these directly — no per-tenant binding is required.

### Wired atomic family: tenant-scoped wallets + reservations (issue #455)

The FIRST **tenant-scoped** atomic family (in `control_plane_store_d1/wallet.rs`).
Unlike the account-global billing/guardrail families, a tenant's wallet, its live holds,
and its settlement ledger live in **that tenant's own D1 database** in the
database-per-tenant topology — so the proxy must run these against a *selected* database,
not the fixed control `env.DB`.

**Per-tenant routing mechanism (binding-name map).** The Workers runtime can reach a D1
database **only through a statically-declared binding** — there is no runtime
"open a database by id" API (verified against `@cloudflare/workers-types`' `D1Database`,
which exposes only `prepare`/`batch`/`exec`/`withSession`, and the D1 Worker API docs). So
the proxy Worker binds each tenant database under its own name and the request selects it
by **name**: `POST /d1/batch` / `/d1/query` now accept an optional `database` field
(`{ "database": "TENANT_DB_ACME", ... }`); the Worker resolves `env[name]`, duck-typing it
back to a `D1Database` (so a caller can never coerce a non-D1 binding such as the
`D1_PROXY_TOKEN` string into a database handle). An omitted/empty `database` (or `"DB"`)
targets the control database, so the #450/#454 control-DB path is byte-for-byte unchanged.
The Rust side derives the binding name deterministically from the tenant id —
`tenant_database_binding("acme") = "TENANT_DB_ACME"` (uppercased, `-`→`_`, prefixed so it
is a valid wrangler identifier that cannot collide with `DB`/`D1_PROXY_TOKEN`). The
**request-param-carries-a-database-id** alternative was rejected: the runtime has no
select-by-id, and a uuid is not a valid binding identifier.

**Onboarding a tenant therefore requires adding its `[[d1_databases]]` binding to
`workers/d1-proxy/wrangler.toml` and redeploying** — the same per-binding,
redeploy-to-onboard reality the #423 Secrets-Store bindings have. `provisioned_tenant_bindings`
reads the tenant→database registry (#440) to know which bindings should exist.

- `reserve_wallet_credits` (the no-oversell proof) mirrors the Postgres `SELECT ... FOR
  UPDATE` + sum-live-holds + conditional insert as **one atomic `/d1/batch`** on the tenant
  binding: an idempotency probe, a guarded `INSERT ... SELECT ... WHERE amount <= balance -
  SUM(active unexpired holds) ... ON CONFLICT (id) DO NOTHING RETURNING id`, and a
  wallet-state read. D1 has no row lock, but a batch is one implicit transaction and SQLite
  serializes writers per database, so N parallel reserves against a balance affording N-1
  admit exactly N-1 — no oversell. RETURNING-empty on the guarded insert = not admitted; the
  sibling state read splits `NoWallet` (no wallet row) from `Insufficient` (available balance
  reported).
- `settle_wallet_reservation` / `release_wallet_reservation` carry only a hold id in their
  trait signature, so they **fan out** over the provisioned tenant bindings to locate the
  database holding the hold (the established id-only-read fan-out), then run the guarded
  transition: `settle` captures the hold as one atomic batch (debit wallet + insert ledger row
  + `active→settled` flip, every statement guarded on the hold still being `active`, so a
  concurrent settle can never double-debit); `release` is a single guarded
  `UPDATE ... WHERE status = 'active' RETURNING` CAS.
- `upsert_wallet`/`get_wallet`/`list_wallet_reservations` route the same way (get/list answer
  empty for an unprovisioned tenant — opt-in). Every op fails closed with the typed
  unimplemented-surface error when no proxy Worker is bound.

**Landed since (issue #456):** the remaining wallet ops — `settle_wallet_balance`,
`adjust_wallet_balance`, `set_wallet_dunning`, `list_wallets` — now route through the same
per-tenant proxy binding.

**Deferred (still erroring), to be wired through the proxy in follow-ups:**
`sweep_expired_wallet_reservations` and payment methods/attempts, both tracked by **#459**.
`sweep`'s money-safety guard reads `payment_attempts.hold_id`, which couples it to the x402
payment_attempts family, so the two land as one unit rather than separately.

### Workflow run budgets: the concurrency contract (issue #456)

Postgres `debit`/`topup` hold the row with `SELECT ... FOR UPDATE`. D1/SQLite has no row
lock, so the D1 mirror uses a **bounded internal optimistic-CAS retry**: read the counters,
decide `Applied`/`Exceeded` through the SAME shared `dimension_exceeded_by` arithmetic, then
a guarded `UPDATE ... WHERE <status + spent counters + caps unchanged since the read>
RETURNING`. An empty `RETURNING` means a concurrent debit/top-up landed in between, so the
op re-reads and retries; `topup` reuses the same `apply_topup` arithmetic under a
caps-guarded CAS-retry, making the raised envelope row-for-row identical across backends.

The retry is **internal**, so the `WorkflowBudgetDebit` contract is UNCHANGED — still
`Applied`/`Exceeded`, with **no new `Conflict` variant**. That keeps caller code identical
across backends and avoids the #415 non-exhaustive-match hazard. The no-lost-debit and
fail-closed-`Exceeded` invariants are preserved, not traded away.

The retry budget is bounded, so exhaustion needs a defined outcome: after the ceiling
(`WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS` = 16, `workflow_budget.rs`) both `debit` and `topup` return
`StorageError::Runtime` naming the method and the attempt count. That is the third
result of the concurrency contract and it is deliberately an ERROR, not a fabricated
`Applied`/`Exceeded`: each attempt re-reads committed state, so exhaustion means sustained
contention on one budget row, and the caller must not be told a debit landed (or was
refused) when neither is known. No counter has moved when this returns — every attempt
that failed its guard wrote nothing — so the caller may safely retry. Postgres, holding
`SELECT ... FOR UPDATE`, has no equivalent path; this is the one observable divergence the
internal retry buys.

### Divergence: mutating an unprovisioned tenant is `NotFound` (issue #456)

Every per-tenant family routes through a per-tenant database binding, so a **write** against
a tenant that has no provisioned database returns the typed `NotFound` rather than
implicitly creating one. This is a deliberate database-per-tenant divergence from the
single-database backends, where the row simply inserts. Reads stay **opt-in**: `get`/`list`
against an unprovisioned tenant answer empty/`None` instead of erroring, so an operator
listing across tenants is never blocked by one unprovisioned org.

### Deploy / binding steps the gate runs live

1. Provision the control database (`D1ControlPlaneStore::provision_control_database`
   over REST, or an already-provisioned uuid), and note its uuid — the same value
   seeded into `storage.d1_control_database_id`.
2. In `workers/d1-proxy/wrangler.toml`, set the `[[d1_databases]]` `database_id`
   (and `database_name`) to that control database uuid.
3. `wrangler secret put D1_PROXY_TOKEN` — the DIY bearer secret. Seed the SAME
   value into FerroGate's Cloudflare credential seam (#405/#417) as the proxy
   client's token reference.
4. `npm install && npm run typecheck && wrangler deploy` under `workers/d1-proxy/`
   (registry access required for install; the dev gate typechecks against the
   pinned `@cloudflare/workers-types`).
5. Point the Rust `D1ProxyClient` at the deployed Worker origin
   (`https://ferrogate-d1-proxy.<subdomain>.workers.dev`) and construct the store
   with `with_proxy_client`.
6. **Per tenant (issue #455):** after `provision_tenant_database(tenant_id)` records
   the tenant's D1 uuid in the registry, add a `[[d1_databases]]` block to
   `workers/d1-proxy/wrangler.toml` with `binding = "TENANT_DB_<TENANT_ID>"`
   (`tenant_database_binding` derivation) and that uuid, then `wrangler deploy`.
   Only after this redeploy can the tenant's wallet `reserve`/`settle`/`release`
   resolve `env["TENANT_DB_<TENANT_ID>"]`.

## Implemented vs erroring trait surface

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
  two-table atomic enqueue, issue #150) is now **implemented via the proxy-Worker
  `/d1/batch` binding** (issue #450) — see the proxy-Worker section above — and
  fails closed with the typed unimplemented-surface error only when no proxy
  Worker is bound.
- **Guardrail policy revisions + bindings** (issue #449, control database):
  `insert_guardrail_policy_revision` (idempotent on `(policy_id, revision)`,
  typed `Conflict` on replay), `get_guardrail_policy_revision`,
  `list_guardrail_policy_revisions`, `get_guardrail_policy_binding`,
  `list_guardrail_policy_bindings`. Account-global guardrail configuration
  (like plans/RBAC). The generation-guarded `activate`/`archive`/`restore` CAS
  transitions need the compare-and-swap transaction the D1 HTTP query API lacks,
  so they are **implemented via the proxy-Worker `/d1/batch` binding** (issue
  #454) — see the proxy-Worker section above — and fail closed with the typed
  unimplemented-surface error only when no proxy Worker is bound.
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
- **Wallets + reservations** (issues #455/#456, TENANT databases, proxy
  Worker): `upsert_wallet`, `get_wallet`, `list_wallet_reservations`, the
  `reserve`/`settle`/`release` trio, and the remaining wallet ops
  `settle_wallet_balance`, `adjust_wallet_balance`, `set_wallet_dunning`,
  `list_wallets`. See the wallet section above for the guarded-CAS shape and the
  hold-id fan-out; `wallet.rs`.
- **Workflow run budgets** (issue #456, TENANT databases, proxy Worker):
  `open_workflow_run_budget`, `debit_workflow_run_budget`,
  `topup_workflow_run_budget`, `get_workflow_run_budget`,
  `list_workflow_run_budgets`. `debit`/`topup` run under a bounded internal
  optimistic-CAS retry that leaves the `WorkflowBudgetDebit` contract unchanged
  — see the concurrency-contract section above; `workflow_budget.rs`.
- **Assets + channels + retention** (issue #456, TENANT databases, proxy
  Worker) — the whole family: assets (`upsert_asset`,
  `create_asset_if_absent`, `create_asset_within_quota` — the quota-guarded
  upsert, `23505` → typed `AlreadyExists` — `get_asset`, `list_assets`,
  `list_withheld_assets`, `tenant_asset_storage_bytes_used`, `delete_asset`,
  `list_all_assets`, `set_asset_version_yank`,
  `delete_asset_variant_if_unreferenced`, `promote_pending_asset_visibility`),
  channels (`upsert_asset_channel`, `list_asset_channels`,
  `delete_asset_channel`, `list_all_asset_channels`,
  `move_asset_channel_if_resolvable` — the move/yank coordination as one atomic
  batch), and retention (`upsert_retention_policy`,
  `list_retention_policies`); `assets.rs`.
- **Usage monthly + metadata rollups** (issue #456, TENANT databases, proxy
  Worker): `get_usage_monthly_rollup`/`list_usage_monthly_rollups` fan out over
  the provisioned tenant bindings (a scope's rollup lives in the OWNING tenant's
  database) and re-merge to the Postgres `ORDER BY`;
  `list_usage_metadata_rollups` routes by organization. The
  `persist_usage_aggregate` durable half commits its rollup upsert and the
  `usage_aggregate_rollups` REPLACE as ONE atomic `/d1/batch` on the owning
  tenant's database; `usage.rs`.
- **Agent schedules + fire history** (issues #460/#246, TENANT databases, proxy
  Worker): schedule definitions plus the idempotent at-most-once fire ledger.
  `list_all_agent_schedules` / `list_due_agent_schedules` fan out and re-sort to
  the Postgres order (`list_due` applies a per-binding `LIMIT`, then re-sorts by
  next-fire-ascending and truncates to a GLOBAL `limit`); id-only ops fan out to
  locate the owning database, and `delete` cascades the fire rows itself as one
  `/d1/batch` because the FK-free D1 dialect drops the Postgres `ON DELETE
  CASCADE`; `agent_schedule.rs`.
- **Observed-agent presence** (issues #460/#357, TENANT databases, proxy
  Worker): `touch_observed_agent_presence` is ONE conditional upsert mirroring
  the Postgres coalesced clause with SQLite's scalar `max()`/`min()` (SQLite has
  no `GREATEST`/`LEAST`) plus `request_count += excluded.request_count`, so a
  burst of touches stays a single-row hot write and a delayed touch never
  regresses the row. `list_observed_agent_presence_since(None, ...)` fans out
  over the provisioned bindings; `observed_presence.rs`.
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

Everything else returns the **typed `unimplemented-backend-surface` error**
(`is_unimplemented_backend_surface` matches it). Every method in the list below
carries a `Result`, so nothing on the unimplemented surface degrades to a
default value. The `warn!`-and-default paths elsewhere in the backend are
runtime-failure degradation on the IMPLEMENTED append/analytics surfaces
(issues #447/#449), mirroring the Postgres backend — they are not unimplemented
surfaces. Nothing fails silently; tests pin the contract.

The proxy Worker serves both the control database and the per-tenant bindings
through the `database` selector (#455), so nothing below is deferred for want of
a binding; each entry carries its own reason. **Given a configured proxy Worker**
that set is now exactly the list below.

That precondition is load-bearing, not a formality: every proxy-backed family
takes its client through `proxy_client(method)`
(`control_plane_store_d1/provisioning.rs`), which returns the SAME typed
`unimplemented-backend-surface` error — naming the calling method — when the
store was built without proxy options. So on a deployment with no proxy Worker
configured, the erroring surface is strictly LARGER than this list: it also
covers every atomic/per-tenant family (wallets, workflow budgets, assets and
channels, retention, agent schedules, observed presence, usage rollups, the
guardrail binding CAS, and the billing-event + outbox enqueue). That widening is
deliberately NOT in the block below, and `check-d1-surface-map.py` cannot see it:
the gate matches string-literal `unimplemented_surface("…")` call sites, and
`proxy_client` passes a `method` variable. The list below is therefore the
static, always-erroring set — the floor, not the ceiling.

<!-- SOURCE OF TRUTH: the `unimplemented_surface("…")` call sites under
     crates/ferrogate-storage/src/control_plane_store_d1/, plus the
     RuntimeControlPlaneBackend::CloudflareD1 arms in
     crates/ferrogate-storage/src/guardrail_evidence.rs and
     crates/ferrogate-storage/src/mcp_identity.rs. Re-derive, do not hand-edit:
     scripts/check-d1-surface-map.py fails when this block, the matching block
     in control_plane_store_d1/mod.rs, and the call sites disagree. -->
<!-- BEGIN D1-ERRORING-SURFACE -->
- **x402 payments (issue #459, deferred org-wide — scope, not capability):**
  payment methods (`upsert_payment_method`, `list_payment_methods`,
  `get_payment_method`, `delete_payment_method`), payment attempts
  (`create_payment_attempt`, `get_payment_attempt`, `list_payment_attempts`,
  `get_payment_attempt_links`, `list_expirable_due_payment_attempts`,
  `list_reconcilable_payment_attempts`, `transition_payment_attempt`), and
  `sweep_expired_wallet_reservations` — the sweep is coupled here because its
  money-safety guard reads `payment_attempts.hold_id`.
- **Agent cost-burn (issue #428):** `add_agent_burn`, `get_agent_burn`,
  `list_agent_cost_burn`. Ordering, not routing — the durable per-agent burn
  ledger lands on the Postgres control-plane store first.
- **Guardrail evidence:** `append_guardrail_evaluation`,
  `query_guardrail_evaluations`, `list_guardrail_evaluations`,
  `list_guardrail_check_evaluations`. Not an atomic family: it is
  enum-dispatched in `crates/ferrogate-storage/src/guardrail_evidence.rs`,
  outside the #437 per-entity surfaces, and that dispatch is unmigrated. NOT
  covered by the "per-entity dispatch surfaces" note below.
- **MCP identity:** the last remaining pre-#425 per-entity dispatch surface,
  in `crates/ferrogate-storage/src/mcp_identity.rs` — mostly non-atomic
  reads/writes, deferred because the dispatch is unmigrated:
  `authorize_mcp_identity`, `authorize_mcp_identity_with_operation`,
  `append_mcp_identity_audit_event_with_operation`, `begin_mcp_oauth_flow`,
  `consume_mcp_oauth_flow`, `commit_mcp_oauth_callback`,
  `get_mcp_oauth_credential`, `list_mcp_oauth_credentials`,
  `claim_mcp_oauth_refresh`, `claim_mcp_oauth_refresh_with_operation`,
  `renew_mcp_oauth_refresh`, `renew_mcp_oauth_refresh_with_operation`,
  `complete_mcp_oauth_refresh`, `complete_mcp_oauth_refresh_with_operation`,
  `release_mcp_oauth_refresh`, `release_mcp_oauth_refresh_with_operation`,
  `reconcile_mcp_oauth_refresh_claim`, `reconcile_mcp_oauth_refresh_renewal`,
  `update_mcp_oauth_revocation_outcome`, `revoke_mcp_oauth_identity`.
<!-- END D1-ERRORING-SURFACE -->

Families that this section previously listed as erroring and that have since
landed: wallets + reservations and the remaining wallet ops (issues #455, #456);
workflow run budgets (#456); assets/channels/retention (#456); usage monthly +
metadata rollups + the `persist_usage_aggregate` durable half (#456); agent
schedules + fire history and observed-agent presence (#460); the guardrail
activate/archive/restore CAS transitions (#454); and
`append_billing_event_with_outbox_enqueue` (#450/#150). (RBAC, site domains, and
the budget-alert ledger — issue #445; request/audit logs, agent runs/events, and
snapshot replay floors — issue #447; billing ledger/outbox/events, guardrail
revisions/bindings, and the managed + self-hosted worker stores — issue #449;
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
`runtime_storage_repositories` (`crates/ferrogate-gateway/src/state.rs`) branches on
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

1. **Proxy-Worker atomic families beyond the keystone.** Issue #450 landed the
   proxy Worker (`workers/d1-proxy/`), its Rust client
   (`ferrogate_cloudflare::d1_proxy`), and the first atomic op
   (`append_billing_event_with_outbox_enqueue`) end-to-end. The guardrail
   activate/archive/restore CAS transitions followed in #454; wallets + wallet
   reservations in #455; the remaining wallet ops, workflow run budgets,
   assets/channels/retention and the usage rollups in #456; agent schedules and
   observed-agent presence in #460 — all over per-tenant bindings resolved
   through the `database` selector. Still to wire through the SAME `/d1/batch` +
   `/d1/query` binding: payment methods/attempts and
   `sweep_expired_wallet_reservations` (**#459**), and agent cost-burn (**#428**).
2. **Proxy-Worker path for the high-write append surface** (request logs, audit
   events, billing events, usage aggregates) and per-request reads. These already
   have a durable D1 SQL translation over the admin HTTP path (issue #447/#449,
   routed to the control database, above); moving their hot-path writes/reads onto
   the proxy binding is a throughput follow-up, distinct from the atomicity
   follow-up in (1).
3. Remaining entity families still erroring: x402 payment methods/attempts +
   `sweep_expired_wallet_reservations` (**#459**, deferred org-wide); agent
   cost-burn (**#428**); guardrail evidence; and MCP identity, the last remaining
   pre-#425 per-entity dispatch surface. See "Implemented vs erroring trait
   surface" above for the method-level list.
4. `/raw` query variant if bulk import ever needs it. (Entity `SELECT`s already
   return their full result set in one query response; `list_databases` now
   follows REST pagination past 1,000 rows; the `batch` request shape is now
   served by the proxy Worker's `/d1/batch`.)
5. Live-Cloudflare integration test (gated on account credentials), mirror
   of `supabase_roundtrip.rs`, including the live proxy-Worker atomic-batch proofs
   the dev gate cannot run (below).
