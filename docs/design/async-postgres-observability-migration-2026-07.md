# #221 slice: async-migrate RequestLog / AuditLog / UsageAggregate repos

Part of issue #221 (migrate all PostgreSQL access to `tokio-postgres` +
`deadpool-postgres`). Prior slices already merged: mcp_identity, rbac, the
billing/wallet/budget-alert/metadata-rollups component, and the
tenancy/quota-policy/api-key component. This doc plans the observability/analytics
storage repos.

## Scope

Convert these `impl PostgresControlPlaneStore` methods in
`crates/ferrogate-storage/src/lib.rs` from sync `with_client`/`with_client_storage`
to async `async_pool.acquire(...).await`:

- **RequestLog**: `append_request_log`, `request_logs_page`, `request_logs`
- **AuditLog**: `append_audit_event`, `audit_events_page`, `audit_events`
- **UsageAggregate**: `upsert_usage_aggregate` (opens a `client.transaction()`),
  `usage_aggregates`

All simple-CRUD except `upsert_usage_aggregate`, which opens a transaction and calls
the sync helpers `upsert_tenant_context_parts` + `replace_usage_rollup`. Those two
helpers now have **no other callers** (the billing slice gave
`append_billing_event_impl` its own `upsert_tenant_context_async`), so they convert to
`async fn` taking `&deadpool_postgres::Transaction<'_>` in place — no duplication.
Add an `observability_operation()` helper (mirrors `tenancy_operation` /
`billing_outbox_operation`).

Then convert the `RuntimeStorageRepositories` facade methods to `async fn` (`.await`
the Postgres arm, Memory arms unchanged), and bridge the now-async calls inside the
sync migration CLI (`export_migration_snapshot` / `import_migration_snapshot`) with the
`bridge_runtime` already present in those functions.

## Architecture decision: keep the AppState wrappers sync, bridge internally

This slice differs from tenancy. The AppState-level wrappers are called from **275
sites** — 202 `record_admin_audit_event` (fire-and-forget audit logging on nearly
every admin handler), 20 `record_request_log`, plus reads. And the read methods
(`request_logs`, `audit_events`, `metering_events`, `usage_aggregates`) are called from
**two raw `std::thread::spawn` background senders in `telemetry.rs`**
(`start_otlp_background_sender`, `start_analytics_background_sender`) that have **no
tokio runtime** — hard blockers that must bridge regardless.

**Decision** (consistent with the `wallet_balance_exhausted` /
`resolve_effective_quota` precedent from earlier slices): keep the AppState
observability wrappers **sync** and bridge the now-async facade calls internally via
`crate::gateway::block_on_sync_bridge`. Affected wrappers: `record_request_log`,
`record_admin_audit_event` (+ its `prepare_admin_audit_event` reads
`next_audit_event_id`, which stays sync — no DB call on Postgres), `usage_aggregates`,
`request_logs`, `audit_events`, `request_logs_page`, `audit_events_page`.

Why not propagate async upward:
- The facades already swallow write errors (`let _ = control_plane.append_...`) and
  reads use `.unwrap_or_default()` — async propagation buys no new error handling.
- Propagating would force `.await` onto 202+ audit call sites, many inside sync
  closures, and the telemetry background threads would **still** need a bridge. Net:
  far larger, riskier diff for no correctness gain.
- `block_on_sync_bridge` already safely handles a multi-thread tokio worker
  (`block_in_place`) or a non-tokio thread (dedicated current-thread runtime), so both
  the async gateway handlers and the sync telemetry threads work unchanged. Audit
  logging already blocks synchronously today → no latency regression.

Net blast radius: ~8 AppState wrapper methods get an internal bridge; **275 call
sites and both telemetry background threads stay untouched**; the storage layer +
facades + migration-snapshot bridges are the real change.

## Steps

1. `PostgresControlPlaneStore`: convert the 8 methods to async (simple-CRUD pattern;
   `upsert_usage_aggregate` gets an async-local `client.transaction().await` threading
   async `upsert_tenant_context_parts` / `replace_usage_rollup`). Add
   `observability_operation()`.
2. Convert `upsert_tenant_context_parts` + `replace_usage_rollup` to `async fn` over
   `&deadpool_postgres::Transaction<'_>`.
3. `RuntimeStorageRepositories` facades → async, `.await` the Postgres arm.
4. `export_migration_snapshot` / `import_migration_snapshot`:
   `bridge_runtime.block_on(...)` the now-async calls.
5. AppState wrappers stay sync; wrap the facade calls in `block_on_sync_bridge`.
6. Test fixups: storage-lib unit tests + `supabase_roundtrip.rs` (wrap direct facade
   calls with the file's `block_on`); CLI tests calling these AppState methods go
   through sync wrappers, so likely untouched — verify.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests; storage-lib,
ferrogate-auth-service, CLI-bin unit tests; targeted integration tests (`usage_reports_e2e`,
`tenant_isolation_admin_api`, `ai_proxy_runtime`, `agentic_lite`, plus request-log /
audit surfaces). No reachable Postgres in the sandbox → real async-pool path exercised
only via in-memory + structural tests; docker-gated supabase tests skip gracefully.

## Remaining after this slice (issue #221 stays open)

AgentRun + Worker (managed + self-hosted) repos; `guardrail_evidence.rs`'s
`spawn_blocking` write path (needs `spawn_blocking`→`tokio::spawn` restructure); then
delete the sync `postgres` driver + `PostgresClientPool` and verify with
`cargo tree -i postgres`.
