# #221 slice: async-migrate the AgentRun repo

Part of issue #221 (migrate all PostgreSQL access to `tokio-postgres` +
`deadpool-postgres`). Prior slices merged: mcp_identity, rbac,
billing/wallet/budget-alert, tenancy/quota/api-key, and observability
(RequestLog/AuditLog/UsageAggregate). This doc plans the AgentRun repo.

## Scope

Convert these `impl PostgresControlPlaneStore` methods in
`crates/ferrogate-storage/src/lib.rs` from sync `with_client`/
`with_client_storage` to async `async_pool.acquire(...).await`:

- `upsert_agent_run`, `agent_run`, `agent_runs`, `append_agent_run_event`,
  `agent_run_events`

All simple-CRUD (no transactions). Add an `agent_run_operation()` helper
(mirrors `observability_operation`/`tenancy_operation`). Convert the
`RuntimeStorageRepositories` facades to `async fn` (`.await` the Postgres arm,
Memory arms unchanged). Bridge the now-async calls inside the sync
`export_migration_snapshot`/`import_migration_snapshot` via the `bridge_runtime`
already present there.

## Architecture decision: keep the AppState wrappers sync, bridge internally

Same reasoning and precedent as the observability slice
(`docs/design/async-postgres-observability-migration-2026-07.md`), the
`wallet_balance_exhausted`/`resolve_effective_quota` pattern, and the
`ferrogate-auth-service` bridge.

The AppState wrappers `record_agent_run` and `record_agent_run_event`
(`state_agent_runtime.rs`) are fire-and-forget (swallow the storage error with
`warn!`). `record_agent_run_event` is reached from **`external_actions.rs`'s
`record_timeline_event` → the Unix-socket external-action authorizer
(`serve_gateway_external_action_authorizer_unix`), a raw `std::thread::spawn`
worker with no tokio runtime** — the hard blocker. So both wrappers stay sync
and bridge internally via `crate::gateway::block_on_sync_bridge`; the
authorizer thread and its `record_timeline_event` sync `fn` are untouched.

Reads (`agent_run`, `agent_runs`, `agent_run_events`) are consumed by:
- `state_agent_runtime.rs::agent_run_summaries` (sync `fn`) and
  `agent_run_detail`/`agent_runs_page` — bridge the now-async facade reads.
- `state_guardrail_evidence.rs` investigation timeline (sync `fn`) — already
  bridges `request_logs()`/`audit_events()` from the observability slice; add
  the same bridge to its `agent_runs()`/`agent_run_events()` calls.

Net: ~2 write wrappers + ~4 read call sites get an internal bridge; the
gateway `agent_runs.rs` handlers and `external_actions.rs` authorizer stay
untouched (they call the sync AppState wrappers, which now bridge).

## Steps

1. `PostgresControlPlaneStore`: convert the 5 methods to async simple-CRUD;
   add `agent_run_operation()`.
2. `RuntimeStorageRepositories` facades → async, `.await` Postgres arm.
3. `export_migration_snapshot`/`import_migration_snapshot`:
   `bridge_runtime.block_on(...)` the now-async agent-run calls.
4. AppState `record_agent_run`/`record_agent_run_event` stay sync; wrap facade
   calls in `block_on_sync_bridge`. Bridge the read call sites in
   `agent_run_summaries`, `agent_run_detail`, and `state_guardrail_evidence`.
5. Test fixups: storage-lib unit tests + `supabase_roundtrip.rs` (wrap direct
   facade calls with the file's `block_on`); CLI tests go through the sync
   wrappers — verify.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests;
storage-lib, CLI-bin unit tests; targeted integration tests (`agentic_lite`,
`ai_proxy_runtime`, `tenant_isolation_admin_api`, `target_capability_e2e`, plus
agent-run admin surfaces). No reachable Postgres → real async-pool path
exercised only via in-memory + structural tests; docker-gated supabase tests
skip gracefully.

## Remaining after this slice (issue #221 stays open)

Worker (managed + self-hosted) repos; `guardrail_evidence.rs`'s
`spawn_blocking` write path (needs `spawn_blocking`→`tokio::spawn` restructure);
then delete the sync `postgres` driver + `PostgresClientPool` and verify with
`cargo tree -i postgres`.
