# #221 slice: async-migrate the Worker repos (managed + self-hosted)

Part of issue #221 (migrate all PostgreSQL access to `tokio-postgres` +
`deadpool-postgres`). Prior slices merged: mcp_identity, rbac,
billing/wallet/budget-alert, tenancy/quota/api-key, observability
(RequestLog/AuditLog/UsageAggregate), and AgentRun. This is the last repo group
before the sync-driver deletion.

## Scope — 24 `PostgresControlPlaneStore` methods, split into two commits

**Commit A — managed-worker** (14 methods):
`upsert_managed_worker_template`, `managed_worker_templates`,
`upsert_agent_worker_instance`, `agent_worker_instances`,
`upsert_managed_worker_session`, `managed_worker_sessions`,
`append_managed_worker_lifecycle_event`, `managed_worker_lifecycle_events`,
`upsert_managed_worker_isolation_selection`, `managed_worker_isolation_selections`,
`upsert_managed_worker_isolation_policy`, `managed_worker_isolation_policies`,
`upsert_managed_worker_isolation_evidence`, `managed_worker_isolation_evidence`.

**Commit B — self-hosted worker** (10 methods):
`upsert_self_hosted_worker_registration`, `self_hosted_worker_registrations`,
`append_self_hosted_worker_heartbeat`, `self_hosted_worker_heartbeats`,
`append_self_hosted_worker_telemetry_event`, `self_hosted_worker_telemetry_events`,
`upsert_self_hosted_worker_artifact`, `self_hosted_worker_artifacts`,
`upsert_self_hosted_worker_checkpoint`, `self_hosted_worker_checkpoints`,
`upsert_self_hosted_run_dispatch` (opens a self-contained `client.transaction()`),
`self_hosted_run_dispatches`.

All simple-CRUD (`with_client`/`with_client_storage`) except
`upsert_self_hosted_run_dispatch`, which opens a self-contained transaction
(insert dispatch row + rewrite its capability rows; no cross-repo call). Convert
that to an async-local `client.transaction().await` threading its inline
statements. Add a `worker_operation()` helper (may add per-commit; can be shared).

Facades: the `RuntimeStorageRepositories` wrappers become `async fn`;
`export/import_migration_snapshot` bridge the now-async calls via the
`bridge_runtime` already present there.

## Architecture: keep the AppState wrappers sync, bridge internally

Same precedent as the observability and AgentRun slices. All 64 CLI call sites
live in `state_agent_runtime.rs`'s AppState wrappers
(`register_self_hosted_worker`, `record_self_hosted_worker_heartbeat`,
`record_self_hosted_worker_telemetry_event`, `record_self_hosted_worker_artifact`,
`record_self_hosted_worker_checkpoint`, `record_managed_worker_lifecycle`
[dead-code/test-only for now], `managed_worker_sessions_page`,
`self_hosted_worker_records_page`, `self_hosted_worker_record`,
`self_hosted_worker_event_stream*`, and the isolation/session upserts inside the
managed-worker session finalizer). These wrappers are sync and called from
`gateway/local.rs` async handlers. Keep them sync and wrap the now-async facade
calls in `crate::gateway::block_on_sync_bridge` — no gateway handler signature
changes, and it stays correct if a future background lifecycle recorder calls
`record_managed_worker_lifecycle` off a non-tokio thread.

No raw-thread caller exists today (confirmed by grep: no `thread::spawn` reaches
these), so this is lower-risk than AgentRun — but the sync-bridge keeps the
wrappers' signatures stable and the blast radius to `state_agent_runtime.rs`.

## Steps (per commit)

1. `PostgresControlPlaneStore`: convert the group's methods to async simple-CRUD
   (`upsert_self_hosted_run_dispatch` → async-local transaction). Add
   `worker_operation()` in commit A; reuse in B.
2. `RuntimeStorageRepositories` facades → async, `.await` Postgres arm.
3. `export/import_migration_snapshot`: `bridge_runtime.block_on(...)` the
   now-async calls for that group.
4. AppState wrappers stay sync; wrap facade calls in `block_on_sync_bridge`.
5. Test fixups: storage-lib unit tests + `supabase_roundtrip.rs` +
   `state_agent_runtime.rs`'s own `#[test]`s (wrap with the module's `block_on`);
   `self_hosted_worker_lifecycle` / worker-management integration tests.

## Verification (each commit)

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests;
storage-lib, CLI-bin unit tests; targeted integration tests (worker registration
/ heartbeat / telemetry / artifact / checkpoint admin surfaces,
`target_capability_e2e`, `agentic_lite`). No reachable Postgres → real
async-pool path exercised only via in-memory + structural tests; docker-gated
supabase tests skip gracefully.

## After this slice

`guardrail_evidence.rs`'s deliberate `spawn_blocking` write path remains (needs
`spawn_blocking`→`tokio::spawn` restructure). Then delete the sync `postgres`
driver + `PostgresClientPool`/Condvar and verify with `cargo tree -i postgres` —
that final cleanup is what closes #221.
