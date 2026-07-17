# #221 slice: async-migrate the Assets repo

Part of issue #221 (migrate all PostgreSQL access to `tokio-postgres` +
`deadpool-postgres`). Prior slices merged: mcp_identity, rbac,
billing/wallet/budget-alert, tenancy/quota/api-key, observability, AgentRun,
Worker (managed + self-hosted). This doc plans the static-asset-hosting repo
(issue #176/#177/#179).

## Scope — 4 storage methods, all simple-CRUD

`impl PostgresControlPlaneStore` in `crates/ferrogate-storage/src/lib.rs`:
`upsert_asset`, `get_asset`, `list_assets`, `delete_asset` — convert from sync
`with_client` to `async_pool.acquire(...).await`. Add an `asset_operation()`
helper. `RuntimeStorageRepositories` facades → `async fn` (`.await` the Postgres
arm, Memory arms unchanged). `export/import_migration_snapshot`: assets are NOT
part of the migration snapshot (verify with grep) — no bridge needed there.

## Architecture — propagate async up (no bridge)

Unlike the observability/AgentRun/Worker slices, the Assets repo has **no
sync-context or background-thread caller**. All call sites are in
`gateway/assets.rs` async handlers (`handle_asset_list`, `handle_asset_push`,
`handle_asset_pull`, `handle_asset_delete`), reached through the AppState
wrappers in `state_assets.rs` (`upsert_asset`, `get_asset`, `list_assets`,
`delete_asset`, `tenant_asset_storage_bytes_used`). So:

- Convert the 5 `state_assets.rs` AppState wrappers to `async fn` and `.await`
  the repository calls (`tenant_asset_storage_bytes_used` awaits its
  `list_assets`).
- Add `.await` at the 8 `gateway/assets.rs` call sites (all already inside
  `async fn`).

This is cleaner than a bridge and matches the tenancy slice's "propagate async
up when every caller is async" approach.

## Steps

1. Storage: 4 methods → async simple-CRUD; add `asset_operation()`.
2. Facades → async, `.await` Postgres arm.
3. `state_assets.rs`: 5 wrappers → async.
4. `gateway/assets.rs`: `.await` the 8 call sites.
5. Test fixups: storage-lib unit tests (`block_on`), `supabase_roundtrip.rs`
   asset round-trip if present, `assets_api.rs`/`assets_quota_e2e.rs`
   integration tests go through async handlers so likely untouched — verify.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests;
storage-lib, CLI-bin unit tests; `assets_api`, `assets_quota_e2e`,
`assets_security`, `asset_bucket_e2e`, `assets_cli` integration tests. No
reachable Postgres → real async-pool path exercised only via in-memory +
structural tests; docker-gated supabase tests skip gracefully.

## After this slice

`guardrail_evidence.rs`'s `spawn_blocking` write path and the remaining sync
`lib.rs` repos (control-plane documents, plans, tool approvals, admin users,
billing ledger reads, usage-monthly rollups, GuardrailPolicyRepository trait,
schema init/validate). Then delete the sync `postgres` driver +
`PostgresClientPool` and verify with `cargo tree -i postgres`.
