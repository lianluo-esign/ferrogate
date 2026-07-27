# #221 slice: async-migrate the document-store / schema cluster

Part of issue #221. This is the LAST repository cluster (only
`guardrail_evidence.rs`'s `spawn_blocking` path remains after it). The generic
control-plane document store (`control_plane_resources` table) + schema
init/validate/seed.

## Scope — 11 inherent `PostgresControlPlaneStore` methods

`crates/ferrogate-storage/src/lib.rs`: `initialize_schema` (opens a DDL
transaction: statement/lock timeout + advisory xact lock + `batch_execute`
schema SQL), `validate_schema`, `seed_missing_resources`, `list_resource_documents`,
`list_documents`, `get_document`, `upsert`, `replace_kind` (transaction: DELETE
+ loop INSERT), `delete`, plus the inherent composites `snapshot` (10×
`list_documents`) and `documents` (10× `list_resource_documents`). Convert from
sync `with_client`/`with_client_storage` to `async_pool.acquire(...).await`; the
two transactions become async-local `client.transaction().await`. Add a
`document_operation()` helper.

## Blast radius — entirely within lib.rs, ZERO external callers

Confirmed by grep: no ferrogate-cli / ferrogate-auth-service / tools caller touches
`upsert`/`get_document`/`list_documents`/`delete`/`replace_kind`/
`seed_missing_resources`/`list_resource_documents`. Every caller is a sync
method inside lib.rs:
- `connect` (bootstrap constructor) → `initialize_schema`, `validate_schema`,
  10× `seed_missing_resources`. **Runs on a raw `std::thread::scope` spawned
  thread** (see `RuntimeStorageRepositories::postgres`, ~8159) with no tokio
  runtime.
- `connect_for_migration` → `initialize_schema`, `validate_schema`.
- `replace_control_plane` → 9× `replace_kind`.
- ~10 `upsert_control_plane_*` facades → `control_plane.upsert(...)`.
- ~9 `delete_control_plane_*` facades → `control_plane.delete(...)`.
- `control_plane_tool_approval` / `_tool_approvals` / `_tool_approval_documents`
  → `get_document` / `list_documents` / `list_resource_documents`.
- Facade `snapshot` / `documents` (on `RuntimeStorageRepositories`) → the
  inherent composites.

## Architecture — keep every caller sync, bridge internally

The `PostgresControlPlaneStore` inherent methods go async. Every sync caller
listed above wraps the now-async call in the storage-internal
`block_on_sync_bridge` (added for the `LedgerSink`/guardrail-policy seams —
`Handle::try_current()` → multi-thread `block_in_place`, else scoped
`current_thread` runtime). This keeps `connect` sync (correct on its raw thread —
no ambient runtime → scoped-runtime path), keeps all facade signatures sync (so
**zero ferrogate-cli changes**), and matches the guardrail-policy precedent.

The inherent composites `snapshot`/`documents` call the now-async
`list_documents`/`list_resource_documents`; since they themselves are only
called from sync facades, keep them sync and bridge their inner calls (or make
them async and bridge at the facade — pick per compile).

## Migration snapshot

`export_migration_snapshot`/`import_migration_snapshot` (on
`RuntimeStorageRepositories`, sync) call the sync facades (`replace_control_plane`,
`upsert_control_plane_tool_approval`, `control_plane_tool_approval_documents`,
etc.), which bridge internally — so, as with guardrail-policy, the snapshot
functions themselves likely need NO change. Verify by compile: if a snapshot
site calls an inherent async method directly, bridge it via the in-scope
`bridge_runtime`.

## Steps

1. Convert the 11 inherent methods to async (2 async-local transactions). Add
   `document_operation()`.
2. Bridge the sync callers: `connect`, `connect_for_migration`,
   `replace_control_plane`, the `upsert_control_plane_*` / `delete_control_plane_*`
   / `control_plane_tool_approval*` facades, and facade `snapshot`/`documents`,
   all via `block_on_sync_bridge`.
3. Fix any snapshot-fn compile fallout.
4. Test fixups: storage-lib unit tests, `supabase_roundtrip.rs`, schema/document
   tests — wrap with the file's `block_on`.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests;
storage-lib + CLI-bin unit tests; config-reload / control-plane / tool-approval
integration tests; supabase_roundtrip. 3-lens adversarial diff-review before
commit. No reachable Postgres → async-pool path exercised via in-memory +
structural tests; the DSN/docker-gated schema tests skip gracefully.

## After this slice

Only `guardrail_evidence.rs`'s `spawn_blocking` write path remains, then delete
the sync `postgres` driver + `PostgresClientPool` and verify with
`cargo tree -i postgres` — that final cleanup closes #221.
