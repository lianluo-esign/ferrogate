# #221 slice: async-migrate billing-ledger / usage-rollup / billing-events reads

Part of issue #221. Prior slices merged: mcp_identity, rbac,
billing/wallet/budget-alert (writes), tenancy/quota/api-key, observability,
AgentRun, Worker, Assets, admin-users. This slice finishes the **billing/usage
subsystem** — the billing *writes* (`append_billing_event_impl` + outbox
sweeper) already migrated in commit 1984631; these are the remaining *reads* +
the billing ledger + usage-monthly rollups.

## Scope — 8 storage methods, all simple-CRUD (no transactions)

`impl PostgresControlPlaneStore` (`crates/ferrogate-storage/src/lib.rs`):
`get_usage_monthly_rollup`, `list_usage_monthly_rollups`,
`append_billing_ledger_entry`, `list_billing_ledger_entries`,
`get_billing_ledger_entry`, `enqueue_billing_report`, `billing_events_page`,
`billing_events` — convert from sync `with_client`/`with_client_storage` to
`async_pool.acquire(...).await`. Add `billing_ledger_operation()` and
`usage_rollup_operation()` helpers. `append_billing_ledger_entry` calls
`self.get_billing_ledger_entry(...)` internally → becomes `.await`.
`get_billing_ledger_entry` has **no facade** (internal-only), so only the
storage method changes for it.

Facades (`RuntimeStorageRepositories`, ~8907-9540) become `async fn` (`.await`
the Postgres arm; Memory arms unchanged). The in-memory backend methods
(`InMemoryControlPlaneStore`, ~6725) stay sync.

## Migration snapshot

Only `billing_events` is in the snapshot (backed by `metering_events`):
- `export_migration_snapshot` (sync): `billing_events: self.billing_events()` →
  `bridge_runtime.block_on(self.billing_events())`.
- `import_migration_snapshot`: imports via `append_billing_event` (already
  async + bridged) — unchanged. Ledger + usage-rollups are NOT in the snapshot.
- The `append_billing_event`-with-report facade's Memory arm calls
  `self.enqueue_billing_report(...).err()` inside an **async fn** → `.await.err()`
  (propagate, no bridge).

## CLI callers — mixed bridge / propagate (8 facade call sites)

Mapped every `repositories.<method>` call site + enclosing-fn context:

**7 sync enclosing → wrap in `crate::gateway::block_on_sync_bridge`:**
- `state.rs`: `list_usage_monthly_rollups`, `get_usage_monthly_rollup` (sync AppState wrappers)
- `state_billing_metering.rs`: `billing_events` (fn `billing_events`), `billing_events`
  + `billing_events_page` (fn `metering_events_page`)
- `state_guardrail_evidence.rs`: `billing_events` (fn `guardrail_investigation` — already
  bridges request_logs/audit_events/agent_runs)
- `state_wallets.rs`: `get_usage_monthly_rollup` (fn `monthly_budget_exceeded`)

**1 async enclosing → `.await`:**
- `state_wallets.rs`: `get_usage_monthly_rollup` (async fn
  `dispatch_budget_threshold_alerts_for_scope`)

Ledger methods (`append_billing_ledger_entry`, `list_billing_ledger_entries`,
`get_billing_ledger_entry`) have **no production caller** — only
`supabase_roundtrip.rs` tests exercise them, so their facades become async and
only the test wraps with `block_on`.

## Steps

1. Storage: 8 methods → async; helpers; internal `get_billing_ledger_entry`
   call `.await`; `billing_events*` (`with_client_storage`) → acquire + query +
   `map_err(postgres_error)`.
2. Facades → async, `.await` Postgres arm.
3. Snapshot: bridge export `billing_events`; async-arm `enqueue_billing_report`
   → `.await.err()`.
4. CLI: bridge 7 sync sites, `.await` the 1 async site.
5. Tests: `supabase_roundtrip.rs` (ledger/rollup/enqueue/billing_events),
   `provider_attempt_idempotency.rs` (`get_usage_monthly_rollup`), storage-lib
   unit tests — wrap with the file's `block_on`.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config + Python CI-gate tests; storage-lib,
CLI-bin unit tests; `usage_reports_e2e`, `provider_attempt_idempotency`,
`supabase_roundtrip`, plus billing/wallet integration tests. Adversarial diff
review (ultracode) before commit. Sandbox has no reachable Postgres, so the
async-pool path is exercised via the in-memory backend + structural tests;
docker-gated supabase tests skip gracefully.

## After this slice

Remaining sync `lib.rs`: document store / schema (+ startup bootstrap),
guardrail-policy `GuardrailPolicyRepository` trait (async-trait conversion,
incl. CAS), and `guardrail_evidence.rs`'s `spawn_blocking` write path. Then
delete the sync `postgres` driver + `PostgresClientPool` and verify with
`cargo tree -i postgres`.
