/**
 * `@ferrogate/sync-bridge` — clean-room port of the Rust crate
 * `ferrogate-sync-bridge`.
 *
 * The Rust crate is a single function, `block_on_sync_bridge(future)`, that ran
 * an async call from a *synchronous* call path (Pingora filter hooks, thread
 * sweep loops, the Unix external-action authorizer). Per PORT-PLAN / inventory
 * §7, Cloudflare Workers are uniformly async, so the mechanism collapses to a
 * plain `await`: every Rust `block_on_sync_bridge(x.await_ing())` call site
 * becomes `await x`.
 *
 * This package embodies that mapping faithfully — same name/semantics
 * (`blockOnSyncBridge`), same drive-to-completion + failure-propagation
 * contract — while preserving the runtime-flavor branch structure as a
 * documented, test-covered model rather than silently dropping it. The
 * OS-thread scheduling (`block_in_place` / scoped `current_thread` runtime) has
 * no CF equivalent and is flagged `// PORT-TODO(inventory §7)` in
 * `bridge.ts` / `runtime.ts`.
 *
 * Modules:
 *  - `bridge`  — `blockOnSyncBridge` + `SyncBridgeFuture`, the public surface.
 *  - `runtime` — `RuntimeFlavor` / strategy model mirroring tokio introspection.
 *
 * ## PORT-TODO(inventory-edge-control §7) — VERDICT: DELETE THIS PACKAGE.
 * ## See `docs/rewrite/parity-audit-dead-packages.md` §1.
 *
 * This package has ZERO importers in every app and package `src` tree, and
 * that is CORRECT rather than a wiring miss — but the right resolution is
 * removal, not indefinite dead weight.
 *
 * `docs/legacy/inventory-edge-control.md` §7 says the crate "has no reason to
 * exist on CF", and the cluster mapping table (line 665) lists its CF/TS target
 * as literally **`Deleted`**. All three Rust caller classes are eliminated by
 * this rewrite: Pingora filter hooks (the data plane is now a Hono proxy),
 * sweep threads (workerd has no threads), and the Unix `SO_PEERCRED` external-
 * action authorizer (no CF equivalent; re-founded on bearer/service-binding
 * trust). `blockOnSyncBridge` reduces to `return await started` — it is `await`
 * with a docstring — and `runtime.ts`'s flavor/strategy model is a parity VIEW
 * of Rust branch structure that can never execute here.
 *
 * A platform-limit marker on a mechanism nothing needs is not a limit worth
 * carrying. Delete `packages/sync-bridge/` and drop the
 * `ferrogate-sync-bridge` row from the crate -> package map in
 * `docs/rewrite/PORT-PLAN.md` in the same edit. Nothing breaks: no importers,
 * and the Rust crate's only dependent was `ferrogate-gateway`, whose TS
 * successor is uniformly async.
 */
export {
  blockOnSyncBridge,
  syncBridgeStrategyFor,
  activeSyncBridgeStrategy,
  type SyncBridgeFuture,
} from "./bridge.js";

export {
  RuntimeFlavor,
  currentRuntimeFlavor,
  strategyForFlavor,
  currentSyncBridgeStrategy,
  type SyncBridgeStrategy,
} from "./runtime.js";
