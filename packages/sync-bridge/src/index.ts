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
