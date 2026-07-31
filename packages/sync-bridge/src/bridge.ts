/**
 * `block_on_sync_bridge` — clean-room port of the sole function in the Rust crate
 * `ferrogate-sync-bridge`.
 *
 * Rust signature:
 *
 * ```rust
 * pub fn block_on_sync_bridge<T>(future: impl Future<Output = T> + Send) -> T
 * where T: Send
 * ```
 *
 * It drives an async computation to completion *from a synchronous caller* and
 * returns its output, re-raising any panic on the caller's thread. Its two
 * branches (`block_in_place` on an ambient multi-thread runtime, else a throwaway
 * `current_thread` runtime on a scoped thread) exist purely so a synchronous
 * Pingora hook / sweep thread / Unix authorizer can call an `.await`-ing method.
 *
 * On Cloudflare Workers the whole call path is already async, so — per
 * inventory §7 — every `block_on_sync_bridge(x.await_ing())` call site becomes a
 * plain `await x`. This function is the faithful embodiment of that: it takes a
 * future (or a thunk producing one), awaits it, returns the value, and propagates
 * a rejection the way Rust re-raises the joined panic.
 */
import {
  currentSyncBridgeStrategy,
  strategyForFlavor,
  type RuntimeFlavor,
  type SyncBridgeStrategy,
} from "./runtime.js";

/**
 * The thing `blockOnSyncBridge` drives to completion.
 *
 * Rust takes an owned `Future` value. The idiomatic TS twin accepts either a
 * `PromiseLike` (an already-started async computation) or a zero-arg thunk that
 * *produces* one — the thunk form mirrors handing the bridge a future to start,
 * and lets a synchronous `throw` inside it surface as a rejection (a re-raised
 * panic) exactly like the async case.
 */
export type SyncBridgeFuture<T> = PromiseLike<T> | (() => T | PromiseLike<T>);

/**
 * Drives `future` to completion and resolves with its output.
 *
 * Behavioural parity with Rust `block_on_sync_bridge`:
 *  - returns the future's `Output` value;
 *  - propagates failure — a rejected promise (or a throwing thunk) surfaces as a
 *    rejection here, the JS analogue of the scoped-join panic re-raise;
 *  - is executor-agnostic: it does not care whether an ambient runtime exists,
 *    because on the Workers event loop there is only ever the one cooperative
 *    executor.
 *
 * PORT-TODO(inventory §7) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **the synchronous `-> T` return is impossible on a JS
 * event loop.** Rust `block_on_sync_bridge` parks the calling THREAD until the
 * future completes; another thread makes progress meanwhile. JS has one
 * cooperative executor per isolate, so parking it is a deadlock by
 * construction — the very task that would resolve the promise can only run
 * after the current stack frame returns. There is no `Atomics.wait` escape
 * either: workerd forbids blocking the main thread, and there is no worker
 * thread to hand the future to.
 *
 * The closest behavior implemented instead: `-> Promise<T>` (an `await`), which
 * is exactly the call-site rewrite the inventory prescribes, with failure
 * propagation preserved — a rejected promise or a throwing thunk surfaces as a
 * rejection, the analogue of the scoped-join panic re-raise. The
 * `block_in_place` and scoped-`current_thread` fallback mechanics are
 * intentionally NOT reproduced; see `runtime.ts` and the pins in
 * `test/runtime.test.ts`.
 */
export async function blockOnSyncBridge<T>(
  future: SyncBridgeFuture<T>,
): Promise<T> {
  // Resolving the thunk here (rather than at the call boundary) keeps a
  // synchronous throw inside it on the rejection path, matching Rust's
  // panic-propagation semantics.
  const started: T | PromiseLike<T> =
    typeof future === "function"
      ? (future as () => T | PromiseLike<T>)()
      : future;
  return await started;
}

/**
 * Parity view of which strategy the bridge would take for a given runtime
 * flavor. At runtime the live strategy is always `currentSyncBridgeStrategy()`
 * (`"event_loop"`); this is exported so tests can assert the branch structure is
 * preserved from the Rust source.
 */
export function syncBridgeStrategyFor(
  flavor: RuntimeFlavor | undefined,
): SyncBridgeStrategy {
  return strategyForFlavor(flavor);
}

/** The strategy this environment actually runs the bridge under. */
export function activeSyncBridgeStrategy(): SyncBridgeStrategy {
  return currentSyncBridgeStrategy();
}
