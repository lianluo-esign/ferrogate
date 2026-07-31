/**
 * Runtime-flavor model — parity twin of the tokio runtime introspection the
 * Rust `block_on_sync_bridge` branches on.
 *
 * Rust picks its strategy from `tokio::runtime::Handle::try_current()` and, when
 * a handle is current, `handle.runtime_flavor()`:
 *   - a `MultiThread` runtime  → drive the future under `block_in_place`;
 *   - any other case (no runtime, or a `current_thread` runtime that would panic
 *     with "cannot start a runtime from within a runtime") → build a throwaway
 *     `current_thread` runtime on a dedicated scoped thread and block on it.
 *
 * On Cloudflare Workers / the JS event loop there is exactly one cooperative
 * async executor and it is neither of tokio's flavors — there is no worker-thread
 * pool to hand back (`block_in_place`) and no way to spawn a scoped OS thread with
 * its own runtime. This enum + detector exist to keep that branch *modelled and
 * testable* rather than silently erased; the actual scheduling collapses to a
 * single `await` in `blockOnSyncBridge`.
 */

/** Mirror of `tokio::runtime::RuntimeFlavor`. */
export enum RuntimeFlavor {
  /** A worker-thread-pool runtime — the branch that used `block_in_place`. */
  MultiThread = "multi_thread",
  /** A single-threaded runtime — the branch that fell back to a scoped thread. */
  CurrentThread = "current_thread",
}

/**
 * The strategy `blockOnSyncBridge` would take, named after the two Rust branches.
 *
 *  - `block_in_place`: an ambient multi-thread runtime is current; the future is
 *    driven on it while the worker thread is yielded back to the scheduler.
 *  - `scoped_current_thread`: no usable ambient runtime; a throwaway
 *    current-thread runtime is built on a dedicated scoped thread.
 *  - `event_loop`: the JS/Workers model — a single cooperative executor; the
 *    call resolves to a plain `await`.
 */
export type SyncBridgeStrategy =
  | "block_in_place"
  | "scoped_current_thread"
  | "event_loop";

// PORT-TODO(inventory §7): tokio runtime introspection has no CF/JS equivalent.
// `Handle::try_current()` / `runtime_flavor()` describe an OS-thread scheduler
// that does not exist on the Workers event loop. We report the ambient executor
// as `undefined` (no tokio-style runtime is ever "current") so the strategy
// resolves to `event_loop`; the two thread-based branches are preserved only as
// documented, test-covered concepts, never taken at runtime.
export function currentRuntimeFlavor(): RuntimeFlavor | undefined {
  return undefined;
}

/**
 * Resolve the conceptual strategy from a runtime flavor, faithfully reproducing
 * the branch structure of the Rust source.
 *
 * Passing `RuntimeFlavor.MultiThread` yields `"block_in_place"`; any other value
 * — including `undefined` (no ambient runtime) and `CurrentThread` — yields
 * `"scoped_current_thread"`, exactly as the Rust `if let Ok(handle) = ... { if
 * flavor == MultiThread { block_in_place } }` / else falls through.
 *
 * At runtime `currentRuntimeFlavor()` is always `undefined`, so the live path is
 * `event_loop`; the flavor-driven mapping is exposed for parity assertions.
 */
export function strategyForFlavor(
  flavor: RuntimeFlavor | undefined,
): SyncBridgeStrategy {
  return flavor === RuntimeFlavor.MultiThread
    ? "block_in_place"
    : "scoped_current_thread";
}

/** The strategy the current (Workers/JS) environment actually uses. */
export function currentSyncBridgeStrategy(): SyncBridgeStrategy {
  // No tokio-style runtime is ever current on the event loop, so rather than
  // reporting the (unreachable) `scoped_current_thread` fallback we name the
  // real mechanism: a cooperative single-executor `await`.
  return "event_loop";
}
