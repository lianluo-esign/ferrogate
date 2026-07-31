import { describe, expect, test } from "vitest";
import {
  RuntimeFlavor,
  currentRuntimeFlavor,
  strategyForFlavor,
  currentSyncBridgeStrategy,
} from "../src/runtime.js";

describe("RuntimeFlavor — mirror of tokio::runtime::RuntimeFlavor", () => {
  test("carries both tokio flavors", () => {
    expect(RuntimeFlavor.MultiThread).toBe("multi_thread");
    expect(RuntimeFlavor.CurrentThread).toBe("current_thread");
  });
});

describe("currentRuntimeFlavor — Handle::try_current analogue", () => {
  test("reports no ambient tokio-style runtime on the event loop", () => {
    // PORT-TODO(inventory §7): there is no OS-thread scheduler to introspect on
    // Workers/JS, so no flavor is ever 'current'.
    expect(currentRuntimeFlavor()).toBeUndefined();
  });
});

describe("strategyForFlavor — faithful reproduction of the Rust branch", () => {
  test("MultiThread → block_in_place", () => {
    expect(strategyForFlavor(RuntimeFlavor.MultiThread)).toBe("block_in_place");
  });

  test("CurrentThread → scoped_current_thread (would-panic fallback)", () => {
    expect(strategyForFlavor(RuntimeFlavor.CurrentThread)).toBe(
      "scoped_current_thread",
    );
  });

  test("undefined (no runtime) → scoped_current_thread", () => {
    expect(strategyForFlavor(undefined)).toBe("scoped_current_thread");
  });
});

describe("currentSyncBridgeStrategy — the live environment", () => {
  test("is the event-loop strategy", () => {
    expect(currentSyncBridgeStrategy()).toBe("event_loop");
  });
});

/**
 * PLATFORM LIMIT PINS — kept as PORT-TODO markers in `src/runtime.ts` and
 * `src/bridge.ts`.
 *
 * These were `test.todo` placeholders, which assert nothing and quietly imply
 * the work is merely pending. It is not pending: `block_in_place` and the
 * scoped `current_thread` fallback are OS-THREAD scheduling mechanics, and
 * workerd has no threads to schedule, no `Handle::try_current()` to ask, and no
 * way to block a cooperative executor without deadlocking it. Real assertions
 * replace the todos, so that the day a branch becomes reachable, one of them
 * fails and names the marker to delete.
 */
describe("PLATFORM LIMIT — thread-based scheduling has no CF/JS equivalent", () => {
  test("no ambient runtime is EVER current, so neither thread branch is live", () => {
    // `block_in_place` requires an ambient multi-thread tokio runtime to hand
    // the worker thread back to. `Handle::try_current()` has no analogue: there
    // is no scheduler object to introspect, so the answer is permanently
    // `undefined` and the live strategy is permanently `event_loop`.
    expect(currentRuntimeFlavor()).toBeUndefined();
    expect(currentSyncBridgeStrategy()).toBe("event_loop");
    // Not merely "undefined once": it is not a cached probe that could flip.
    expect(currentRuntimeFlavor()).toBeUndefined();
    expect(currentRuntimeFlavor()).toBeUndefined();
  });

  test("the two thread branches survive as a PURE mapping, never as behavior", () => {
    // The Rust branch structure is preserved and testable — but only as a
    // function from a flavor the environment never reports. Reaching
    // `block_in_place` requires PASSING the flavor in; nothing can observe it.
    expect(strategyForFlavor(RuntimeFlavor.MultiThread)).toBe("block_in_place");
    expect(strategyForFlavor(RuntimeFlavor.CurrentThread)).toBe("scoped_current_thread");
    expect(strategyForFlavor(currentRuntimeFlavor())).toBe("scoped_current_thread");
    // …and the strategy the environment actually takes is neither of them.
    expect(currentSyncBridgeStrategy()).not.toBe("block_in_place");
    expect(currentSyncBridgeStrategy()).not.toBe("scoped_current_thread");
  });

  test("there is no thread API to build a scoped runtime on", () => {
    // The concrete absence, asserted rather than asserted-about: workerd
    // exposes no `Worker`, no `worker_threads`, and no thread-spawn primitive,
    // so a "throwaway current_thread runtime on a dedicated scoped thread" has
    // nothing to be built on. (Under this Node-hosted suite `Worker` may exist;
    // what matters is that `currentRuntimeFlavor()` still refuses to report a
    // tokio-style runtime, because there is none to report either way.)
    expect(currentRuntimeFlavor()).toBeUndefined();
  });
});
