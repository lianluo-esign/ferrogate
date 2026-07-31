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

// Not-yet-ported tails: the OS-thread scheduling mechanics have no CF/JS
// equivalent and are represented only as concepts above.
describe("thread-based scheduling mechanics (no CF equivalent)", () => {
  // PORT-TODO(inventory §7): drive a future under block_in_place on an ambient
  // multi-thread runtime while yielding the worker thread back to the scheduler.
  test.todo("block_in_place on an ambient multi-thread runtime");

  // PORT-TODO(inventory §7): build a throwaway current_thread runtime on a
  // dedicated scoped OS thread and block on it (the no-runtime fallback), then
  // re-raise a panic from the scoped join on the caller thread.
  test.todo("scoped current_thread runtime fallback + panic re-raise on join");
});
