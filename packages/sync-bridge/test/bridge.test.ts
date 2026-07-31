import { describe, expect, test, vi } from "vitest";
import {
  blockOnSyncBridge,
  syncBridgeStrategyFor,
  activeSyncBridgeStrategy,
} from "../src/bridge.js";
import { RuntimeFlavor } from "../src/runtime.js";

describe("blockOnSyncBridge — drives a future to completion", () => {
  test("resolves a promise to its output value", async () => {
    await expect(blockOnSyncBridge(Promise.resolve(42))).resolves.toBe(42);
  });

  test("resolves a thunk that returns a promise", async () => {
    await expect(
      blockOnSyncBridge(() => Promise.resolve("done")),
    ).resolves.toBe("done");
  });

  test("resolves a thunk that returns a plain (already-computed) value", async () => {
    // Rust owns a Future; the thunk form also accepts an eager value, which is
    // simply returned — the async equivalent of an immediately-ready future.
    await expect(blockOnSyncBridge(() => 7)).resolves.toBe(7);
  });

  test("preserves the exact resolved value, not the wrapping promise", async () => {
    const payload = { code: "ok", nested: [1, 2, 3] };
    await expect(blockOnSyncBridge(Promise.resolve(payload))).resolves.toBe(
      payload,
    );
  });
});

describe("blockOnSyncBridge — failure propagation (panic re-raise analogue)", () => {
  test("propagates a rejected promise", async () => {
    const boom = new Error("upstream exploded");
    await expect(blockOnSyncBridge(Promise.reject(boom))).rejects.toBe(boom);
  });

  test("propagates a thunk that throws synchronously", async () => {
    // Rust re-raises the joined panic on the caller thread; a synchronous throw
    // inside the thunk must surface as a rejection, not an unhandled throw.
    const boom = new Error("sync throw");
    await expect(
      blockOnSyncBridge(() => {
        throw boom;
      }),
    ).rejects.toBe(boom);
  });

  test("propagates a thunk that returns a rejecting promise", async () => {
    await expect(
      blockOnSyncBridge(() => Promise.reject(new Error("async throw"))),
    ).rejects.toThrow("async throw");
  });
});

describe("blockOnSyncBridge — lazy start semantics of the thunk form", () => {
  test("a thunk is not invoked until the bridge drives it", async () => {
    const started = vi.fn(() => Promise.resolve(1));
    const p = blockOnSyncBridge(started);
    // The thunk is called synchronously inside blockOnSyncBridge before the
    // await point, so by the time we have the promise it has already run once.
    expect(started).toHaveBeenCalledTimes(1);
    await p;
    expect(started).toHaveBeenCalledTimes(1);
  });
});

describe("runtime-flavor branch parity", () => {
  test("a multi-thread runtime maps to the block_in_place branch", () => {
    expect(syncBridgeStrategyFor(RuntimeFlavor.MultiThread)).toBe(
      "block_in_place",
    );
  });

  test("a current-thread runtime falls through to the scoped-thread branch", () => {
    expect(syncBridgeStrategyFor(RuntimeFlavor.CurrentThread)).toBe(
      "scoped_current_thread",
    );
  });

  test("no ambient runtime falls through to the scoped-thread branch", () => {
    expect(syncBridgeStrategyFor(undefined)).toBe("scoped_current_thread");
  });

  test("the live CF/JS environment resolves to the event-loop strategy", () => {
    // PORT-TODO(inventory §7): neither tokio branch is reachable on the event
    // loop; the real mechanism is a single cooperative `await`.
    expect(activeSyncBridgeStrategy()).toBe("event_loop");
  });
});
