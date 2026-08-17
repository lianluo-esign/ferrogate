/**
 * Unit contract for the per-request audit-defer sink (`src/store/audit-sink.ts`).
 *
 * This is the seam that lets the login mint move its audit-chain append OFF the
 * <1s response path onto `ctx.waitUntil`. The three properties that make it safe
 * to do so are pinned here in isolation, with no store or runtime:
 *
 *  1. it only collects while ACTIVE — every other path (and every test without
 *     an activated sink) audits inline, byte-for-byte as before;
 *  2. `defer` collects THUNKS and does not start them — nothing runs until
 *     `drain`, so the response can return first;
 *  3. `drain` runs the collected work SEQUENTIALLY (same `chain_key` appends
 *     contend on `UNIQUE(chain_key, seq)`; serial execution avoids self-races)
 *     and swallows errors (a lost audit row must never fail a settled response).
 */
import { describe, expect, it } from "vitest";

import { DeferredAuditSink } from "../src/store/audit-sink.js";

describe("DeferredAuditSink", () => {
  it("is inactive by default and reports no pending work", () => {
    const sink = new DeferredAuditSink();
    expect(sink.active).toBe(false);
    expect(sink.pending).toBe(false);
  });

  it("collects deferred thunks WITHOUT starting them, then runs them on drain", async () => {
    const sink = new DeferredAuditSink();
    sink.activate();
    expect(sink.active).toBe(true);

    let started = false;
    sink.defer(async () => {
      started = true;
    });
    // `defer` must NOT invoke the thunk — the response returns before drain.
    expect(started).toBe(false);
    expect(sink.pending).toBe(true);

    await sink.drain();
    expect(started).toBe(true);
    expect(sink.pending).toBe(false);
  });

  it("runs deferred work SEQUENTIALLY, in registration order", async () => {
    const sink = new DeferredAuditSink();
    sink.activate();
    const order: number[] = [];
    let live = 0;
    let maxConcurrent = 0;
    const make = (n: number) => async () => {
      live += 1;
      maxConcurrent = Math.max(maxConcurrent, live);
      await Promise.resolve();
      order.push(n);
      live -= 1;
    };
    sink.defer(make(1));
    sink.defer(make(2));
    sink.defer(make(3));

    await sink.drain();
    expect(order).toEqual([1, 2, 3]);
    // Serial: at most one append in flight at a time.
    expect(maxConcurrent).toBe(1);
  });

  it("SWALLOWS a failing append and still runs the rest", async () => {
    const sink = new DeferredAuditSink();
    sink.activate();
    const ran: number[] = [];
    sink.defer(async () => {
      ran.push(1);
    });
    sink.defer(async () => {
      throw new Error("audit write failed");
    });
    sink.defer(async () => {
      ran.push(3);
    });

    // drain must not reject even though the middle thunk throws.
    await expect(sink.drain()).resolves.toBeUndefined();
    expect(ran).toEqual([1, 3]);
  });

  it("drain clears the queue so a second drain is a no-op", async () => {
    const sink = new DeferredAuditSink();
    sink.activate();
    let runs = 0;
    sink.defer(async () => {
      runs += 1;
    });
    await sink.drain();
    await sink.drain();
    expect(runs).toBe(1);
  });

  it("deactivate flips `active` off but keeps already-collected work for drain", async () => {
    const sink = new DeferredAuditSink();
    sink.activate();
    let ran = false;
    sink.defer(async () => {
      ran = true;
    });
    sink.deactivate();
    // The handler closes the window BEFORE draining onto waitUntil; the pending
    // thunk must survive that transition.
    expect(sink.active).toBe(false);
    expect(sink.pending).toBe(true);
    await sink.drain();
    expect(ran).toBe(true);
  });
});
