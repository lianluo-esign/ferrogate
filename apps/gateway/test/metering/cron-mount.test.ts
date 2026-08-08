/**
 * The MOUNT of the Cron sweep — the wave-13 finding.
 *
 * ## What was already proved, and what was not
 *
 * `durable.test.ts` drives `MeteringUsageSink.sweep` directly and proves the
 * recovery logic completely: a stranded `billing_report_outbox` row is
 * re-published, the grace window is honoured, the retry ladder dead-letters.
 * `cron-trigger.test.ts` proves the deploy config: `[triggers] crons` exists and
 * `typeof handler.scheduled === "function"`.
 *
 * Neither proves the thing BETWEEN them. The wave-13 mount-mutation sweep
 * emptied the body of `gatewayScheduled` in `src/index.ts` — deleting
 * `await usage.sweep({ env, ctx })`, leaving an `async` function that returns
 * immediately — and all 1711 gateway tests stayed GREEN. A Cron firing every
 * minute into a handler that does nothing is indistinguishable, to that suite,
 * from working recovery; the only symptom in production is charges that sit on
 * the ledger and are never reported, which is money.
 *
 * This file is that gate. It invokes the ENTRY MODULE's `scheduled` — the exact
 * value workerd calls, imported from `src/worker.ts`, not a locally rebuilt
 * sink — and requires it to reach the durable outbox.
 *
 * ## Why "reached the outbox table" and not "delivered a charge"
 *
 * `gatewayScheduled` calls `usage.sweep({ env, ctx })` with NO `now` argument,
 * so the due-cutoff is real wall-clock time minus `OUTBOX_SWEEP_GRACE_SECONDS`.
 * Making a delivery happen would mean either back-dating a row (asserting on a
 * hand-written `event_json`, i.e. on a fixture rather than on the wiring) or
 * pinning the clock the module-level sink was constructed with, which the
 * composition root deliberately does not expose. The observable that the mutant
 * cannot fake is simpler and sits closer to the seam: the handler must issue the
 * due-list query against `env.BILLING_DB`. An empty body issues nothing.
 *
 * `RecordingDatabase` is a transparent decorator over the REAL `BILLING_DB`
 * binding, so what runs is the real SQL against the real D1 — the recording is
 * only a tap on the way through.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { controlNamespaceOverD1 } from "../support/control-namespace.js";
import { beforeEach, describe, expect, it } from "vitest";
import handler from "../../src/worker.js";
import { RecordingDatabase, RecordingQueue, applyControlMigration } from "./d1-harness.js";

/** The table the sweep — and nothing else in a request-free isolate — reads. */
const OUTBOX_TABLE = /billing_report_outbox/i;

function scheduledOf(): NonNullable<typeof handler.scheduled> {
  const scheduled = handler.scheduled;
  if (typeof scheduled !== "function") {
    throw new Error(
      "the gateway entry module exports no `scheduled` handler; see cron-trigger.test.ts",
    );
  }
  return scheduled;
}

describe("MOUNT: the [triggers] cron handler reaches the durable billing outbox", () => {
  beforeEach(async () => {
    await applyControlMigration();
  });

  it("issues the due-list query against env.BILLING_DB", async () => {
    const db = new RecordingDatabase();
    const queue = new RecordingQueue();
    const ctx = createExecutionContext();

    // Post-#863 `gatewayScheduled` enumerates the roster and sweeps each
    // TENANT OBJECT's outbox; `env.BILLING_DB` is swept only for the unscoped
    // compatibility posture — i.e. when the roster names no tenants. A tenant
    // object's due-list RPC cannot be tapped the way `RecordingDatabase` taps a
    // D1 binding, so the roster is emptied for this invocation (the pool's
    // per-test isolated storage restores the fixture rows afterwards). The
    // wave-13 mutant — an emptied `gatewayScheduled` body — still fails this:
    // it issues no due-list query against ANY backend.
    await (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB.prepare(
      "DELETE FROM tenant_databases",
    ).run();

    await scheduledOf()(
      { cron: "* * * * *", scheduledTime: Date.now(), noRetry: () => undefined } as never,
      { ...(env as unknown as Record<string, unknown>), CONTROL_DATA: controlNamespaceOverD1(db), BILLING: queue } as never,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    // The assertion the empty-body mutant fails: it executes no statement at
    // all, so nothing in `executed` can mention the outbox.
    expect(
      db.executed.map((statement) => statement.sql).filter((sql) => OUTBOX_TABLE.test(sql)),
      "the scheduled handler never touched billing_report_outbox — is `usage.sweep` still wired?",
    ).not.toHaveLength(0);
  });

  it("does not reject when the billing bindings are absent", async () => {
    // The other half of the contract `MeteringUsageSink.sweep` promises: a Cron
    // invocation with no durable backend must return quietly. A throwing
    // `scheduled` is a failed Cron invocation, which Cloudflare retries.
    const ctx = createExecutionContext();
    await expect(
      scheduledOf()(
        { cron: "* * * * *", scheduledTime: Date.now(), noRetry: () => undefined } as never,
        {} as never,
        ctx,
      ),
    ).resolves.toBeUndefined();
    await waitOnExecutionContext(ctx);
  });
});
