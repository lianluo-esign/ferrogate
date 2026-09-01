/**
 * The Zero-D1 Plan B billing OUTBOX co-migration (`sink.ts` `#deliverOnce` +
 * `MeteringUsageSink.sweepPlatform`).
 *
 * The dual-write leg proved in `platform-billing.test.ts` shadows an
 * UNATTRIBUTED settlement's `billing_events` + `billing_ledger` into the
 * authoritative `PlatformDataObject`. This file covers the THIRD row and its
 * recovery drain, both gated DEFAULT-OFF:
 *
 *  - `GATEWAY_PLATFORM_BILLING_OUTBOX` (write shadow): upgrade the platform
 *    shadow from a 2-row (event+ledger) to a 3-row (event+ledger+outbox) commit
 *    issued as ONE `platformDb.batch()` (#150 atomicity in the DO's single
 *    implicit transaction), then reap that platform outbox row in the SAME
 *    best-effort pass so the platform outbox is EMPTY at rest.
 *  - `GATEWAY_PLATFORM_BILLING_DRAIN` (recovery sweep): a one-minute-Cron
 *    `sweepPlatform()` that re-publishes only crash-stranded platform outbox
 *    rows. `writeOutbox = OUTBOX || DRAIN`, so the sweep is never run against a
 *    store the write path was not also feeding.
 *
 * As in the sibling file these drive the sink through its real `UsageSink`
 * surface with the real `@ferrogate/billing` pricing, and assert against the
 * REAL `PLATFORM_DATA` object (through the same `platformDatabaseFrom` facade
 * production uses). Where "empty at rest" alone cannot distinguish "wrote then
 * reaped" from "never wrote", a {@link RecordingDatabase} over the live object
 * proves the 3-row batch carried the outbox insert AND the reap ran.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  BILLING_OUTBOX_DELETE_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  GATEWAY_PLATFORM_BILLING_DRAIN,
  GATEWAY_PLATFORM_BILLING_OUTBOX,
  InMemoryBillingReportPublisher,
  InMemoryLedgerStore,
  InMemoryMeteringOutbox,
  ManualClock,
  type MeteringDatabase,
  type MeteringDiagnostics,
  type MeteringUsageSink,
  TrackingScheduler,
  createMeteringUsageSink,
} from "../../src/metering/index.js";
import {
  RecordingDatabase,
  RecordingQueue,
  platformBillingDb,
  resetPlatformBilling,
  storedPlatformBillingEvents,
  storedPlatformBillingLedger,
  storedPlatformBillingOutbox,
} from "./d1-harness.js";
import { pricedBook, usageFixture } from "./fixtures.js";
import { env } from "cloudflare:test";

/** The `ManualClock` epoch both the settlement and the sweep run against. */
const NOW = 1_700_000_000;

interface Harness {
  readonly sink: MeteringUsageSink;
  readonly ledger: InMemoryLedgerStore;
  readonly outbox: InMemoryMeteringOutbox;
  readonly publisher: InMemoryBillingReportPublisher;
  readonly scheduler: TrackingScheduler;
  readonly errors: { stage: string; error: unknown }[];
}

/** A sink whose settlement authority is the in-memory ledger (as in the sibling
 * file); the platform object is the only durable store under test here. */
function harness(platformDatabase?: (env: unknown) => MeteringDatabase | undefined): Harness {
  const ledger = new InMemoryLedgerStore();
  const outbox = new InMemoryMeteringOutbox();
  const publisher = new InMemoryBillingReportPublisher();
  const scheduler = new TrackingScheduler();
  const clock = new ManualClock(NOW);
  const errors: { stage: string; error: unknown }[] = [];
  const diagnostics: MeteringDiagnostics = {
    onError: (stage, error) => errors.push({ stage, error }),
  };
  const sink = createMeteringUsageSink({
    priceBook: pricedBook(),
    ledger,
    outbox,
    publisher,
    scheduler,
    clock,
    diagnostics,
    ...(platformDatabase === undefined ? {} : { platformDatabase }),
  });
  return { sink, ledger, outbox, publisher, scheduler, errors };
}

/** The PLATFORM_DATA binding plus any gate flags, passed through the drain env so
 * the DEFAULT `platformDatabaseFrom` resolver is what selects the object. */
function platformEnv(flags: Record<string, unknown> = {}): Record<string, unknown> {
  return { PLATFORM_DATA: (env as unknown as { PLATFORM_DATA: unknown }).PLATFORM_DATA, ...flags };
}

/** A usage with no tenant — the gateway could not attribute it to any tenant. */
function unattributedUsage(overrides: Record<string, unknown> = {}) {
  return usageFixture({ tenantId: undefined, projectId: undefined, ...overrides });
}

describe("MeteringUsageSink — platform billing outbox co-migration (Zero-D1 Plan B)", () => {
  beforeEach(async () => {
    await resetPlatformBilling();
  });

  it("writes a 3-row event+ledger+outbox batch and reaps the outbox in-pass (OUTBOX on)", async () => {
    // A RecordingDatabase over the LIVE platform object: "empty at rest" alone
    // cannot tell "wrote+reaped" from "never wrote", so prove both statements ran.
    const recording = new RecordingDatabase(platformBillingDb() as unknown as MeteringDatabase);
    const h = harness(() => recording);

    h.sink.record(unattributedUsage(), {
      env: platformEnv({ [GATEWAY_PLATFORM_BILLING_OUTBOX]: "on" }),
    });
    await h.scheduler.idle();

    // The settlement authority still recorded and delivered the charge once.
    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.errors).toHaveLength(0);

    // The atomic batch carried the outbox insert, and the same pass reaped it.
    const executed = recording.executed.map((entry) => entry.sql);
    expect(executed).toContain(BILLING_OUTBOX_INSERT_SQL);
    expect(executed).toContain(BILLING_OUTBOX_DELETE_SQL);
    // The insert is issued inside the batch, strictly before the reap `run()`.
    expect(executed.indexOf(BILLING_OUTBOX_INSERT_SQL)).toBeLessThan(
      executed.indexOf(BILLING_OUTBOX_DELETE_SQL),
    );

    // Event + ledger landed in the real object; the outbox is EMPTY at rest.
    expect(await storedPlatformBillingEvents()).toHaveLength(1);
    expect(await storedPlatformBillingLedger()).toHaveLength(1);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
  });

  it("also writes+reaps the platform outbox under DRAIN alone (writeOutbox = OUTBOX || DRAIN)", async () => {
    // The DRAIN gate forces the write shadow so its recovery sweep is never run
    // against an unfed store — identical observable outcome to OUTBOX on.
    const recording = new RecordingDatabase(platformBillingDb() as unknown as MeteringDatabase);
    const h = harness(() => recording);

    h.sink.record(unattributedUsage(), {
      env: platformEnv({ [GATEWAY_PLATFORM_BILLING_DRAIN]: "on" }),
    });
    await h.scheduler.idle();

    expect(h.errors).toHaveLength(0);
    const executed = recording.executed.map((entry) => entry.sql);
    expect(executed).toContain(BILLING_OUTBOX_INSERT_SQL);
    expect(executed).toContain(BILLING_OUTBOX_DELETE_SQL);

    expect(await storedPlatformBillingEvents()).toHaveLength(1);
    expect(await storedPlatformBillingLedger()).toHaveLength(1);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
  });

  it("leaves the platform object untouched for an ATTRIBUTED charge even with OUTBOX on", async () => {
    const h = harness();

    // Default fixture carries organization_id `tenant_a`; the gate never matters
    // because the leg is upstream-gated on `tenantIdForCharge === undefined`.
    h.sink.record(usageFixture(), {
      env: platformEnv({ [GATEWAY_PLATFORM_BILLING_OUTBOX]: "on" }),
    });
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.errors).toHaveLength(0);
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
    expect(await storedPlatformBillingLedger()).toHaveLength(0);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
  });

  it("never fails a settled+delivered charge when the 3-row platform batch throws (OUTBOX on)", async () => {
    const throwing: MeteringDatabase = {
      prepare: () => {
        const statement = {
          bind: () => statement,
          run: async () => ({}),
          all: async () => ({}),
        };
        return statement;
      },
      batch: () => Promise.reject(new Error("platform object unavailable")),
    };
    const h = harness(() => throwing);

    h.sink.record(unattributedUsage(), {
      env: { PLATFORM_DATA: {}, [GATEWAY_PLATFORM_BILLING_OUTBOX]: "on" },
    });
    await h.scheduler.idle();

    // The charge settled, delivered and the in-isolate outbox drained — the leg
    // is best-effort and OUTSIDE the retry contract.
    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.outbox.size).toBe(0);
    // Exactly one platform-billing failure, observed rather than swallowed, and
    // the batch throwing before the reap means the DELETE never ran.
    expect(h.errors).toHaveLength(1);
    expect(h.errors[0]?.stage).toBe("platform-billing");
    // Nothing landed in the real object; it is empty at rest.
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
  });

  it("sweepPlatform recovers a crash-stranded platform outbox row exactly once", async () => {
    // 1. Drive one OUTBOX-on settlement so a real event+ledger land in the
    //    object; the request path reaps the outbox row, leaving it empty at rest.
    const driver = harness();
    driver.sink.record(unattributedUsage(), {
      env: platformEnv({ [GATEWAY_PLATFORM_BILLING_OUTBOX]: "on" }),
    });
    await driver.scheduler.idle();
    expect(driver.errors).toHaveLength(0);

    const events = await storedPlatformBillingEvents();
    expect(events).toHaveLength(1);
    expect(await storedPlatformBillingLedger()).toHaveLength(1);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);

    // 2. Re-insert a STRANDED intent for that same ledger id — the shape an
    //    isolate death after the platform batch but before the in-pass reap
    //    leaves behind. `next_attempt_unix` is well past the sweep grace window.
    const strandedId = events[0]?.billing_event_id ?? "";
    await platformBillingDb()
      .prepare(BILLING_OUTBOX_INSERT_SQL)
      .bind(strandedId, NOW - 3600, NOW - 3600, NOW - 3600, events[0]?.event_json ?? "{}")
      .run();
    expect(await storedPlatformBillingOutbox()).toHaveLength(1);

    // 3. A DRAIN sink: NO tenant/control database bound (so `#backend` cannot
    //    resolve control and the sweep can only touch the platform object it
    //    builds by hand), a recording queue, the DEFAULT platform resolver.
    const recordingQueue = new RecordingQueue();
    const drainSink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: { database: () => undefined, queue: () => recordingQueue },
      clock: new ManualClock(NOW),
    });

    await drainSink.sweepPlatform({ env: platformEnv() });

    // The stranded charge is re-published exactly once and the row reaped.
    expect(recordingQueue.sent).toHaveLength(1);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);

    // 4. A SECOND sweep is a no-op — nothing due, no duplicate report.
    await drainSink.sweepPlatform({ env: platformEnv() });
    expect(recordingQueue.sent).toHaveLength(1);
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
  });

  it("sweepPlatform is inert with no platform object bound and with no queue bound", async () => {
    const recordingQueue = new RecordingQueue();
    const drainSink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: { database: () => undefined, queue: () => recordingQueue },
      clock: new ManualClock(NOW),
    });

    // (a) No PLATFORM_DATA in the env: the default resolver returns undefined and
    //     the sweep self-skips without reaching the queue.
    await expect(drainSink.sweepPlatform({ env: {} })).resolves.toBeUndefined();
    expect(recordingQueue.sent).toHaveLength(0);

    // (b) A platform object IS bound but no Queue producer is: the sweep still
    //     self-skips (recovery without a publisher would strand the row again).
    const noQueueSink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: { database: () => undefined, queue: () => undefined },
      clock: new ManualClock(NOW),
    });
    await expect(noQueueSink.sweepPlatform({ env: platformEnv() })).resolves.toBeUndefined();
  });
});
