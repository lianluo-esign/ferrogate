/**
 * The Zero-D1 Plan B billing dual-write leg (`sink.ts` `#deliverOnce`).
 *
 * An UNATTRIBUTED settlement — one with no tenant object to own it — has its
 * `billing_events` + `billing_ledger` rows shadowed into the authoritative
 * `PlatformDataObject` alongside the control write, so removing the control D1
 * cannot strand the platform billing rows no tenant fan-out reader can reach.
 *
 * These drive the sink through its real `UsageSink` surface with the real
 * `@ferrogate/billing` pricing, and assert against the REAL `PLATFORM_DATA`
 * object (through the same `platformDatabaseFrom` facade production uses) — a
 * genuinely different store from the settlement authority, so a row seen there
 * proves the leg reached the object. The authority here is the in-memory ledger
 * (the control-D1 authority write is covered by `d1.test.ts`); what is under
 * test is the leg's gating, its data, and its best-effort isolation.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
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
  type PlatformBillingEventRow,
  type PlatformBillingLedgerRow,
  resetPlatformBilling,
  storedPlatformBillingEvents,
  storedPlatformBillingLedger,
  storedPlatformBillingOutbox,
} from "./d1-harness.js";
import { pricedBook, usageFixture } from "./fixtures.js";
import { env } from "cloudflare:test";

interface Harness {
  readonly sink: MeteringUsageSink;
  readonly ledger: InMemoryLedgerStore;
  readonly outbox: InMemoryMeteringOutbox;
  readonly publisher: InMemoryBillingReportPublisher;
  readonly scheduler: TrackingScheduler;
  readonly errors: { stage: string; error: unknown }[];
}

function harness(platformDatabase?: (env: unknown) => MeteringDatabase | undefined): Harness {
  const ledger = new InMemoryLedgerStore();
  const outbox = new InMemoryMeteringOutbox();
  const publisher = new InMemoryBillingReportPublisher();
  const scheduler = new TrackingScheduler();
  const clock = new ManualClock(1_700_000_000);
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

/** The PLATFORM_DATA binding, passed through the drain env so the DEFAULT
 * `platformDatabaseFrom` resolver is what selects the object — the production wiring. */
function platformEnv(): { PLATFORM_DATA: unknown } {
  return { PLATFORM_DATA: (env as unknown as { PLATFORM_DATA: unknown }).PLATFORM_DATA };
}

/** A usage with no tenant — the gateway could not attribute it to any tenant. */
function unattributedUsage(overrides: Record<string, unknown> = {}) {
  return usageFixture({ tenantId: undefined, projectId: undefined, ...overrides });
}

describe("MeteringUsageSink — platform billing dual-write (Zero-D1 Plan B)", () => {
  beforeEach(async () => {
    await resetPlatformBilling();
  });

  it("shadows an UNATTRIBUTED settlement's event + ledger into the platform object", async () => {
    const h = harness();
    expect(await storedPlatformBillingEvents()).toHaveLength(0);

    h.sink.record(unattributedUsage(), { env: platformEnv() });
    await h.scheduler.idle();

    // The settlement authority still recorded and delivered the charge.
    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.outbox.size).toBe(0);
    expect(h.errors).toHaveLength(0);

    const events: PlatformBillingEventRow[] = await storedPlatformBillingEvents();
    expect(events).toHaveLength(1);
    expect(events[0]?.request_id).toBe("fg-000000000000002a");
    expect(events[0]?.provider_attempt_index).toBe(0);
    // Every row in the object is unattributed by construction — tenant_id is NULL.
    expect(events[0]?.tenant_id).toBeNull();
    expect(JSON.parse(events[0]?.event_json ?? "{}").request_id).toBe("fg-000000000000002a");

    const ledgerRows: PlatformBillingLedgerRow[] = await storedPlatformBillingLedger();
    expect(ledgerRows).toHaveLength(1);
    expect(ledgerRows[0]?.tenant_id).toBeNull();
    expect(ledgerRows[0]?.organization_id).toBeNull();
    // The ledger id equals the event id (same charge, one batch).
    expect(ledgerRows[0]?.id).toBe(events[0]?.billing_event_id);
  });

  it("writes NO platform outbox row with the flags unset (default-OFF baseline)", async () => {
    const h = harness();

    // With neither GATEWAY_PLATFORM_BILLING_OUTBOX nor _DRAIN in the env, the
    // shadow stays a 2-row event+ledger batch — byte-identical to production.
    h.sink.record(unattributedUsage(), { env: platformEnv() });
    await h.scheduler.idle();

    expect(await storedPlatformBillingEvents()).toHaveLength(1);
    expect(await storedPlatformBillingLedger()).toHaveLength(1);
    // The mutable outbox is NOT shadowed unless a flag opts in.
    expect(await storedPlatformBillingOutbox()).toHaveLength(0);
    expect(h.errors).toHaveLength(0);
  });

  it("does NOT touch the platform object for an ATTRIBUTED (tenant) settlement", async () => {
    const h = harness();

    // Default fixture carries organization_id `tenant_a`.
    h.sink.record(usageFixture(), { env: platformEnv() });
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    // The tenant object owns an attributed charge; the platform object never sees it.
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
    expect(await storedPlatformBillingLedger()).toHaveLength(0);
  });

  it("never fails a settled, delivered charge when the platform write throws", async () => {
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

    h.sink.record(unattributedUsage(), { env: { PLATFORM_DATA: {} } });
    await h.scheduler.idle();

    // The charge settled, delivered and the outbox drained — the leg is best-effort.
    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.outbox.size).toBe(0);
    // The failure is observed, not swallowed silently, and never re-driven.
    expect(h.errors).toHaveLength(1);
    expect(h.errors[0]?.stage).toBe("platform-billing");
    // Nothing landed in the real object either.
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
  });

  it("skips the leg entirely when no platform object is bound", async () => {
    const h = harness();

    // No PLATFORM_DATA in the drain env: the default resolver returns undefined
    // and the leg self-skips without touching the settlement.
    h.sink.record(unattributedUsage(), { env: {} });
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.publisher.delivered).toHaveLength(1);
    expect(h.errors).toHaveLength(0);
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
  });
});
