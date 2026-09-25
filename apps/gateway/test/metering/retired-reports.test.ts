import { env } from "cloudflare:test";
import { beforeEach, expect, it, vi } from "vitest";
import {
  SettledBillingReportPublisher,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
} from "../../src/metering/index.js";
import { resetTenantBillingState, tenantObjectDb } from "../tenant-object.js";
import { pricedBook, usageFixture } from "./fixtures.js";

beforeEach(() => resetTenantBillingState(["tenant_a"]));

it("settles exactly once without publishing even when stale BILLING bindings exist", async () => {
  const send = vi.fn(() => Promise.reject(new Error("retired queue")));
  const rc = { env: { ...env, BILLING: { send, sendBatch: send } } };
  const sink = createMeteringUsageSink({
    priceBook: pricedBook(),
    bindings: meteringBindingsFromEnv,
  });
  sink.record(usageFixture());
  await sink.flush(rc);
  sink.record(usageFixture());
  await sink.flush(rc);
  await sink.sweep(rc, Math.floor(Date.now() / 1000) + 3600);
  expect(send).not.toHaveBeenCalled();
  const db = tenantObjectDb("tenant_a");
  expect(await db.prepare("SELECT COUNT(*) AS n FROM billing_ledger").first()).toEqual({ n: 1 });
  expect(await db.prepare("SELECT COUNT(*) AS n FROM billing_report_outbox").first()).toEqual({
    n: 0,
  });
  const publisher = new SettledBillingReportPublisher();
  expect("delivered" in publisher).toBe(false);
});
