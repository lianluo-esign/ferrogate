import { beforeEach, describe, expect, it } from "vitest";
import { D1ExperimentObserver, type ShadowLegRecord } from "../../src/experiments/index.js";
import { tenantObjectDb } from "../tenant-object.js";
import { resetExperimentTables, storedTenantShadowLegs } from "./harness.js";

const RECORD: ShadowLegRecord = {
  legId: "request-1~shadow",
  clientRequestId: "request-1",
  experimentId: "experiment-1",
  tenantId: "tenant_a",
  projectId: "project-1",
  apiKeyId: "key-1",
  logicalModel: "split-model",
  provider: "mirror-provider",
  providerModel: "mirror-model",
  statusCode: 200,
  latencyMs: 12,
  promptTokens: 10,
  completionTokens: 4,
  totalTokens: 14,
  costUsd: 0.00001,
  observedAtUnix: 1_700_000_000,
};

beforeEach(async () => {
  await resetExperimentTables();
});

describe("tenant-authoritative experiment legs", () => {
  it("writes the object idempotently — the sole destination, no control projection", async () => {
    // The production contract (#859/#881): a shadow leg is tenant data. The
    // owning object is the ONLY destination; the control projection was DROPPED
    // by control migration 0043, so there is nowhere else for the leg to go.
    const observer = new D1ExperimentObserver({
      tenantDatabase: (_env, tenantId) => tenantObjectDb(tenantId),
    });

    await observer.observeShadowLeg(RECORD, {});
    expect(observer.stats).toMatchObject({ written: 1, dropped: 0, failed: 0 });
    expect(await storedTenantShadowLegs("tenant_a")).toHaveLength(1);

    // `ON CONFLICT (leg_id)` replaces the row rather than double-counting the arm.
    await observer.observeShadowLeg(RECORD, {});
    expect(observer.stats).toMatchObject({ written: 2, dropped: 0, failed: 0 });
    expect(await storedTenantShadowLegs("tenant_a")).toHaveLength(1);
  });

  it("drops the leg — never half-writes it — when the tenant object is unreachable", async () => {
    const observer = new D1ExperimentObserver({
      tenantDatabase: () => undefined,
    });

    await observer.observeShadowLeg(RECORD, {});
    expect(observer.stats).toMatchObject({ written: 0, dropped: 1, failed: 0 });
    expect(await storedTenantShadowLegs("tenant_a")).toHaveLength(0);
  });
});
