import { env } from "cloudflare:test";
import { controlNamespace } from "../support/control-namespace.js";
import { beforeEach, describe, expect, it } from "vitest";
import {
  D1ExperimentObserver,
  sweepExperimentProjections,
  type ShadowLegRecord,
} from "../../src/experiments/index.js";
import { tenantObjectDb } from "../tenant-object.js";
import { controlDb, resetExperimentTables, storedShadowLegs } from "./harness.js";

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
  await tenantObjectDb("tenant_a").prepare("DELETE FROM experiment_shadow_legs").run();
});

describe("tenant-authoritative experiment legs", () => {
  it("writes the object and a tenant-qualified projection idempotently", async () => {
    const observer = new D1ExperimentObserver({
      tenantDatabase: (_env, tenantId) => tenantObjectDb(tenantId),
      projectionDatabase: () => controlDb(),
    });

    await observer.observeShadowLeg(RECORD, {});
    const tenant = tenantObjectDb("tenant_a");
    expect(
      await tenant
        .prepare("SELECT COUNT(*) AS count FROM experiment_shadow_legs")
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(await storedShadowLegs()).toHaveLength(1);

    await observer.observeShadowLeg(RECORD, {});
    expect(
      await tenant
        .prepare("SELECT COUNT(*) AS count FROM experiment_shadow_legs")
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(await storedShadowLegs()).toHaveLength(1);
    const projection = (await storedShadowLegs())[0] as unknown as Record<string, unknown>;
    expect(projection.projection_key).toContain("tenant_a");
  });

  it("repairs a missing control projection from the object on a scheduled sweep", async () => {
    const observer = new D1ExperimentObserver({
      tenantDatabase: (_env, tenantId) => tenantObjectDb(tenantId),
      projectionDatabase: () => controlDb(),
    });
    await observer.observeShadowLeg(RECORD, {});
    await controlDb().prepare("DELETE FROM experiment_shadow_legs").run();

    await sweepExperimentProjections(
      {
        CONTROL_DB: controlDb(),
        CONTROL_DATA: controlNamespace(),
        TENANT_DATA: (env as unknown as { TENANT_DATA: unknown }).TENANT_DATA,
      },
      ["tenant_a"],
    );

    expect(await storedShadowLegs()).toHaveLength(1);
  });

  it("pages through every object leg instead of repeating the first page", async () => {
    const observer = new D1ExperimentObserver({
      tenantDatabase: (_env, tenantId) => tenantObjectDb(tenantId),
      projectionDatabase: () => controlDb(),
    });
    for (let index = 0; index < 3; index += 1) {
      await observer.observeShadowLeg(
        {
          ...RECORD,
          legId: `request-${index}~shadow`,
          clientRequestId: `request-${index}`,
          observedAtUnix: RECORD.observedAtUnix + index,
        },
        {},
      );
    }
    await controlDb().prepare("DELETE FROM experiment_shadow_legs").run();

    await sweepExperimentProjections(
      {
        CONTROL_DB: controlDb(),
        CONTROL_DATA: controlNamespace(),
        TENANT_DATA: (env as unknown as { TENANT_DATA: unknown }).TENANT_DATA,
      },
      ["tenant_a"],
      2,
    );

    expect(await storedShadowLegs()).toHaveLength(3);
  });
});
