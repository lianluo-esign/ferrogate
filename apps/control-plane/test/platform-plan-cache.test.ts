import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  PLATFORM_PLAN_SNAPSHOT_KEY,
  platformPlanFromKv,
} from "../../gateway/src/ratelimit/plan-source.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import {
  publishPlatformPlanCache,
  refreshPlatformPlanCache,
} from "../src/store/platform-plan-cache.js";
import { projectPlan, projectTenantAccount } from "../src/store/quota_registry.js";
import { applySchema, db } from "./d1.js";

beforeAll(applySchema);

describe("platform DO -> KV -> gateway quota defaults", () => {
  it("publishes the committed typed plan and assignment together, without tenant private fields", async () => {
    let raw = "";
    const kv = {
      put: vi.fn(async (key: string, value: string) => {
        expect(key).toBe(PLATFORM_PLAN_SNAPSHOT_KEY);
        raw = value;
      }),
      get: async () => raw,
    } as unknown as KVNamespace;
    await projectPlan(
      db(),
      {
        id: "speed-plan",
        name: "Speed",
        default_rpm_limit: 9,
        default_tpm_limit: 1234,
        default_model_allowlist: ["safe"],
      },
      1,
      { PLATFORM_CONFIG: kv },
    );
    await projectTenantAccount(
      db(),
      { id: "speed-tenant", plan_id: "speed-plan", private_email: "must-not-be-cached" },
      1,
      { PLATFORM_CONFIG: kv },
    );
    expect(raw).not.toContain("must-not-be-cached");
    expect(kv.put).toHaveBeenCalledTimes(2);
    const result = await platformPlanFromKv(kv, "speed-tenant");
    expect(result?.plan).toMatchObject({
      id: "speed-plan",
      defaultRpmLimit: 9,
      defaultTpmLimit: 1234,
      defaultModelAllowlist: ["safe"],
    });
  });

  it("publishes a downshift and an explicit no-plan assignment", async () => {
    let raw = "";
    const kv = {
      put: async (_key: string, value: string) => {
        raw = value;
      },
      get: async () => raw,
    } as unknown as KVNamespace;
    await projectPlan(db(), { id: "speed-low", default_rpm_limit: 1 }, 1, { PLATFORM_CONFIG: kv });
    await projectTenantAccount(db(), { id: "speed-switch", plan_id: "speed-low" }, 1, {
      PLATFORM_CONFIG: kv,
    });
    expect((await platformPlanFromKv(kv, "speed-switch"))?.plan?.defaultRpmLimit).toBe(1);
    await projectTenantAccount(db(), { id: "speed-switch", plan_id: null }, 2, {
      PLATFORM_CONFIG: kv,
    });
    // A fresh isolate sees the newly published unassignment; old isolates use bounded TTL.
    const freshKv = { get: async () => raw } as unknown as KVNamespace;
    expect(await platformPlanFromKv(freshKv, "speed-switch")).toMatchObject({ plan: undefined });
  });

  it("a failed KV write does not discard the authoritative mutation, and republishing repairs it", async () => {
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const failingKv = {
        put: async () => {
          throw new Error("KV down");
        },
      } as unknown as KVNamespace;
      await projectPlan(db(), { id: "speed-repair", default_rpm_limit: 2 }, 1, {
        PLATFORM_CONFIG: failingKv,
      });
      expect(
        await db()
          .prepare("SELECT default_rpm_limit FROM plans WHERE id = ?")
          .bind("speed-repair")
          .first("default_rpm_limit"),
      ).toBe(2);
      let raw = "";
      const kv = {
        put: async (_key: string, value: string) => {
          raw = value;
        },
      } as unknown as KVNamespace;
      expect((await publishPlatformPlanCache({ db: db(), kv })).status).toBe("published");
      expect(
        JSON.parse(raw).plans.find((plan: { id: string }) => plan.id === "speed-repair")
          .defaultRpmLimit,
      ).toBe(2);
    } finally {
      warning.mockRestore();
    }
  });

  it("does no I/O without KV and refuses an incomplete batch", async () => {
    expect(await publishPlatformPlanCache({ db: {} as D1Database })).toEqual({
      status: "unconfigured",
    });
    await refreshPlatformPlanCache({} as D1Database);
    const kv = { put: vi.fn() } as unknown as KVNamespace;
    const broken = { prepare: () => ({}), batch: async () => [] } as unknown as D1Database;
    await expect(publishPlatformPlanCache({ db: broken, kv })).rejects.toThrow("incomplete");
    expect(kv.put).not.toHaveBeenCalled();
  });
});

it("the real maintenance tick republishes quota plans", async () => {
  const bindings = env as unknown as ControlPlaneBindings;
  const report = await runScheduledTick(bindings);
  expect(report.platformPlanCache.status).toBe("published");
  expect(await bindings.PLATFORM_CONFIG?.get(PLATFORM_PLAN_SNAPSHOT_KEY)).not.toBeNull();
});
