import { describe, expect, it } from "vitest";
import { PLATFORM_BILLING_GROUP_SNAPSHOT_KEY } from "../../gateway/src/inference/billing-group-source.js";
import { publishPlatformBillingGroupsCache } from "../src/store/platform-billing-group-cache.js";

/**
 * The write half of the billing-group KV channel (#961): the control plane
 * projects the authoritative `platform_billing_groups` rows into ONE account-global
 * `PLATFORM_CONFIG` snapshot the gateway money path reads KV-first, replacing the
 * per-tenant Durable Object fan-out. Mirrors `platform-config-cache.test.ts`.
 *
 * The `db` here is a hand-built fake so the assertion is purely "what the store
 * reads becomes the KV value" — the store↔D1 SQL is covered by the deployed-Worker
 * `admin-billing-group.test.ts`, not re-proven against a fake.
 */
describe("platform billing-group cache", () => {
  it("publishes one revisioned snapshot of only the money-path fields", async () => {
    // `listGroups()` fires two `.all()`s (groups, then edges); `revision()` fires
    // one `.first()`. The fake routes by table name so call order is irrelevant.
    const db = {
      prepare(sql: string) {
        return {
          sql,
          async all<T>(): Promise<{ results: T[] }> {
            if (sql.includes("platform_billing_group_providers")) {
              return {
                results: [{ group_id: "bg_alpha", provider_id: "chan-1" }] as unknown as T[],
              };
            }
            return {
              results: [
                {
                  id: "bg_alpha",
                  name: "alpha",
                  provider_type_id: "openai",
                  multiplier: 1.5,
                  description: null,
                  enabled: 1,
                },
                {
                  id: "bg_beta",
                  name: "beta",
                  provider_type_id: "openai",
                  multiplier: 2,
                  description: null,
                  enabled: 0,
                },
              ] as unknown as T[],
            };
          },
          async first<T>(): Promise<T> {
            return { revision: 9 } as unknown as T;
          },
        };
      },
    } as unknown as D1Database;

    let writtenKey = "";
    let writtenValue = "";
    const kv = {
      async put(key: string, value: string) {
        writtenKey = key;
        writtenValue = value;
      },
    } as unknown as KVNamespace;

    const result = await publishPlatformBillingGroupsCache({ db, kv, nowUnix: 123 });

    expect(result).toEqual({ status: "published", revision: 9, groups: 2 });
    expect(writtenKey).toBe(PLATFORM_BILLING_GROUP_SNAPSHOT_KEY);
    expect(JSON.parse(writtenValue)).toEqual({
      schema_version: 1,
      revision: 9,
      published_at_unix: 123,
      groups: [
        // name-ordered, edges folded in, DISABLED group kept with `enabled:false`
        { id: "bg_alpha", multiplier: 1.5, enabled: true, provider_ids: ["chan-1"] },
        { id: "bg_beta", multiplier: 2, enabled: false, provider_ids: [] },
      ],
    });
    // Only the four money-path fields travel — no name/description/provider_type.
    expect(writtenValue).not.toContain("description");
    expect(writtenValue).not.toContain("provider_type_id");
  });

  it("is a no-op when the shared KV binding is not configured", async () => {
    const result = await publishPlatformBillingGroupsCache({ db: {} as D1Database, nowUnix: 123 });
    expect(result).toEqual({ status: "unconfigured" });
  });
});
