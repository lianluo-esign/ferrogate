import { describe, expect, it } from "vitest";
import { TENANT_STATUS_SNAPSHOT_KEY } from "../../gateway/src/tenant-status-snapshot.js";
import { publishTenantStatusCache } from "../src/store/tenant-status-cache.js";

/**
 * The write half of the `tenants.status` KV channel: the control plane projects
 * the authoritative `tenants` rows into ONE `PLATFORM_CONFIG` snapshot the gateway
 * lifecycle gate reads KV-first, removing the per-request control read from the
 * auth hot path. Mirrors `platform-config-cache.test.ts`.
 *
 * The `db` is a hand-built fake so the assertion is purely "what the store reads
 * becomes the KV value"; the store↔D1 SQL is a plain `SELECT id, status FROM
 * tenants` shared verbatim with the gateway read.
 */
describe("tenant-status cache", () => {
  it("publishes one snapshot mapping id → raw status (NULL folded to empty)", async () => {
    const db = {
      prepare(_sql: string) {
        return {
          async all<T>(): Promise<{ results: T[] }> {
            return {
              results: [
                { id: "t_active", status: "active" },
                { id: "t_suspended", status: "suspended" },
                { id: "t_null", status: null },
              ] as unknown as T[],
            };
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

    const result = await publishTenantStatusCache({ db, kv, nowUnix: 123 });

    expect(result).toEqual({ status: "published", rows: 3 });
    expect(writtenKey).toBe(TENANT_STATUS_SNAPSHOT_KEY);
    expect(JSON.parse(writtenValue)).toEqual({
      schema_version: 1,
      published_at_unix: 123,
      statuses: { t_active: "active", t_suspended: "suspended", t_null: "" },
    });
  });

  it("is a no-op when the shared KV binding is not configured", async () => {
    const result = await publishTenantStatusCache({ db: {} as D1Database, nowUnix: 123 });
    expect(result).toEqual({ status: "unconfigured" });
  });
});
