import { describe, expect, it } from "vitest";
import { PLATFORM_CATALOG_SNAPSHOT_KEY } from "../../gateway/src/inference/platform-catalog.js";
import { publishPlatformCatalogCache } from "../src/store/platform-config-cache.js";

describe("platform config cache", () => {
  it("publishes one complete revisioned snapshot without provider secret values", async () => {
    const row = {
      model_id: "model-1",
      model_name: "gpt-current",
      offering_id: "offering-1",
      provider_id: "provider-1",
      provider_upstream_protocol: "openai.responses",
      provider_api_key_var: "UPSTREAM_API_KEY",
    };
    const prepared: string[] = [];
    const db = {
      prepare(sql: string) {
        prepared.push(sql);
        return { sql };
      },
      async batch() {
        expect(prepared[0]).toContain("platform_catalog_revisions");
        expect(prepared[1]).toContain("platform_catalog_models");
        return [{ results: [{ revision: 17 }] }, { results: [row] }];
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

    const result = await publishPlatformCatalogCache({ db, kv, nowUnix: 123 });

    expect(result).toEqual({ status: "published", revision: 17, rows: 1 });
    expect(writtenKey).toBe(PLATFORM_CATALOG_SNAPSHOT_KEY);
    expect(JSON.parse(writtenValue)).toEqual({
      schema_version: 1,
      revision: 17,
      published_at_unix: 123,
      rows: [row],
    });
    expect(writtenValue).not.toContain("sk-");
  });

  it("is a no-op when the shared KV binding is not configured", async () => {
    const result = await publishPlatformCatalogCache({
      db: {} as D1Database,
      nowUnix: 123,
    });
    expect(result).toEqual({ status: "unconfigured" });
  });
});
