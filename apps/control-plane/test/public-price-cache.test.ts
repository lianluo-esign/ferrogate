import { describe, expect, it } from "vitest";
import { PUBLIC_PRICE_SNAPSHOT_KEY } from "../../gateway/src/inference/public-price-snapshot.js";
import { publishPublicPriceCache } from "../src/store/public-price-cache.js";

/**
 * The write half of the public-model-price KV channel: the control plane
 * projects the two authoritative platform pricing tables into ONE
 * `PLATFORM_CONFIG` snapshot the gateway `resolvePublicModelPrices` reads
 * KV-first, removing the two per-request control reads from the inference build
 * path. Mirrors `tenant-status-cache.test.ts` / `platform-config-cache.test.ts`.
 *
 * The `db` is a hand-built fake so the assertion is purely "what the store reads
 * becomes the KV value"; the store↔D1 SQL is shared verbatim with the gateway
 * reader, so it is not re-stated here.
 */
describe("public-price cache", () => {
  it("publishes one snapshot carrying both pricing tables verbatim", async () => {
    const priceRow = {
      id: "m1",
      model_key: "gpt",
      aliases_json: "[]",
      enabled: 1,
      input_price_per_1m: 3,
      output_price_per_1m: 6,
      cached_input_price_per_1m: null,
      cache_write_price_per_1m: null,
      reasoning_price_per_1m: null,
      audio_second_price_per_1m: null,
      audio_character_price_per_1m: null,
    };
    const providerRow = { id: "p1", cost_multiplier: 1.5 };
    const db = {
      prepare(_sql: string) {
        return {};
      },
      async batch<T>(_statements: unknown[]): Promise<{ results: T[] }[]> {
        return [
          { results: [priceRow] as unknown as T[] },
          { results: [providerRow] as unknown as T[] },
        ];
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

    const result = await publishPublicPriceCache({ db, kv, nowUnix: 123 });

    expect(result).toEqual({ status: "published", prices: 1, providerCosts: 1 });
    expect(writtenKey).toBe(PUBLIC_PRICE_SNAPSHOT_KEY);
    expect(JSON.parse(writtenValue)).toEqual({
      schema_version: 1,
      published_at_unix: 123,
      prices: [priceRow],
      provider_costs: [providerRow],
    });
  });

  it("throws when the batch returns an incomplete result", async () => {
    const db = {
      prepare(_sql: string) {
        return {};
      },
      async batch(_statements: unknown[]): Promise<unknown[]> {
        return [{ results: [] }]; // second statement's result missing
      },
    } as unknown as D1Database;
    const kv = { async put() {} } as unknown as KVNamespace;
    await expect(publishPublicPriceCache({ db, kv, nowUnix: 1 })).rejects.toThrow(
      /incomplete result/,
    );
  });

  it("is a no-op when the shared KV binding is not configured", async () => {
    const result = await publishPublicPriceCache({ db: {} as D1Database, nowUnix: 123 });
    expect(result).toEqual({ status: "unconfigured" });
  });
});
