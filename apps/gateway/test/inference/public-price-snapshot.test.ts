/**
 * The public-model-price KV fast-path core (`src/inference/public-price-snapshot.ts`).
 *
 * The pure half of the projection: the provider-cost fold that BOTH the KV path
 * and the control path in `resolvePublicModelPrices` share (so they can never
 * disagree on a multiplier), the snapshot parser (any shape violation → null →
 * control fallback), and the KV reader that folds an absent/malformed/throwing
 * read to null. These are plain stubs, so the branch logic is proven without a
 * live binding — the twin of `tenant-status-snapshot.test.ts`.
 */
import { describe, expect, it } from "vitest";

import {
  PUBLIC_PRICE_SNAPSHOT_KEY,
  type PublicPriceSnapshot,
  parsePublicPriceSnapshot,
  platformProviderCostMap,
  readPublicPriceSnapshot,
} from "../../src/inference/public-price-snapshot.js";

/** A KV `get` double returning a fixed payload (or throwing). */
function fakeKv(payload: string | null | (() => never)) {
  let gets = 0;
  return {
    kv: {
      get(_key: string, _options?: { cacheTtl?: number }): Promise<string | null> {
        gets += 1;
        if (typeof payload === "function") return Promise.resolve(payload());
        return Promise.resolve(payload);
      },
    },
    gets: () => gets,
  };
}

function snapshotJson(overrides: Partial<PublicPriceSnapshot> = {}): string {
  const snapshot: PublicPriceSnapshot = {
    schema_version: 1,
    published_at_unix: 1_700_000_000,
    prices: [],
    provider_costs: [],
    ...overrides,
  };
  return JSON.stringify(snapshot);
}

describe("platformProviderCostMap", () => {
  it("folds numeric and numeric-string multipliers, dropping the non-finite/negative", () => {
    const map = platformProviderCostMap([
      { id: "p_num", cost_multiplier: 1.5 },
      { id: "p_str", cost_multiplier: "2" },
      { id: "p_zero", cost_multiplier: 0 },
      { id: "p_null", cost_multiplier: null },
      { id: "p_neg", cost_multiplier: -1 },
      { id: "p_nan", cost_multiplier: "not-a-number" },
    ]);
    // Faithful to the pre-snapshot inline fold: a finite, non-negative value
    // survives, a negative or non-numeric one drops out (→ `1` default). NULL
    // coerces via `Number(null) === 0`, so it is retained as 0 exactly as the
    // original control read did — this fold changes nothing about that.
    expect([...map.entries()]).toEqual([
      ["p_num", 1.5],
      ["p_str", 2],
      ["p_zero", 0],
      ["p_null", 0],
    ]);
  });
});

describe("parsePublicPriceSnapshot", () => {
  it("accepts a well-formed snapshot", () => {
    const parsed = parsePublicPriceSnapshot(
      snapshotJson({
        prices: [
          {
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
          },
        ],
        provider_costs: [{ id: "p1", cost_multiplier: 1 }],
      }),
    );
    expect(parsed?.prices).toHaveLength(1);
    expect(parsed?.provider_costs).toEqual([{ id: "p1", cost_multiplier: 1 }]);
  });

  it("rejects a wrong schema version, a non-array table, or malformed JSON", () => {
    expect(
      parsePublicPriceSnapshot(
        JSON.stringify({ schema_version: 2, published_at_unix: 1, prices: [], provider_costs: [] }),
      ),
    ).toBeNull();
    expect(
      parsePublicPriceSnapshot(
        JSON.stringify({ schema_version: 1, published_at_unix: 1, prices: {}, provider_costs: [] }),
      ),
    ).toBeNull();
    expect(
      parsePublicPriceSnapshot(
        JSON.stringify({ schema_version: 1, published_at_unix: 1, prices: [] }),
      ),
    ).toBeNull();
    expect(parsePublicPriceSnapshot("{ not json")).toBeNull();
  });
});

describe("readPublicPriceSnapshot", () => {
  it("reads the shared key with a short cache TTL", async () => {
    const seen: Array<[string, unknown]> = [];
    const kv = {
      get(key: string, options?: { cacheTtl?: number }): Promise<string | null> {
        seen.push([key, options]);
        return Promise.resolve(snapshotJson({ provider_costs: [{ id: "p1", cost_multiplier: 2 }] }));
      },
    };
    const snapshot = await readPublicPriceSnapshot(kv);
    expect(snapshot?.provider_costs).toEqual([{ id: "p1", cost_multiplier: 2 }]);
    expect(seen).toEqual([[PUBLIC_PRICE_SNAPSHOT_KEY, { cacheTtl: 30 }]]);
  });

  it("folds an absent, malformed, or throwing read to null", async () => {
    expect(await readPublicPriceSnapshot(fakeKv(null).kv)).toBeNull();
    expect(await readPublicPriceSnapshot(fakeKv("{bad").kv)).toBeNull();
    expect(
      await readPublicPriceSnapshot(
        fakeKv(() => {
          throw new Error("kv down");
        }).kv,
      ),
    ).toBeNull();
  });
});
