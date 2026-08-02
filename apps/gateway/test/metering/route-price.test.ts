/**
 * `routePriceSettledCostUsd` — the model-registry pricing leg of settlement (#663).
 *
 * The end-to-end proof lives in `./unpriced.test.ts` (real Worker, real D1).
 * This file pins the REFUSALS, which that one cannot see: each of them is a
 * case where returning a number would be a confidently wrong bill, and each
 * would be invisible in an end-to-end test because "no settled cost" and "a
 * settled cost that happens to match" both produce a ledger row.
 */
import { describe, expect, it } from "vitest";

import type { Usage } from "../../src/inference/ports.js";
import { routePriceSettledCostUsd } from "../../src/metering/index.js";

/** A minimal served `Usage`; every test overrides only what it is about. */
function usage(overrides: Partial<Usage> = {}): Usage {
  return {
    requestId: "req_1",
    route: "openai.chat.completions",
    logicalModel: "probe",
    provider: "probe-provider",
    providerModel: "probe-model",
    stream: false,
    status: 200,
    promptTokens: 1_000,
    completionTokens: 500,
    totalTokens: 1_500,
    ...overrides,
  };
}

describe("routePriceSettledCostUsd", () => {
  it("prices both sides at the route's own per-1M rates", () => {
    const cost = routePriceSettledCostUsd(usage({ inputPricePer1m: 3.0, outputPricePer1m: 15.0 }));
    // 1000/1e6 × 3 + 500/1e6 × 15 = 0.003 + 0.0075
    expect(cost).toBeCloseTo(0.0105, 12);
  });

  it("prices a genuinely free route at zero rather than refusing it", () => {
    // `0` and `undefined` are different statements on a `[[models]]` row — the
    // config schema is `nonnegative`, not `positive`, precisely so a free route
    // is expressible — and only the second may fall through to the rate card.
    expect(routePriceSettledCostUsd(usage({ inputPricePer1m: 0, outputPricePer1m: 0 }))).toBe(0);
  });

  it("refuses when the route carries no prices at all", () => {
    expect(routePriceSettledCostUsd(usage())).toBeUndefined();
  });

  it("refuses when a side that produced tokens has no price", () => {
    // Billing only the priced half would be a settled figure that is wrong by
    // the whole of the other half — and `charge()` would take it as
    // authoritative. Deferring to the card is the honest answer.
    expect(routePriceSettledCostUsd(usage({ inputPricePer1m: 3.0 }))).toBeUndefined();
    expect(routePriceSettledCostUsd(usage({ outputPricePer1m: 15.0 }))).toBeUndefined();
  });

  it("settles a one-sided call against the one price it needs", () => {
    // No completion tokens ⇒ the absent output price prices nothing, so it is
    // not a reason to refuse. (An embeddings-shaped call.)
    const cost = routePriceSettledCostUsd(
      usage({
        completionTokens: 0,
        totalTokens: 1_000,
        inputPricePer1m: 3.0,
        outputPricePer1m: undefined,
      }),
    );
    expect(cost).toBeCloseTo(0.003, 12);
  });

  it("refuses when nothing at all was observed", () => {
    // The `gateway_estimate` case — a non-2xx upstream, or a stream cut before
    // any usage frame — and also `/v1/images`, which settles on an image count.
    // A `0` here would be an AUTHORITATIVE $0 and would suppress the rate card
    // for a request the card can price perfectly well.
    expect(
      routePriceSettledCostUsd(
        usage({
          promptTokens: undefined,
          completionTokens: undefined,
          totalTokens: undefined,
          inputPricePer1m: 3.0,
          outputPricePer1m: 15.0,
        }),
      ),
    ).toBeUndefined();
  });

  it("repairs a provider-omitted split before pricing it (#140)", () => {
    // The provider reported only a total. `charge()` reconciles the split
    // before applying the rate card, so a settled cost computed from the RAW
    // counts would sit ~one whole side away from the card's estimate and trip
    // the divergence warning on every such response.
    const cost = routePriceSettledCostUsd(
      usage({
        promptTokens: 1_000,
        completionTokens: 0,
        totalTokens: 1_500,
        inputPricePer1m: 3.0,
        outputPricePer1m: 15.0,
      }),
    );
    // completion is repaired to 1500 − 1000 = 500, i.e. the same $0.0105.
    expect(cost).toBeCloseTo(0.0105, 12);
  });

  it("refuses a non-finite or negative price", () => {
    // Depth, not duplication: the config schema rejects these, and a negative
    // settled cost would be a CREDIT to the customer conjured from a typo.
    expect(
      routePriceSettledCostUsd(usage({ inputPricePer1m: -1, outputPricePer1m: 15.0 })),
    ).toBeUndefined();
    expect(
      routePriceSettledCostUsd(usage({ inputPricePer1m: Number.NaN, outputPricePer1m: 15.0 })),
    ).toBeUndefined();
    expect(
      routePriceSettledCostUsd(
        usage({ inputPricePer1m: Number.POSITIVE_INFINITY, outputPricePer1m: 15.0 }),
      ),
    ).toBeUndefined();
  });
});
