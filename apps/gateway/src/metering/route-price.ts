/**
 * The MODEL-REGISTRY leg of settlement (issue #663) — `MeteringSinkOptions.settledCostUsd`.
 *
 * ## The defect this closes
 *
 * `[[models]]` rows carry `input_price_per_1m` / `output_price_per_1m`
 * (`inference/catalog.ts`), and until this file existed the ONLY consumer of
 * those numbers was cost-based ROUTING (`inference/strategy.ts`). Metering
 * never saw them, so a model priced on its registry row but absent from
 * `PriceBook.withDefaultRateCard()` — an 11-entry hard-coded list with no
 * `("*","*")` wildcard — made `charge()` throw `price_not_found` and the sink
 * fail closed. A live 200 with 377 prompt + 12 completion tokens left
 * `billing_ledger`, `billing_events` and `billing_report_outbox` all at zero.
 *
 * Fail-closed is right when NOTHING knows the price (#129: billing zero for a
 * real call is a free-inference bug). It is wrong when the operator DID state
 * the price and the gateway simply never carried it across.
 *
 * ## Why this is the `settledCostUsd` seam and not a rate-card entry
 *
 * Feeding registry prices into the `PriceBook` would need a per-`env` book
 * rebuilt from the registry, while the sink is module-scoped and the registry
 * is a per-request binding. `settledCostUsd` is the seam that already exists
 * for "the data plane priced this request itself", and `charge()` already
 * treats such a cost as authoritative, breaks it into input/output components,
 * Legacy rate-card mode may compare the result with its card, but production
 * serving-offering mode deliberately has no wildcard reference to consult or
 * compare.
 */
import { inputTokenSplit, outputTokenSplit, reconcileSplit } from "@ferrogate/billing";
import type { Usage } from "../inference/ports.js";

/** USD per token, from a USD-per-1M-tokens rate. */
const PER_1M = 1_000_000;

/**
 * The cost this request's SERVED route prices itself at, or `undefined` when
 * the route states no usable price for the tokens that were actually consumed.
 *
 * Three refusals, each of which would otherwise be a silent under-bill:
 *
 *  1. **No observed tokens at all.** `promptTokens`/`completionTokens`/
 *     `totalTokens` all absent is the `gateway_estimate` case — a non-2xx
 *     upstream, or a stream the client cut before any usage frame — and also
 *     covers `/v1/images`, which settles on an image count and not on tokens.
 *     Returning `0` there would convert "nothing observed" into an authoritative
 *     $0 settlement. Serving-offering mode records this as unpriced.
 *  2. **A side with tokens but no price.** A row that prices only input, on a
 *     response that produced completion tokens, cannot settle the whole call;
 *     billing only the priced half is a wrong number stated with confidence.
 *     Returning `undefined` lets serving-offering mode record the missing price
 *     instead of charging another route's card value.
 *  3. **A non-finite or negative price.** The config schema already rejects
 *     these (`z.number().nonnegative()`), so this is depth rather than
 *     duplication — a negative settled cost would be a CREDIT to the customer
 *     conjured from a config typo, and `charge()`'s `authoritativeCost` would
 *     discard it anyway.
 *
 * The token split is reconciled first, for the same reason `charge()` does it
 * (#140): a provider that reports only `total_tokens` must not have the missing
 * side billed at $0. Doing it here as well is what keeps this settled figure
 * within the divergence tolerance of the rate-card estimate in legacy mode.
 * Serving-offering mode does not consult a card.
 */
export function routePriceSettledCostUsd(usage: Usage): number | undefined {
  // The AUDIO arm (issue #703), checked FIRST and returning outright.
  //
  // It is first because the token arm below opens by refusing a usage row with
  // no observed tokens, and an audio row has none by construction: transcription
  // settles on seconds and speech on characters. Reaching that refusal would
  // send every audio call to a legacy rate card. A live, successful,
  // correctly-priced call would otherwise be refused instead of using the
  // serving route's audio price.
  // That is precisely the #663 defect, and this arm is what stops audio
  // reproducing it.
  //
  // It is not a second accounting shape: the same `Usage` row, the same
  // `settledCostUsd` seam, the same `charge()` treatment of an authoritative
  // cost. Only the multiplicand differs, because the unit does.
  const audio = audioSettledCostUsd(usage);
  if (audio !== undefined) {
    return audio;
  }

  if (
    usage.promptTokens === undefined &&
    usage.completionTokens === undefined &&
    usage.totalTokens === undefined
  ) {
    return undefined; // (1) nothing observed — serving-offering mode records unpriced
  }

  const input = priceOrUndefined(usage.inputPricePer1m);
  const output = priceOrUndefined(usage.outputPricePer1m);
  if (input === undefined && output === undefined) {
    return undefined; // the route states no price at all
  }

  const tokens = reconcileSplit({
    prompt_tokens: usage.promptTokens ?? 0,
    completion_tokens: usage.completionTokens ?? 0,
    total_tokens: usage.totalTokens ?? 0,
    cached_input_tokens: usage.cachedInputTokens ?? 0,
    cache_write_tokens: usage.cacheWriteTokens ?? 0,
    reasoning_tokens: usage.reasoningTokens ?? 0,
  });

  // (2) a billable side the route does not price ⇒ refuse the whole settlement.
  if (tokens.prompt_tokens > 0 && input === undefined) return undefined;
  if (tokens.completion_tokens > 0 && output === undefined) return undefined;

  // #667. The split is taken from `@ferrogate/billing` rather than recomputed,
  // because THIS figure and `charge()`'s rate-card estimate are compared against
  // each other by the divergence check (#152). Two settlement paths that split
  // the same tokens differently would trip that warning on every cached request
  // — a false alarm loud enough to be ignored, which is how a real divergence
  // gets missed.
  //
  // A rate the route does not state falls back to the ordinary input/output
  // rate, matching `estimateCost`'s rule exactly: a `[[models]]` row that names
  // no cached rate has not stated a discount, and inventing one would shrink an
  // invoice by a number no operator chose. The cost is that a cache-heavy call
  // on a row-priced model bills its cache reads at the fresh rate until the
  // operator adds `cached_input_price_per_1m` — conservative, visible, and
  // fixable in config.
  const { cachedRead, cacheWrite, fresh } = inputTokenSplit(tokens);
  const { reasoning, visible } = outputTokenSplit(tokens);
  const cachedRate = priceOrUndefined(usage.cachedInputPricePer1m) ?? input ?? 0;
  const writeRate = priceOrUndefined(usage.cacheWritePricePer1m) ?? input ?? 0;
  const reasoningRate = priceOrUndefined(usage.reasoningPricePer1m) ?? output ?? 0;

  return (
    (fresh * (input ?? 0) +
      cachedRead * cachedRate +
      cacheWrite * writeRate +
      visible * (output ?? 0) +
      reasoning * reasoningRate) /
    PER_1M
  );
}

/**
 * The audio surface's settled cost, or `undefined` when this row is not an
 * audio row (issue #703).
 *
 * The three refusals mirror the token arm's, one unit over:
 *
 *  1. **No observed quantity.** A transcription whose provider reported no
 *     duration has `audioSeconds` ABSENT — not zero — and this returns
 *     `undefined` so serving-offering mode records an unmeasured row. Reading an
 *     absent duration as `0` would settle a real, billable call authoritatively
 *     at $0, which is the free-inference bug #129 named.
 *  2. **A quantity the route does not price.** A row that states no audio rate
 *     cannot settle an audio call; deferring is the honest answer.
 *  3. **A non-finite or negative rate**, via {@link priceOrUndefined} — a
 *     negative settled cost is a credit conjured from a config typo.
 *
 * Both quantities are priced on the INPUT side of the estimate. That is not a
 * convenience: `charge()` splits an authoritative cost into input/output
 * components, and for both audio operations the billable quantity IS the input
 * (the recording that was decoded, the text that was synthesized). Attributing
 * it to output would put the number in the column an operator reads as "what the
 * model produced".
 */
function audioSettledCostUsd(usage: Usage): number | undefined {
  const seconds = usage.audioSeconds;
  if (typeof seconds === "number" && Number.isFinite(seconds) && seconds > 0) {
    const rate = priceOrUndefined(usage.audioSecondPricePer1m);
    return rate === undefined ? undefined : (seconds * rate) / PER_1M;
  }
  const characters = usage.audioCharacters;
  if (typeof characters === "number" && Number.isFinite(characters) && characters > 0) {
    const rate = priceOrUndefined(usage.audioCharacterPricePer1m);
    return rate === undefined ? undefined : (characters * rate) / PER_1M;
  }
  return undefined;
}

/** (3) A price is usable only if it is a finite, non-negative number. */
function priceOrUndefined(price: number | undefined): number | undefined {
  if (price === undefined || !Number.isFinite(price) || price < 0) return undefined;
  return price;
}
