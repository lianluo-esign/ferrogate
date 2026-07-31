/**
 * Shared fixtures for the metering suite.
 *
 * Nothing here stands in for the code under test: the price book is a real
 * `@ferrogate/billing` `PriceBook`, the ledger/outbox/publisher are the shipped
 * in-memory implementations, and the clock is the shipped {@link ManualClock}
 * (the outbox's contract is entirely "due at", so a suite that cannot move time
 * can only reach the happy path).
 */
import { PriceBook, modelPriceUsd, priceEntry } from "@ferrogate/billing";
import type { Usage } from "../../src/inference/ports.js";
import type { MeteredCharge } from "../../src/metering/index.js";

/** The provider/model pair every priced fixture uses. */
export const PRICED_PROVIDER = "openai-main";
export const PRICED_MODEL = "gpt-4o-mini-2024-07-18";

/**
 * A rate card with exactly one exact rule.
 *
 * Deliberately NOT `withDefaultRateCard()`: that card carries a `("*", …)`
 * wildcard family, and a wildcard would make the fail-closed test unreachable
 * for every model whose name happens to match.
 */
export function pricedBook(): PriceBook {
  return PriceBook.new([
    // $0.15 / 1M input, $0.60 / 1M output — the real gpt-4o-mini card.
    priceEntry(PRICED_PROVIDER, PRICED_MODEL, modelPriceUsd(0.15, 0.6)),
  ]);
}

/** A `Usage` as the inference data plane emits it. */
export function usageFixture(overrides: Partial<Usage> = {}): Usage {
  return {
    requestId: "fg-000000000000002a",
    route: "openai.chat.completions",
    logicalModel: "gpt-4o-mini",
    provider: PRICED_PROVIDER,
    providerModel: PRICED_MODEL,
    stream: false,
    status: 200,
    promptTokens: 11,
    completionTokens: 4,
    totalTokens: 15,
    tenantId: "tenant_a",
    projectId: "project_1",
    ...overrides,
  };
}

/**
 * The cost of {@link usageFixture} under {@link pricedBook}:
 * 11 * 0.15/1e6 + 4 * 0.60/1e6 = 1.65e-6 + 2.4e-6 = 4.05e-6 USD ⇒ 4 credits
 * (4.05 credits, rounded half away from zero).
 */
export const FIXTURE_COST_USD = 4.05e-6;
export const FIXTURE_CREDITS = 4n;

/** A hand-built charge, for store/outbox tests that need no pricing. */
export function chargeFixture(
  id: string,
  credits: bigint,
  overrides: Partial<MeteredCharge["entry"]> = {},
): MeteredCharge {
  const entry: MeteredCharge["entry"] = {
    id,
    request_id: id,
    provider_attempt: { provider_attempt_id: id, provider_attempt_index: 0 },
    tenant: { organization_id: "tenant_a", project_id: "project_1" },
    logical_model: "gpt-4o-mini",
    provider: PRICED_PROVIDER,
    provider_model: PRICED_MODEL,
    usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    usage_source: "provider_usage",
    status_code: 200,
    cost: { input_cost: 1.65e-6, output_cost: 2.4e-6, total_cost: 4.05e-6, currency: "USD" },
    credits: 4.05,
    unit_price: modelPriceUsd(0.15, 0.6),
    cost_source: "billing_price_book",
    occurred_at_unix: 1_700_000_000,
    ...overrides,
  };
  return {
    id,
    requestId: entry.request_id,
    entry,
    event: {
      request_id: entry.request_id,
      provider_attempt: entry.provider_attempt,
      tenant: entry.tenant,
      logical_model: entry.logical_model,
      provider: entry.provider,
      provider_model: entry.provider_model,
      usage: entry.usage,
      usage_source: entry.usage_source,
      status_code: entry.status_code,
      occurred_at_unix: entry.occurred_at_unix,
      metadata: {},
    },
    credits,
    occurredAtUnix: 1_700_000_000,
  };
}
