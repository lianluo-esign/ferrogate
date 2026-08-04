# Serving Offering Billing Design (#814)

## Problem

The tenant catalog now carries one price per physical offering, but the
inference metering sink can still fall back to the process-wide
`PriceBook.withDefaultRateCard()` when the serving route does not produce a
settled cost. That makes a wildcard provider card a second source of truth and
can charge a route the operator did not price.

## Decisions

1. The physical route that actually served the request is the only inference
   settlement source. Its prices are already copied onto `Usage` after failover
   and canary selection, so the existing `routePriceSettledCostUsd` function
   remains the price calculation boundary.
2. `MeteringUsageSink` gets an explicit `serving_offering` settlement mode. In
   that mode a missing, non-finite, or incomplete route price is unpriced: the
   sink writes a durable `billing_events` row with no `cost_usd`, emits the
   existing diagnostic, and never calls the rate-card pricing path. A numeric
   zero remains an authoritative free price.
3. `PriceBook.withDefaultRateCard()` is retained as a provisioning seed
   snapshot. `packages/storage` already copies that data into
   `DEFAULT_TENANT_MODEL_CATALOG`; it is not imported as a live billing source.
   The default card remains available to independent platform/asset and legacy
   rate-card consumers, but production inference is wired to
   `serving_offering` and cannot read it for settlement.
4. Divergence comparison is not run in `serving_offering` mode. There is no
   valid wildcard reference to compare against. The billing event and ledger
   continue to carry `provider`, which is the configured channel name, plus
   `provider_model`, so a charge can be attributed to the serving channel.
5. Nullable offering prices remain nullable through the catalog projection and
   metering event. `NULL` means unpriced; numeric `0` means free.

## Verification shape

- Sink tests prove a wildcard card cannot price an unpriced serving offering and
  that a zero offering still settles at zero.
- Gateway tests drive a real fallback response and a canary response through
  dispatch, then assert the ledger provider/channel and settled amount.
- A mutation assertion changes the fallback/canary input price and requires the
  ledger amount to move by the exact delta.
- The durable unpriced path asserts `billing_events.cost_usd` is null and that
  no ledger or outbox charge is created.

