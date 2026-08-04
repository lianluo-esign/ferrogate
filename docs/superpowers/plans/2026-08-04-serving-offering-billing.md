# Serving Offering Billing Implementation Plan

## Goal

Close issue #814 without allowing the inference settlement path to consult the
wildcard provider rate card.

## Tasks

1. Add a red sink test for `serving_offering` mode: an offering with no usable
   route price must persist only an unpriced event, while a numeric zero must
   settle as a zero-cost gateway charge. Commit the failing test first.
2. Implement the sink mode and a shared unpriced-event helper. In serving mode,
   ignore the rate card for inference settlement, suppress card divergence
   checks, and preserve diagnostics and durable NULL-cost recording. Commit the
   minimal implementation.
3. Add a real composed-gateway fallback test. Make the primary return an error,
   serve from a differently priced fallback, assert the provider/channel and
   exact cost, then mutate the fallback input price and assert the expected
   delta. Commit the integration test.
4. Add a canary-served gateway test with a distinct channel price and assert the
   canary channel and amount are used. Update the production composition root to
   opt into `serving_offering` mode and update only tests whose legacy fixtures
   intentionally exercise rate-card settlement. Commit wiring and tests.
5. Review all changed comments and run focused billing/gateway tests, both
   package typechecks, root typecheck, generated-client check, diff check, and
   lint. Record baseline failures separately. Commit only necessary cleanup.

## Verification

```text
bun run --filter '@ferrogate/billing' test
bun run --filter '@ferrogate/billing' typecheck
bun run --filter '@ferrogate/app-gateway' test
bun run --filter '@ferrogate/app-gateway' typecheck
bun run typecheck
bun run generate
git diff --check
bun run lint
```

## Review Gate

Before merge, an independent agent must inspect the final PR head, rerun the
relevant tests, perform the required mutation check, and return `MERGE: YES`.

