<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, the gateway-front Worker
  (#470): the veto-only shell in front of the container-hosted Pingora data
  plane, and Runner B of the governed-decision conformance suite.
-->

# gateway-front (#470)

The Worker in front of the container-hosted Pingora data plane, implementing the
shell contract frozen in
[`docs/cloudflare-data-plane-decision.md`](../../docs/cloudflare-data-plane-decision.md)
§6.

## What it may do

Terminate TLS, own the custom domain, route to the container, pre-warm an
instance, serve `/healthz`, and **veto** on facts it can compute at the edge with
no control-plane read:

| Fact | Code | Why it is host-independent |
|---|---|---|
| No bearer credential | `missing_api_key` | The origin has no key to find either. |
| Body over the configured cap | `payload_too_large` | The cap is a deployment constant, not a policy. |
| Body is not JSON at all | `invalid_json` | Parsing JSON needs no tenant state. |
| Presented secret is on the operator deny list | `invalid_api_key` | Matched by SHA-256 of the secret, so the shell never resolves a token to a key id. |

Everything else -- scopes, quota, wallets, guardrails, models, routing, caching,
metering -- returns `defer`: *"I made no governed call; ask the authority."*

Note what is deliberately **absent**: no typed request validation. A typed
verdict is not host-independent, so an edge `invalid_request` would need the
origin's schema to agree with it, and a disagreement would produce false
rejections. A directional contract permits that; users would not forgive it.

## What it must not do

Decide `allow`. Author, adjust or consume any metered amount. Evaluate a
guardrail policy for effect. Serve from cache without the origin having seen the
request. `src/shell.ts` is the whole of the shell's governed surface, on purpose:
anything the conformance runner cannot see is something nobody is checking.

`forwardToOrigin` is a **stub** in this slice and returns 501. #470 froze the
decision and this contract; binding the container origin
(`getContainer`/`containerFetch`) is #472. A shell that cannot reach the
authority must not invent one, so failing closed is the correct placeholder.

## Runner B of the conformance suite

`POST /__conformance/decide` (404 unless `CONFORMANCE=1`, never set in
production) takes a fixture from `tests/fixtures/governed-decisions/` verbatim
and returns the canonical `GovernedDecisionRecord` the shell produces. It calls
the same `decideShell` the request path calls -- a conformance route exercising
a copy of the shell would prove nothing about the shell.

```
npm ci
npm run typecheck
npm test          # boots the real Worker in workerd via vitest-pool-workers
```

`npm test` runs the whole committed corpus through the Worker and asserts, per
fixture, that the answer matches the corpus's declared shell expectation byte for
byte **and** is directionally legal against the authority's decision (§8d). No
Docker, no Cloudflare account, no network.

Runner A -- the authority -- lives in
`crates/ferrogate-cli/src/gateway/governed_decision_conformance_test.rs` and
drives the same corpus through the real `decide_ai_request` seam. CI runs both
(`.github/workflows/governed-decision-conformance.yml`).
