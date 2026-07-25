<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, the governed-decision
  conformance corpus (#470): fixture format, the rules that keep it load-bearing,
  and the two runners that consume it.
-->

# Governed-decision conformance corpus (#470)

One corpus, committed at the repository root, read by two hosts, owned by
neither. Specified in
[`docs/cloudflare-data-plane-decision.md`](../../../docs/cloudflare-data-plane-decision.md)
§8.

## Runners

| Runner | Lives in | Drives | Asserts |
|---|---|---|---|
| A -- the authority | `crates/ferrogate-cli/src/gateway/governed_decision_conformance_test.rs` | the real `decide_ai_request` admission seam | canonical JSON is **byte-identical** to `expect` |
| B -- the veto-only shell | `workers/gateway-front/test/` (workerd, via vitest-pool-workers) | the real `gateway-front` Worker over `/__conformance/decide` | the answer matches `worker_shell.expect` **and** is directionally legal against `expect` |

Both run in CI (`.github/workflows/governed-decision-conformance.yml`). Neither
uses Docker, a Cloudflare account or the network.

## Fixture format

```jsonc
{
  "id": "money/wallet-balance-exhausted",
  "schema": 1,                       // must equal GOVERNED_DECISION_SCHEMA
  "description": "…",                // what governed behaviour this pins; >30 chars, asserted
  "world": {
    "config": { /* deserialised straight into the real Config */ },
    "draining": false,               // optional
    "wallets": [ { "tenant_id": "tenant-1", "balance_credits": "0" } ],
    "quota_policies": [ /* StoredQuotaPolicy rows */ ]
  },
  "request": {
    "endpoint": "chat.completions",  // or "responses"
    "headers": { "authorization": "Bearer secret-1" },
    "headers_bytes": { },            // header values that are legal HTTP bytes but not UTF-8
    "body": { /* JSON */ },          // or "body_raw" for a body that is not JSON
    "body_over_limit": false,        // the Session-side read hit the cap, as a fact
    "now_unix": 1784937600
  },
  "expect": {                        // the authority's golden decision
    "schema": 1, "outcome": "deny", "status": 429,
    "code": "wallet_balance_exhausted",
    "durable_writes": ["request_log"], "audit_events": []
  },
  "worker_shell": {
    "deny_list": [],                 // SHA-256 hex of revoked bearer secrets
    "expect": { "schema": 1, "outcome": "defer", "status": 0 }
  }
}
```

## Rules that keep this load-bearing rather than decorative

- **Amounts are decimal strings parsed as integers**, never floats and never
  compared lexically -- the #469 discipline applied to the fixture format itself,
  so the suite cannot re-introduce the bug it exists to prevent.
- **Goldens are generated from the authority but checked in**, so a behaviour
  change shows up as a reviewable diff rather than a silently-updated
  expectation. This is the anti-#383 mechanism: a contract that is invisible at
  the call site becomes visible in a golden file.
- **Coverage gate.** Every entry in `GOVERNED_ERROR_VOCABULARY` marked
  `FixtureCoverage::Required` must appear as some fixture's expected code. A
  reproducible governed outcome with no fixture fails Runner A.
- **The vocabulary is scanned out of the source.** A new governed code in
  `chat.rs` or `auth.rs` with no vocabulary entry fails
  `governed_decision_test.rs`, which forces an explicit stage and coverage
  decision before it can ship.
- **What is not covered is enumerated, not omitted.** Codes that need fault
  injection, seeded run state, or the not-yet-extracted dispatch seam carry a
  written reason, and the size of that set is pinned by a test.

## Scope today

The corpus covers the **admission** half of the governed path (steps 13-32 of
the decision record's §1). The dispatch half (33-52: guardrails, policy engine,
cache, TPM consume, wallet hold, dispatch, billing) is still written straight
into the Pingora `Session` and is therefore not yet a value to compare; its
codes are listed with `FixtureCoverage::PendingDispatchSeam`.
