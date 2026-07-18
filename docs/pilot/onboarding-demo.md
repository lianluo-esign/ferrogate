<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Scripted, reproducible onboarding demo of the Secure Agent Gateway evidence chain.
-->

---
title: Pilot Onboarding Demo
description: A scripted demo a solutions engineer can run from the repo, with no partner infrastructure.
permalink: /pilot/onboarding-demo/
---

# Onboarding demo — the evidence chain, live

A scripted walkthrough a solutions engineer runs at pilot kickoff (or in a
pre-sales call). Every act is driven by the repo's own test harnesses, so
the demo is **reproducible without a partner environment** and every
behavior shown is the same code path the pilot will run — not slideware.

Timing: ~30 minutes of demo over ~10 minutes of command runtime.

## Setup

```bash
# Pinned toolchain (repo standard)
rustup toolchain install 1.88.0

# Build the gateway + auth binaries once, up front. The ferrogate-test
# harness looks for target/debug/ferrogate{,-auth} by default
# (override with FERROGATE_TEST_FERROGATE_BIN / _AUTH_BIN).
cargo +1.88.0 build --bin ferrogate --bin ferrogate-auth
```

Two tiers of demo, depending on what's available:

- **Tier 1 (always works, zero external services):** local-process E2E
  tests and the `ferrogate-test` local API harness. Acts 1–4.
- **Tier 2 (full evidence chain, needs a Postgres/Supabase DSN):** the
  live `guardrail-supabase` scenario — block/redact/shadow evidence joins,
  restart durability, RBAC. Act 5. Export `FERROGATE_SUPABASE_DSN` first;
  the scenario creates and drops its own unique schema, so any dev
  database works.

Note for constrained machines: run the scoped commands below as written —
they build only what each act needs.

## Act 1 — the gateway is a real, contract-tested API surface (2 min)

```bash
cargo +1.88.0 run -p ferrogate-test -- list
cargo +1.88.0 run -p ferrogate-test -- run-all
```

`run-all` boots real `ferrogate` processes and drives the Admin, auth, and
gateway APIs end to end — identity, API-key scoping, routing, billing
records. Talking point: the OpenAPI contract cannot drift from the runtime
(CI fails on route drift, #203), so what the partner scripts against is
what actually runs.

## Act 2 — a request trips a guardrail; a blocked action has no side effect (5 min)

```bash
cargo +1.88.0 test -p ferrogate-cli --test guardrail_managed_action_e2e
```

What the audience sees (the test output narrates it): a real gateway and
managed worker are started; an agent's **capability-allowed** MCP tool call
and a CLI action are each blocked by a class-scoped guardrail policy
provisioned through the Admin API; a clean action on an unrelated tool
passes untouched.

Talking points, each one asserted by the test (#200):

- The guardrail runs **after** capability policy and **before** execution:
  a blocked input produces **no MCP/tool side effect and no usage charge**.
- The block lands in the agent-run timeline as a `guardrail.blocked`
  event, retrieved through the Admin API — this is the evidence the
  investigation view joins later.
- Scoping is per canonical target (`mcp:server:tool`): the MCP policy never
  fires on the CLI action and vice versa.

Related deeper cut, if the audience is technical:
`cargo +1.88.0 test -p ferrogate-cli --test guardrail_tool_governance_e2e`
(the in-process tool-governance chokepoint, covering MCP + HTTP backends).

## Act 3 — a redaction, and measured (not asserted) detector accuracy (5 min)

```bash
cargo +1.88.0 test -p ferrogate-guardrails --features conformance
```

This runs the adapter conformance suite and the evaluation runner over the
shipped detectors, including the two self-hostable semantic adapters
driven by **recorded fixtures — zero network**:

- **Presidio (DLP/PII):** returns entity spans; the adapter converts them
  to surgical `[REDACTED]` patches on the exact matched bytes — this is
  the redaction path the pilot uses (`adapters/presidio.rs`).
- **LLM-Guard (prompt injection):** detect-only by design; the demo shows
  a prompt-injection sample scored and failed.
- **Sanitization, test-enforced:** the raw matched value never appears in
  serialized evidence — findings carry category, span, score, and an HMAC
  fingerprint only.
- **The evaluation runner computes precision/recall/F1, FP/FN case ids,
  and latency percentiles** against the labeled reference corpus; the
  resulting numbers are test-asserted and quoted in
  `docs/guardrails/adapters/*.md`.

Talking point (honesty is the feature): the printed numbers include real
misses — e.g. Presidio recalls 0.25 on the *injection* cases because it is
the PII path, and LLM-Guard has a recorded false positive on an
instruction-shaped benign prompt (`docs/guardrails/adapters/*.md` publish
these as known limitations). In the pilot, the same runner scores the
partner's own labeled shadow traffic — promotion to enforce is gated on
those measured numbers (`success-criteria.md`), not on vendor claims.

## Act 4 — a capability denial: least privilege at the target level (5 min)

```bash
cargo +1.88.0 test -p ferrogate-cli --test target_capability_e2e
```

A real gateway + managed-worker authorizer over a Unix socket, driving
allow-vs-sibling-deny decisions for all five managed-action families: MCP
server/tool, filesystem path+operation, network host/port/method, secret
destination, and CLI argv (#204).

Talking points:

- The grant allows one concrete target and denies its sibling **in the
  same capability class** — class-level "Filesystem allowed" is not a
  least-privilege claim; this is.
- Decisions are made on canonical normalized targets with adversarial
  coverage: path traversal, symlink and **hardlink** escapes,
  percent-encoded traversal, alternate host notations, DNS rebinding, IDN
  homoglyphs. Worth saying out loud: this suite found a genuine hardlink
  workspace-escape during development and it was fixed fail-closed — the
  partner benefits from tests that actually bite.
- Every decision emits evidence (subject, selector, canonical target,
  policy revision, outcome, request/trace/run ids), and approval +
  execution compare the **same canonical action fingerprint**, so
  "approve A, execute B" fails closed.

## Act 5 (Tier 2) — the investigation timeline over durable evidence (10 min)

```bash
export FERROGATE_SUPABASE_DSN='postgres://...'   # any dev Supabase/Postgres
cargo +1.88.0 run -p ferrogate-test -- guardrail-supabase --tls-mode require
```

This is the full #199 evidence chain against a live database, and the
closest local reproduction of the pilot's steady state. The scenario
(readable script: `tools/ferrogate-test/src/guardrails.rs`) drives distinct
clients through **block, redact, shadow, streaming, buffered, and
unguarded** guardrail paths, then proves the evidence story:

- A guardrail **block** and a guardrail-**redacted successful** request are
  each joined to their audit and billing evidence.
- **Shadow vs enforced** and **fail vs detector-error** are distinct,
  queryable fields on per-check records; streaming paths persist explicit
  per-check semantics.
- Evidence access is RBAC-governed (`guardrails.evidence.read` via dynamic
  role grants); unauthorized and **cross-tenant access is denied**; rows
  are RLS-protected; inputs are stored as HMAC fingerprints only.
- The gateway is restarted mid-scenario and the evidence **survives**.
- Policy **rollback/unbind** is exercised, and the scenario cleans up its
  schema completely.

Close the act in the Admin console: start from the request id of the
blocked request and walk the unified investigation view
(`/admin/v1/investigations`) — Identity, Route, Policy revision, per-check
guardrail verdicts, Approval, Provider/Tool execution, Usage/Cost, outcome
in one timeline. Then hand the partner's security engineer a request id
and a stopwatch: the pilot's target is who/why/target/action/cost in
**under 10 minutes** (`success-criteria.md`, #199).

## Wrap-up script (1 min)

"Everything you just saw is the shipped product exercised by its own test
suite — the same binaries, policies, and evidence tables the pilot deploys
in your VPC. Nothing left this machine. The pilot adds exactly two things:
your real workload, and your labels on your shadow traffic. The runbook
takes it from here."

Then hand over `vpc-pilot-runbook.md` and agree on the numbers in
`success-criteria.md`.
