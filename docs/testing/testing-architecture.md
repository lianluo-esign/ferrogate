# Testing Architecture

Companion reference for the binding **Testing Architecture** taxonomy in
`AGENTS.md`. That table is the constraint; this document is the manual — file
locations, when each layer is required, how to run it, and the open design work.

The organizing rule: FerroGate's tests are a *layered system*. Each layer
answers one question. A green layer never stands in for the layer above it. The
failure mode we are explicitly defending against is "the endpoint returns 200
and the tests are green, but the runtime does not behave as claimed" — the
`#188` asset-quota-scope bug, where quota overrides were writable and readable
through the admin API but the runtime only ever read the tenant scope.

---

## The layers

### 1. Static gate

- **Mechanism:** `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo metadata --locked
  --format-version=1`, `python3 scripts/check-openapi.py`, `git diff --check`.
- **Answers:** does it build clean and match the declared API/schema contract?
- **Required for:** every change. Cheapest proof; run first.
- **CI owner:** `.github/workflows/rust-quality.yml`.

### 2. Unit

- **Mechanism:** dedicated sibling `*_test.rs` modules, or public-boundary
  integration tests under `crates/*/tests/*.rs`; `cargo +1.88.0 test
  --workspace --all-features`, or narrow with
  `cargo test -p <crate> <module::path>`.
- **File layout:** business-logic files contain no test bodies, fixtures,
  assertions, or test-only helpers. They may contain only a minimal
  `#[cfg(test)] #[path = "..."] mod ...;` declaration when the sibling test
  module needs private-item access. New inline `mod tests { ... }` blocks are
  forbidden. If a feature change adds or substantively changes test logic in a
  legacy inline block, move the whole block to a dedicated file instead of
  extending it in place. Mechanical fixture-field alignment alone does not
  require an unrelated whole-module move.
- **Answers:** is the isolated logic correct?
- **Scale today:** ~1,130 `#[test]` and ~22 `#[tokio::test]`. The async unit
  layer is deliberately noted as *thin*: most concurrency/streaming correctness
  currently rides on the E2E harness. When you touch a concurrency or streaming
  path, push a reproducing test **down** to the lowest layer that can express
  it rather than leaving it to a slow E2E run.
- **Required for:** any pure-logic change (config parsing, policy evaluation,
  cost math, encoders).

### 3. Property

- **Mechanism:** `proptest`. In use in `crates/ferrogate-billing/tests/
  billing_scenarios.rs` and `crates/ferrogate-policy/tests/policy_scenarios.rs`.
- **Answers:** do invariants hold across generated inputs, not just the cases a
  human picked?
- **Where it belongs:** state machines and invariants — routing fallback order,
  quota reserve/settle/rollback, streaming stage transitions, ack/settlement
  ordering. Do **not** sprinkle it over ordinary branch logic; a table-driven
  unit test is clearer there.
- **Under-used today.** Two crates use it. The routing and quota state machines
  are the next highest-value targets.

### 4. Crate integration

- **Mechanism:** `crates/*/tests/*.rs` compiled as separate integration
  binaries. Examples: `ferrogate-cli/tests/quota_policies_e2e.rs`,
  `rbac_enforcement_gates.rs`, `assets_quota_e2e.rs`, `bedrock_provider_e2e.rs`,
  `vertex_provider_e2e.rs`, `wallet_e2e.rs`. Shared helpers in
  `crates/ferrogate-cli/tests/support/mod.rs`.
- **Answers:** do wired-together modules behave correctly at a real in-process
  boundary (real config load, real repository trait, real dispatch)?
- **Required for:** changes that span more than one module inside a crate.

### 5. Contract / compliance

- **Mechanism today:** `ferrogate-test api-contract` proves the runtime's fixed
  routes and methods are the ones the OpenAPI contract declares.
  `ferrogate-test component-compliance` provides the reusable component
  lifecycle and currently applies it to quota scopes; the live-Supabase variant
  proves the same path through durable storage.
- **Answers:** does the runtime actually obey the cross-cutting contract it
  claims — routes, telemetry, audit evidence, and **scope**?
- **This is the layer that catches `#188`.** A quota/scope/telemetry claim is
  only proven here when the test asserts that *what a component writes is what
  the runtime reads*, and that the component emits the audit/telemetry evidence
  it advertises. See "Open work" below for the component classes not yet wired
  to the reusable runner.

### 6. Cross-component chain

- **Mechanism:** `ferrogate-test gateway-billing-chain` (a real gateway request
  settles into the billing ledger), `ferrogate-test guardrail-supabase` (a
  guardrail block produces durable, queryable evidence in Supabase).
- **Answers:** does a full request produce the correct *downstream* effect, not
  just a correct response body?
- **Required for:** any change to usage→ledger settlement, guardrail evidence,
  or another producer→consumer handoff across service boundaries.

### 7. Durability

- **Mechanism:** `ferrogate-test postgres-restart`, `postgres-tls-restart`,
  `supabase-restart` (Docker-backed).
- **Answers:** does persisted state survive restart/crash?
- **Required for:** storage/migration/schema changes and anything that claims
  durability.

### 8. E2E harness

- **Mechanism:** `ferrogate-test ci` and `ferrogate-test run-all` against a
  freshly built local FerroGate image/container. `ci` is the deterministic
  aggregate entrypoint (Admin API + auth API + gateway API coverage).
- **Answers:** does the operator-visible behavior close end-to-end?
- **Required for:** every feature — per `AGENTS.md`, a feature is not done until
  operator input, gateway execution, failure behavior, observable evidence, and
  regression coverage are connected, not verified as fragments.
- **CI owner:** `.github/workflows/rust-e2e-harness.yml`.

### 9. Live (opt-in)

- **Mechanism:** `ferrogate-test supabase-live-smoke`, `supabase-live-restart`,
  `supabase-live-token4ai-provider`, `guardrail-supabase`,
  `component-compliance-supabase`. Gated behind explicit DSN/credential env
  vars; never part of the default gate.
- **Answers:** does it work against real external services, not local doubles?
- **Required for:** changes to the live Supabase/provider integration surface,
  run before release rather than on every PR.

### 10. Performance

- **Mechanism:** `cargo test -p ferrogate-cli --test runtime_perf --test
  ai_proxy_perf -- --nocapture`, `--test parser_perf`;
  `docs/performance-testing.md`; reports in `docs/performance-reports/`.
- **Answers:** did latency/throughput regress?
- **Rule:** performance is a *separate* line from correctness. It must never
  become a silent PR gate — a perf number moving is a signal to investigate, not
  an automatic red X on an unrelated change.

### 11. Coverage

- **Mechanism:** `cargo llvm-cov`; baseline snapshots in
  `docs/testing/coverage-baseline-*.md` (epic `#112`).
- **Answers:** which code paths are unexercised?
- **Rule:** coverage is a *diagnostic to find missing tests*, not a target to
  farm. A high number with no compliance-layer proof still hides `#188`-class
  bugs. Note the documented instrumented-run flake: run `llvm-cov` per-crate or
  serialized to avoid the `ai_proxy_runtime` port-contention flake.

---

## How the layers map to CI

CI stays split by business/runtime boundary (see `AGENTS.md` → CI Workflow
Structure). `.github/workflows/ci.yml` is the thin orchestrator; `rust-ci` is
the aggregate branch-protection gate. Reusable modules:

| Workflow | Layers it owns |
|---|---|
| `rust-quality.yml` | Static gate |
| `rust-core-policy-tests.yml` | Unit + Property + Crate integration (core/config/policy/routing) |
| `rust-control-plane-tests.yml` | control plane/auth/storage/billing/observability |
| `rust-agentic-gateway-tests.yml` | agentic gateway/MCP/provider runtime |
| `rust-ai-proxy-tests.yml` | AI proxy/upstream proxy |
| `rust-cli-tooling-tests.yml` | CLI/tooling/test-harness |
| `rust-gateway-runtime.yml` | gateway runtime + performance smoke |
| `rust-e2e-harness.yml` | E2E harness (Contract, Cross-component chain, Durability, E2E) |
| `rust-supabase-storage-tests.yml` | Supabase/Postgres storage + durability |

These workflows are release gates: the top-level orchestrators trigger only on
`release: published`, and reusable modules are `workflow_call`-only. They do not
replace local proof for commits between releases. Locally,
`scripts/local-test-modules.sh <module>` mirrors these gates
(`quality`, `core-policy`, `control-plane`, `agentic-gateway`, `ai-proxy`,
`cli-tooling`, `gateway-runtime`, `e2e-harness`, `supabase-storage`). Run the
narrowest module that covers your change before pushing.

---

## Choosing layers for a change (decision shortcut)

1. Did you change **only pure logic**? Static + Unit (+ Property if it is a
   state machine/invariant).
2. Did you change **wiring inside a crate**? Add Crate integration.
3. Did you change a **provider/guardrail/policy/quota surface**? Add
   Contract/compliance — prove write-path == read-path and evidence emission.
4. Did you change a **producer→consumer handoff** (billing, evidence, exports)?
   Add Cross-component chain.
5. Did you change **persistence/schema/migration**? Add Durability.
6. Is it a **feature**? The E2E harness must close the loop regardless.
7. Touching **hot-path performance**? Run the Performance layer and record the
   number; do not gate the PR on it silently.

"Unit tests pass" is never sufficient for rows 3–6.

---

## The issue loop: tests feed continuous iteration

The test system is wired to the GitHub issue queue on purpose. A test run is not
only a pass/fail gate — it is a source of the next iteration's work. Anything a
test layer surfaces that is not fixed inside the same change must become a
trackable issue, so it is developed and iterated instead of decaying into a
skipped test or a stale TODO. This is the same closed loop as `AGENTS.md` →
Dynamic Workflow (work is pulled from the issue queue) and Commit Requirements
(every commit references its issue).

### When a test run produces an issue

| Trigger | Action |
|---|---|
| A real bug found, not fixed in this change | File a bug issue; add a failing regression test at the lowest layer that reproduces it; the fix makes it pass. Do not `#[ignore]` it away. |
| A flaky test (fails unrelated to the change) | Confirm against `main`, open or link a tracking issue, record it in the affected suite. No blind retries. |
| A missing capability / new feature idea surfaced mid-test | File a feature issue against its owning surface and prioritize it in the queue — do not scope-creep it into the current change. |
| A compliance/contract gap (a component passes its own suite but violates a cross-cutting contract) | File it as a compliance issue and, if reusable, fold it into the Contract/compliance layer. Example already filed: #210. |

### House style for the issue (match the existing queue)

- Title: `[area][priority]` — e.g. `[testing][P1]`, `[guardrails][P0]`,
  `[billing][P2]`. Area = the owning product/runtime surface; priority = `P0`
  (incident/blocker), `P1` (proven-bug guard / near-term), `P2` (iteration).
- Body: `Problem` → `Scope` → `Acceptance` (checkboxes) → `Non-goals`. Link the
  parent epic and any related issue at the top.
- Labels: reuse existing ones (`enhancement`, `test`, `security`,
  `closed-loop`, `priority:pN`, and the surface label). Do not invent labels.
- Link both ways: reference the issue number from the failing suite (a comment
  in the test file or scenario) and from the commit that acts on it.

### Do not

- Do not silence a finding with `#[ignore]`, a skipped `ferrogate-test`
  scenario, or an inline TODO instead of an issue.
- Do not batch unrelated findings into one issue — one defect or capability per
  issue keeps the queue prioritizable.
- Do not mark a test-surfaced issue done from a green unit run alone when it
  touches a cross-cutting or runtime-wiring surface (same rule as the layers).

## Open work: the reusable component-compliance layer

Tracked in **#210**.

**Current status:** `tools/ferrogate-test` now has a reusable
`ComponentContract` runner. It owns the lifecycle instead of trusting a
component to call arbitrary assertions: write -> read -> runtime exercise ->
verify -> cleanup. `component-compliance` forces all four generic quota scopes
through it locally, and `component-compliance-supabase` runs the same contract
against a unique live schema. Tenant asset quota is asserted at runtime;
project/workspace/key asset quota writes are rejected because stored assets and
their usage are tenant-owned. This closes the concrete #188-style write-only
scope gap without inventing fake narrower-scope usage semantics.

**Remaining gap:** provider telemetry/billing and Guardrail allow/block evidence
remain point scenarios (`gateway-billing-chain`, `guardrail-supabase`). They are
not yet implementations of the shared contract, so #210 remains open and the
full compliance layer must not be presented as complete.

**Next component contracts:**

- **Provider adapter:** emits usage/cost telemetry with the required attributes;
  the cost that reaches billing equals the cost the adapter reported; fallback
  and error paths still settle usage.
- **Guardrail:** both the block path and the allow path emit auditable evidence;
  blocked content produces durable, queryable evidence.
- **Policy scope / quota override:** implemented for generic quota scope
  enforcement and tenant asset quota; unsupported narrower asset scopes fail at
  the write boundary instead of returning a value the runtime ignores.

Sequence from here: (1) adapt the provider billing chain to the shared runner;
(2) adapt Guardrail allow/block evidence; (3) force every concrete adapter
through its class contract. The local quota contract is part of the `ci`
aggregate; the durable form is part of the live Supabase release slice.
