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
- **Making a storage read FAIL (#543):** a tenant-scope decision that reads the
  control plane has a failure branch, and that branch is a security decision:
  `rbac_catalog_scope` must propagate (the four RBAC catalog GETs answer
  `503 storage_unavailable`) and must never degrade to an empty or — far worse
  — unfiltered scope. No storage double in the tree could produce that input: a
  real `AppState` runs on `RuntimeStorageRepositories`, whose in-memory backend
  swallows even a poisoned lock into `unwrap_or_default()`, so every read it
  serves succeeds. `crates/ferrogate-gateway/src/tenant_scope_reads.rs` is the
  seam that fixes this — the resolvers take `&impl TenantScopeReads` instead of
  `&AppState`, and its `#[cfg(test)]` `fault::FaultyTenantScopeReads` answers
  from canned rows, records the reads attempted, and returns `Err` for any read
  armed with `.failing(..)`. **A new scope resolver that reads storage adds its
  read to that trait rather than building a second harness**: one method, one
  `TenantScopeRead` variant, and its failure branch becomes testable. Used by
  `server/rbac_test.rs` and the `#543` block of `auth_test.rs`.

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
  lifecycle and applies it to quota scopes plus every canonical provider
  adapter family's settlement. `guardrail-supabase` runs Guardrail policy
  write/read plus allow/block evidence through the same lifecycle. The
  live-Supabase paths prove quota and Guardrail behavior through durable storage.
- **Answers:** does the runtime actually obey the cross-cutting contract it
  claims — routes, telemetry, audit evidence, and **scope**?
- **This is the layer that catches `#188`.** A quota/scope/telemetry claim is
  only proven here when the test asserts that *what a component writes is what
  the runtime reads*, and that the component emits the audit/telemetry evidence
  it advertises. The provider adapter registry and compliance matrix are checked
  for exact set equality before runtime E2E starts.

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
  `mcp-identity-supabase`, `target-capability-supabase`,
  `component-compliance-supabase`. Gated behind
  explicit DSN/credential env vars; never part of the default gate.
- **Isolation contract:** every live scenario creates a unique per-run schema,
  reuses that exact schema across its internal restarts, then drops it and
  verifies its exact `pg_namespace` row is absent. Early returns use the same
  RAII cleanup. `--keep-supabase-schema` is the only opt-in retention path.
  Cleanup never wildcard-drops a shared prefix because live scenarios may run
  concurrently.
- **Answers:** does it work against real external services, not local doubles?
- **Required for:** changes to the live Supabase/provider integration surface,
  run before release rather than on every PR.
- **Load boundary:** keep every live scenario bounded and low-volume. Live
  Supabase is not a performance target; do not run load, stress, throughput, or
  high-concurrency benchmarks through these commands.
- **MCP candidate opponent path:** `ferrogate-test gateway-api` owns the local
  deterministic client-wire contract. The external Tier-1 target tracked by
  #570 is `ferrogate-test mcp-candidate-client-official`. It installs
  `@modelcontextprotocol/client@2.0.0` from a committed npm lockfile, verifies
  npm integrity plus SDK commit `cc4b41617ce3601b1290d67216ea0b194a3cd9ac`
  and candidate spec commit
  `71e306956a4959c9655e5036be215d41986596e6`, then drives two real local
  FerroGate instances in official SDK `auto` mode and one of them in `legacy`
  mode. Modern discover/list/call requests alternate between instances. Rust
  independently checks that instance sequence, the observed headers and
  request metadata, absence of modern session state, 2025-11-25 legacy
  initialize, private cache metadata on `tools/list`, discovered tool, and
  completed tool result. The command is opt-in
  and is not part of `ci` because
  a clean run installs an external npm artifact; merely compiling or listing
  the command is not conformance evidence.

### 10. Performance

- **Mechanism:** `cargo test -p ferrogate-cli --test runtime_perf --test
  ai_proxy_perf -- --nocapture`, `--test parser_perf`;
  `docs/performance-testing.md`; reports in `docs/performance-reports/`.
- **Answers:** did latency/throughput regress?
- **Rule:** performance is a *separate* line from correctness. It must never
  become a silent PR gate — a perf number moving is a signal to investigate, not
  an automatic red X on an unrelated change.
- **Storage boundary:** use in-memory storage or a dedicated local Postgres
  instance. Never point the Performance layer at Supabase or another shared
  managed database.

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
| `governed-decision-conformance.yml` | Governed-decision conformance (#470): Runner A, the Rust authority; Runner B, the Worker shell |
| `rust-cli-tooling-tests.yml` | CLI/tooling/test-harness |
| `rust-platform-crate-tests.yml` | gateway trunk, agent worker, secrets/payments/cloudflare/sync-bridge (#561) |
| `rust-gateway-runtime.yml` | gateway runtime + performance smoke |
| `rust-e2e-harness.yml` | E2E harness (Contract, Cross-component chain, Durability, E2E) |
| `rust-supabase-storage-tests.yml` | Supabase/Postgres storage + durability |

These workflows are release gates: the top-level orchestrators trigger only on
`release: published`, and reusable modules are `workflow_call`-only. They do not
replace local proof for commits between releases. Locally,
`scripts/local-test-modules.sh <module>` mirrors these gates
(`quality`, `core-policy`, `control-plane`, `agentic-gateway`,
`governed-decisions`, `ai-proxy`, `cli-tooling`, `platform-crates`,
`gateway-runtime`, `e2e-harness`, `supabase-storage`). Run the narrowest module
that covers your change before pushing.

That list and that table are both checked, not maintained by hand:
`scripts/check-ci-crate-coverage.py` fails when a workspace member is selected
by no workflow reachable from `ci.yml` or by no module in that script, and when
a `cargo test` name filter on either surface selects no test. The list here had
already drifted — `governed-decisions` and `platform-crates` are #470's and
#561's and neither appeared above — which is the documented-surface half of
exactly the drift that gate exists to catch, one layer out from where it can
see.

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

## Assertions must be able to fail

Picking the right layer is not enough. The layer can be right, the
implementation correct, the suite fully green — and the load-bearing line still
uncovered. In one session six items in a row failed this way (`#500`): break the
logic on purpose and every suite stayed green. 14 surviving mutations on `#460`
alone, 7 of 7 on `#471`'s Worker half.

**The rule:** if you can break the thing a test names and the test stays green,
the test does not cover it.

### The one-minute review check

Applied by hand, on a diff, without building anything:

1. Name the one line the change exists for — the filter, the constant, the flag,
   the seed value.
2. Name a one-token edit to it: `false` → `true`, `1` → `0`, `&[…]` → `&[]`,
   `Some` → `None`, delete the row, delete the call, swap the connection target.
3. Find the assertion that goes red, and **read it**. Do not infer it from the
   test's name or its comments.

If step 3 takes longer than a minute, that is the finding — say so and move on.
"There are 85 tests" is not an answer to step 3; on `#489`, all 85 stayed green
while the defect the issue was filed to fix was restored.

### Named anti-patterns

Each of these reads as thorough. Each stayed green under the mutation named
beside it — except the last, which reds, but on a different assertion from the
one the test is named for. Both are the same failure: the named claim is
unproven either way.

| Anti-pattern | Seen in | Assert instead |
|---|---|---|
| **Text, not behaviour.** The SQL string is pinned as a substring while a mocked transport replays canned rows regardless of what was sent, so `enabled = 1`, `IS NOT NULL` and `<=` are never *filters*. | `#460` due scan; every boundary — exactly-due, disabled, null-next-fire, not-yet-due — was unpinned | The rows that come back across the boundary, one case per boundary. |
| **Sending side, never applying side.** The client proves it *asked* for the sealed container; nothing proves the peer was ever told. | `#471` (the `#188`/`#397` write-succeeds/runtime-ignores shape, one layer up) | The request the dependency actually receives, or the state it actually reaches. |
| **A conclusion pinned on an unguarded premise.** `!sql.contains("CAST")` is justified by "the columns are already INTEGER" — and nothing pins the columns as INTEGER. | `#460`; the portability test compares column *names* only, so flipping them to TEXT stays green | The premise, at the layer that owns it. |
| **A comment carrying the invariant.** The comment says "VALUES seeds `request_count` literal 1"; the assertion covers `params`, and the literal is inline SQL. The mirror case: a substring match over the whole method window, which a comment inside that window satisfies. | `#460`; `#480` `search_path` | The value at the point it takes effect. A comment is not an assertion, and an assertion a comment can satisfy is not one either. |
| **A vacuous fixture.** A re-sort asserted over rows that were already sorted; a truncate asserted over 2 rows with `limit = 10`. | `#460` fire-list | Input that is wrong in the direction the transform fixes. |
| **A guard coarser than the rule it enforces.** One audit walked a single directory by filename prefix while its convention spanned three crates; another signed off on `(file, fn)`, so a *new* capture inside an already-blessed function was pre-approved. | `#495`; `#526`, fixed by keying on `(file, fn, idiom, exact count)` | Key the guard on the exact thing that must not change, and prove its reach covers the whole class it claims. |
| **A count asserted as fact with no mechanism.** "236 transactions across 41 files", in a comment. It was 42 by the next slice. | `#480` | Compute it in the test, or assert a floor and label the bare number as a dated measurement — `async_postgres_test.rs:66-71` took the second option deliberately, because a count that had to be edited on every new query gets edited without thought. What fails is a number no assertion reads. |
| **Red for an unrelated reason.** The schedule-count test does fail on the broken implementation — on `status === 200`, because the route 400s with `no such table`. `count` is never reached, so the assertion the test is named for is still unproven, and the entry that used to sit here predicted the opposite outcome from the same reasoning. | `#482`, corrected once the suite could actually run (`#559`) | The named observable on a path the earlier post-conditions cannot short-circuit — here, list the schedules from a *rebuilt* instance, so `count` is reached whether or not the object was evicted. Failing that, order the assertions so the named one reds first, and say in the title which line actually reds (`destroy-alarm.test.ts` took the second option). A test that fails for the wrong reason passes for the wrong reason too. |

### Where mutation reasoning is not enough

Two failures in the same session were invisible to "would a mutation red this?",
because they are properties of the *unmutated* run:

- **A test that reds on correct code.** `#471`'s `container-egress.test.ts:625`
  asserted `allowedHosts == [GOVERNED_HOST]` after a failed reset; the SDK
  assigns the field *before* the call that throws, so it is `[]`. Nobody
  noticed, because nothing ran it. Only reading the dependency's source finds
  this. An un-run test is an unverified claim — write it, then say so. A whole
  suite can be in that state: `ferrogate-gateway` compiled its tests in every CI
  run and executed none of them until `#561`, which is why
  `scripts/check-ci-crate-coverage.py` now fails when a workspace member is
  selected by no `cargo test` that CI reaches.
- **A cross-check that shares the blind spot.** `#511`'s second reader was
  line-oriented, so it agreed with the const parser's inability to see a
  multi-row `VALUES`. Two readers only cross-check if they fail differently.

### Who owns which half

Under speed mode the author writes tests they do not run, so "mutate it and
watch it go red" is not currently an authoring proof step. It splits:

- **Author (design obligation):** write the assertion so that mutating the line
  *would* red it, and say in the commit which mutation it is aimed at. Claim
  nothing about having observed it.
- **Review and gate (proof obligation):** run the check above; the gate performs
  the mutation and confirms the red. A surviving mutation on a load-bearing
  surface — wallet/settlement, egress enforcement, the due-scan filter, any
  deny/allow decision — is a bug, not a metric.

### Precedent and tooling status

`scripts/test_openapi_contract.py:413,462` already hand-rolls this technique:
`test_real_spec_mutations_reject_…` mutates the real spec and asserts the
validator rejects it. That shape generalises to any in-tree checker.

`cargo-mutants` is **not adopted yet** and is not installed on the dev boxes.
The intended first targets are the crates carrying money, security and
scheduling logic — `crates/ferrogate-storage`, `crates/ferrogate-runtime`,
`crates/ferrogate-cloudflare`, `crates/agent-worker` — one crate at a time,
report-only, no score committed and no blocking gate until a baseline exists:

```bash
cargo mutants -p ferrogate-storage --list      # what would be mutated
cargo mutants -p ferrogate-storage             # long; run one crate at a time
```

Deliberately unresolved until someone runs it: the per-mutant test timeout on a
suite this slow, whether each mutant should run the whole workspace suite or
only the owning crate's, and therefore whether a `.cargo/mutants.toml` is worth
having at all. No config is committed, because a filter config nobody has run
`--list` against can silently examine nothing — which is the exact defect class
this section exists to prevent. Adding a CI job is also premature, though not
because push/PR triggers are barred: `AGENTS.md` → CI Workflow Structure keeps
`ci.yml` on `release: published` and the modules `workflow_call`-only, and the
two path-filtered `push`/`pull_request` exceptions (`workers.yml`,
`api-contract-drift.yml`) each argue their own cost asymmetry in the file
header. That is the bar, and a run of unknown duration cannot meet it yet.

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

## Implemented component-compliance layer

Implemented through **#210**, with the canonical provider matrix completed by
**#214**.

**Current status:** `tools/ferrogate-test` has a reusable
`ComponentContract` runner. It owns the lifecycle instead of trusting a
component to call arbitrary assertions: write -> read -> runtime exercise ->
verify -> cleanup. `component-compliance` forces all four generic quota scopes
through it locally, and `component-compliance-supabase` runs the same contract
against a unique live schema. Tenant asset quota is asserted at runtime;
project/workspace/key asset quota writes are rejected because stored assets and
their usage are tenant-owned. This closes the concrete #188-style write-only
scope gap without inventing fake narrower-scope usage semantics.

The provider contract proves OpenAI-compatible primary success, exact GPT-5.5
pricing, fallback attribution, and streaming/non-streaming terminal errors that
report usage. Its canonical matrix also covers Anthropic, Gemini, Grok/xAI,
OpenRouter, Azure OpenAI, Bedrock, and Vertex with deterministic real wire-shape
fixtures. Runtime and harness consume one adapter-family registry, and exact
set equality is checked before E2E starts, so removing a case or registering a
new family without one fails closed. Each case compares request/trace and
provider-attempt attribution, exact provider usage and configured cost across
the gateway billing event and standalone billing ledger. Streaming is exercised
for every implemented adapter transport that exposes reported usage. Provider
errors without usage remain non-billable, while multi-attempt settlement proves
distinct attempt identities and replay idempotency.

The Guardrail contract writes and reads a DB-backed policy, exercises allow and
block, polls the tenant-authorized evidence API, then verifies evaluation,
per-check, audit, and request-log rows directly in live Supabase. The existing
restart, rollback, redaction, and streaming assertions remain around that shared
contract.
