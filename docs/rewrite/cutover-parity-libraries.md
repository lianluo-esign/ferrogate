# Cutover certification — the 21 Rust crates vs the TypeScript libraries

**Question this document answers:** *is the TypeScript a 1:1 replica of the Rust,
crate by crate and algorithm by algorithm, and would a test fail if it stopped
being one?*

**Date:** 2026-08-01 · **Tree:** `/home/dev/ferrogate-ts` (`main-ts`) ·
**Method:** read the Rust, read the TS, then MUTATE the TS and watch the suite.
Nothing below is inherited from `parity-audit-*.md`; where those documents were
stale, this one says so.

**Headline verdict — three sentences.**
1. **The library layer (12 of 13 `packages/*`) is a faithful, often
   line-for-line replica**, and the six correctness-critical algorithm families
   named in the cutover brief are all reproduced; five of six are held by tests
   I proved RED by mutation.
2. **Deleting `crates/**` today would lose four things that have no TypeScript
   equivalent anywhere** (§6) — none of them on the inference request path, all
   of them account-management or non-Cloudflare-topology, and three of the four
   already carry honest markers.
3. **One security invariant is implemented correctly and held by nothing**
   (§4.4, guardrail evidence-fingerprint KEYING) — found by mutation this wave,
   marker added, test-only to close.

**Recommendation: do NOT delete `crates/**` yet.** Not because parity is absent —
it is overwhelmingly present — but because §6's four items are cheap to
re-derive from the Rust and impossible to re-derive once it is gone. Close §6
and §4.4 first; that is days of work, not weeks.

---

## 0. Measurements (all re-derived this wave, none quoted)

| Metric | Value | How |
|---|---:|---|
| Rust, all crates | 455,938 lines / 726 files | `find crates -name '*.rs'` |
| TypeScript source (`packages/*/src` + `apps/*/src`) | 121,515 lines | `find … -name '*.ts'` |
| TypeScript tests | 84,053 lines | `packages/*/test`, `apps/*/test`, `e2e` |
| Suite result | **5607 → 5649 passed · 0 failed · 0 skipped · 9 todo** | `bun run test` at the root, run twice |
| Test files / vitest projects | 299 files across **24** projects | ditto |

The suite was run at the start of this audit (5607 passed) and again at the end
(5649 passed), both `exit 0`, both 24 projects. The 42-test delta is a
CONCURRENT agent landing work mid-session, not anything this audit did — its only
source edit was a docstring. Recorded rather than smoothed over, because a
moving tree is exactly the condition under which a mutation edit can be silently
clobbered (see §2).
| Durable Object classes declared + exported | 7 | `class_name` in the 5 `wrangler.toml` |
| `PORT-TODO` markers in `src` | **155** | 48 mention `PLATFORM LIMIT`; 5 say `NOT A PLATFORM LIMIT` |

The Rust line count is dominated by inline `#[cfg(test)]`: excluding test
modules, `ferrogate-gateway` is ~1,468 production lines out of 144,052, and
`ferrogate-storage` ~4,177 out of 77,239. **The 456k-vs-121k ratio is not a
missing-code signal.** The honest comparison is production-Rust ≈ 22k lines vs
TS-source 121k — the TS is larger because it carries its documentation and its
platform-mapping rationale inline.

---

## 1. Crate → package/app census: 21 crates, 21 answers

PORT-PLAN.md's map lists **20 of the 21 crates**. `ferrogate-cloudflare` is
absent from it entirely — see row 21 and §6.1.

| # | Rust crate | prod lines | TS target | Exists? | Behaviour equivalent? |
|---|---|---:|---|---|---|
| 1 | `ferrogate-core` | 215 | `packages/core` | ✅ | ✅ full — every `pub` item has a TS twin, plus Zod schemas and a `Result` type Rust gets from the language |
| 2 | `ferrogate-config` | 125¹ | `packages/config` | ✅ | ✅ **56 of 56 portable validators**; 5 TLS/ACME validators dropped with a compensating INERT diagnostic (§4.6) |
| 3 | `ferrogate-policy` | 147¹ | `packages/policy` | ✅ | ✅ + 1 deliberate hardening (§4.1) |
| 4 | `ferrogate-guardrails` | 4,927 | `packages/guardrails` | ✅ | ✅ code; ⚠️ one invariant untested (§4.4) |
| 5 | `ferrogate-secrets` | 171¹ | `packages/secrets` | ✅ | ✅ 3 backends (`env://`, `vault://`, `cf://`); provisioning half is a real platform limit |
| 6 | `ferrogate-providers` | 294¹ | `packages/providers` | ✅ | ✅ 8/8 adapter families, alias tables byte-identical; ⚠️ AI-Gateway routing leg unmounted (§4.5) |
| 7 | `ferrogate-routing` | 135 | `packages/routing` | ✅ | ✅ + a Durable Object the Rust could not need (§4.5) |
| 8 | `ferrogate-storage` | 4,177 | `packages/storage` | ✅ | ✅ for the ported surface; Postgres→D1 rewrites the concurrency primitive (§4.3) |
| 9 | `ferrogate-billing` | 447 | `packages/billing` | ✅ | ✅ (§4.2) |
| 10 | `ferrogate-payments` | 149¹ | `packages/payments` | ✅ | ✅ ported; deliberately unmounted by directive (§5.3) |
| 11 | `ferrogate-observability` | 148¹ | `packages/observability` | ✅ | ✅ + now has a producer (§5.4) |
| 12 | `ferrogate-sync-bridge` | 80 | `packages/sync-bridge` | ✅ | N/A by construction — **recommend DELETE** (§5.1) |
| 13 | `ferrogate-gateway` | 1,468¹ | `apps/gateway` | ✅ | ✅ 31/31 contract ops mounted + gated |
| 14 | `ferrogate-runtime` | 808¹ | `apps/gateway` + `apps/agent-runtime` | ✅ | ✅ for the ported surface |
| 15 | `ferrogate-admin` | 328 | `apps/control-plane` | ✅ | ✅ 197/197 ops mounted + gated |
| 16 | `ferrogate-auth-service` | 6,786 | `apps/control-plane` | ✅ | ✅ auth/RBAC/lifecycle ported; D1-backed |
| 17 | `ferrogate-control-plane-client` | 506¹ | `apps/cli` | ✅ | ✅ incl. the OpenAPI↔CLI parity gate (§3) |
| 18 | `ferrogate-mcp` | 107¹ | `apps/mcp` | ✅ | ✅ 6/6 ops; ⚠️ credential store bypassed as committed (§5.5) |
| 19 | `agent-worker` | 1,410¹ | `apps/agent-runtime` | ✅ | ⚠️ 3 of 4 isolation backends are genuine platform limits; the 4th is unbound (§5.5) |
| 20 | `ferrogate-cli` | 633¹ | `apps/cli` | ✅ | ✅ >200 operations covered, gated |
| 21 | **`ferrogate-cloudflare`** | 463¹ | **none** — absent from PORT-PLAN | ❌ | ⚠️ mostly correctly absent; 4 slices unported (§6.1) |

¹ heuristic (lines from the first `#[cfg(test)]` to EOF are excluded); treat as a
lower bound, not a measurement.

**Route-surface parity is separately gated and passing.** 251 contract
operations = 197 control-plane + 31 gateway + 15 agent-runtime + 6 mcp + 2
shared. Each app has a test asserting every one of its owned `operation_id`s is
registered on the app the Worker exports (`apps/*/test/contract.test.ts`), and
`apps/gateway/src/routes/index.ts:108` — `PENDING_MODULE_OPERATION_IDS` — is
empty.

---

## 2. Mutation protocol used

For every claim of the form "a test would fail if it regressed", I:
`cp` the file → `sha256sum` it → apply the mutation with a **Python literal
replace with an `assert count == 1`** → **grep the file back off disk to CONFIRM
the mutation landed** → run the suite → restore → `sha256sum -c` → re-run.

**The CONFIRM step earned its place immediately.** My first attempt used the
`perl -0777 -pe 's{\Q…\E}{…}'` recipe from MOUNT-SEAMS §2 on a line containing a
JS template literal. Perl interpolated `${apiKeyId}` in the *replacement*, the
substitution silently did nothing, and `bun run test` printed **80/80 GREEN** —
which, without the CONFIRM grep, is indistinguishable from "the seam is
ungated". Every mutation below was additionally checked for *semantic* effect,
not just byte change (the trap flagged in the cutover brief).

---

## 3. The six correctness-critical algorithm families

### 3.0 Summary

| Family | TS reproduces? | Held by a test? | Evidence |
|---|---|---|---|
| policy — multi-level quota merge | ✅ verbatim | ✅ | §4.1 |
| policy — counter-key namespacing (security) | ✅ + hardened | ✅ **mutation-proven** | §4.1 |
| billing — settled-cost authority, `price_not_found`, bigint credits, idempotency, outbox | ✅ | ✅ **mutation-proven** | §4.2 |
| storage — wallet no-oversell, CAS family, state machine, monotonic upserts | ✅ (primitive re-expressed) | ✅ **mutation-proven** | §4.3 |
| guardrails — detector families, HMAC evidence, bounded findings, bulkhead/breaker/deadline | ✅ | ⚠️ **one gap** | §4.4 |
| providers/routing — adapters, retry, breaker, failover, canary | ✅ | ✅ **mutation-proven** (canary) | §4.5 |
| config — `validate()` helpers | ✅ 56/56 portable | ✅ **mutation-proven** | §4.6 |

---

## 4. Family by family

### 4.1 policy — quota merge and the counter-key namespace

**Merge: verbatim.** `packages/policy/src/quota.ts::resolveEffectiveQuota` is a
line-for-line reproduction of `crates/ferrogate-policy/src/quota.rs`:

- Scope chain iterated `tenant → project → workspace → key`, identically.
- `deniedBy` short-circuits on the FIRST disabled policy, returning defaults for
  everything else — same as Rust's `..EffectiveQuota::default()`.
- `modelAllowlist` is the INTERSECTION of every scope declaring a non-empty list;
  an empty list at a scope means "no opinion", not "deny everything".
- All six numeric dimensions (`rpm`, `tpm`, `monthlyBudgetUsd`,
  `agentCostBudgetUsd`, `monthlyEgressBytesBudget`, `downloadRpmLimit`) are
  `min`-across-the-chain, and the winning `*Scope` is recorded. **The tie rule is
  preserved exactly**: `updateMinScope` overrides on `<=`, so given the
  tenant→key iteration order a tie goes to the MOST SPECIFIC scope, which is
  what keeps a per-key cap counted per-key. Rust splits this into
  `update_min_u64_scope` / `update_min_f64_scope`; TS has one number type, so one
  function — no behavioural difference.
- `assetStorageQuotaBytes` / `assetMaxObjectBytes` are tenant-scope-only in both.
- **Plan floors** fill in only where no policy set a value, and are keyed on the
  TENANT scope when a tenant id is present — Rust `plan_scope`, reproduced.

**The counter-key namespace (SECURITY-CRITICAL): reproduced AND deliberately
extended.** `QuotaScopeSelector.counterKey` returns `"key:{apiKeyId}"` for a key
winner and `"{kind}:{id}"` otherwise, so a tenant that mints a virtual key whose
id is literally `"tenant:victim"` produces `"key:tenant:victim"` — structurally
unequal to the victim's aggregate window.

The port then **closes a reachable hole the Rust still has.**
`crates/ferrogate-gateway/src/auth.rs:225` — `tpm_window` — falls back to
`api_key_id.to_string()`, the **RAW id with no prefix**, when the TPM limit has
no winning scope. That state is reachable: `resolve_effective_quota` sets a
plan-default TPM with no scope when the chain carries no tenant id. `request_windows`
(line 183) does NOT have this bug; only `tpm_window` does.
`apps/gateway/src/ratelimit/keys.ts::tpmWindow` uses the namespaced fallback for
both dimensions and documents the deviation in a PORT-DEVIATION block. The same
file adds `assertNamespacedCounterKey`, a fail-closed boundary guard run by
**every** limiter and the DO stub factory, so a future call site cannot
re-introduce the raw-id path silently.

**MUTATION (proven).** `counterKey` → return the raw `apiKeyId` for the `key`
scope:
- `packages/policy` → **RED**, `test/quota.test.ts:178`.
- `apps/gateway` `test/ratelimit/` → **RED, 40 of 121 tests**, including
  end-to-end `SELF` requests (`spend.test.ts` etc.) — so the derivation is
  proven on the DEPLOYED path, not just in the unit.
- Restored: 80/80 and 121/121 green.

**Verdict: PARITY, with one documented security hardening. Held.**

### 4.2 billing

`packages/billing/src/ledger.ts::charge` reproduces
`crates/ferrogate-billing/src/ledger.rs::charge` clause for clause:

- **Gateway-settled cost is authoritative** (#135). When the event carries a
  settled cost, that figure is recorded; the `PriceBook` is consulted only for
  the input/output split, and `unit_price` degrades to `usd(0,0)` when no rule
  exists.
- **Drift is logged, never enforced** (#152). `costDiverges` uses the same 5%
  relative tolerance and $0.0001 absolute floor. Rust's `tracing::warn!` becomes
  an injected `onDivergence` callback — the correct port of a global logger into
  a package with no I/O.
- **Fail-closed `price_not_found`** (#129): no settled cost AND no rule ⇒ throw,
  never bill zero. Mapped to HTTP **422** in `service.ts:75`, matching
  `service.rs:251`.
- **Integer credits as `bigint` end to end.** `wallet_delta_credits` /
  `wallet_balance_after_credits` are `bigint` in both `event.ts` and `ledger.ts`,
  parsed by `z.union([z.bigint(), z.number().int()])` so a JSON-number wire value
  round-trips, and compared by widening both sides with `BigInt` so a reloaded
  entry still equals a fresh one. This is the faithful port of Rust `Option<i64>`.
  **Caveat, stated rather than hidden:** `credits_for_usd` is `f64` in Rust and
  `number` in TS — that is parity, not a float leak; the *derived credit rate* is
  floating in both. `packages/storage`'s wallet amounts are `number`, not
  `bigint` (§4.3).
- **Idempotent ledger writes**: `ledgerEntryId` is `ferrogate:{trace}:{request}`
  (or `ferrogate:{request}` with no trace) — byte-identical to Rust.

**MUTATION (proven).** Neutralise the `price_not_found` throw and fall through to
a zero-cost entry (the exact "bill nothing instead of refusing" regression):
- `packages/billing` → **RED, 2 tests** (`ledger.test.ts:51`, `service.test.ts:63`).
- `apps/gateway` `test/metering/` → **RED, 4 tests**, including
  `expect(h.ledger.size).toBe(0)` — i.e. a test that asserts NO ledger row is
  written, which is the property that actually matters.
- Restored green.

**Durable outbox:** `packages/storage/src/d1/billing-d1.ts` (400 lines) +
`apps/gateway/src/metering/sink.ts` over the declared `BILLING_DB` D1 and
`BILLING` Queue producer. Both bindings are committed and the metering sink is
mount-gated (`apps/gateway/test/metering/wiring.test.ts`).

**Verdict: PARITY. Held.**

### 4.3 storage

The Postgres→D1 translation changes the *concurrency primitive* and preserves
the *guarantee*. That distinction is the whole risk surface here, and it is
handled correctly.

**Wallet reserve — NO-OVERSELL.** Rust (`wallet.rs:317`) takes
`SELECT balance_credits FROM wallets WHERE tenant_id = $1 FOR UPDATE`, then sums
live holds, then compares, then inserts — four statements inside one Postgres
transaction. D1/SQLite has no `FOR UPDATE`, so
`packages/storage/src/d1/wallet-d1.ts:230` re-expresses it as a **single
`db.batch([...])` of three statements** where the admission decision IS the
insert:

```sql
INSERT INTO wallet_reservations (…)
SELECT ?, ?, ?, 'active', ?, NULL, ?, ?
  FROM wallets w
 WHERE w.tenant_id = ?
   AND ? <= w.balance_credits - COALESCE((SELECT SUM(r.amount_credits)
                                            FROM wallet_reservations r
                                           WHERE r.tenant_id = ? AND r.status='active'
                                             AND r.expires_at_unix > ?), 0)
ON CONFLICT (id) DO NOTHING
RETURNING id                 -- empty RETURNING == not admitted
```

Statement 0 is the idempotency probe (a replay with a different tenant or amount
is a `conflict`, matching Rust); statement 2 distinguishes `no_wallet` from
`insufficient`. Expired holds self-release (`expires_at_unix > ?`) in both. And
`requireAtomicBatch(handle, …)` runs FIRST on every guarded write, so a REST
transport that cannot offer an atomic batch makes the write throw rather than
silently run non-atomically.

**MUTATION (proven).** Replace the balance predicate with a tautology
(`? >= -1 - 0*COALESCE(…)`, which keeps the statement shape and the bind order so
the mutation is provably *semantic*, not cosmetic):
`packages/storage` → **RED, 3 tests** in `test/d1/wallet-d1.test.ts`. Those tests
are not toy: one fires **5 concurrent `reserveWalletCredits` without awaiting in
between** against a balance affording 4 and asserts exactly 4 admitted; another
fires **20 against a balance affording 7** and asserts exactly 7; both then
re-read `SUM(amount_credits)` off the real D1 to confirm the durable state agrees
with what callers were told. They run against a real D1 in workerd.

**Other members of the family (read, not mutated — listed as such):**

- **workflow-budget optimistic CAS** — `d1/workflow-budget-d1.ts:338/367/397`:
  guarded `UPDATE … WHERE id = ? AND status = 'active' … RETURNING`, `undefined`
  ⇒ the guard missed. Rust used `SELECT … FOR UPDATE` (`workflow_budget.rs:302,397`).
  Same guarantee, re-expressed. **UNVERIFIED by mutation this wave.**
- **guardrail-binding generation CAS** — lives in
  `apps/gateway/src/guardrails/d1.ts:127` (`UPDATE guardrail_policy_bindings SET …
  WHERE policy_id = ? AND generation = ?`), with the pure transition builders and
  `nextGuardrailBindingGeneration` (overflow-guarded) in
  `packages/storage/src/guardrail-binding.ts`. A CAS loss surfaces as the exact
  Rust conflict message. **UNVERIFIED by mutation this wave.**
- **payment-attempt state machine** — `packages/storage/src/payment-attempt.ts`,
  8 states + `transitionPaymentAttempt` + terminality, ported from
  `payment_attempt.rs`. It has **no dedicated test file in `packages/storage/test/`**;
  coverage is indirect via `apps/control-plane/src/routes/payment_attempt.ts` and
  `apps/cli`. Given x402 is deprioritized this is proportionate, but it is the
  thinnest-covered item in this section. **Flagged, not mutated.**
- **monotonic upserts** — `packages/storage/src/d1/monotonic.ts`
  (`TenantMonotonicUpserts`, `ControlMonotonicUpserts`) with
  `test/d1/monotonic.test.ts`; the SQLite `max()` idiom the Rust D1 tests also
  assert (`control_plane_store_d1_test.rs:1683`).

**One typed-domain deviation worth recording:** storage carries credit amounts as
`number`, not `bigint`. JS numbers are exact to 2^53; Rust's `i64` runs to ~9.2e18.
A tenant balance above ~9,007,199,254,740,991 credits would lose precision. That
is not reachable at any plausible credit scale, and the billing EVENT domain is
`bigint`, but the two layers do not use the same integer type and nothing asserts
the boundary. **Recorded as a known, bounded deviation — not a defect today.**

**Verdict: PARITY on the proven items. Held for wallet no-oversell.**

### 4.4 guardrails — ⚠️ THE ONE REAL FINDING OF THIS AUDIT

**Everything about the code is right.**

- **Detector families:** the emitted rule-id vocabulary is IDENTICAL between
  `deterministic.rs` and `deterministic.ts` — `detector.truncated`,
  `request.endpoint`, `request.model`, `request.provider`,
  `secret.aws_access_key_id`, `secret.github_token`, `secret.openai_api_key`,
  `size.input_bytes` (set-equal, verified by extracting every dotted string
  literal from both files). The three secret regexes are **character-identical**,
  including `\bsk-(?:proj-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})\b` and
  `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`.
- **Non-persisted evidence:** `matched_text` is `null` at every construction site.
- **Bounded findings:** `MAX_FINDINGS_PER_EVALUATION = 10_000` in both. The test
  (`test/deterministic.test.ts:219`) asserts the EXACT length
  (`MAX_FINDINGS_PER_EVALUATION + 1`), that the truncation marker is the LAST
  finding, that there is exactly one, and — the part that makes it non-vacuous —
  a negative control at line 291 that a below-cap input emits no marker.
- **custom_http bulkhead / circuit-breaker / deadline:** a faithful port —
  deadline checked BEFORE execution, semaphore acquired with the remaining
  budget, `circuitFailureThreshold` / `circuitCooldownMs` / `halfOpenProbe`
  reproducing `custom_http.rs`'s `enter_circuit` / `record_failure` exactly,
  including the rule that an error which `!affects_circuit()` resets rather than
  trips. Rust's `tokio::sync::Semaphore` → an async `Semaphore` in `async.ts`.

**The gap: nothing proves the evidence fingerprints are KEYED.**

All three fingerprint sites HMAC under the configured key —
`adapters/transport.ts:140 hmacEvidenceFingerprint` (used by `llm_guard.ts:196`
and `workers_ai_llama_guard.ts:389`) and the private
`deterministic.ts:339 #hmacFingerprint`. But every assertion in the tree is a
SHAPE assertion, `/^hmac-sha256:[0-9a-f]{64}$/`, which an unkeyed SHA-256 also
satisfies.

**Two mutations, both semantically real, both GREEN:**

| Mutation | Result |
|---|---|
| `hmacEvidenceFingerprint`: `key.asBytes()` → `new Uint8Array(0)` (keyed evidence downgraded to a plain digest of the sensitive value) | **407/407 guardrails tests GREEN** |
| `DeterministicDetector#hmacFingerprint`: key → the constant `"FIXED"` | **407/407 guardrails GREEN and 112/112 `apps/gateway/test/guardrails/` GREEN** |

Why this matters and is not pedantry: an *unkeyed* digest of a short secret (an
API-key fragment, a name, an account number) is reversible by dictionary attack.
Removing the key is precisely the regression the keying exists to prevent, and it
is invisible to the suite.

**Not everything is unheld.** The gateway's envelope-level fingerprint
(`apps/gateway/src/guardrails/evidence.ts:73 envelopeFingerprint`) fails CLOSED to
the literal `hmac-sha256:unavailable` when no key is configured, exactly as Rust
did, and `apps/gateway/test/guardrails/evidence.test.ts:103` pins it. The config
guard that an empty `fingerprint_secret_ref` is rejected is ported and tested
(`deterministic.ts:205`). Only the per-FINDING fingerprints are unheld.

**Action (test-only, no source change):** assert two detectors with DIFFERENT
keys produce DIFFERENT fingerprints for the SAME input, plus the same-key
reproducibility control. A `PORT-TODO` recording this — with the mutation
evidence — was added to `packages/guardrails/src/index.ts` by this audit
(the only source edit it made; 407/407 and `tsc --noEmit` re-verified after).

**Verdict: code PARITY; evidence GAP. Fix before cutover — it is hours of work.**

### 4.5 providers / routing

**Adapter coverage: 8/8, exhaustive.** `crates/ferrogate-providers/src/` and
`packages/providers/src/` have a 1:1 file map (`anthropic`, `anthropic_messages`,
`azure`, `bedrock`, `canonical`, `cloudflare`, `gemini`, `grok`, `models`,
`openai`, `openrouter`, `registry`, `sigv4`, `types`, `vertex`). The
`SUPPORTED_PROVIDER_ADAPTER_FAMILIES` alias table is **byte-identical**, down to
the 13 OpenAI-compatible aliases in order (`openai`, `deepseek`, `newapi`,
`sub2api`, `cliproxyapi`, `cli-proxy-api`, `vllm`, `llama.cpp`, `llama-cpp`,
`llamacpp`, `tgi`, `ollama`, `ollama-compatible`) and the `xai`, `azure`,
`aws-bedrock`, `vertex-ai` singles.

**Retry predicate:** `types.rs:465` `status == 429 || (500..=599)` ⇔
`types.ts:367` `status === 429 || (status >= 500 && status <= 599)`, dispatched
per family through the registry. `apps/gateway/src/inference/reliability.ts:84`
wraps `adapterFor`'s throw in a `catch → false`, reproducing Rust's
`.unwrap_or(false)` — an unidentifiable family is NOT retried.

**Circuit breaker + failover ladder:** `reliability.ts` (620 lines) ports
`ProviderCircuitState`, `attemptDecision` and `dispatchWithFailover`; the
defaults reproduce Rust's exactly, and **both are "off"** —
`provider_dispatch_max_retries` is `unwrap_or_default()` ⇒ 0, and the breaker
config is built with `?` over both threshold and cooldown ⇒ absent unless an
operator sets both. Keeping that faithful is what makes the wiring a wiring
change and not a behaviour change. `PROVIDER_CIRCUIT` is a declared, exported DO.
`ModelResolver.candidates` ports `AppState::candidate_model_routes`
(`state_routing.rs:489`) and `catalog.ts` carries `fallbacks` with Rust's
asymmetric defaults preserved and explained (primary ⇒ `priority 0, weight 1`;
fallback ⇒ `priority 100, weight 1`) — getting that wrong would let an
alphabetically-earlier fallback outrank the primary.

**Deterministic canary bucketing: byte-identical.** `packages/routing/src/fnv.ts`
reproduces FNV-1a-64 with `bigint` and an explicit `& 0xffff…n` mask emulating
Rust's `wrapping_mul`, and the `salt \0 stickyKey` UTF-8 framing verbatim.
`canarySelected` / `shadowSampled` keep the `0 ⇒ never`, `>=100 ⇒ always`
short-circuits and the distinct `"canary"` / `"shadow"` salts.

**MUTATION (proven).** FNV prime `0x…01b3n` → `0x…01b5n`: `packages/routing` →
**RED**, `test/fnv.test.ts` "known vectors". Restored green.
*Honest scoping of that result:* only the known-vector test goes red. The
distribution tests compute their expectation from the package's own
`rolloutBucket`, so they are self-consistent by construction — correct for
proving the gateway MOUNTS the package (which is their job,
`apps/gateway/test/inference/reliability.test.ts:515`), but they do not pin the
values to Rust. The pinning comes from the three canonical FNV-1a-64 vectors plus
the `rolloutBucket("ab","c") !== rolloutBucket("a","bc")` separator test, which
together fix the constants and the framing. **There is no Rust-generated golden
bucket table.** That is adequate, and it is cheap to make airtight.

**Two genuine gaps in this family, both marked, one significant:**

1. **Cloudflare AI Gateway routing (#406) is unreachable in production.**
   `packages/providers/src/registry.ts` applies `applyCloudflareAiGatewayRouting`
   after preparation, but `apps/gateway/src/inference/adapters.ts` builds its OWN
   `defaultAdapterRegistry` by wrapping the eight adapter classes one at a time
   via `packageProviderAdapter(...)`, never going through that class. So the
   AI Gateway's free caching, rate-limiting and observability are in effect for
   no tenant. It is also not *configurable*: `providerRecordSchema` is `.strict()`
   and has no `cloudflare_ai_gateway` key, so a provider carrying the Rust block
   would be REJECTED, not ignored. The marker at `registry.ts:8` states this
   accurately and lists the three edits to close it. **This is the textbook
   instance of this project's defect class, correctly identified and still open.**
2. **`ModelRegistry` / `RouteMatcher` have no consumer.** The former is superseded
   by the gateway's own resolver (all four routing strategies ARE implemented, in
   `apps/gateway/src/inference/strategy.ts`); the latter is an interface whose
   implementer is the operator reverse-proxy fall-through. Both marked. Low risk.

**Verdict: PARITY on the algorithms. One real unmounted feature (#406).**

### 4.6 config — the `validate()` census

**Rust: 61 distinct `fn validate_*`. TypeScript: 68 distinct `function validate*`.**

| Bucket | Count | Notes |
|---|---:|---|
| Rust validator with a direct TS twin | 54 | same name, camelCased |
| Rust validators merged into one TS function | 2 → 1 | `validate_positive_optional_u32` + `_u64` → `validatePositiveOptional` (TS has one number type) |
| Rust validators DELIBERATELY dropped | **5** | `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`, `validate_acme_http01_tls`, `validate_manual_tls_files` |
| TS validators with no Rust twin | 12 | `validateCapabilityTargetSelector`, `validateClusterSnapshotShape`, `validateDetectorEndpoint`, `validateMcpHttpEndpoint`, `validateMcpOauthConfig`, `validateMcpServerConfig`, `validateMcpStaticHeader`, `validateMcpTlsConfig`, `validateJsonShape`, `validateSecretRef`, `validateConfig`, `validateConfigAsync`, `validateExtensionPermissionNamesForPackage` |

**So the portable coverage is 56 of 56.** The five absences are all TLS/ACME, all
N/A behind Cloudflare's edge TLS termination.

**And the operational question — "what does a missing validator mean?" — is
answered correctly rather than ignored.** The naive failure mode is that a config
which SHOULD be rejected is silently accepted, which tells an operator TLS is
configured when it is not. `packages/config/src/validate/sections.ts:736
inertTlsWarnings` is the compensating control: `[tls]` and `[tls.acme]` still
DECODE (so a legacy TOML/Caddyfile round-trips, matching Rust's acceptance) but
the load emits an explicit INERT warning naming exactly why the section cannot
work ("the edge terminates TLS before the Worker is invoked… a Worker cannot own
the :80 HTTP-01 challenge listener, has no filesystem for the ACME `storage_dir`,
and cannot exec a DNS-01 hook"). It is warn-only on purpose, and the reason is
written down: refusing would break the Caddyfile migration path that Rust accepts.
The genuinely-portable half of the TLS surface is KEPT and still validated —
`admin_api.tls_cert_path`/`tls_key_path` must be set together, and
`storage.postgres_tls_mode` is still checked.

**MUTATION (proven).** Unmount ONE validator — delete the
`validateGuardrails(config, apiKeyIds, modelNames, providerNames)` call at
`validate.ts:398` (replaced with a `void [...]` so the bindings stay used and the
mutation is about REACHING the validator, not about compiling):
`packages/config` → **RED, 49 of 757 tests**. Restored: 751 passed / 6 todo.
So the validator table is genuinely mounted and a silently-dropped validator
cannot hide.

**Verdict: PARITY, 56/56 portable, with the 5 absences compensated and explained.**

---

## 5. The standing question: `sync-bridge`, `schemas`, `payments`

I re-ran the importer census this wave with a Python module-specifier extractor
over every `.ts` under `apps/*/src` and `packages/*/src` (comments stripped;
multi-line imports handled). **The prior audit's "legitimately dead" ruling is
CONFIRMED for all three — but with two corrections to its supporting facts, and
one upgrade of its recommendation.**

Current census (only the packages at issue):

| package | importers |
|---|---|
| `sync-bridge` | **0**, in both layers |
| `schemas` | **0**, in both layers (it imports `@ferrogate/core` 14×; nothing imports it) |
| `payments` | 3 value imports, all from `packages/policy/src/x402/wire.ts` |

### 5.1 `sync-bridge` — LEGITIMATELY DEAD → **CONFIRM. RECOMMEND DELETING IT.**

The Rust crate is one 80-line function, `block_on_sync_bridge(future) -> T`, which
parks a THREAD so a synchronous Pingora filter hook, a sweep thread, or the Unix
`SO_PEERCRED` external-action authorizer can call an `.await`ing method. All three
caller classes are eliminated by this rewrite by construction: Pingora is gone
(the data plane is a Hono proxy), workerd has no threads, and the Unix authorizer
has no CF equivalent. `docs/legacy/inventory-edge-control.md` §7 lists the crate's
CF/TS target as literally `Deleted`.

`packages/sync-bridge/src/bridge.ts::blockOnSyncBridge` is honest about what it
became: its body is `return await started`. It is `await` with a docstring. The
`RuntimeFlavor`/strategy model in `runtime.ts` is a parity VIEW of Rust branch
structure that cannot execute on this platform.

**It genuinely has no purpose on Cloudflare. Recommendation: delete
`packages/sync-bridge/` (250 source lines, 2 test files, 21 tests) and drop the
`ferrogate-sync-bridge` row from PORT-PLAN.md's crate→package map in the same
edit.** Nothing breaks: zero importers, and the Rust crate's only dependent was
`ferrogate-gateway`, whose TS successor is uniformly async. The package's own
`index.ts:24` already carries exactly this verdict. **This audit does not delete
it** — that is a repo-structure change outside this document's scope.

### 5.2 `schemas` — LEGITIMATELY DEAD as a barrel → **CONFIRM**, and its two prior defects are now CLOSED

~90% of `packages/schemas/src/index.ts` is a pure re-export of `@ferrogate/core`.
Apps import those symbols from `@ferrogate/core` directly — the same single source
of truth — so routing them through an extra hop buys nothing. Correctly dead.

**Correction to the prior audit, in the TS's favour:** its two substantive findings
have since been fixed and I verified both.
- `errorEnvelopeSchema` no longer declares the flat `{code, message, requestId}`
  fiction; `wire.ts` now carries the corrected nested envelope and says so.
- `OPENAPI_OPERATION_COUNT = 251` is still one of three declarations, but the
  drift risk is closed: all three are now independently pinned to the **same JSON
  document** rather than to each other (`apps/control-plane/test/contract.test.ts:71`,
  `apps/gateway/test/contract.test.ts:48`, `packages/schemas/test/wire.test.ts`
  reading the file off disk). Adding an operation fails in three places at once.
  The reasoning for keeping it a literal rather than deriving it — that a derived
  constant would agree with the contract *by construction* and make the gate
  unfailable — is exactly right, and is the vacuous-assertion lesson applied.

**Verdict: keep, do not wire, no action.**

### 5.3 `payments` — LEGITIMATELY DEAD by directive → **CONFIRM**

Not orphaned: `packages/policy/src/x402/wire.ts:34,63,71` imports
`RequestBodyHash`, `validateSolanaAddress` and the wire types from it, and
`packages/policy/package.json` declares the dependency. This is the healthy
"consumed by a package, not an app" shape, with real imports. The app-layer
absence is a *deferral* under the standing x402/Solana directive, not a miss —
Rust used it on the live gateway path (`state_x402_negotiation.rs`,
`state_x402_reconciler.rs`), and those are precisely the paths deferred. The port
itself is complete: 2,183 TS source lines against 2,073 Rust production lines,
1:1 module map (`attempt_state`, `error`, `intent`, `proof`, `sdk`, `wire`),
54 tests.

**Verdict: keep, do not wire, no action.**

### 5.4 `observability` — the prior audit's #1 finding is now CLOSED

The prior audit's largest item was "an entire deployed Worker is unreachable —
receiver and wire format built, NO PRODUCER". That is fixed:
`apps/gateway/src/telemetry/emit.ts` imports `@ferrogate/observability` for real
(2 value imports), `apps/gateway/wrangler.toml` declares the
`[[services]] TELEMETRY_COLLECTOR` binding, and the span carries the trace id
adopted by `middleware/trace.ts` — which also closes the "correlation id computed
and discarded" item. `AE_MAX_BLOB_BYTES` is corrected from 5120 to 16 KiB.

Two residues remain, both accurately marked in
`packages/observability/src/index.ts`: `AnalyticsEngineSink` has no importer
(`apps/telemetry` re-implements it locally — a duplication to collapse, not a gap
to wire), and `OtlpBackend` has no importer (the gateway builds a
`CloudflareBackend` for both transports). The marker also records, commendably,
that the inference-specific emit LEG is not *independently* gated even though the
package's mount is — deleting the `route-module.ts` call alone leaves all 27
telemetry tests green because the global middleware still emits.

### 5.5 Composition-root residues that survive as committed (integrate-step owned)

These are not library-parity defects — the implementations exist and are tested —
but they change what a `wrangler deploy` of the committed tree actually runs, so a
cutover decision needs them on the record:

| Worker | As committed | Consequence |
|---|---|---|
| `apps/mcp` | `FG_DEV_IN_MEMORY_PORTS = "1"` at `wrangler.toml:37` | Auth, approvals, guardrails and secrets ARE durable in every posture (improved this wave). But `resolvePorts` still short-circuits at `ports.ts:1723`, so `DurableCredentialStore` and the identity cipher stay in-memory: OAuth grants die with the isolate |
| `apps/agent-runtime` | `FG_DEV_IN_MEMORY_PORTS = "1"` at `wrangler.toml:64`; both D1 stanzas commented out | Real `d1ApiKeyPort` / `d1WorkerIdentityPort` adapters now exist and win when `DB`/`CONTROL_DB` are bound, and `resolveDeps` fails CLOSED when neither is available — but as committed both are the dev bundle. `governance` and `upstreams` have no durable leg in any posture |
| `apps/agent-runtime` | `CONTAINER_SANDBOX` / `[[containers]]` commented out | `@cloudflare/sandbox` IS a declared dependency; the binding is commented because Containers need a paid account. So `agent-worker`'s 4th (and only portable) isolation backend is declared and unbound. The other three (Firecracker/`/dev/kvm`+vsock, Docker `exec`, local process `fork`) are genuine platform limits, marked as such at `runs/governance.ts:27` |

---

## 6. What deleting `crates/**` would actually LOSE

This is the section that should decide the cutover, and it is short.

### 6.1 `ferrogate-cloudflare` — the crate PORT-PLAN forgot (the material item)

It is the 21st crate and it appears in **no row** of PORT-PLAN.md's crate→package
map. There is no `@ferrogate/cloudflare`. Instead there are **three independent
partial Cloudflare v4 clients**, each decoding the `{success, errors, result}`
envelope itself: `packages/secrets/src/cloudflare-client.ts` (Secrets Store manage
plane), `packages/storage/src/tenant-rest.ts` (D1 query API — on the request path),
and `packages/providers`' AI-Gateway surface.

**Most of the crate is CORRECTLY absent** — it existed because the Rust gateway
ran OUTSIDE Cloudflare and had to reach every product over REST; this port runs
INSIDE it, so `d1.rs`/`d1_proxy.rs` are superseded by the native D1 binding, the
Workers AI / AI Gateway calls by their bindings, and the agent memory/schedule
hops by Durable Objects. Deleting a REST hop in favour of a binding is the POINT.

**Four slices are genuinely unported, with no TS equivalent anywhere:**
1. `r2.rs` — per-tenant R2 bucket provisioning (`r2_bucket_name_for_tenant`,
   create-bucket, the already-exists reconciliation codes);
2. `r2_token.rs` — minting SCOPED temporary R2 S3 credentials (read/write
   permission-group ids, jurisdiction) — how a tenant gets credentials narrower
   than the account token;
3. `scopes.rs` + `CloudflareClient::preflight` — the required token-permission-group
   list and the cheap GET that names WHICH group is missing instead of failing at
   first use;
4. the shared retry/backoff honouring Cloudflare's global ~1,200 req / 5 min API
   limit, plus the typed `AUTHENTICATION_CODES` / `MISSING_SCOPE_CODES` mapping.

These are account-MANAGEMENT operations, not data-plane ones, which is why no
request path misses them — and exactly why they are the things a fresh
re-derivation would be most painful. All four are named in the marker at
`packages/secrets/src/cloudflare-client.ts:27`, which is the ONLY place in the tree
that mentions `ferrogate-cloudflare` at all.

### 6.2 The other three losses

| Loss | Where it is marked | Severity |
|---|---|---|
| Cloudflare AI Gateway routing (#406) — fully ported in `packages/providers/src/cloudflare.ts`, reachable by nothing, and not even expressible in the strict provider schema | `packages/providers/src/registry.ts:8` | **Medium** — a live product feature (free caching/rate-limiting/observability) is off for every tenant |
| The Rust reference for `agent-worker`'s three non-portable isolation backends and snapshot support | `apps/agent-runtime/src/runs/governance.ts:27,55` | Low — genuine platform limits, honestly recorded, `snapshotSupported: false` pinned by a test |
| Postgres-specific storage semantics (`FOR UPDATE`, `SET search_path`, composite-unique error codes) that the D1 ports re-express | `packages/storage/src/d1/*` docstrings | Low — the guarantees are ported and, for the wallet, mutation-proven |

---

## 7. UNVERIFIED — stated plainly rather than guessed

Everything in this list is *believed correct from reading the code*, and was NOT
mutation-tested this wave. Do not read this document as certifying them.

1. **Workflow-budget optimistic CAS** — read and matched against
   `workflow_budget.rs`; not mutated.
2. **Guardrail-binding generation CAS** — read and matched; not mutated.
3. **Payment-attempt state machine** — read and matched; **no dedicated test file
   in `packages/storage/test/`**, only indirect coverage. Thinnest item in §4.3.
4. **The 197 control-plane operations' individual semantics.** The *contract*
   (path/method/auth/scope/rbac/registration) is gated for all 197. Per-operation
   request/response body parity against the Rust admin handlers was not audited
   here; `apps/control-plane/test/crud.test.ts` covers ~170 generically.
5. **Streaming byte-for-byte SSE framing.** TESTING.md's MSW approach exists and
   `apps/gateway` has streaming suites, but I did not diff normalised frames
   against Rust `messages_stream.rs` / `responses_stream.rs` output.
6. **The 12 non-mutated `packages/config` validators' message TEXT.** Presence and
   reachability are proven; exact diagnostic strings were spot-checked, not
   exhaustively diffed.
7. **`sigv4` (Bedrock) and Vertex OAuth signing correctness** against real AWS/GCP
   canonical-request vectors.
8. **Anything requiring the live Cloudflare account** — per the standing rule, the
   one authorised deploy is held for a separate human-gated run. Every result in
   this document is from `@cloudflare/vitest-pool-workers` in local workerd.
9. **The `storage` `number` vs billing `bigint` credit-domain boundary** (§4.3) —
   no test asserts what happens above 2^53.

---

## 8. Ranked actions before deleting `crates/**`

1. **Close §4.4** — assert the guardrail evidence fingerprint is KEYED (different
   keys ⇒ different fingerprints, same key ⇒ same). Test-only. Hours.
2. **Extract the four unported `ferrogate-cloudflare` slices** (§6.1) into
   `@ferrogate/cloudflare`, or write them down in a document that survives the
   deletion. This is the only item where the Rust is genuinely irreplaceable.
3. **Mount Cloudflare AI Gateway routing** (§4.5 gap 1) — three edits, already
   enumerated in the marker: carry `cloudflare_ai_gateway` on `PhysicalRoute`,
   delegate `adapters.ts` to `ProviderAdapterRegistry`, and add a test asserting
   the PREPARED ENDPOINT is the AI Gateway host.
4. **Remove `FG_DEV_IN_MEMORY_PORTS = "1"` from the two committed `wrangler.toml`
   files** (§5.5), or move it into an `[env.dev]` block. Integrate-step owned.
5. **Mutation-test the three UNVERIFIED storage CAS/state-machine items** (§7.1–3)
   and give `payment-attempt.ts` a dedicated test file.
6. **Delete `packages/sync-bridge/`** and its PORT-PLAN row (§5.1).
7. **Add a Rust-generated golden bucket table** for `rolloutBucket` (§4.5) — cheap
   insurance that costs nothing and expires the moment the Rust is deleted.
8. **Add the missing `ferrogate-cloudflare` row to PORT-PLAN.md's crate→package
   map**, even if the answer is "mostly superseded by bindings; see §6.1". A map
   with 20 of 21 crates is how this one went unnoticed for fourteen waves.

---

## 9. Changes this audit made to the tree

One source edit, and one new document.

- `packages/guardrails/src/index.ts` — added the `PORT-TODO(cutover-parity-libraries §4.4)`
  marker recording the unheld fingerprint-keying invariant, with both mutation
  results and the exact test to write. No behaviour changed; 407/407 tests and
  `tsc --noEmit` re-verified after the edit.
- This file.

No test was weakened, skipped or deleted. No composition root, `wrangler.toml`,
`index.ts` or `worker.ts` was touched. No `crates/**` or `workers/**` file was
read for anything other than comparison, and none was modified. Every mutation
was reverted and verified by `sha256sum -c`.
