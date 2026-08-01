# Cert2 — the TypeScript LIBRARIES, certified on their own terms

**Date:** 2026-08-01 · **Tree:** `/home/dev/ferrogate-ts` (`main-ts`) ·
**Scope:** all 15 `packages/*`, against the Rust crates they replace.

**The question this document answers is NOT "does the TypeScript match the
Rust".** The project owner has stated that the Rust system is itself a
half-finished product and that TypeScript is now the forward platform. So the
question is: **is the TypeScript library layer complete and correct on its own
terms**, and where it diverges from Rust, **which of the three classes is the
divergence in**?

| Class | Meaning | Cutover |
|---|---|---|
| **A — REGRESSION** | Behaviour was COMPLETE and WORKING in Rust and the port dropped or broke it | **BLOCKS** |
| **B — RUST NEVER FINISHED** | Rust side is a stub / orphan / abandoned half-path. Copying it would be wrong | product backlog |
| **C — DELIBERATE** | Obsolete on Workers, a genuine platform limit, or an explicit product decision | no action |

Nothing below is inherited from `cutover-parity-libraries.md`. Where that
document was right I say so and cite the fresh evidence; where it was wrong I
correct it. Every "a test would fail if this regressed" claim is backed by a
mutation I applied, confirmed off disk, ran, and reverted.

---

## 0. Headline verdict — five sentences

1. **The library layer is in materially better shape than at the last
   certification.** All four items the previous audit named as blocking are
   closed and I re-proved each one by mutation: the guardrail evidence-fingerprint
   keying gap (its §4.4), the four unported `ferrogate-cloudflare` slices (its
   §6.1), and three of its nine UNVERIFIED items (workflow-budget CAS,
   guardrail-binding generation CAS, payment-attempt CAS).
2. **`packages/sso`, `packages/identity` and `packages/cloudflare` — the three
   never-certified packages — are the strongest code in the tree**, not the
   weakest; the OIDC relying party in particular is a *superset* of the Rust,
   which validated no `nonce` at all.
3. **The `sync-bridge` deletion was correct** and I re-derived the reasoning
   from the Rust rather than accepting the prior ruling.
4. **Exactly ONE CLASS A item survives in this scope** (L1: Cloudflare AI
   Gateway routing, #406) — and it is a *composition-root* defect in
   `apps/gateway`, not a library defect: `packages/providers` and
   `packages/config` both carry the feature completely and correctly.
5. **Three security-or-parity invariants are implemented correctly and held by
   NOTHING** (L2, L3, L4) — all three found by mutations that SURVIVED this
   wave, all three test-only to close, none of them a Rust regression.

**Recommendation for the library layer: GO, conditional on L1.** L1 is three
edits that are already enumerated in the source marker. L2–L4 are hours of test
work and should land in the same wave, because "correct code, green tests that
do not hold it" is this project's documented dominant defect mode and all three
are instances of it.

---

## 1. Measurements — all re-derived this wave

| Metric | Value | Method |
|---|---:|---|
| `bun run test` at the root | **exit 0**, 24 vitest projects, **0 failed, 0 skipped** | run twice (start + end of this audit) |
| Total tests | **6,633** (6,624 passed + 9 todo) | per-project totals, summed |
| `packages/*` alone | **139 test files · 2,719 tests** (2,710 passed + 9 todo) | each package's own `bun run test`, run SERIALLY |
| `apps/*` alone | 203 test files · 3,914 tests | root run |
| `bun run typecheck` | **exit 0**, 21 named projects + `e2e` = **22**, zero diagnostics | root |
| Rust, everything | 455,938 lines / 726 files | `find crates -name '*.rs'` |
| Rust, production-only (est.) | **≈220,180 lines / 374 files** | per-file: count to the FIRST `#[cfg(test)]`, drop `*_test.rs`, `tests/`, `examples/` |
| TypeScript source (`packages/*/src` + `apps/*/src`) | **142,495 lines / 499 files** | `find` |
| `PORT-TODO` markers in `packages/*/src` | **51** | grep |
| `PORT-TODO` markers in `apps/*/src` | 100 | grep |

> **Correction to `cutover-parity-libraries.md` §0.** That document reported
> production Rust as "≈22k lines" and used it to argue the 456k-vs-121k ratio
> was harmless. **That number is wrong by an order of magnitude** — its
> heuristic evidently cut at the first `#[cfg(test)]` seen *anywhere* rather
> than per file. The honest comparison is **≈220k production Rust vs 142k TS
> source**, and the gap is still not a missing-code signal: `ferrogate-storage`
> alone is ≈46k, of which `lib.rs` is ≈15k of trait definitions plus a full
> in-memory reference store, and its TS successor externalises the schema into
> `sql/d1-ts/**` (1,533 SQL lines) instead of embedding it. But the ratio should
> be stated correctly rather than flattered.

### Per-package size census

| package | src files / lines | test files / lines | tests | Rust crate (prod. lines est.) |
|---|---:|---:|---:|---|
| `billing` | 7 / 1,765 | 7 / 984 | 74 | `ferrogate-billing` (2,151) |
| `cloudflare` | 9 / 1,935 | 9 / 1,822 | 146 | `ferrogate-cloudflare` (2,848) |
| `config` | 29 / 8,532 | 15 / 6,060 | 757 | `ferrogate-config` (18,666) |
| `core` | 7 / 435 | 6 / 338 | 31 | `ferrogate-core` (215) |
| `guardrails` | 19 / 6,716 | 13 / 2,646 | 439 | `ferrogate-guardrails` (6,941) |
| `identity` | 18 / 2,982 | 10 / 2,260 | 136 | `ferrogate-auth-service::{sso,scim}` |
| `observability` | 9 / 2,476 | 7 / 1,101 | 67 | `ferrogate-observability` (2,116) |
| `payments` | 9 / 2,183 | 6 / 1,151 | 54 | `ferrogate-payments` (2,032) |
| `policy` | 11 / 2,530 | 6 / 1,704 | 113 | `ferrogate-policy` (2,134) |
| `providers` | 19 / 4,422 | 5 / 1,086 | 75 | `ferrogate-providers` (4,555) |
| `routing` | 5 / 416 | 5 / 343 | 28 | `ferrogate-routing` (136) |
| `schemas` | 2 / 276 | 6 / 616 | 56 | — (barrel over `core`) |
| `secrets` | 12 / 1,899 | 7 / 893 | 79 | `ferrogate-secrets` (1,190) |
| `sso` | 17 / 2,256 | 10 / 1,794 | 110 | `ferrogate-auth-service::saml` (551) |
| `storage` | 36 / 9,998 | 36 / 7,238 | 554 | `ferrogate-storage` (46,061) |

---

## 2. Roster change since the last certification

| Change | Verdict |
|---|---|
| `packages/sso` — NEW, never certified | certified below (§5.1) |
| `packages/identity` — NEW, never certified | certified below (§5.2) |
| `packages/cloudflare` — NEW, never certified | certified below (§5.3); **closes the previous audit's §6.1** |
| `packages/sync-bridge` — DELETED | **deletion CONFIRMED correct** (§6) |

**Net: 13 → 15 packages.** `PORT-PLAN.md` still carries a
`ferrogate-sync-bridge → packages/sync-bridge` row (line 83) and lists
`sync-bridge` in the wave-2 task list (line 162). Those are now stale prose
pointing at a directory that does not exist. Cosmetic, but it is exactly the
class of map error that hid `ferrogate-cloudflare` for sixteen waves, so it
should be fixed rather than left.

---

## 3. Mutation protocol

For every "a test would fail if this regressed" claim:

`cp` the file → apply the edit with a Python literal replace carrying
`assert count == 1` → **re-read the file OFF DISK and assert the new text is
present AND the old text is gone** → run the owning project's `bun run test` →
restore from the copy → re-read and confirm.

The confirm-off-disk step is not ceremony. A concurrent dev-loop agent landed
work in this tree *while this audit ran* (`apps/gateway`'s and
`apps/control-plane`'s test counts were stable, but tasks #141–#143 changed state
mid-session), and a silently-clobbered mutation is indistinguishable from an
ungated seam. Every mutation below was additionally checked to be **semantically**
real, not merely a byte change — e.g. the wallet predicate was replaced with a
tautology that PRESERVES the statement shape and bind order, so it could not
"pass" by breaking SQL arity.

**Every mutation in this document was reverted.** A final root `bun run test`
after the last revert: 24 projects, exit 0, zero `FAIL` tokens.

---

## 4. The correctness-critical algorithm families

### 4.0 Scoreboard

| Family | TS reproduces it? | Would a test fail if it regressed? |
|---|---|---|
| policy — multi-level quota merge (min-across, allowlist intersection) | ✅ verbatim | ✅ **RED** (4 + 2 tests) |
| policy — counter-key namespacing (SECURITY) | ✅ + hardened past Rust | ✅ **RED** (1 unit + ~40 gateway) |
| billing — settled-cost authority, fail-closed `price_not_found`, bigint credits, idempotency, outbox | ✅ | ✅ **RED** (2 unit + 4 gateway) |
| storage — wallet no-oversell | ✅ (primitive re-expressed) | ✅ **RED** (3 concurrency tests) |
| storage — workflow-budget CAS | ✅ | ✅ **RED** (2) — *was UNVERIFIED* |
| storage — guardrail-binding generation CAS | ✅ | ✅ **RED** (2) — *was UNVERIFIED* |
| storage — payment-attempt state machine | ✅ | ✅ **RED** (1) — *was UNVERIFIED* |
| storage — monotonic upserts | ✅ | ✅ **RED** (2) |
| storage — **cents ↔ credits (wave 17)** | ✅ exact `bigint`, no float | ✅ **RED** (1) |
| guardrails — detector families | ✅ set-equal, regexes char-identical | ✅ (vocabulary diffed mechanically) |
| guardrails — HMAC evidence fingerprints | ✅ | ✅ **RED at all 3 sites** — *was the previous audit's ONE finding* |
| guardrails — bounded findings (mechanism) | ✅ | ✅ (fail-closed marker, unredactability, negative control) |
| guardrails — bounded findings (**the cap VALUE**) | ✅ 10,000 | ❌ **SURVIVED** → L4 |
| guardrails — custom_http bulkhead / deadline | ✅ | ✅ (deadline + semaphore suites) |
| guardrails — custom_http breaker `affects_circuit` rule | ✅ faithful | ❌ **SURVIVED** → L3 |
| providers — adapter coverage 8/8, alias table | ✅ byte-identical | ✅ (family registry test) |
| providers — retry predicate | ✅ | ✅ **RED** (1) |
| routing — deterministic canary bucketing (FNV-1a-64) | ✅ byte-identical | ✅ **RED** (known vectors) |
| config — `validate()` census | ✅ 56 / 56 portable | ✅ **RED** (49 tests on one unmount) |
| sso — SAML raw-octet signature verification | ✅ + hardened | ✅ **RED** (8) |
| identity — OIDC `aud`/`iss`/`exp`/`nonce`/PKCE/state | ✅ superset of Rust | ✅ **RED** (5 on nonce alone) |
| identity — JWKS rotation (happy path + forced refresh + cooldown) | ✅ | ✅ (4 tests) |
| identity — JWKS **refuse-to-serve-stale on fetch failure** | ✅ | ❌ **SURVIVED** → L2 |
| identity — SCIM tenant authz | ✅ + exact-scope hardening | ✅ **RED** (1) |

---

### 4.1 policy — the quota merge and the counter-key namespace

**Merge.** `packages/policy/src/quota.ts::resolveEffectiveQuota` reproduces
`crates/ferrogate-policy/src/quota.rs`: scope chain `tenant → project →
workspace → key`; `deniedBy` short-circuits on the FIRST disabled policy; the
six numeric dimensions are `min`-across-the-chain with the winning scope
recorded; `modelAllowlist` is the INTERSECTION of every scope declaring a
non-empty list (empty = "no opinion", not "deny all"); `assetStorageQuotaBytes`
/ `assetMaxObjectBytes` are tenant-only; plan floors fill only where no policy
spoke.

The tie rule is preserved exactly: `updateMinScope` (line 110) overrides on
`<=`, so given the tenant→key iteration order a tie goes to the MOST SPECIFIC
scope — which is what keeps a per-key cap counted per-key rather than collapsing
onto the tenant window.

**MUTATIONS (both RED).**

| Mutation | Result |
|---|---|
| `updateMinScope`: `candidate <= current.value` → `>=` (min-across becomes max-across) | `packages/policy` **RED, 4 tests**, incl. "workspace cannot widen tenant ceiling" and "winning scope recorded per dimension" |
| allowlist intersection → union (`.filter(...)` → `new Set([...a, ...b])`) | `packages/policy` **RED, 2 tests**, incl. "a contradictory intersection denies every model" |

**The counter-key namespace (SECURITY-CRITICAL).**
`QuotaScopeSelector.counterKey` returns `` `key:${apiKeyId}` `` for a key winner
and `` `${kind}:${id}` `` otherwise, so a tenant that mints a virtual key whose
id is literally `tenant:victim` produces `key:tenant:victim` — structurally
unable to equal the victim's aggregate window.

**MUTATION (RED, and RED on the DEPLOYED path).** `counterKey` → return the raw
`apiKeyId` for the `key` scope:
- `packages/policy` → **RED**, `test/quota.test.ts` "counter_key is namespaced
  for every scope including key (cross-tenant DoS guard)";
- `apps/gateway` → **RED across ~20 named test files** — `auth.test.ts`,
  `contract.test.ts`, `rbac.test.ts`, `lifecycle-chain.test.ts`,
  `assets/egress.test.ts`, `assets/r2.test.ts`, `assets/governed-actions.test.ts`
  and more, including `SELF.fetch` end-to-end requests. The derivation is
  therefore gated on the Worker the deploy actually runs, not only in the unit.

The port also closes a hole the Rust still has:
`crates/ferrogate-gateway/src/auth.rs:225` (`tpm_window`) falls back to
`api_key_id.to_string()` — the RAW id, unprefixed — when the TPM limit has no
winning scope, a state reachable when the chain carries no tenant id.
`apps/gateway/src/ratelimit/keys.ts` namespaces both dimensions and adds
`assertNamespacedCounterKey`, a fail-closed boundary guard invoked by
**every** limiter (`do-limiter.ts:46`, `memory.ts:53`) so a future call site
cannot silently reintroduce the raw-id path.

**Verdict: PARITY + one documented hardening. Held, on the deployed path.**

### 4.2 billing

`packages/billing/src/ledger.ts::charge` reproduces `ledger.rs::charge`:
gateway-settled cost is authoritative (#135) with the price book consulted only
for the input/output split; drift is logged and never enforced (#152, same 5%
relative / $0.0001 absolute tolerance, Rust's `tracing::warn!` correctly ported
to an injected `onDivergence` callback rather than a global logger inside a
package with no I/O); `price_not_found` is fail-closed (#129) and maps to HTTP
422 in `service.ts:75` exactly as `service.rs:251`; `ledgerEntryId` is
`ferrogate:{trace}:{request}` byte-identically.

**Integer credits as `bigint` end to end.** `wallet_delta_credits` /
`wallet_balance_after_credits` are `bigint` in `event.ts` and `ledger.ts`,
parsed by `z.union([z.bigint(), z.number().int()])` so a JSON-number wire value
round-trips, compared by widening both sides. `credits_for_usd` is `f64` in Rust
and `number` in TS — that is parity, not a leak; the derived credit *rate* is
floating on both sides.

**MUTATION (RED, unit AND deployed).** Neutralise the throw and fall through to
a zero-cost entry — the exact "bill nothing instead of refusing" regression:
- `packages/billing` → **RED, 2** (`ledger.test.ts`, `service.test.ts`);
- `apps/gateway` → **RED, 4** — `metering/durable.test.ts` "persists NOTHING for
  a model with no rate-card rule", `metering/gateway.test.ts` "bills NOTHING…",
  and two in `metering/sink.test.ts`. Three of the four assert the ABSENCE of a
  row, which is the property that actually matters.

**Durable outbox.** `packages/storage/src/d1/billing-d1.ts` implements
`append_billing_event_with_outbox_enqueue` — the event claim and the
`billing_report_outbox` row in ONE transaction, "only a claim that WON enqueues",
with attempts / `next_attempt_unix` / `dead_lettered_at_unix` and a
dead-letter query. `apps/gateway/wrangler.toml` declares both `BILLING_DB` (D1)
and `BILLING` (Queue) with an extensively documented alias for the RBAC reader.

**Verdict: PARITY. Held.**

### 4.3 storage — including the wave-17 cents↔credits boundary

**Wallet no-oversell.** Rust took `SELECT … FOR UPDATE` + sum holds + compare +
insert inside one Postgres transaction. D1/SQLite has no `FOR UPDATE`, so
`d1/wallet-d1.ts:330` re-expresses it as a **single `db.batch([...])` of three
statements where the admission decision IS the insert**: S0 is the idempotency
probe (a replay with a different tenant or amount is a `conflict`, matching
Rust), S1 is the guard (`INSERT … SELECT … FROM wallets w WHERE w.tenant_id = ?
AND ? <= w.balance_credits - COALESCE((SELECT SUM(...) WHERE status='active' AND
expires_at_unix > ?), 0) ON CONFLICT DO NOTHING RETURNING id` — an empty
`RETURNING` is "not admitted"), S2 distinguishes `no_wallet` from `insufficient`.
Expired holds self-release on both sides. `requireAtomicBatch` runs FIRST on
every guarded write, so a transport that cannot offer an atomic batch throws
instead of silently running non-atomically.

**MUTATION (RED).** Balance predicate → the shape-preserving, arity-preserving
tautology `? >= -1 - 0 * COALESCE(…)`: **RED, 3 tests** in
`test/d1/wallet-d1.test.ts`, including 5 unawaited concurrent reserves against a
balance affording 4 (asserts exactly 4) and 20 against a balance affording 7
(asserts exactly 7), both re-reading `SUM(amount_credits)` off the real D1 in
workerd afterwards.

**Workflow-budget optimistic CAS — previously UNVERIFIED, now PROVEN.**
`d1/workflow-budget-d1.ts` implements three guarded `UPDATE … RETURNING`
statements. `casApplyDebit` guards on `status='active'` AND the exact counters
read AND the cap set; the increment is relative (`spent_x + ?`) so the value
written derives from the same committed row the guard checked. `casWriteCaps`
deliberately OMITS the counters from its guard so a top-up composes with
concurrent debits and conflicts only with concurrent top-ups — a subtlety worth
noting because getting it wrong would make top-ups spuriously fail under load.

**MUTATION (RED).** Neutralise the counter guard
(`AND spent_credits = ?` → `AND (spent_credits = ? OR 1=1)`, ×3, arity
preserved): **RED, 2 tests** — "10 parallel single-tool-call debits against a cap
of 4 apply exactly 4" and "12 parallel cost debits of 10 against a cost cap of 55
apply exactly 5".

**Guardrail-binding generation CAS — previously UNVERIFIED, now PROVEN.** The
pure transition builders (`packages/storage/src/guardrail-binding.ts`,
overflow-guarded `nextGuardrailBindingGeneration`) are shared verbatim by every
backend; the SQL CAS is `apps/gateway/src/guardrails/d1.ts`
(`GUARDRAIL_BINDING_UPDATE_CAS_SQL … WHERE policy_id = ?1 AND generation = ?6
RETURNING policy_id`, plus a separate INSERT arm gated on `NOT EXISTS`).

**MUTATION (RED).** `AND generation = ?6` → `AND (generation = ?6 OR 1=1)`:
`apps/gateway` → **RED, 2** — "the CAS is decided by SQLite, not by the read" and
"a lost UPDATE race is reported as a conflict, never as success".

**Payment-attempt state machine — previously UNVERIFIED, now PROVEN.**
`transitionPaymentAttempt` is a pure CAS: already-`toState` ⇒ idempotent; current
∈ `allowedFrom` AND generation matches ⇒ applied at `generation + 1`; else
conflict. `isPaymentAttemptStateTerminal` treats an unknown spelling as
non-terminal.

**MUTATION (RED).** Drop `currentGeneration === expectedGeneration` from the
applied branch: **RED, 1** — "CAS transition: conflict on a stale generation
(lost update)".

> **Correction to the prior audit.** It called this "the thinnest-covered item"
> because there is no `test/payment-attempt.test.ts`. There is not — the tests
> live in a `describe("payment-attempt state machine (deprioritized §1.5.4)")`
> block inside `test/site-domain.test.ts:51`. That is a **filing** problem, not a
> coverage problem; the guard is genuinely held. Move the block to its own file
> so the next reader does not repeat the mistake.

**Monotonic upserts.** `d1/monotonic.ts` uses SQLite's two-argument scalar
`max()` / `min()` idiom. **MUTATION (RED):** `last_seen_at_unix = max(…)` →
`min(…)`: **RED, 2** — "an OUT-OF-ORDER touch does not move last_seen backwards"
and "CONCURRENT touches all count and converge on the max timestamp".

**The wave-17 control-cents ↔ tenant-credits conversion — checked specifically
for float contamination, and CLEAN.** `packages/storage/src/credits.ts` is the
single conversion site and it is `bigint` throughout:

- `CREDITS_PER_USD = 1_000_000n`, `CENTS_PER_USD = 100n`,
  `CREDITS_PER_CENT = 10_000n` — exact by construction on the way in;
- `centsToCredits(cents: number): bigint` **refuses** any non-`Number.isSafeInteger`
  input rather than laundering it, then does `BigInt(cents) * CREDITS_PER_CENT`;
- `creditsToCents` is the only lossy direction, floors toward **negative
  infinity** (so a reported balance is never more than the customer has), and
  **nothing decides anything on its result** — every arithmetic decision is taken
  in credits;
- `bindCredits(credits: bigint): string` marshals as a DECIMAL STRING because D1
  rejects a `bigint` parameter outright and a `number` is lossy past 2^53, and it
  range-checks against int64 first (past which SQLite would store a REAL and
  start drifting *inside* the database — the one failure no reader could later
  detect);
- `creditsFromText` is the exact reader and **throws** if a credit column arrives
  as a non-safe-integer double, which is why the exact queries select
  `CAST(<column> AS TEXT)`.

`apps/control-plane/src/store/wallet_projection.ts` and `routes/wallets.ts` route
every adjust/charge through `centsToCredits`, and the only `Number(...)` on the
path is `balance_after_cents: Number(creditsToCents(nextCredits))` — a DISPLAY
field whose magnitude is bounded by int64/10,000 ≈ 9.2e14, comfortably inside
2^53.

**MUTATION (RED).** `BigInt(cents) * CREDITS_PER_CENT` →
`BigInt(cents * Number(CREDITS_PER_CENT))` (the exact float contamination the
module exists to prevent): **RED, 1** — `credits.test.ts` "is exact where a
`number` multiply is not".

**Bounded deviation, recorded not hidden (→ L9).** The conversion boundary is
exact, but `packages/storage/src/wallet.ts`'s *reservation* surface still carries
`amountCredits` / `balanceCredits` / `availableCredits` as `number`, while
`ensureWallet` / `settleWalletBalance` / `balanceCreditsExact` are `bigint`-exact.
Per-request reservation amounts are tiny, so nothing is reachable today; but two
integer domains meet in one file and no test asserts the 2^53 boundary.

**Verdict: PARITY on every member of the family, all mutation-held.**

### 4.4 guardrails — code parity, and TWO surviving mutations

**Detector families — mechanically diffed, IDENTICAL.** I extracted every dotted
string literal from `deterministic.rs` and `deterministic.ts`: both sides emit
exactly `detector.truncated`, `request.endpoint`, `request.model`,
`request.provider`, `secret.aws_access_key_id`, `secret.github_token`,
`secret.openai_api_key`, `size.input_bytes` — **set-equal, no extras on either
side**. The three secret patterns are **character-identical**:
`\bsk-(?:proj-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})\b`,
`\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b`,
`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`.

**Non-persisted evidence.** `matched_text` is `null` at every construction site.

**HMAC-fingerprinted evidence — THE PRIOR AUDIT'S ONE FINDING IS CLOSED.** Its
§4.4 reported that both fingerprint sites HMAC correctly but every assertion in
the tree was a SHAPE assertion (`/^hmac-sha256:[0-9a-f]{64}$/`) an *unkeyed*
SHA-256 also satisfies, and that two semantically-real mutations both left
407/407 GREEN. `packages/guardrails/test/fingerprint-keying.test.ts` now exists
and covers all three sites with the right assertion shape (different keys ⇒
different fingerprints; NOT the unkeyed digest; NOT the empty-key HMAC; IS
exactly HMAC-SHA-256 per an independent oracle; same key ⇒ stable).

**MUTATIONS (both RED — the exact two the prior audit ran).**

| Mutation | Then | Now |
|---|---|---|
| `hmacEvidenceFingerprint`: `key.asBytes()` → `new Uint8Array(0)` | 407/407 GREEN | **RED, 10+ tests** across SITE 1, SITE 3 (`WorkersAiLlamaGuard`, `LlmGuardPromptInjection`, `Presidio`) |
| `DeterministicDetector#hmacFingerprint`: key → the constant `"FIXED"` | 407/407 GREEN | **RED, 3 tests** (SITE 2) |

**Bounded findings — mechanism held, VALUE not (→ L4).**
`MAX_FINDINGS_PER_EVALUATION = 10_000` in both. The test at
`test/deterministic.test.ts:220` is genuinely excellent about the *mechanism*: it
asserts exactly one truncation marker, that it is LAST, that it is zero-width at
`[0,0)` and therefore **unredactable by construction** (re-deriving Rust's
`has_unredactable_findings` predicate inline and proving the predicate is not
vacuously false against an ordinary finding), plus a negative control that a
below-cap input emits no marker.

But it computes both its input size (`MAX_FINDINGS_PER_EVALUATION + 500`) and its
expectation (`MAX_FINDINGS_PER_EVALUATION + 1`) **from the constant**, so the
constant is free.

**MUTATION (SURVIVED).** `10_000` → `20_000`: **439/439 GREEN.**

**custom_http bulkhead / breaker / deadline — one surviving mutation (→ L3).**
The port is faithful: the deadline is checked BEFORE execution, the semaphore is
acquired with the remaining budget, `circuitFailureThreshold` /
`circuitCooldownMs` / `halfOpenProbe` reproduce `custom_http.rs`'s
`enter_circuit` / `record_failure` line for line, including the rule that an
error which does NOT `affects_circuit()` **resets the half-open probe and does
not increment `consecutive_failures`** (Rust `custom_http.rs:169`, TS
`custom_http.ts:151`).

The *taxonomy* is pinned (`test/contract.test.ts:22` asserts
`timeout`/`invalid_response` → true, `unauthorized` → false). The breaker's
*consumption* of it is not.

**MUTATION (SURVIVED).** Delete the `if (!error.affectsCircuit()) { … return; }`
early return, so an unauthorized/policy error counts toward the breaker:
**439/439 GREEN.** A detector misconfigured to return 401 would trip its own
circuit open and every request would take the fallback path, invisibly to the
suite.

**Verdict: code PARITY, complete. Two evidence gaps (L3, L4), both test-only.**

### 4.5 providers / routing

**Adapter coverage: 8/8, exhaustive.** `crates/ferrogate-providers/src/` and
`packages/providers/src/` map 1:1 on every non-infrastructure module
(`anthropic`, `anthropic_messages`, `azure`, `bedrock`, `canonical`,
`cloudflare`, `gemini`, `grok`, `models`, `openai`, `openrouter`, `registry`,
`sigv4`, `types`, `vertex`); the TS extras are `crypto`, `json`, `schemas`,
`index` (the last replacing Rust's `lib`).

**Alias table: byte-identical, order-identical.** I extracted every string
literal from both `SUPPORTED_PROVIDER_ADAPTER_FAMILIES` bodies. After removing
the TS enum-variant names Rust expresses as an `enum` (`OpenAiCompatible`,
`Anthropic`, …), the alias sequence is **exactly equal**, down to the 13
OpenAI-compatible aliases in order (`openai`, `deepseek`, `newapi`, `sub2api`,
`cliproxyapi`, `cli-proxy-api`, `vllm`, `llama.cpp`, `llama-cpp`, `llamacpp`,
`tgi`, `ollama`, `ollama-compatible`) and the `xai`, `azure`, `aws-bedrock`,
`vertex-ai` singles.

**Retry predicate.** `types.rs:465` `status == 429 || (500..=599)` ⇔
`types.ts:368`. `apps/gateway/src/inference/reliability.ts:84` wraps
`adapterFor`'s throw in `catch → false`, reproducing Rust's `.unwrap_or(false)`:
an unidentifiable family is NOT retried.

**MUTATION (RED).** Drop the `429` arm: `packages/providers` → **RED**,
`registry-cloudflare.test.ts` "wraps error normalization + retryable
classification".

**Circuit breaker + failover ladder.** `reliability.ts` ports
`ProviderCircuitState`, `attemptDecision` and `dispatchWithFailover`, and — the
part that makes the wiring a wiring change rather than a behaviour change —
reproduces Rust's defaults, where **both are OFF**:
`provider_dispatch_max_retries` is `unwrap_or_default()` ⇒ 0, and the breaker
config is built with `?` over both threshold and cooldown ⇒ absent unless an
operator sets both. `catalog.ts` preserves Rust's asymmetric fallback defaults
(primary ⇒ `priority 0, weight 1`; fallback ⇒ `priority 100, weight 1`) —
getting that wrong would let an alphabetically-earlier fallback outrank the
primary.

**Deterministic canary bucketing: byte-identical.** `packages/routing/src/fnv.ts`
reproduces FNV-1a-64 with `bigint` and an explicit 64-bit mask emulating Rust's
`wrapping_mul`, and the `salt \0 stickyKey` UTF-8 framing verbatim.
`canarySelected` / `shadowSampled` keep the `0 ⇒ never` / `>=100 ⇒ always`
short-circuits and the distinct `"canary"` / `"shadow"` salts.

**MUTATION (RED).** FNV prime `…01b3n` → `…01b5n`: `packages/routing` → **RED**,
`test/fnv.test.ts` "known vectors".

*Honest scoping, unchanged from the prior audit and re-confirmed:* only the
known-vector test goes red. The distribution tests compute their expectation from
the package's own `rolloutBucket`, so they are self-consistent by construction —
correct for proving the gateway MOUNTS the package, but they do not pin values to
Rust. The pinning comes from the three canonical FNV-1a-64 vectors plus the
`rolloutBucket("ab","c") !== rolloutBucket("a","bc")` separator test. **There is
still no Rust-generated golden bucket table**, and the window to generate one
closes when `crates/**` is deleted.

**Verdict: PARITY on every algorithm. The unmounted routing leg is L1.**

### 4.6 config — the `validate()` census, re-derived mechanically

I extracted every `fn validate_*` from `crates/ferrogate-config/src/**` and every
`function validate*` from `packages/config/src/**` and diffed them under
snake→camel:

| Bucket | Count | Detail |
|---|---:|---|
| Rust validators with a direct TS twin | **54** | same name, camelCased |
| Rust validators merged into one TS function | **2 → 1** | `validate_positive_optional_u32` + `_u64` → `validatePositiveOptional` (TS has one number type) |
| Rust validators DELIBERATELY dropped | **5** | `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`, `validate_acme_http01_tls`, `validate_manual_tls_files` |
| TS validators with no Rust twin | **14** | 12 MCP/capability/detector/JSON-shape validators + `validateConfig` / `validateConfigAsync` (entry points) |
| **Rust total / TS total** | **61 / 68** | |

**Portable coverage is 56 of 56.**

**What each MISSING one means operationally — the question the brief asks, and
it is answered rather than dodged.** I read all five in the Rust: they are
**fully implemented, not stubs** (`validate_tls` at `validate.rs:547` rejects
`acme.enabled` combined with `cert_path`/`key_path`, requires both paths when TLS
is on, and delegates to `validate_manual_tls_files`). So the naive failure mode
is real: a config that SHOULD be rejected would be silently accepted, telling an
operator TLS is configured when it is not.

The compensating control is `packages/config/src/validate/sections.ts:736
inertTlsWarnings`, and it is genuinely reached — `loader.ts:103` splices it into
every load, and `test/platform-limits.test.ts:149` drives it **through the
loader** rather than by calling it directly. `[tls]` and `[tls.acme]` still
DECODE (so a legacy TOML/Caddyfile round-trips, matching Rust's acceptance) but
the load emits an explicit INERT warning naming exactly why the section cannot
work: the edge terminates TLS before the Worker is invoked, a Worker cannot own
the `:80` HTTP-01 challenge listener, has no filesystem for the ACME
`storage_dir`, and cannot exec a DNS-01 hook. Warn-only on purpose, with the
reason written down (refusing would break the Caddyfile migration path Rust
accepts). The genuinely-portable half of the TLS surface is KEPT and still
validated: `admin_api.tls_cert_path`/`tls_key_path` must be set together, and
`storage.postgres_tls_mode` is still checked.

**MUTATION (RED).** Unmount ONE validator — replace the
`validateGuardrails(config, apiKeyIds, modelNames, providerNames)` call at
`validate.ts:398` with `void [...]` (so the bindings stay used and the mutation
is about REACHING the validator, not about compiling): `packages/config` →
**RED, 49 of 757 tests**. A silently-dropped validator cannot hide.

**CLASS C. Verdict: PARITY, 56/56 portable, absences compensated and explained.**

---

## 5. The three never-certified packages

### 5.1 `packages/sso` — SAML 2.0 SP (vs `ferrogate-auth-service::saml`, 551 prod lines)

The Rust is **finished and was wired** (`sso.rs::handle_saml_authorize` /
`handle_saml_acs` serve real routes), so this is a genuine parity target, not a
Class B stub.

**Binding choice preserved, and it is the right one.** Both sides implement the
**HTTP-Redirect binding**, whose signature is a *detached* RSA signature over the
URL query octet string — deliberately avoiding XML-DSig exclusive C14N entirely.
Verify first, parse the now-authenticated XML second. `flow.ts:148` enforces that
ordering explicitly and says why.

**Raw-octet signature verification — the security core, reproduced exactly.**
`RedirectBindingParams` keeps `*Raw` fields holding the EXACT percent-encoded
octets as received and never re-serialises. `signedOctetString()` rebuilds
`SAMLResponse=…[&RelayState=…]&SigAlg=…` in the binding's **fixed spec order**,
not the received order. A repeated parameter takes the LAST occurrence, matching
the Rust loop — and, as the docstring notes, what matters is not *which* wins but
that the SAME occurrence feeds both the signed string and the decoded payload,
or an attacker could append a second `SAMLResponse` and have the signature
checked against one and the assertion parsed from the other.

**MUTATION (RED).** Verify over a re-serialised form
(`SAMLResponse=${this.samlResponseRaw}` → `${urldecode(this.samlResponseRaw)}`):
`packages/sso` → **RED, 8 tests**, including — by name — *"a signature valid over
a RE-SERIALISED form but not the raw octets is refused"* and *"the signed octet
string is rebuilt in the binding's fixed order, not the received order"*. Those
tests were written to catch precisely this.

**Certificate handling.** `x509.ts` walks the DER by hand rather than trusting a
library: it detects `[0] EXPLICIT version` from the context tag (so the SPKI is
the 6th child for v1 and the 7th for v2/v3 rather than assumed), rejects trailing
octets after the `Certificate` SEQUENCE, requires the `rsaEncryption` OID
`1.2.840.113549.1.1.1`, and rejects a BIT STRING with non-zero unused bits. It
returns BOTH `spki` (what WebCrypto's `importKey` consumes) and `pkcs1` (the Rust
port's observable output, kept so the two ports stay diffable) — a thoughtful
choice, since `ring` consumed the bare `RSAPublicKey` and WebCrypto consumes the
enclosing SPKI.

It also refuses a non-RSA certificate **at config time** rather than leaning on
the verifier to fail at every user's first login — a deliberate improvement,
documented as one.

**The trust model is stated honestly, not glossed.** `x509.ts:155-181` records
that workerd has no trust store, so this port does not and cannot validate a
chain, honour `notBefore`/`notAfter` on the certificate, or consult a CRL/OCSP
responder — **and that the Rust did not either**. SAML IdP signing certificates
are conventionally self-signed and pinned out of band; the configured certificate
IS the trust anchor. What a tenant loses relative to a CA model is revocation and
expiry, which is inherent to key pinning and identical on both sides.

**Assertion validation: every Rust check present, in Rust's order** — status must
be `Success`, `InResponseTo` must match the pending request, `Issuer` must equal
the configured `saml_idp_entity_id`, the audience must include this SP,
`NotBefore`/`NotOnOrAfter` are skew-adjusted by the same 300 s
(`SAML_CLOCK_SKEW_SECS`), and the email falls back configured-attribute → `email`
→ `mail` → the WS-Federation claim URI → `NameID`, then must pass
`is_valid_email`. Every failure is a hard rejection.

Two deliberate hardenings over Rust, both correct:
- `asciiLowercase` re-implements Rust's `to_ascii_lowercase` rather than using
  `String.prototype.toLowerCase`, which is Unicode-aware and would fold
  characters Rust leaves alone (Turkish `İ`, the Kelvin sign) — two IdP users
  could collapse onto one account here but not there;
- size caps (`MAX_SAML_RESPONSE_B64_CHARS`, `MAX_INFLATED_SAML_RESPONSE_BYTES`)
  and a `fatal: true` UTF-8 decoder, so a malformed sequence is a refusal rather
  than a run of U+FFFD that could make two readers disagree about a value.

**The replay defence is structurally correct AND cross-checked against the
durable twin.** `handleSamlAcs` consumes the flow state via `ports.flows.take` —
the only replay defence, since the signature stays valid forever.
`packages/sso/src/store-contract.ts` exports an **executable contract** run by
both `packages/sso/test/store-contract.test.ts` (in-memory) and
`apps/control-plane/test/sso-store-contract.test.ts:55` (D1), and it contains
*"presenting an EXPIRED state still burns it"* plus *"concurrent takes of the
same state: exactly ONE wins"* and a full field round-trip. **This is the direct
structural fix for the wave-15 defect where a D1 SSO store did not burn EXPIRED
state because only the in-memory twin was ever run against the contract.**

**One minor sharp edge, recorded not inflated.** `flow.ts:173` passes
`spEntityId: stored.samlSpEntityId ?? ""` into the audience check. A config
missing `saml_sp_entity_id` is refused on the *authorize* leg (`saml_config_incomplete`,
500) but not on the ACS leg, so the audience comparison would be against `""`. It
is not reachable as an attack — the assertion must already have verified against
the tenant's pinned certificate — but a symmetric `saml_config_incomplete` guard
in `handleSamlAcs` would cost one line.

**Verdict: PARITY + hardening. 110 tests. Mutation-held.**

### 5.2 `packages/identity` — OIDC RP + SCIM 2.0 (vs `ferrogate-auth-service::{sso,scim}`)

**This package is a SUPERSET of the Rust, and the difference is a security fix.**

Reading `sso.rs::handle_sso_authorize` (line 459 onward) and
`handle_sso_callback`: the Rust authorize URL is
`…?response_type=code&client_id=…&redirect_uri=…&scope=openid%20email%20profile&state=…&code_challenge=…&code_challenge_method=S256`.
**There is no `nonce` parameter, and `handle_sso_callback` performs no nonce
check.** Rust validates `iss` (`validation.set_issuer`), `aud`
(`validation.set_audience`), `exp` (jsonwebtoken's default), signature-by-`kid`
against a JWKS fetched fresh on every callback, and — a genuinely good touch —
rejects an explicit `email_verified: false`. But OIDC's answer to code/token
injection is absent.

`packages/identity/src/oidc/claims.ts` adds it and treats it as required:
`nonce` must be **strictly a string and strictly equal** (a non-string that
stringifies to the expected value, e.g. `["nonce-123"]`, is a forgery, not a
match). The schema migration `sql/d1-ts/control/0002_sso_flow_nonce.sql` persists
it. The module also adds `azp` enforcement for multi-audience tokens, `iat`/`nbf`
future-dating checks, a `sub` presence check, and a 60 s skew — deliberately an
order of magnitude tighter than the SAML 300 s, with the reason written down (the
ID token arrives over a back-channel exchange this service performs itself, so
the only clock difference in play is IdP-vs-Worker, not a browser's).

`iss` is an **exact match after normalising exactly one trailing slash, NOT a
prefix match** — the comment names the bypass (`https://idp.test.evil.example`
passes a naive `startsWith`).

**MUTATION (RED).** Disable the nonce check: **RED, 5 tests** — three in
`oidc-claims.test.ts` (wrong nonce, no nonce, non-string nonce that stringifies
correctly) and two in `oidc-flow.test.ts` driving the whole callback
("REFUSES an ID token carrying the WRONG nonce (token injection)").

**JWS verification (`jws.ts`) is exemplary, including its own honesty.** The
algorithm comes from an **allow-list**, never from the token: `none` and `HS*`
are simply absent, so algorithm-confusion is refused before a key is imported.
Every failure returns a refusal value; nothing throws, so a caller cannot mistake
an exception path for "verified". The header's own `alg` must equal the one the
caller asked to verify under.

And the module docblock states plainly that its `kty`/`crv`/`jwk.alg` guards are
**redundant defence in depth, not a tested control** — that removing all three
leaves the suite GREEN because `crypto.subtle.importKey` rejects the same inputs
one line later, with the probe results printed inline — while naming the two
mutations that DO go red (`M1` deleting the verify-result check, `M3` falling
back to RS256 for an unknown `alg`). That is exactly the calibration this project
has been asking for: claim what is proven, disclaim what is not.

**JWKS rotation.** `jwks.ts` adds a cache the Rust did not have (Rust refetched
per callback). Positive TTL 300 s, chosen as the bound on how long a WITHDRAWN
key can still be honoured, matched to the documented Okta/Entra/Auth0 key-retirement
propagation window. An unknown `kid` forces ONE immediate refetch (a rotation
announces itself that way) **rate-limited to one per 30 s**, because the caller
controls the `kid` and without the cooldown the path is an unauthenticated
outbound-request amplifier at the IdP. Entries with `use !== "sig"` or a
`key_ops` lacking `verify` are filtered out. Four tests cover the TTL, the forced
refresh, the cooldown, and per-URI isolation.

**One surviving mutation here (→ L2).** See §7.

**SCIM tenant authz (`scim/auth.ts` vs `scim.rs::resolve_scim_tenant`).** The
architecture is right and stated: this is the ONE place a SCIM request acquires a
tenant, and the tenant it acquires is the one stamped on the provisioning key —
**nothing downstream ever takes a tenant id from a path segment, query parameter
or body field, so a SCIM token cannot ask for another tenant because there is no
channel through which to ask.** It reuses the same prefix+hash+active-check
api-key resolution the gateway uses, so revoking through
`/admin/v1/virtual-keys` takes effect here with no second code path, and it runs
`requireUsableTenancy` so a suspended tenant's SCIM token stops working.

The scope check is **exact equality**, deliberately not `startsWith` and not
case-insensitive, with the reason inline (`scim` and `scim.provisioning` are
different scopes). `SCIM_PROVISION_SCOPE` is deliberately NOT `admin.write`, so
the far more numerous `admin.write` holders are not silently also directory
administrators.

**MUTATION (RED).** `scope === SCIM_PROVISION_SCOPE` →
`scope.startsWith("scim")`: **RED, 1** — "scope matching is exact — a prefix or
superstring does not pass".

**Verdict: PARITY + a real security improvement over Rust. 136 tests.**

### 5.3 `packages/cloudflare` — CLOSES the previous audit's §6.1

The previous certification's single most material item was that
`ferrogate-cloudflare` — the 21st crate — had no TS equivalent at all, and that
four slices were "genuinely unported, with no TS equivalent anywhere". **All four
now exist**, and I verified each against the Rust rather than against the
changelog:

| §6.1 slice | TS | Fidelity check |
|---|---|---|
| 1. per-tenant R2 bucket provisioning (`r2.rs`) | `r2.ts` | `R2_BUCKET_NAME_MAX_LEN=63`, `MIN=3`, `R2_BUCKET_ALREADY_EXISTS_CODES=[10004,10073]`, `ensureTenantBucket`, the create/list/delete surface, and the `r2BucketPath` traversal guard all match |
| 2. scoped temporary R2 S3 credentials (`r2_token.rs`) | `r2-token.ts` | present, 1,822 test lines across the package |
| 3. `scopes.rs` + `preflight` | `scopes.ts` | **all 8 permission groups present, in the same order, with the same `access` strings**; `usedBy` prose differs slightly (TS drops issue numbers, adds "incl. tenant database lifecycle" and "distinct from the S3 key pair") — clearer, and `test/scopes.test.ts` pins every row verbatim |
| 4. shared retry/backoff + typed error taxonomy | `retry.ts`, `errors.ts`, `envelope.ts` | `maxRetries: 4`, `baseBackoffMs: 1_000`, `maxBackoffMs: 60_000` and `RETRYABLE_STATUSES = [429,500,502,503,504]` are **the Rust defaults verbatim** (`client.rs:140-170`); `Retry-After` wins, itself capped; arithmetic saturates (`Infinity` collapses to the cap) exactly as Rust's `checked_shl` + `saturating_mul` |

**One deliberate, documented divergence, and it is the right call.** Rust retried
EVERY method on a 5xx. `retry.ts` makes retry **opt-IN for non-GET**, defaulting
to GET-only, because a retried `POST /accounts/{id}/tokens` creates a SECOND
credential whose secret Cloudflare returns exactly once and can never be read
back. The schedule is also deterministic (no jitter) on purpose, so
`test/retry.test.ts` can assert the millisecond SEQUENCE rather than a call
count — a provability argument, made explicitly.

**MUTATION (RED).** Drop `429` from `RETRYABLE_STATUSES`: **RED, 4 tests** across
`retry.test.ts` and `client.test.ts` ("an exhausted 429 surfaces RateLimited
carrying the attempt count").

**One fidelity deviation found (→ L5).** `r2BucketNameForTenant` canonicalises as
`"{domain}:{len}:{tenant}"` before hashing. Rust's `len` is `tenant.len()` —
**UTF-8 bytes**. TS's is `tenant.length` — **UTF-16 code units**. For any tenant
id containing a non-ASCII character the two produce **different bucket names**.
The golden vectors pinned in `test/r2.test.ts` (`ferrogate-acme-59964e92…`,
`ferrogate-8785c455…` for `""`, `ferrogate-b50a9d2c…` for `"!!!"`) are all ASCII,
so nothing catches it. Injectivity within TS is preserved; only cross-port name
agreement is broken. Severity LOW — see §7 L5 for why.

**Verdict: the crate is now genuinely ported. 146 tests.**

---

## 6. Was deleting `sync-bridge` right? — YES, re-derived from the Rust

I did not accept the prior ruling. `crates/ferrogate-sync-bridge/src/lib.rs` is
**one 81-line function**, `block_on_sync_bridge(future) -> T`, which parks an OS
thread so a *synchronous* caller can drive an `.await`ing method. Its three
caller classes are:

1. synchronous Pingora filter hooks — **Pingora is eliminated**; the TS data plane
   is a Hono proxy that is `async` end to end;
2. a background sweep thread — **workerd has no threads**;
3. the Unix `SO_PEERCRED` external-action authorizer — **no CF equivalent exists**.

All three are eliminated *by construction*, not by omission.
`docs/legacy/inventory-edge-control.md` §7 already listed the crate's CF/TS
target as literally `Deleted`, and the deleted TS shim's own body had degenerated
to `return await started` — `await` with a docstring.

**Verification that the deletion was clean:** `grep -rn "sync-bridge"` over
`packages/`, `apps/`, `e2e/` and every `package.json` / `tsconfig.json` /
`wrangler.toml` returns **nothing** — the only remaining hits are historical
prose in `docs/`, plus the two stale `PORT-PLAN.md` lines noted in §2. `bun run
typecheck` is clean across all 22 projects and the full suite is green.

**CLASS C. Deletion CONFIRMED correct.**

---

## 7. Findings, classified

### L1 — CLASS A · MEDIUM · **the only cutover-blocking item in this scope**
### Cloudflare AI Gateway routing (#406) is unreachable in production

**The Rust side is FINISHED AND LIVE — I checked, because that is what decides
the class.** `crates/ferrogate-gateway/src/state.rs:1477` holds
`provider_adapters: Arc<ProviderAdapterRegistry>` and `state.rs:4850` constructs
it; `crates/ferrogate-providers/src/registry.rs:83,104,125` calls
`CloudflareRouting::capture(&provider)` on **every** prepare path and
`registry.rs:45` applies `apply_cloudflare_ai_gateway_routing`. The config side
is complete too: `types.rs:1413` carries
`Provider.cloudflare_ai_gateway: Option<…>` and `validate.rs:291`
(`validate_cloudflare_ai_gateway_providers`) enforces a top-level `[cloudflare]`
block, a non-empty `account_id`, a non-empty `gateway_id`, and a valid
`aig_token_secret_ref`. This is **not** a Rust stub. **CLASS A.**

**The TS LIBRARY layer is complete.**
`packages/providers/src/cloudflare.ts` (`applyCloudflareAiGatewayRouting`, the
per-family chat/messages/responses/embeddings surface map, BYOK auth
preservation) is fully ported and tested, `packages/providers/src/registry.ts`
applies it after preparation, and `packages/config` accepts and validates the
block (`schema/entities.ts:61`, `validate/sections.ts:798-805`, the port of
`validate_cloudflare_ai_gateway_providers`).

**The defect is at the `apps/gateway` composition root.**
`apps/gateway/src/inference/adapters.ts` builds its OWN `defaultAdapterRegistry`
by wrapping the eight adapter classes one at a time via
`packageProviderAdapter(kind, new XAdapter())`, never going through
`ProviderAdapterRegistry`. So the capture/apply is skipped on every request the
deployed data plane serves, and `applyCloudflareAiGatewayRouting` has zero
callers outside `packages/providers`.

It is also **not configurable on the deployed Worker**:
`apps/gateway/src/inference/catalog.ts:81` `providerRecordSchema` is `.strict()`
(line 136) and has no `cloudflare_ai_gateway` key, so a provider record carrying
the Rust block would be **REJECTED**, not ignored — a config-acceptance
regression on top of the feature regression.

**Consequence:** the AI Gateway product's free caching, rate-limiting and
observability are off for every tenant, and a Rust operator's working config
would be refused.

**Already marked, accurately, at `packages/providers/src/registry.ts:8`**, with
the three closing edits enumerated: (1) carry `cloudflare_ai_gateway` onto
`PhysicalRoute` in `catalog.ts`; (2) have `adapters.ts` delegate to
`ProviderAdapterRegistry`; (3) add a test asserting the PREPARED ENDPOINT is the
AI Gateway host — not merely that the function works when called directly, which
is what stays green today. **Owned by `apps/gateway`; cross-referenced here
because the library half is certified complete.**

### L2 — TEST GAP · security-relevant · TS-native (NOT a Rust regression)
### JWKS cache: nothing proves it refuses to serve a stale document when the refetch fails

`packages/identity/src/oidc/jwks.ts:88-98` — when the TTL has expired, the cache
refetches; if the refetch returns `null` it does
`this.entries.delete(jwksUri); return null;` with the comment *"Do NOT serve the
expired document: a stale key past its TTL is the rotated-away key this cache
exists to stop honouring."*

**MUTATION (SURVIVED).** Replace that branch with "serve the cached entry when
the refetch fails": **136/136 GREEN.**

The four existing JWKS tests do not reach it: *"does NOT serve a rotated-away key
past the TTL"* exercises a **successful** refetch that no longer publishes the
key, and all three fail-closed tests start from an **empty** cache. The
combination TTL-expired **+** populated cache **+** failing fetch is untested.

**Why it matters:** an attacker who can make the IdP's JWKS endpoint unreachable
— or a plain IdP outage — extends the life of a withdrawn or compromised signing
key **indefinitely**, which is the exact property the module's docblock claims to
provide.

**Class:** not CLASS A. The Rust had **no JWKS cache at all**
(`sso.rs::fetch_jwks` runs on every callback), so nothing was dropped; this is a
new TS invariant that arrived untested. It should still be closed, because
"correct code, green tests that do not hold it" is this project's documented
dominant defect mode.

**To close (test-only):** populate the cache, advance past `JWKS_CACHE_TTL_SECONDS`,
make the fetcher fail, assert `findKey` returns `null` **and** that a subsequent
successful fetch repopulates.

### L3 — TEST GAP · reliability · code is a faithful port
### The custom_http breaker's `affects_circuit` rule is held by nothing

`packages/guardrails/src/custom_http.ts:149-160` reproduces
`crates/ferrogate-guardrails/src/custom_http.rs:167-183` exactly, including the
rule that an error which does NOT affect the circuit resets `halfOpenProbe` and
returns **without** incrementing `consecutiveFailures`.

**MUTATION (SURVIVED).** Delete the early return: **439/439 GREEN.**

The taxonomy itself IS pinned (`test/contract.test.ts:22-25`). Its *use* is not.
A detector misconfigured to return 401/403 would trip its own circuit open —
every request silently taking the fallback path — and the suite would not notice.

**To close (test-only):** drive `circuitFailureThreshold` consecutive
`unauthorized` errors and assert the circuit stays CLOSED, plus the positive
control that the same count of `timeout` errors opens it.

### L4 — TEST GAP · LOW · the bounded-findings cap VALUE is unpinned

`MAX_FINDINGS_PER_EVALUATION = 10_000` matches Rust. The truncation *mechanism*
is very well tested (see §4.4). But the test derives BOTH its input size and its
expected length from the constant, so the constant is self-consistent by
construction.

**MUTATION (SURVIVED).** `10_000` → `20_000`: **439/439 GREEN.**

Not a bypass — it is a per-request memory bound, and doubling it doubles the
worst case. Same shape as the FNV distribution-test caveat in §4.5: correct for
proving the mechanism, useless for pinning the number.

**To close (test-only):** one literal assertion, `expect(MAX_FINDINGS_PER_EVALUATION).toBe(10_000)`,
with a comment citing `deterministic.rs`.

### L5 — DEVIATION · LOW · R2 bucket-name digest uses UTF-16 length

See §5.3. Rust length-prefixes with UTF-8 **bytes**, TS with UTF-16 **code
units**; they diverge for any non-ASCII tenant id. Injectivity within TS holds
and the ASCII golden vectors match.

Severity is LOW **because nothing consumes it on either side** — see L6 — so
there are no Rust-provisioned buckets whose names TS would fail to reproduce. It
becomes MEDIUM the moment tenant R2 provisioning is wired, because a bucket name
IS the tenant isolation boundary. **Fix is one line**
(`new TextEncoder().encode(tenant).length`) plus a non-ASCII golden vector, and it
is far cheaper to do now than after `crates/**` is gone.

### L6 — CLASS B · `packages/cloudflare`'s account-management surface has no consumer — and neither did Rust's

`@ferrogate/cloudflare` has exactly **ONE** importer in the whole tree:
`packages/storage/src/tenant-rest.ts` (for the retry policy). R2 provisioning,
scoped-token minting, `scopes`/`preflight` and the D1 database-lifecycle client
are unconsumed.

**Before calling that a gap I checked the Rust, and the Rust is the same.**
`grep`-ing every `.rs` outside the crate for `ensure_tenant_r2_bucket`,
`r2_bucket_name_for_tenant`, `create_scoped_r2_token` and `.preflight(` returns
**zero production call sites** — the only references are the crate's own tests
and three `examples/*_live_probe.rs` binaries. Nine crates list
`ferrogate-cloudflare` in `Cargo.toml`, but the actual `use ferrogate_cloudflare::`
sites are: `ferrogate-config` re-exporting `CloudflareConfig`;
`ferrogate-guardrails` using the HTTP client for Workers AI;
`ferrogate-gateway::state_assets.rs:613` + `server/asset_bucket.rs` using it for
**Workers Static Assets publishing**; and `state_routing.rs` for two default URLs.

So the Rust shipped a per-tenant R2 provisioning API that nothing ever called.
**CLASS B — product backlog on TS, not a parity blocker.** Porting it anyway was
still the right call: it is the one part of the Rust that is genuinely expensive
to re-derive once deleted, and the previous certification named exactly that.

*(Adjacent, and flagged for the DATA-PLANE certification rather than decided
here: the Workers-Static-Assets publishing store IS a live Rust path.
`packages/config` validates the `workers-static-assets` backend
(`validate.ts:258`, `enums.ts:122`) but I found no TS implementation of the
3-step publish flow. On Workers the natural answer is the native R2 binding
`env.ASSETS`, which `apps/gateway` does use — so this is plausibly CLASS C, but
it is an `apps/gateway` question and I am not certifying it here.)*

### L7 — DEBT · LOW · three independent Cloudflare v4 envelope decoders remain

The previous audit's complaint that the tree held "three independent partial
Cloudflare v4 clients, each decoding the `{success, errors, result}` envelope
itself" is **still true**, even though the canonical implementation now exists:
`packages/secrets/src/cloudflare-client.ts`,
`packages/guardrails/src/adapters/workers_ai_llama_guard.ts` and
`packages/storage/src/tenant-rest.ts` each still decode their own, and only the
last one adopted anything from `@ferrogate/cloudflare` (the retry). The markers
in `packages/secrets/src/cloudflare-client.ts:9,32,50` acknowledge this
accurately and say the file "becomes a re-export" when the shared package lands.
It has landed. Consolidation debt, not a defect.

### L8 — CLASS C · `packages/schemas` still has ZERO importers — confirm, keep, do not wire

Re-derived with a comment-stripped module-specifier extractor over every `.ts`
under `packages/*/src` and `apps/*/src`: **0 importers.** It imports
`@ferrogate/core` 14× and nothing imports it; apps take those symbols from
`@ferrogate/core` directly, which is the same single source of truth. Its 56
tests still earn their place: the `OPENAPI_OPERATION_COUNT = 251` gate is now
pinned in three places that each read the **JSON document off disk**
independently, rather than agreeing with each other. Keeping it a literal rather
than deriving it is the vacuous-assertion lesson applied correctly — a derived
constant would agree by construction and the gate would be unfailable.

### L9 — DEVIATION · LOW · two integer domains for credits, boundary unasserted

`packages/storage`'s reservation surface (`reserveWalletCredits`,
`availableCredits`, `StoredWallet.balanceCredits`) is `number`; the
adjust/settle/read-exact surface and the whole billing EVENT domain are `bigint`.
JS numbers are exact to 2^53; Rust's `i64` runs to ~9.2e18. A balance above
~9,007,199,254,740,991 credits (≈ $9.0 billion at 1 credit = 1 µUSD) would lose
precision on the reservation path. Not reachable at any plausible scale, per-request
reservation amounts are tiny, and the wave-17 conversion boundary is exact — but
the two layers do not share an integer type and nothing asserts what happens at
the seam.

### L10 — HOUSEKEEPING
- `PORT-PLAN.md:83` and `:162` still reference the deleted `packages/sync-bridge`.
- `packages/storage`'s payment-attempt tests live inside
  `test/site-domain.test.ts`. Move them to `test/payment-attempt.test.ts`.
- `packages/config/test/port-todo.test.ts:96` carries
  `test.todo("re-export CloudflareConfig from @ferrogate/cloudflare")` and
  `src/schema/entities.ts:517` says "no such package was created" — both now
  false. `@ferrogate/cloudflare` exists.

---

## 8. Corrections to `cutover-parity-libraries.md`

| Its claim | Status now |
|---|---|
| §4.4 guardrail evidence-fingerprint keying is unheld (its single finding) | **CLOSED.** `test/fingerprint-keying.test.ts` exists; both of its surviving mutations now go RED |
| §6.1 four `ferrogate-cloudflare` slices have no TS equivalent anywhere | **CLOSED.** `packages/cloudflare` delivers all four; 146 tests; retry mutation RED |
| §7.1 workflow-budget CAS UNVERIFIED | **VERIFIED — RED, 2 tests** |
| §7.2 guardrail-binding generation CAS UNVERIFIED | **VERIFIED — RED, 2 tests** |
| §7.3 payment-attempt state machine "thinnest-covered", no dedicated test file | **VERIFIED — RED, 1 test.** The file claim is true; the coverage claim was wrong (tests are in `site-domain.test.ts`) |
| §5.1 recommend deleting `packages/sync-bridge` | **DONE, and independently re-confirmed correct** |
| §0 "production Rust ≈ 22k lines" | **WRONG by ~10×.** ≈220k by a per-file heuristic |
| §4.5 "AI Gateway routing unmounted (#406)" | **STILL OPEN** — now classified CLASS A with the Rust wiring cited |
| §4.3 storage credits are `number` not `bigint` | **PARTLY SUPERSEDED.** The conversion boundary and the adjust/settle path are now exact `bigint`; the reservation surface is still `number` (L9) |
| §5.4 observability residues (`AnalyticsEngineSink`, `OtlpBackend` unimported) | **STILL TRUE**, still accurately marked at `packages/observability/src/index.ts:58-82` |

---

## 9. UNVERIFIED — stated plainly rather than guessed

Believed correct from reading the code; **not** mutation-tested this wave. Do not
read this document as certifying them.

1. `sigv4` (Bedrock) and Vertex OAuth signing against real AWS/GCP canonical-request
   vectors. (`packages/providers/src/sigv4.ts:17` explicitly says this is not a
   deferral and points at `test/crypto-sigv4.test.ts`; I did not audit those vectors.)
2. Streaming SSE framing byte-for-byte against Rust `messages_stream.rs` /
   `responses_stream.rs`. Out of the library scope, but nothing here proves it.
3. The exact diagnostic message TEXT of the 54 config validators I did not mutate
   (presence and reachability ARE proven).
4. `packages/payments`' x402 wire/proof/intent semantics beyond its 54 tests —
   deprioritized by standing directive; `packages/policy/src/x402/wire.ts` is its
   only importer (3 value imports), which is a healthy consumed-by-a-package shape.
5. `packages/secrets`' `vault://` backend against a real Vault KV v2 server (the
   `env://` and `cf://` reference-parsing surfaces match `lib.rs:88-110` verbatim).
6. Whether `packages/sso` and `packages/identity` are correctly MOUNTED on the
   deployed control-plane Worker. Importer counts say yes (identity 4, sso 3, all
   from `apps/control-plane`), and `MOUNT-SEAMS.md` records `CP-S1`/`CP-S2`/`CP-S3`
   as 18/10/12 RED — but re-proving the mount belongs to the control-plane
   certification, not here.
7. Anything requiring the live Cloudflare account. Every result above is from
   `@cloudflare/vitest-pool-workers` in local `workerd`.
8. The L9 credit-domain boundary above 2^53.

---

## 10. Ranked actions

1. **Close L1** (CLASS A, blocks cutover) — three edits, already enumerated in
   `packages/providers/src/registry.ts:8`. The third one is the one that matters:
   a test asserting the PREPARED ENDPOINT is the AI Gateway host.
2. **Close L2** — JWKS stale-serve test. Security-relevant, ~20 lines.
3. **Close L3** — breaker `affects_circuit` test, with a positive control.
4. **Close L4** — one literal assertion pinning `MAX_FINDINGS_PER_EVALUATION`.
5. **Fix L5** — UTF-8 byte length in `r2BucketNameForTenant` + a non-ASCII golden
   vector. Do it while `crates/**` is still readable.
6. **Generate a Rust golden bucket table for `rolloutBucket`** (§4.5) — cheap
   insurance that expires the moment the Rust is deleted.
7. **Collapse L7's three CF v4 envelope decoders** onto `@ferrogate/cloudflare`.
8. **L10 housekeeping** — the two stale `PORT-PLAN.md` sync-bridge lines, the
   misfiled payment-attempt tests, and the two now-false "no `@ferrogate/cloudflare`
   package" claims.
9. **Add the L9 boundary assertion** (or unify the reservation surface on `bigint`).

---

## 11. What this audit changed in the tree

**Nothing but this file.**

No source file was modified. No test was weakened, skipped or deleted. No new
`PORT-TODO` marker was added — the one CLASS A gap in scope (L1) already carries
an accurate marker, and L2/L3/L4 are TS-native test gaps rather than CLASS A
regressions, so under the stated scope they are reported here rather than marked
in source. No `crates/**` or `workers/**` file was read for anything other than
comparison, and none was modified.

**Mutations applied and reverted this wave: 22.** Nineteen went RED; **three
SURVIVED** — and those three are L2, L3 and L4, the only findings in this
document that were not already known. (Two of the nineteen, the guardrail
fingerprint sites, are the exact mutations that SURVIVED at the previous
certification and now go RED; two more, the counter-key and `price_not_found`
mutations, were additionally re-run against `apps/gateway` to prove the
derivation on the deployed path rather than only in the unit.)

Every mutation was confirmed present on disk before its test run and confirmed
absent after its revert. A final root `bun run test` after the last revert
returned **exit 0 across all 24 projects with zero `FAIL` tokens**, and
`bun run typecheck` is clean across all 22.

### Mutation ledger

| # | Target | Result |
|---|---|---|
| 1 | `policy/quota.ts` `counterKey` → raw `apiKeyId` | RED (policy 1; gateway ~20 files) |
| 2 | `policy/quota.ts` `updateMinScope` `<=` → `>=` | RED (4) |
| 3 | `policy/quota.ts` allowlist intersection → union | RED (2) |
| 4 | `billing/ledger.ts` neutralise `price_not_found` throw | RED (billing 2; gateway 4) |
| 5 | `storage/credits.ts` `centsToCredits` → float multiply | RED (1) |
| 6 | `storage/d1/wallet-d1.ts` balance predicate → tautology | RED (3) |
| 7 | `storage/d1/workflow-budget-d1.ts` counter guard → `OR 1=1` | RED (2) |
| 8 | `gateway/guardrails/d1.ts` generation guard → `OR 1=1` | RED (2) |
| 9 | `storage/payment-attempt.ts` drop generation equality | RED (1) |
| 10 | `storage/d1/monotonic.ts` `max()` → `min()` | RED (2) |
| 11 | `guardrails/adapters/transport.ts` HMAC key → empty | RED (10+) |
| 12 | `guardrails/deterministic.ts` fingerprint key → `"FIXED"` | RED (3) |
| 13 | `guardrails/custom_http.ts` drop `!affectsCircuit()` return | **SURVIVED → L3** |
| 14 | `guardrails/deterministic.ts` cap `10_000` → `20_000` | **SURVIVED → L4** |
| 15 | `providers/types.ts` drop `429` from retry predicate | RED (1) |
| 16 | `routing/fnv.ts` FNV prime `01b3` → `01b5` | RED (1) |
| 17 | `config/validate.ts` unmount `validateGuardrails` | RED (49) |
| 18 | `sso/redirect-binding.ts` sign over re-serialised form | RED (8) |
| 19 | `identity/oidc/claims.ts` disable nonce check | RED (5) |
| 20 | `identity/oidc/jwks.ts` serve stale doc on fetch failure | **SURVIVED → L2** |
| 21 | `identity/scim/auth.ts` exact scope → `startsWith` | RED (1) |
| 22 | `cloudflare/retry.ts` drop `429` from retryable statuses | RED (4) |
