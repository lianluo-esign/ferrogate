# Parity audit — POLICY/CORE cluster

**Scope:** `packages/{config,policy,guardrails,secrets,billing}` vs
`crates/ferrogate-{config,policy,guardrails,secrets,billing}` (read-only reference),
against `docs/legacy/inventory-policy-core.md` and `inventory-data-billing.md §2`.

**Method:** symbol-level diff of every Rust `pub fn` / `pub struct` / `pub enum`
against the TS export surface; field-level diff of all 61 `pub struct`s in
`config/types.rs` and all 11 in `types.rs` against their Zod schemas; call-order
diff of `Config::validate()`; algorithm read-through of the quota merge,
`charge()`, the deterministic scan loop, and the `custom_http` bulkhead; and a
`grep`-based **mounting** check of every ported entry point against `apps/`.

**Audit only.** No behavior was changed. Five `PORT-TODO` markers were added
(listed in §7). All five suites were run before and after: **1142 passing, 9 todo,
0 failing**; `tsc --noEmit` clean in all five.

---

## 1. Headline: the stated LOC ratios are an artifact, not a parity signal

The brief cites ratios of 0.40–0.61. Those compare Rust source **including** its
inline `#[cfg(test)] mod tests` blocks and `*_test.rs` files against TS source
**excluding** its `test/` directory. Rust carries 32–59% of its LOC as in-tree
tests. Measured production-to-production:

| crate | Rust total | Rust tests | Rust prod | TS src | TS tests | **prod ratio** | brief's ratio |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ferrogate-config` | 20 577 | 9 490 | 11 087 | 8 208 | 4 602 | **0.74** | 0.40 |
| `ferrogate-policy` | 4 215 | 2 081 | 2 134 | 1 865 | 1 310 | **0.87** | 0.44 |
| `ferrogate-guardrails` | 10 525 | 3 594 | 6 931 | 6 470 | 2 233 | **0.93** | 0.61 |
| `ferrogate-secrets` | 2 884 | 1 696 | 1 188 | 1 655 | 753 | **1.39** | 0.57 |
| `ferrogate-billing` | 3 490 | 1 339 | 2 151 | 1 674 | 905 | **0.78** | 0.48 |

The residual shortfall is accounted for line-for-line below; the remainder is TS
being terser than Rust for the same behavior (Zod `.default()` vs `#[serde(default)]`
+ a `fn default_x()`; a `type` union vs a `#[derive]`d enum with `as_str`/`FromStr`).

**Nothing in this cluster is a stub.** The real defects are not missing
algorithms — they are three fully-implemented, fully-tested modules that **no
Worker mounts**, which is precisely the defect class this repo keeps hitting.

---

## 2. Findings table

Severity: **P1** = a security/correctness guarantee is currently vacuous ·
**P2** = operator-visible behavior silently absent · **P3** = recorded decision /
low-priority.

| # | Area | Finding | Severity | Evidence | Marker |
|---|---|---|---|---|---|
| F1 | policy | **`BasicPolicyEngine` is never constructed.** Operator `[[policies]]` deny rules are fully validated at load and **never enforced** at runtime. | **P1** | Rust: `ferrogate-gateway/src/state.rs:7079 build_policy_engine`, held at `:1516`, evaluated in `state_quota_and_policy.rs`. TS: `grep -rn "BasicPolicyEngine\|PolicyDecision\|PolicySubject" apps/` → **0 hits**, while `validatePolicies` cross-checks every rule. | `packages/policy/src/policy-engine.ts` |
| F2 | policy | **Workflow-run budget preflight is never called.** `preflightWorkflowBudget` + `resolveWorkflowBudgetEnvelope` + the durable `@ferrogate/storage` half are ported and tested; nothing consumes them, so a capped run spends without limit and the `exhausted` flip gates nothing. | **P1** | Rust consumer: `ferrogate-gateway/src/server/agent_runs.rs`. TS: `grep -rn "preflightWorkflowBudget\|WorkflowRunBudget\|workflow_run_budget" apps/` → **0 hits**. `apps/agent-runtime/src/runs/lifecycle.ts` has an unrelated "open-job budget", no cost/token/tool-call/wall-clock ledger. | `packages/policy/src/workflow-budget.ts` |
| F3 | secrets | **`cf://` cannot read a real Secrets Store binding.** `CfSecretBindings` reads only a plain **string** (injected map or `FERROGATE_CF_SECRET_*` var). The CF-native path the inventory §4.8 names — `await env.MY_SECRET.get()` on a `[[secrets_store_secrets]]` stanza — is implemented nowhere; with a real stanza, `lookup()` calls `.trim()` on a `SecretsStoreSecret` object → `TypeError`. | **P2** | `grep -rn secrets_store_secrets packages apps --include=*.ts` → prose only (`apps/control-plane/src/ports.ts:377`, this package's doc comment). `packages/secrets/src/cloudflare-bindings.ts:139`. | `packages/secrets/src/cloudflare-bindings.ts` |
| F4 | config | **x402 spend-policy bodies are unvalidated, and the stated blocker is stale.** `x402_spend_policies` is `z.array(z.unknown())`; only `(scope_type, scope_id)` blankness/duplication is checked. The marker says the typed model "lives in `@ferrogate/policy` … until that crate is ported" — it **is** ported (`packages/policy/src/x402/config.ts`, 459 lines, `validateX402SpendPolicy`). Genuinely unported anywhere: `X402ScopeChain`, `X402PolicyScopeRef`, `EffectiveX402SpendPolicy`, `resolve_effective_x402_spend_policy`, `X402SpendPolicyConfig`, `load_x402_spend_policy_toml`, `default_x402_spend_policy`. | **P3** (x402 deprioritized by directive) | `packages/config/src/schema/config.ts:99`; `crates/ferrogate-config/src/x402_scope.rs`, `x402.rs`. | `packages/config/src/x402-scope.ts` |
| F5 | billing | **`createBillingService` is mounted on nothing.** All four routes, constant-time bearer auth, 1 MiB cap and page clamp are ported as a ready Fetch handler; no Worker mounts it. Defensible (Rust ships it as a standalone process; the 251-op contract has no `/v1/billing/*`; the gateway settles in-process via `metering/*` + the outbox) — but `[billing_service] enabled/endpoint` still parses and validates, so an operator's block looks honored while nothing answers. Decide: mount it, or declare it N/A the way `[tls]` already does. | **P3** | `grep -rn "createBillingService\|/v1/billing/charge" apps/` → 0 hits; `docs/openapi/runtime-api-contract.json` has no billing operation outside `/admin/v1/billing-*`. | `packages/billing/src/service.ts` |
| F6 | config | `Config::load` file-format dispatch: no TOML/YAML parser exists in the workspace (`grep` for `smol-toml`/`@iarna/toml`/`yaml`/`js-yaml` → 0). **Closed at the CLI** (`apps/cli/src/ports.ts` injects `Bun.TOML.parse`/`Bun.YAML.parse` and refuses a format it has no parser for); open on the edge by design (no filesystem). Already marked; **not** a new gap. | — | `packages/config/src/loader.ts:6` | (existing) |
| F7 | guardrails | DNS-level SSRF filtering has no workerd equivalent (`GuardrailDnsResolver`). Compensated by a **strictly tightened** literal/host check (scheme allowlist, credentials/query/fragment rejection, IPv4-mapped v6, `inet_aton` octal/hex/integer/short forms, `*.localhost`, raw + WHATWG-canonical host). Residual gap (a public hostname resolving to a private IP) is real and pinned by shape. Already marked; **not** a new gap. | — | `packages/guardrails/src/net.ts:21`, `test/net.test.ts` | (existing) |

---

## 3. `config` — the answers to the specific questions

**"How many validators does the TS actually implement?"**
`crates/ferrogate-config/src/config/validate.rs` declares **93 distinct `fn`s**
(98 `fn` tokens). `packages/config/src/validate.ts` + `validate/*.ts` declare
**118**. `Config::validate()`'s call sequence is reproduced **verbatim, in Rust
order** (the order is observable — it decides which of several errors an operator
sees first). Diffing Rust fn names against TS (snake↔camel normalized), the only
Rust names with no TS counterpart are:

| Rust fn | Status |
|---|---|
| `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`, `validate_acme_http01_tls`, `validate_manual_tls_files` | **Removed as N/A on Cloudflare** (CF terminates TLS; the Rust pre-flight is pingora's `load_certs_and_key_files`; no `:80` HTTP-01 listener, no ACME storage dir). Compensated: the schemas stay so legacy TOML/Caddyfile still decodes, and `inertTlsWarnings` says out loud that the section is inert. Reason recorded at the removed call site (`validate.ts:414`). |
| `normalize_listen_addr` | Renamed → `isValidSocketAddr`. |
| `validate_positive_optional_u32` / `_u64` | Merged → `validatePositiveOptional` (TS has one number type). |
| `upsert_or_replace_{agent_workflow,mcp_server,plugin,prompt_template}` | Inlined into `materializeSkillPackageResources[WithPrevious]` (present, `validate/plugins.ts`). |
| `contains`, `name`, `value`, `validate` | Trait-impl/method names, not free validators. |

Everything else — including all 5 plugin-permission validators, the
skill-package resource capability check, the Postgres identifier/DSN checks,
prompt-placeholder checks, managed-worker action lists, the R2 host/region rules,
the tenancy-posture warnings and the `#515/#540` tenant-identity refusal — is
present.

**"Which config STRUCTS/fields exist in Rust but have no Zod schema at all?"**
**None.** 61 `pub struct`s in `config/types.rs` + 11 in the Caddyfile intermediate
`types.rs`; 102 exported Zod schemas in `packages/config/src/schema/`. A
mechanical field-level diff reports exactly three unmatched fields, all correct:

- `Config.control_api` and `Config.admin_api_alias` — raw inputs consumed by
  `migrateControlPlaneAliases` **before** the schema runs (a Worker has no serde
  `skip_deserializing`); both-present is still a hard error, alias-only still warns.
- `Config.api_keys_are_control_plane_documents` — `#[serde(skip)]` in Rust,
  surfaced as `ValidateOptions.apiKeysAreControlPlaneDocuments`.
- (`ManagedWorkerCapabilityTargetGrantConfig` matches
  `managedWorkerCapabilityTargetGrantSchema`; name drop only.)

`GuardrailRule.provider_runtime` is `#[serde(flatten)]` in Rust and is `.merge()`d
in TS — correct, not missing.

The Caddyfile bridge is complete: all 11 intermediate structs, every field, and a
directive-string diff of the Rust recursive-descent parser against the TS one
returns **no** Rust directive absent from TS.

---

## 4. `policy`

| Behavior | Status |
|---|---|
| Multi-level quota merge (Tenant→Project→Workspace→Key) | **1:1.** Fixed scope order, fail-closed short-circuit on the first `enabled = false`, allowlist **intersection**, `min`-across for rpm/tpm/monthly-budget/agent-cost(#428)/egress-bytes(#262)/download-rpm(#262), per-dimension winning-scope selectors, tie-to-most-specific via the `<=` fold, tenant-only asset dims (#259). Verified against `quota.rs` line by line. |
| Plan floors (#168) | **1:1.** Fills only what no policy set; keyed on the Tenant selector; never tightens or loosens an explicit value; asset dims via `?? plan.default…`. |
| **Counter-key namespacing (security-critical)** | **Present and correct.** `key` → `key:{api_key_id}` (never the raw id); `tenant:`/`project:`/`workspace:` prefixed. **Tested**: 1 test in `packages/policy/test/quota.test.ts` + **7** in `apps/gateway/test/ratelimit/keys.test.ts`, including "an api_key_id crafted to look like a tenant scope cannot collide", the project/workspace variant, and "attacker and victim resolve to DIFFERENT windows end to end". This one is genuinely well-defended. |
| Workflow budget: envelope min-compose, `deadlineUnix` (ceil-to-second), fail-closed preflight, dimension-qualified denial codes | **Ported 1:1, NEVER CALLED → F2.** |
| `evaluateNodeDispatch` | Ported 1:1. **Not** part of F2: it has no consumer in the Rust tree either (only `ferrogate-policy`'s own tests), so its absence from `apps/` is parity. |
| `BasicPolicyEngine` / `PolicyRule` / `PolicySubject` | **Ported 1:1, NEVER CONSTRUCTED → F1.** |
| `Stored*` types + `dimensionExceededBy` | Correctly **re-exported** from `@ferrogate/storage` (one definition, matching the Rust dependency direction) — a previously-drifted duplicate was collapsed. |
| x402 spend policy / decision | Ported (deprioritized surface): `x402/config.ts` 459 L, `x402/decision.ts` 461 L, wire re-exported from `@ferrogate/payments`. |

Note: `apps/gateway`'s per-key `allowedModels`/`deniedModels` check is **not** a
substitute for F1 — it is sourced from the D1 `api_keys` row and cannot express a
`(subject × models × providers)` rule.

---

## 5. `guardrails` — complete vs partial

Every Rust `pub fn`/`pub struct`/`pub enum` in `contract.rs`, `envelope.rs`,
`deterministic.rs`, `policy.rs`, `custom_http.rs`, `net.rs`, `adapters/*`,
`conformance.rs` and `evaluation.rs` has a TS counterpart. Detail:

| Area | Verdict |
|---|---|
| **Deterministic detector** | **Complete.** All four families: keywords, regex, 3 built-in secret patterns whose expressions are **byte-identical** to `deterministic.rs` (verified by substring match), and JSON-schema/pointer + request constraints. Coalesced same-source group scan **plus** the per-segment rescan that restores `\b`/`^` anchors; dedupe on `(category, segment_id, byte_start, byte_end)`; non-overlapping redaction patches via per-segment interval probes; `MAX_FINDINGS_PER_EVALUATION = 10_000` with the single zero-width `detector.truncated` (Critical, **uncovered by a patch** → unredactable → fail closed); secrets Critical @0.99, keyword/regex High @1.0; `matched_text` hard-wired to `null`. |
| **JSON Schema** | **Complete for the assertion + applicator vocabulary of Draft 2020-12**, hand-written (461 L) because the workspace admits no JSON-Schema dependency. Two *documented behaviors*, both matching the `jsonschema` crate's defaults: remote/absolute `$ref` is **not** fetched and **fails closed** (SSRF), and `format` is an annotation. 348 L of tests. |
| **HMAC-fingerprinted, non-persisted evidence** | **Complete.** Synchronous pure-TS SHA-256/HMAC (WebCrypto is async and would force promises through the per-match sink), with RFC-style known-answer tests. `sha256:<hex>` for content fingerprints, `hmac-sha256:<hex>` for keyed evidence; secret detection **refuses to construct** without a `fingerprint_key`. |
| **`custom_http` bulkhead / breaker / deadline** | **Complete.** Deadline check → circuit gate (open+cooldown / half-open probe) → source projection → payload cap → semaphore permit **bounded by the deadline** (→ `overloaded`) → retry loop capped at 1 with per-attempt `min(timeout, remaining)` → bounded response read (`content-length` pre-check + streamed cap) → `parseDetectorResponse` (new `verdict` **and** legacy `match`+`matched_text`) → `validateDetectorResult` (patch validity, finding ranges on char boundaries) → circuit bookkeeping. Full `DetectorErrorKind` taxonomy and status mapping. |
| **Three remote adapters** | **Complete.** Presidio (transform-capable, code-point→byte offsets, `pii.presidio.<entity>`), LLM-Guard prompt injection (detect-only), Workers-AI Llama-Guard (`interpretResponse` for `"safe"`/`"unsafe\nS2,S9"`/bool/object, `normalizeHazardCode`, `hazardName`, category allow-list, `classifyCloudflareError`) — plus the shared `DetectorTransport`/`HttpJsonTransport`/`FixtureTransport`, `AdapterCounters`, `configDigest`, `charIndexToByteOffset`, `hmacEvidenceFingerprint`, `nativeAdapterFailureModes`. The Llama-Guard adapter additionally gains a **native Workers-AI binding** client alongside the REST one. |
| **Policy composition** | **Complete.** All 18 Rust types, all 5 `DetectorDefinition` kinds with their `validate()` rules and every `default_detector_*` constant (2000 ms, 16, 3, 30 000 ms, 1 MiB, 256 KiB, `"en"`, 50 %), `administrativeRank`, `scopeMatches`, `aggregateCheckOutcomes` (All/Any/Threshold), `selectPolicyRevisions`, `immutableId`. |
| **Envelope + patches** | **Complete.** All 11 Rust `pub fn`s, incl. `normalizeRequest`/`normalizeResponse` (SSE accumulation), `validateContentPatchesForSegments`, `validateContentPatchPermissions` (mutable-source table → `ProtectedPath`), `applyContentPatchesToDocument` (live re-fingerprint → `StalePatch`, right-to-left splice), `parseProtocolPath`. |
| **Conformance + evaluation** | Ported (6 behaviours, `MockAdapter`, `PROBE_SECRET`; corpus, P/R/F1 + latency percentiles, shadow scoring, `PromotionGate` hysteresis). Not referenced from `apps/` — matching Rust, where they are `feature = "conformance"`/test-only. |
| **SSRF DNS** | **Partial by platform** → F7. `filterResolvedDetectorAddresses` is ported for parity and deliberately unwired (there is no resolved-address list to filter). |

Mounting check: all five detectors, `selectPolicyRevisions`,
`aggregateCheckOutcomes` and `applyContentPatchesToDocument` **are** reachable
from `apps/gateway/src/guardrails/*` (and the deterministic detector from
`apps/mcp` and `apps/agent-runtime`). No unmounted guardrail module.

---

## 6. `secrets` — which schemes actually work

| Scheme | Works? | Detail |
|---|---|---|
| `env://NAME` | **Yes** | Via an injected `EnvLike` (workerd has no `process.env`; `defaultEnv()` returns `process.env` under Bun/Node, `{}` otherwise). Empty/whitespace = unset, matching `non_empty_env`. Residual, honestly marked: a Worker call site that forgets to thread `c.env` sees an empty env, indistinguishable from unset. |
| `vault://<mount>/<path>#<field>` | **Yes** | `GET {addr}/v1/{mount}/data/{path}` over `fetch`, `X-Vault-Token`, reads `data.data.<field>`, checks `errors`. `caCertPath` is **accepted and ignored** (workerd exposes no trust-store hook) — pinned by a test asserting it never reaches the request, and deliberately not rejected so one config serves both the CLI and the Worker. |
| `cf://<store>/<name>` | **Partly → F3** | Works from an injected exact-name map or a plain-string `FERROGATE_CF_SECRET_<NAME>` var, with the lossy-mapping ambiguity guard (non-canonical name + no exact binding ⇒ **throw**, never a possibly-wrong credential) ported verbatim. **Does not work from an actual `[[secrets_store_secrets]]` binding**, which is the only real read path on Cloudflare. |
| REST manage plane | **Yes** | `create_secret` with `scopes:["workers"]`, canonical-name `[a-z0-9-]+` guard, existence-check-only `resolve()` (never returns a value), beta caps (1 store / 100 secrets / 1024 B) with hard error + soft warning at 90 and the three env overrides. |
| Redaction | **Yes** | `toJSON` + `nodejs.util.inspect.custom` on `VaultConfig.token`, `CfSecretBindings.values`, `CfSecretsStoreConfig.api_token_ref`, `DetectorSecret`. |

Also worth recording: **`@ferrogate/secrets` is imported by zero apps** — the
`Provider.secret_ref` / `cf://` resolution path is not wired into the gateway's
credential lookup. That is an `apps/` wiring gap, not a package gap, and it is the
practical reason F3 has not bitten yet.

---

## 7. `billing`

| Behavior | Status |
|---|---|
| `PriceBook` lookup precedence (exact → `(p,*)` → `(*,m)` → `(*,*)`), fail-closed `undefined` | **1:1** |
| `credits_per_usd = 1e6`, `BYTES_PER_BILLED_GB = 1e9`, `DEFAULT_EGRESS_PRICE_PER_GB = 0.09`, `egressCostUsd`, 11-entry default rate card, `fromJson` (array **or** object form) | **1:1** |
| `TokenUsage.reconcileSplit` (#140 three-way repair) and `ModelPrice.estimate` | **1:1** |
| `charge()` source-of-truth rule (#135): finite `cost_usd ≥ 0` is authoritative; `settledBreakdown` splits by rate-card ratio, else by token counts, `total_cost` always equals the settled figure | **1:1** |
| **5 % divergence warning (#152)** | **1:1 and improved.** `costDiverges(settled, expected)` is a *pure, independently testable* function — 5 % relative, `$0.0001` absolute floor, floor also used as the relative base — and the `tracing::warn!` becomes an injected `onDivergence` callback. It **never** overrides the settled figure. |
| Fail-closed `price_not_found` (HTTP 422) when no settled cost **and** no rule | **1:1** |
| Idempotency: `ledgerEntryId` (`ferrogate:provider-attempt:{id}` / legacy `{trace}:{request}` / `{request}`), byte-equal replay ⇒ no-op, divergent replay ⇒ `billing_idempotency_conflict` (409), `billingErrorHttpStatus` 422/409/500 | **1:1** |
| **Integer-credit precision** | **Correct.** Wallet fields (`wallet_delta_credits`, `wallet_balance_after_credits`) are `bigint`; `credits` stays `number`, matching Rust `f64` / the `credits DOUBLE` column. One narrowing to note: `ledgerEntryToWire` renders the wallet bigints through `Number()` — lossless below 2⁵³ ≈ 9.0 × 10¹⁵ credits ≈ **$9.0 billion**, so not actionable, but it is the one place the no-drift property is dropped for the wire. |
| `validateRequestMetadata` (8 entries / 64 / 256), `BillingEventSink` + bounded `InMemoryBillingEventSink` | **1:1** |
| **Outbox** | **Implemented and mounted** — `apps/gateway/src/metering/outbox.ts` + `packages/storage/src/d1/billing-d1.ts`, with `MAX_BILLING_OUTBOX_ATTEMPTS`, `next_attempt_unix` backoff, dead-lettering, and admin replay routes in `apps/control-plane/src/routes/billing.ts`. **Not a gap.** |
| HTTP service | Routes/auth/limits/errors ported as a Fetch handler; the `TcpListener` accept-loop deliberately dropped (documented). **Mounted on nothing → F5.** |
| x402 inbound | Deferred per directive: `settleInboundPayment` / `validateInboundX402Endpoint` are stubs, `InboundX402Challenge` / `build_payment_required` / `ValidatedInboundX402Endpoint` absent; 3 `it.todo`s. Already marked. |

---

## 8. Test posture (measured, this audit)

| package | files | passing | todo | notes |
|---|---:|---:|---:|---|
| `config` | 13 (1 = `port-todo.test.ts`, todo-only) | 519 | 6 | incl. `platform-limits.test.ts` pinning every kept marker |
| `policy` | 5 | 80 | 0 | 17 quota tests incl. the counter-key DoS guard |
| `guardrails` | 12 | 407 | 0 | 348 L of JSON-Schema tests, 427 L of SSRF tests |
| `secrets` | 6 | 69 | 0 | |
| `billing` | 7 | 67 | 3 | todos are the x402-inbound legs |
| **total** | 43 | **1142** | **9** | |

The `platform-limits.test.ts` convention in `config`/`secrets`/`billing` is the
right one and should be kept: every retained `PORT-TODO` has an assertion that
*fails* if the platform ever closes the gap, so a marker can never rot into a
claim nobody re-checks. **F1/F2/F3 are exactly the cases that convention does not
cover** — a mounting failure is invisible to a package-local suite by
construction, which is why they need a wiring assertion in `apps/`, proven red by
deleting the call.

---

## 9. Markers added by this audit

| file | anchor | finding |
|---|---|---|
| `packages/policy/src/policy-engine.ts` | `class BasicPolicyEngine` | F1 |
| `packages/policy/src/workflow-budget.ts` | `preflightWorkflowBudget` | F2 |
| `packages/secrets/src/cloudflare-bindings.ts` | `CfSecretBindings.lookup` | F3 |
| `packages/config/src/x402-scope.ts` | module header | F4 |
| `packages/billing/src/service.ts` | `createBillingService` | F5 |

Each states the exact gap, the `grep` that reproduces it, the Rust composition
root it corresponds to, and what closing it requires — including, for F1 and F2,
the mutation that must turn the new wiring assertion red.

---

## 10. Recommended order

1. **F1** — wire `BasicPolicyEngine` from `config.policies` in the gateway
   composition root. Smallest change, largest exposure: a deny rule that silently
   allows is worse than no deny rule, because the operator believes it holds.
2. **F2** — call `preflightWorkflowBudget` on the run-step path before dispatch,
   then the durable debit. Both halves already exist and are tested.
3. **F3** — teach `CfSecretBindings` the `SecretsStoreSecret.get()` shape
   (`EnvLike` widening + one `await`), keeping the ambiguity guard ahead of the
   read. No platform blocker.
4. **F5** — decide and write it down (mount, or declare N/A next to
   `billingServiceConfigSchema`).
5. **F4** — leave until x402 is un-deprioritized, but correct the stale rationale
   now so the next reader is not told a dependency is missing when it is not.
