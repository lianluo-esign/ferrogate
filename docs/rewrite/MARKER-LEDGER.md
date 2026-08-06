# PORT-TODO marker ledger — the cutover residue, classified

> **Historical marker record, superseded 2026-08-05 for tenant storage.** Any
> D1-per-tenant, REST or proxy marker below describes the earlier cutover state.
> The current design is CONTROL D1 plus a SQLite Durable Object per tenant;
> see [`per-tenant-durable-object-storage-2026-08.md`](../design/per-tenant-durable-object-storage-2026-08.md).
> The ledger entries remain unchanged as historical audit evidence.

**Produced:** 2026-08-01, wave 15 (the "verdicts, not volume" wave).
**Scope of authority:** this file classifies every `PORT-TODO(` occurrence in the
repository. It does not close any of them.

## 0. The one-line answer

**The TypeScript is not yet a 1:1 replica of the Rust, and `crates/**` must not
be deleted in this wave.**

The raw marker count DID materially overstate the residue — 21 of the 130
in-source markers tracked no work at all — but the remainder does not collapse
into "correctly-kept platform limits". After classification there are **56
portable markers covering ~43 distinct work items**, and among them are
user-visible behavioural regressions against the Rust and several
security/money-relevant gaps, enumerated in §5. Their only specification is the
Rust tree.

**And the residue is still growing.** Eight NEW portable markers (§3.1b) were
written into owned scope by a concurrent parity-certification pass *during the
ninety minutes this ledger took to produce* — including the finding that the
admission ladder (rate limit, monthly budget, wallet balance, quota scope) was
silently dropped from two of the five Workers when the Rust single process was
split. That is not a marker-hygiene problem; it is an architectural parity
defect that no marker had previously recorded. **The correct reading is that
marker burndown has NOT hit diminishing returns — targeted parity auditing is
still finding first-order defects at a high rate, and the discovery curve has
not flattened.** Any cutover decision taken on the "130 markers, mostly platform
limits" framing would have been taken on a false premise.

---

## 1. Method, and what "canonical" means

`grep -rn 'PORT-TODO(' -I . | grep -v node_modules` returns **170 lines**.
Splitting by location resolves the "130 canonical + ~25 narrative" ambiguity
exactly:

| Location | Count | Status |
|---|---:|---|
| `packages/*/src/**` + `apps/*/src/**` | **130** | **CANONICAL** — the ledger's subject |
| `docs/rewrite/*.md` | 8 | narrative *about* markers |
| `sql/d1-ts/**` | 6 | schema-side markers (out of owned scope; classified in §6) |
| `apps/*/wrangler.toml` | 10 | binding-side markers (out of owned scope; classified in §6) |
| `*/README.md` | 6 | doc mirrors of src markers |
| `*/test/**` | 7 | test prose + 2 real assertions |
| **Total** | **170** | |

"Canonical" = a `PORT-TODO(` in a source file under the owned scope. Everything
else is a mirror, a pointer, or prose, and is the reason every previous count
was wrong.

Classification was NOT taken from the markers' own self-descriptions. Each
load-bearing factual claim that could be checked mechanically was checked; §4
records the checks and the two that came back false.

---

## 2. Counts

### Canonical — **this is a moving snapshot, not a stable figure**

**As classified (the 130 that existed at 05:40 on 2026-08-01):**

| Class | Count | Meaning |
|---|---:|---|
| **P — PORTABLE** | **48** | Real remaining work, implementable on Cloudflare |
| **L — PLATFORM LIMIT** | **51** | Genuinely impossible; each names its specific limitation |
| **D — DEPRIORITIZED** | **10** | x402/Solana, by standing user directive |
| **N — NOT A MARKER** | **20** | Narrative cross-refs and closure epitaphs → de-marked |
| **(removed)** | **1** | Verified stale-and-closed; rewritten as an epitaph (§4.2) |

De-marking the 21 that tracked nothing took the greppable count 130 → **109**.

**As re-measured at 06:17, ninety minutes later:**

```
grep -rho 'PORT-TODO(' packages/*/src apps/*/src | wc -l   →  134
  PORT-TODO(P:  65      PORT-TODO(L:  49      PORT-TODO(D:  10      unprefixed: 10
```

**+25 markers in ninety minutes**, every one of them P, all written by
concurrent parity-certification passes: 8 on the data plane (§3.1b) and 17 more
across `apps/control-plane` (`admin_api_key`, `admin_model`, `admin_provider`,
`rbac`, `wallets`, `billing`, `guardrail_policy`, `site_domain`, `agent_run`,
`prompt`, `responses`, `store/d1` ×2, …) plus `apps/cli/src/receipt.ts`.

So the honest count of portable residue is **65 markers and rising**, not 48,
and not the 130 the wave brief started from. The classification below is
correct and still useful — it is what separates the 51 real platform limits
from everything else, permanently. The *total* is not a number this ledger can
fix, because it is being discovered faster than it is being burned down.

### Normalised shape

Every kept marker now carries its class inline and is machine-greppable:

```
PORT-TODO(P: inventory-request-path §1.3): ...
PORT-TODO(L: inventory §5.8) — PLATFORM LIMIT, NOT CLOSED. ...
PORT-TODO(D: §3 — x402 DEPRIORITIZED): ...
```

```sh
grep -rc 'PORT-TODO(P:' packages/*/src apps/*/src   # the residue
grep -rc 'PORT-TODO(L:' packages/*/src apps/*/src   # the accepted limits
```

N-class occurrences were rewritten to `PORT_TODO(` (underscore) so they no
longer match `PORT-TODO(` and stop polluting future counts. **Two exceptions,
deliberately left verbatim:** `apps/cli/src/commands/serve.ts:81` and `:442` are
inside operator-facing *string literals* that `apps/cli/test/serve.test.ts:60`
and `:124` assert on by exact text. Editing them would either break a test or
require editing a test, both forbidden. They are L.

---

## 3. The classified table

### 3.1 P — PORTABLE (48 markers / ~35 items)

| # | File:line | Item | Cost |
|---|---|---|---|
| P1 | `apps/gateway/src/inference/errors.ts:70` | **CORS is not ported anywhere in `apps/gateway`.** Rust `apply_cors_headers` runs on 9 response call sites. | ~0.5 d |
| P2 | `apps/gateway/src/routes/index.ts:236` | `listTools` answers 501. Needs the extension registry + scoped projection. | part of P3 |
| P3 | `apps/gateway/src/routes/index.ts:245` | `executeTool` answers 501. Needs approval record + governed chokepoint + backend dispatch. | 1–2 wk (with P2) |
| P4 | `apps/gateway/src/routes/index.ts:256` | `executeFunction` answers 501. Sandboxed dispatch; belongs to `apps/agent-runtime`. | 1 wk + paid-plan prereq |
| P5 | `apps/gateway/src/inference/handlers.ts:362` | Typed profile-resolution errors absent: a misspelled/forbidden `x-ferrogate-config` silently yields the DEFAULT posture instead of `NotFound`/`Disabled`/`NotAllowed`. | ~0.5 d |
| P6 | `apps/gateway/src/inference/candidates.ts:199` | Eligibility gate is WIDER than Rust on three legs — it admits candidates Rust refuses. | ~1 d + a decision |
| P7 | `apps/gateway/src/inference/estimate.ts:26` | BPE token count not ported; `chars/4` only. Feeds budget admission. | ~1 d |
| P8 | `apps/gateway/src/inference/catalog.ts:146` | `[[models]].cache_enabled` is unrepresentable: an operator's per-model cache opt-out on the model row does nothing. | ~0.5 d |
| P9 | `apps/gateway/src/cache/key.ts:50` | Response-cache key incomplete; needs a middleware-ordering change, not two fields. | 1–2 d |
| P10 | `apps/gateway/src/inference/schemas.ts:33` | Request schema is STRICTER than the Rust extractor — risk of a false 400 on a payload Rust accepted. | audit, ~0.5 d |
| P11 | `apps/gateway/src/middleware/auth.ts:155` | `POST /v1/mcp` unknown method should be JSON-RPC `-32601`; cross-app. | ~0.5 d |
| P12 | `apps/gateway/src/index.ts:161` | `ClientActionTimeModule` + `run_pre_request_hooks` entirely unported; signing half in `apps/cli` also unported. | 3–5 d |
| P13 | `apps/gateway/src/adapters.ts:977` | **Self-hosted worker transport: the AEAD seal is not verified.** Secret + identity binding are; the sealed frame is not. | ~2 d |
| P14 | `apps/gateway/src/ports.ts:269`, `adapters.ts:20`, `assets/sigv4.ts:174`, `keys/provider-secrets.ts:50` (leg 2) | Secrets → Cloudflare Secrets Store; requires making `ModelResolverFactory` async (a composition-root edit). Only provable on the authorised deploy. | 2–3 d + deploy |
| P15 | `apps/gateway/src/guardrails/evidence.ts:268` | `guardrail_evaluations` / `guardrail_check_evaluations` **do not exist in `sql/d1-ts/`** — guardrail evidence is in-memory only. | ~2 d |
| P16 | `apps/gateway/src/assets/ports.ts:789` | `audit_events` retention executor: one line in `gatewayScheduled`, owned by the integrate step. | <1 d |
| P17 | `apps/gateway/src/assets/handlers.ts:304`, `metering/ports.ts:419` | Unjoinable-action metric + the observability/worker/audit AE families. Needs the `TELEMETRY` dataset declared. | 1–2 d |
| P18 | `apps/gateway/src/metering/index.ts:43` | Drain scheduled per-REQUEST not per-RECORDED-USAGE; wrong only on provider failover. Exact one-line close is written in the marker. | <0.5 d |
| P19 | `apps/gateway/src/metering/sink.ts:188` | `cost_usd` is not settled BEFORE dispatch as Rust does. | 1–2 d |
| P20 | `apps/gateway/src/assets/ports.ts:44` | Multipart create/upload-part/complete deliberately dropped; Rust `asset_bucket.rs` exposed them. **Needs product ratification, not just code.** | ~3 d if reinstated |
| P21 | `apps/gateway/src/assets/ports.ts:615` | Cross-tenant publish-approval check and the ClamAV/HTTP malware scanner are unported (2 of the read gate's 3 legs). | 3–5 d |
| P22 | `apps/control-plane/src/routes/resource.ts:175` + `packages/schemas/src/index.ts:89` | ~60 per-resource admin mutation schemas; bodies are `passthrough()` today. | 1–2 wk |
| P23 | `apps/control-plane/src/routes/admin_overview.ts:39` | Admin console bundle does not exist. **Product-sequenced last by standing directive** — excluded from the parity number. | wks (deferred) |
| P24 | `apps/control-plane/src/store/d1.ts:929` | Two DDL gaps vs `sql/d1-ts/control/0001_init_control.sql`; perf/ergonomics. | ~1 d |
| P25 | `apps/mcp/src/index.ts:39` | `mcp_worker_deploy` (tenant hosted-MCP Worker upload, Workers-for-Platforms). Correctly relocated to control-plane; still absent. | ~1 wk |
| P26 | `apps/mcp/src/ports.ts:645` | MCP asset reader needs an `[[r2_buckets]]` binding. **Blocked on R2 not being enabled on the live account.** | ~1 d after prereq |
| P27 | `apps/agent-runtime/src/ports.ts:971` | `governance` port still in-memory; needs Containers/`@cloudflare/sandbox`. | ~1 wk + paid-plan prereq |
| P28 | `apps/agent-runtime/src/durable/hash.ts:33` | BLAKE2b/sha256/constant-time-compare duplicated; move to `packages/core`. | ~0.5 d |
| P29 | `packages/storage/src/index.ts:26` | **Three exports with zero importers anywhere under `apps/`** (`D1BillingEventLedger`, `TenantMonotonicUpserts`, `ControlMonotonicUpserts`). Gated by `test/mount-inventory.test.ts`. | ~1 wk to mount or delete |
| P30 | `packages/storage/src/retention.ts:10` | **CLOSED by #744:** `apps/gateway/src/assets/retention.ts` calls the asset/version executor and orphan-blob GC from `gatewayScheduled`, with policy selection, audit, and lifecycle metrics. | done |
| P31 | `packages/storage/src/index.ts:85` | Duplicate schedule engine: `apps/control-plane/src/schedule/*` is a rival ~1650-line implementation; the package one is dead. `jitterSecs` is applied by nothing. | 2–3 d |
| P32 | `packages/storage/src/budget-alerts.ts:22`, `d1/budget-alerts-d1.ts:46` | Threshold comparison + webhook delivery absent: **an operator who configures budget alert thresholds is never notified.** | ~2 d |
| P33 | `packages/policy/src/workflow-budget.ts:133` | `cost` and `tool_calls` — 2 of 4 workflow budget dimensions — are never debited; owner is `apps/agent-runtime`'s run-step path. | ~2 d |
| P34 | ~~`packages/providers/src/registry.ts:8`~~ | **CLOSED by issue #672.** The routing is mounted on the path the data plane actually takes — `withCloudflareAiGatewayRouting` in `apps/gateway/src/inference/adapters.ts`, which every entry of `defaultAdapterRegistry` is built through — configured by `[[providers]].cloudflare_ai_gateway` + the `GATEWAY_CLOUDFLARE` account block, and pinned by `apps/gateway/test/inference/cloudflare-ai-gateway-mount.test.ts` through `SELF.fetch`. The registry's own routing leg was DELETED rather than left as a second mechanism; the marker's replacement prose on `registry.ts` is the epitaph. | done |
| P35 | `packages/providers/src/models.ts:7` | `ModelRegistry` has NO consumer and its enum is declared twice; `fallbacks`/`routingStrategy`/`contextWindow`/price reach no dispatcher. | ~3 d |
| P36 | `packages/observability/src/index.ts:58` | `AnalyticsEngineSink` has no importer — `apps/telemetry` declares its own. Two implementations of one contract. | ~1 d |
| P37 | `packages/sync-bridge/src/index.ts:24` | Verdict: **delete the package.** Zero importers; the inventory's CF target is literally `Deleted`. | <0.5 d |
| P38 | `packages/config/src/routing.ts:5`, `schema/enums.ts:16`, `schema/entities.ts:516`, `validate.ts:328`, `packages/secrets/src/cloudflare-client.ts:4` | Five package relocations blocked on `@ferrogate/mcp` / `@ferrogate/cloudflare` not existing. **Zero parity impact** — behaviour is ported and pinned; organisational only. | 1–2 d total |

### 3.1b P — the eight that arrived MID-WAVE (all P, none prefixed)

Written by a concurrent parity-certification pass (task #109, "certify data-plane
parity") between 06:00 and 06:20 on 2026-08-01 — after the classification table
in §3.1 was frozen. They are **deliberately left unprefixed**: their files were
under active concurrent edit, and a whole-file read-modify-write to insert a
class token risks clobbering an in-flight change (a hazard this project has hit
before). The next wave should prefix them `P:`.

They are the most consequential findings in this ledger.

| # | File:line | Item | Severity |
|---|---|---|---|
| **P39** | `apps/mcp/src/auth.ts:74` | **The ADMISSION half of Rust's `authenticate()` is absent on `apps/mcp`.** `finalize_auth` charged `429 rate_limit_exceeded`, `429 monthly_budget_exceeded`, `429 wallet_balance_exhausted`, `403 quota_scope_disabled`, `503 quota_resolution_unavailable` before any tool ran. `grep -rn "rate_limit_exceeded\|monthly_budget_exceeded" apps/mcp/src` returns nothing — **a rate-limited or budget-exhausted key is admitted**, and `tools/call` is a spend surface. | **money + abuse** |
| **P40** | `apps/agent-runtime/src/middleware/auth.ts:424` | Same defect, nine bearer operations (`/v1/agent-runs`, `/v1/agent-jobs/**`, `/v1/agents/**`): **rate-limit-free and spend-free.** | **money + abuse** |
| **P41** | `apps/gateway/src/ratelimit/workflow.ts:71` | **The workflow GRAPH gate is not ported** — only the run budget envelope. `[[agent_workflows]]` is parsed and validated by `packages/config` and then consulted by nothing (`grep -rn "agent_workflows\|agentWorkflows" apps/` → nothing). Thirteen Rust refusal codes absent (`workflow_not_found`, `workflow_disabled`, `workflow_not_allowed`, `workflow_node_required`, …). | **policy bypass** |
| **P42** | `apps/gateway/src/assets/scan.ts:51` | **Gate 1 of `screen_asset_push` is missing**: the per-asset-type content-type allowlist, and the `mcp_manifest` stdio refusal — the check that stops a published manifest making a *consuming* agent spawn an arbitrary local process. | **security** |
| **P43** | `apps/gateway/src/assets/handlers.ts:894` | **Asset egress quota + download RPM cap not ported.** `monthly_egress_bytes_budget` and `download_rpm_limit` are read by nothing; `429 asset_egress_quota_exceeded` / `429 asset_download_rate_limit_exceeded` do not exist here. | **money** |
| **P44** | `apps/gateway/src/routes/readiness.ts:32` | **The drain flag is read on 1 route out of 31.** `GATEWAY_DRAIN=true` flips `/readyz` to 503 and leaves `/v1/chat/completions` serving. Rust re-checks `is_draining()` on every AI request (`503 node_draining`); `grep -rn "node_draining" apps/` returns nothing. An operator draining before a migration still takes new billable traffic. Note this is *distinct* from the L-class drain marker 15 lines above it in the same file. | **operational** |
| **P45** | `packages/guardrails/src/index.ts:26` | **Evidence-fingerprint KEYING is held by no test.** The HMAC is implemented correctly, but every assertion in this package and in `apps/gateway/test/guardrails/` is a SHAPE assertion (`/^hmac-sha256:[0-9a-f]{64}$/`) that cannot distinguish a keyed digest from an unkeyed one — proven by two independent mutations. This is the project's signature defect class (vacuous assertion), found again. | **test integrity** |
| **P46** | `apps/agent-runtime/src/runs/events.ts:92` | `?limit=0` and `?limit=abc` answer 200 with 100 rows where Rust answers `400 invalid_event_cursor`; plus a resume-token format divergence. | **correctness** |

### 3.2 L — PLATFORM LIMIT (51 markers)

Each names a specific, real limitation. Grouped by the limitation, not the file.

| Limitation | Markers |
|---|---|
| **workerd has no filesystem** | `config/loader.ts:6`, `config/validate/capability-target.ts:125`, `config/validate/entities.ts:282` |
| **workerd has no ambient process environment** (`env` is a per-invocation argument) | `config/secrets.ts:6`, `config/caddyfile/parser.ts:7`, `secrets/env.ts:11` |
| **Bindings (incl. Secrets Store) resolve at DEPLOY time**; no runtime open-by-name/uuid | `storage/tenant-router.ts:709`, `secrets/cloudflare-bindings.ts:17`, `control-plane/ports.ts:461`, `control-plane/store/api_keys.ts:66`, `mcp/ports.ts:1351` |
| **No TLS trust-store hook / no custom CA root** | `secrets/http.ts:11`, (also a leg of `config/validate/entities.ts:282`, `storage/provider.ts:62`) |
| **workerd exposes no DNS resolver hook** — a hostname resolving to a private IP cannot be blocked pre-connect | `guardrails/net.ts:21` |
| **A Worker cannot bind a listening socket** | `billing/service.ts:5`, `cli/commands/serve.ts:6`, `:81`, `:442` |
| **A Worker has no process** — no process-lifetime counters, no `ArcSwap` reload, no runtime drain flag, no ordered request-id counter | `observability/prometheus.ts:5`, `gateway/telemetry/emit.ts:41`, `gateway/inference/ports.ts:695`, `gateway/routes/readiness.ts:17`, `control-plane/routes/admin_config_ops.ts:69` |
| **No shared mutable state across isolates** — breaker/shadow-budget become per-isolate | `gateway/inference/reliability.ts:317`, `gateway/inference/shadow.ts:146` |
| **Cache API cannot express nearest-neighbour lookup** over stored vectors | `gateway/cache/semantic.ts:27` |
| **Analytics Engine read side is account-scoped REST**; no offline emulation | `control-plane/adapters.ts:389` |
| **R2's `R2Bucket` binding has no presign method** (presign is an S3-API feature ⇒ two credentials) | `gateway/assets/ports.ts:502` |
| **D1 has no transaction spanning two databases**; SQLite `LIKE` folds ASCII only | `storage/d1/usage-d1.ts:33`, `control-plane/store/d1.ts:246` |
| **No warm TCP connection pool** (no `deadpool-postgres` equivalent) | `storage/provider.ts:62` |
| **workerd cannot spawn a process** (no `fork`/`exec`, no pipes, no process table) ⇒ stdio MCP impossible | `mcp/transport.ts:10`, `:620`, `mcp/ports.ts:44`, `:1106`, `mcp/protocol.ts:87` |
| **No Unix domain sockets ⇒ no `SO_PEERCRED`**; no mTLS termination in a Worker; no KVM/vsock/namespaces; no live-process checkpoint | `agent-runtime/ports.ts:314`, `middleware/auth.ts:244`, `runs/governance.ts:27`, `:55`, `runs/do.ts:30` |
| **WebCrypto has no synchronous Ed25519 and no XChaCha20** | `config/signed-snapshot.ts:7`, `mcp/ports.ts:1519` |
| **No `fetch` error taxonomy** (plain `TypeError`/`DOMException`) | `gateway/inference/dispatch.ts:35` |
| **JS has no deterministic destructor (`Drop`)**; `JSON.parse` loses u64 precision before validation | `payments/proof.ts:31`, `payments/intent.ts:336` |
| **A 128 MiB isolate cannot buffer an SSE body** ⇒ incremental screening, and a mid-stream denial frame with no Rust counterpart | `gateway/guardrails/middleware.ts:300`, `gateway/guardrails/stream.ts:518` |
| **Cloudflare terminates TLS before the Worker** ⇒ no cert/ACME/listener pre-flight | `config/schema/sections.ts:262` |
| **A Worker never sees a socket peer address** | `config/network-access.ts:7` |
| **No OS-thread scheduler; cannot block the event loop** | `sync-bridge/bridge.ts:53`, `runtime.ts:43` |

Two caveats recorded rather than smoothed over:

* `packages/payments/src/intent.ts:336` is L **at this seam only**. A lossless
  JSON tokenizer at the caller (or `JSON.parse` source-text access) could
  preserve u64 exactly. It is left L because the package is D-class anyway; if
  x402 is ever revived, re-open this one as P.
* `apps/gateway/src/keys/provider-secrets.ts:50` carries TWO legs. Leg 1 (dynamic
  `cf://` name) is a genuine L. Leg 2 (the synchronous `ModelResolverFactory`) is
  **portable**, so the marker is classed **P** (P14), not L, per the rule against
  downgrading to shrink the number.

### 3.3 D — DEPRIORITIZED (10 markers)

x402/Solana, per the standing user directive. No parity claim is made about them.

`config/schema/config.ts:99` · `config/x402-scope.ts:7` · `:124` ·
`config/validate/sections.ts:828` · `storage/payment-attempt.ts:5` ·
`storage/d1/wallet-d1.ts:511` · `billing/x402-inbound.ts:5` · `:167` · `:181` ·
`control-plane/routes/x402_spend_policy.ts:19`

One consequence worth surfacing because it is *not* purely deferred work:
`D1WalletStore.sweepExpiredWalletReservations` sweeps **unconditionally**,
lacking the Postgres `NOT EXISTS (payment_attempts …)` guard. Harmless while
x402 is off; a correctness bug the day it is switched on.

### 3.4 N — NOT A MARKER (20, rewritten to `PORT_TODO(`)

**Closure epitaphs** (the marker is closed; the prose was still matching the
grep): `control-plane/store/worker_registry.ts:7` · `store/api_keys.ts:34` ·
`routes/admin_mcp_server.ts:10` · `mcp/catalog.ts:7` · `mcp/durable.ts:688` ·
`mcp/session.ts:17` · `mcp/transport.ts:427` ·
`agent-runtime/durable/adapters.ts:235`

**Cross-references to a marker defined elsewhere**: `secrets/index.ts:72` ·
`secrets/http.ts:44` · `storage/index.ts:22` · `observability/index.ts:27` ·
`sync-bridge/index.ts:17` · `config/x402-scope.ts:16` ·
`control-plane/schedule/engine.ts:541` · `cli/ports.ts:709`

**"Parity boundary, not a gap"** — verified: nothing is unported, the TS
replicates the Rust (or replicates its *absence*) verbatim:
`gateway/streaming/openai.ts:191` · `streaming/responses.ts:352` ·
`streaming/usage.ts:119` · `gateway/inference/anthropic.ts:69`

---

## 4. Verification — what was checked, and what came back false

### 4.1 Claims checked and CONFIRMED

| Claim | Check | Result |
|---|---|---|
| No CORS anywhere in `apps/gateway` | `grep -rin 'access-control-allow-origin\|apply_cors' apps/gateway/src` | 3 hits, **all inside the marker comment itself** — confirmed absent |
| Rust has 9 `apply_cors_headers` call sites | `grep -rn apply_cors_headers crates/` | 9 — confirmed |
| No BPE tokenizer is paid for | `grep -c 'tiktoken\|gpt-tokenizer' bun.lock` | 0 — confirmed |
| Anthropic cache-token counters absent from Rust too | `grep -rn cache_creation_input_tokens crates/` | 0 — marker is byte-faithful, correctly N |
| `@ferrogate/sync-bridge` has zero importers | workspace grep | 0 outside itself — confirmed, safe to delete |
| `AnalyticsEngineSink` (package) has no importer | workspace grep | confirmed; `apps/telemetry` declares its own |
| `payment_attempts`, `guardrail_evaluations` absent from D1 | `grep -rn … sql/d1-ts/` | both absent — confirmed |
| `msw` is not a devDependency | `grep '"msw"' package.json */*/package.json` | absent — confirmed |
| MCP server-catalog epitaph is honest | `apps/mcp/src/durable.ts:29` imports `loadAdminServerCatalog`; `apps/control-plane` writes the `mcp-servers` documents it reads | **mounted** — epitaph correct |
| Workflow budget pre-flight is mounted | `ratelimit/workflow.ts` ← `ratelimit/middleware.ts:131` | mounted; only the `cost`/`tool_calls` DEBIT is missing (P33) |

### 4.2 Claims that came back FALSE

1. **`packages/storage/src/d1/usage-d1.ts:427` was stale — the marker was
   describing work that had been done.** It claimed
   *"`apps/gateway/src/ratelimit/middleware.ts` … still never invokes
   `reserveTokenBudget`, so the token budget is not yet enforced on a live
   request"*. It does:
   `apps/gateway/src/ratelimit/middleware.ts:752` calls
   `resolved.limiter.reserveTokenBudget(tokenBudgetCounterKey(apiKeyId),
   reading.committedTokens, reading.budget, estimatedTokens)` inside step 5b of
   the admission ladder, fed by `src/ratelimit/token-budget.ts` and released in
   the middleware's `finally`. **Marker removed, replaced with a dated epitaph
   citing that anchor.** This is the only marker deleted this wave.

2. **`packages/storage/src/index.ts:26` undercounts its own finding.** The
   header says *"Seven exports are still dead"* and then lists **nine** bullets;
   `test/mount-inventory.test.ts`'s `DEAD` array holds **eight** symbols (the
   ninth, `D1AssetMetadataStore`, is dead by *duplication* and cannot be asserted
   by importer count). The correct figure is **8 exports dead by absence + 2 dead
   by duplication**. The marker text was left otherwise intact — the finding is
   real and its gate is sound — but the count in it should not be quoted.

### 4.3 What was NOT verified — stated so the number is not over-trusted

* The 51 L claims were **spot-checked, not exhaustively re-derived**. ~15 were
  checked against the named API surface and all held; the rest are accepted on
  the strength of the marker naming a specific, falsifiable limitation. If any
  single L is wrong, it becomes a P.
* **No mutation testing was run this wave.** The mount-seam proofs from earlier
  waves are taken as given. Given this project's documented history of
  semantically-inert mutation recipes, "83 seams proven RED" should be re-earned
  before cutover, not inherited.
* Cost estimates are single-engineer calendar estimates from reading the seam
  and its Rust counterpart. They are not bottom-up plans.
* Only marker text was changed this wave. `bun run test` was run across all
  workspaces after the rewrite (§7).
* **The 17 `apps/control-plane` markers that appeared at ~06:15 are NOT
  classified in §3.1.** They arrived after the table was frozen and were
  self-tagged `P:` by their author. They are counted in §2 and excluded from the
  §5 cost model, which therefore understates the residue.
* The eight mid-wave findings (§3.1b) are recorded on the authority of the
  agent that wrote them; their `grep` evidence is quoted inside each marker and
  was **not** independently re-run here. Two spot-checks did hold:
  `grep -rn "node_draining" apps/` → 0 and
  `grep -rn "rate_limit_exceeded" apps/mcp/src` → 0.

---

## 5. The true portable residue

**~43 distinct work items behind 56 markers.** Excluding P23 (admin console,
deferred by directive) and the D class:

| Band | Items | Estimate |
|---|---:|---|
| Small (< 1 day) | 15 | 9–11 dev-days |
| Medium (1–3 days) | 15 | 28–40 dev-days |
| Large (≥ 1 week) | 12 | 65–95 dev-days |
| **Total** | **42** | **≈ 100–145 dev-days (20–29 dev-weeks, one engineer)** |

**Treat this as a floor, not an estimate.** Eight items — a fifth of the total,
and the most severe fifth — were discovered in the last ninety minutes by one
targeted audit of one surface. The discovery curve has not flattened, so the
honest statement is "at least 100–145 dev-days, with an unknown remainder that
further per-surface audits will find". A defensible number requires finishing
the data-plane certification pass (task #109) first; this ledger cannot
substitute for it.

Three items additionally carry **non-engineering prerequisites** and cannot be
scheduled until those clear:

* **P26** — R2 is **not enabled** on the live Cloudflare account.
* **P4, P27** — Containers/`@cloudflare/sandbox` need a **paid plan and a
  published image**.
* **P14** — Secrets Store bindings are deploy-time and unexercisable under
  `wrangler dev --local`; only the one authorised deploy can prove it.

### The subset that blocks deleting `crates/**`

Deleting the Rust destroys the only specification for these. They are the
cutover gate, not the whole residue:

**Admission / money / abuse (4) — the most serious class, all found mid-wave:**
P39 + P40 (the admission ladder was dropped from `apps/mcp` and
`apps/agent-runtime` when the Rust single process was split into five Workers —
spend surfaces with no rate limit, no budget, no wallet check) ·
P43 (asset egress quota + download RPM unenforced) ·
P41 (workflow graph gate absent; 13 refusal codes missing).

**Security-relevant (3):**
P42 (asset content-type allowlist + `mcp_manifest` stdio refusal missing) ·
P13 (self-hosted worker transport AEAD seal unverified) ·
P21 (cross-tenant publish-approval + malware scan legs unported) ·
P6 (eligibility gate admits candidates Rust refuses).

**Behavioural regressions against the Rust (5):**
P1 (CORS entirely absent) · P2/P3/P4 (three contract operations answer 501) ·
P5 (profile-resolution errors silently downgraded to the default posture) ·
P8 (`[[models]].cache_enabled` silently ignored) ·
P44 (drain honoured on 1 route of 31) · P46 (`?limit=0` → 200 instead of 400).

**Specification-bearing (3):**
P7 (Rust embeds the `cl100k_base`/`o200k_base` vocabularies) ·
P10 (the Rust extractor defines what a legitimate payload is) ·
P20 (Rust `asset_bucket.rs` is the multipart contract).

**Test-integrity (1):**
P45 (evidence-fingerprint keying held by no test — the Rust is the only
statement of what the key is FOR).

**Recommendation:** keep `crates/**`. Those sixteen items must be closed or
formally ratified as accepted divergences — with the Rust behaviour transcribed
into this repo — before the Rust can be deleted. The remaining ~26 items are
internal wiring, dead-code removal and duplication cleanup; they do not need the
Rust and can proceed in parallel.

**Recommendation on process, which matters more than the number:** finish the
per-surface parity certification (task #109) across all five Workers *before*
re-asking the cutover question. Marker classification alone was never going to
answer it — half the severe defects in this ledger had no marker at all until
someone read the Rust handler next to the TS handler and compared them line by
line. The marker file is a record of what has been *noticed*, not a measure of
what is *missing*.

---

## 6. Out-of-scope markers (40) — classified, not edited

Owned scope is comment text under `packages/*/src` and `apps/*/src`. These were
classified but left untouched; they are mirrors or belong to other slices.

| File | Class | Note |
|---|---|---|
| `sql/d1-ts/tenant/0001_init_tenant.sql:43` | D | `payment_attempts` |
| `sql/d1-ts/tenant/0001_init_tenant.sql:383` | P | asset handlers / object storage |
| `sql/d1-ts/control/0001_init_control.sql:178` | L | per-tenant D1 binding at runtime |
| `sql/d1-ts/control/0001_init_control.sql:259` | P | provider secrets composition (P14) |
| `sql/d1-ts/control/0001_init_control.sql:597`, `:690` | P | `billing_events` / `request_logs` / `audit_events` → Analytics Engine (P17) |
| `apps/gateway/wrangler.toml:47`, `:211`, `:495` | P | Secrets Store + routing tables + `ASSET_ENTITLEMENTS` → D1 (P14) |
| `apps/gateway/wrangler.toml:932`, `:935` | P | `SESSION` DO declared with no reader |
| `apps/gateway/wrangler.toml:938` | P | Workers AI Llama Guard detector |
| `apps/gateway/wrangler.toml:943` | P | `TELEMETRY` AE dataset (P17) |
| `apps/mcp/wrangler.toml:112` | N | session-manager epitaph |
| `apps/mcp/wrangler.toml:194` | L | deploy-time key binding, no rotation |
| `apps/mcp/wrangler.toml:207` | P | MCP audit rows → `apps/telemetry` |
| `e2e/tests/gateway.spec.ts:149`, `e2e/tests/mcp.spec.ts:22`, `:223` | P | E2E assertions widen when P34/P11 land |
| `apps/gateway/test/inference/provider-mock.ts:13` | P | swap to `msw` (verified absent) |
| `packages/storage/README.md` ×5, `apps/gateway/README.md:59` | — | doc mirrors of P14/P29/P30, D, L |
| `apps/cli/test/serve.test.ts` ×3, `apps/control-plane/test/crud.test.ts:704`, `packages/sync-bridge/test/*.ts` ×2 | — | test prose; 2 are real assertions pinning L markers |
| `docs/rewrite/*.md` ×8 | — | narrative about markers |

**A future count should use `grep -rn 'PORT-TODO(' packages/*/src apps/*/src`,
not a repo-wide grep.** The repo-wide number has never been the residue.

---

## 7. Changes made by this wave

* 127 marker lines rewritten in place (comment text only): class prefix added to
  107 P/L/D markers, 20 N markers de-marked to `PORT_TODO(`.
* 1 marker deleted as verified-stale (`storage/d1/usage-d1.ts:427`, §4.2) and
  replaced with an epitaph citing the anchor that closed it.
* 2 markers left verbatim by necessity (`apps/cli/src/commands/serve.ts:81`,
  `:442` — test-asserted string literals).
* **No executable code, no test, and no config file was changed.**
* `bun run test` run across all workspaces after the rewrite; green.
