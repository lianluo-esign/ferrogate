<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, decision record for the
  Cloudflare execution target of the LLM data plane (issue #470): the governed
  request path enumerated, Workers-native vs Container-hosted vs hybrid, the
  policy-divergence argument, the extracted decide_ai_request seam, and the
  governed-decision conformance suite that now runs both hosts over one corpus.
-->

# Cloudflare execution target for the LLM data plane (decision #470)

**Status: decided; the decision seam and the conformance suite are built, the
data-plane deployment is not.** Issue #470 freezes the choice before anyone
builds the deployment; #471, #472, #473, #474 and #475 are gated behind it.

The first slice of #470 was this record alone. Code review bounced it because a
decision record is not an acceptance criterion: the record itself argued that
the adopted Worker shell "**still requires a conformance fixture (§8)**", and no
fixture, no corpus and no runner existed. That is now addressed:

| Landed | Where |
|---|---|
| `decide_ai_request(…) -> Result<AiRequestPlan, GovernedDecision>` — the admission half of the governed path as a **value** | `crates/ferrogate-cli/src/gateway/chat.rs`, `gateway/governed_decision.rs` |
| The governed error vocabulary, scanned out of the source so a new code cannot ship without a coverage decision | `gateway/governed_decision.rs`, `gateway/governed_decision_test.rs` |
| The committed corpus — 37 fixtures, mandatory money cases, decimal-string amounts | `tests/fixtures/governed-decisions/` |
| Runner A (Rust, in-process authority) | `gateway/governed_decision_conformance_test.rs` |
| Runner B (the veto-only Worker shell, in workerd) | `workers/gateway-front/` |
| CI job failing on divergence | `.github/workflows/governed-decision-conformance.yml` |

What is **not** built, and is stated in code rather than only in prose: the
dispatch half of the governed path (steps 33-52) is still a sequence of side
effects, so its nine error codes carry
`FixtureCoverage::PendingDispatchSeam` in the vocabulary table. See §8f for why
that boundary is where it is, and §12 for the acceptance box this record still
cannot close in any developer environment.

Read [`docs/cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md)
(#424) first: it already decided *where the FerroGate runtime runs* relative to
Cloudflare compute, and this record does not re-open that. #424 answers "how do
we host FerroGate"; #470 answers the narrower and sharper question **"which
process makes the governed decision for a request that must never leave
Cloudflare"**. Also relevant:
[`cloudflare-agent-gateway.md`](cloudflare-agent-gateway.md) (#413, the
fronting-Worker/tethered principle),
[`cloudflare-container-isolation.md`](cloudflare-container-isolation.md) (#415,
the container tier the agent runs in),
[`cloudflare-secrets-resolution.md`](cloudflare-secrets-resolution.md) (#423,
bindings-only secret reads).

Every Cloudflare fact below was fetched from the CF developer docs on
**2026-07-25** and carries a source URL in §11. Anything not documented by
Cloudflare is labelled **assumed** or **unknown** in place — no guessed number
is presented as a measurement.

## Contents

- [The constraint](#the-constraint)
- [1. The governed path, enumerated](#1-the-governed-path-enumerated)
- [2. The options considered](#2-the-options-considered)
- [3. Policy divergence is the deciding factor](#3-policy-divergence-is-the-deciding-factor)
- [4. Cold start, CPU and latency](#4-cold-start-cpu-and-latency)
- [5. State access](#5-state-access)
- [6. Decision](#6-decision)
- [7. What would change my mind](#7-what-would-change-my-mind)
- [8. The governed-decision conformance suite](#8-the-governed-decision-conformance-suite)
- [9. Tethered egress, end to end](#9-tethered-egress-end-to-end)
- [10. What this record does not settle](#10-what-this-record-does-not-settle)
- [11. Verified sources](#11-verified-sources)
- [12. The acceptance boxes, and the one that no developer environment can close](#12-the-acceptance-boxes-and-the-one-that-no-developer-environment-can-close)

---

## The constraint

FerroGate's data plane is **Pingora** — `serve()` at
`crates/ferrogate-cli/src/gateway/mod.rs:189` builds a Pingora `Server`, wraps
`FerroGateway` in `http_proxy_service_with_name`, binds a TCP or TLS listener
and blocks in `run_forever()`. That is a native process with its own tokio
runtime, its own listen sockets and a resident `deadpool`/`tokio-postgres` pool
(`crates/ferrogate-storage/src/async_postgres.rs:96`), plus ten always-on
background sweepers started before the listener (`mod.rs:226-240`).

The precise reason it cannot be a Worker is worth stating accurately, because
the loose version ("isolates have no sockets") is now **false** and arguing from
it would be arguing from a stale premise:

- Workers **do** have outbound raw TCP via `connect()` from `cloudflare:sockets`
  — that is how Postgres-over-Workers works, and Hyperdrive productises it.
- What Workers do **not** have is (a) **inbound** TCP: "it is not possible to
  make an inbound TCP connection to your Worker", listening is "coming soon";
  (b) sockets that outlive a request — "TCP sockets cannot be created in global
  scope and shared across requests", which is exactly the resident-pool model;
  (c) native code execution — an isolate runs JS/WASM, and Pingora is neither.

So the blocker is structural but narrower than folklore: **a Worker can be a
client of anything; it cannot be Pingora, and it cannot hold FerroGate's
resident state.** Every Worker we ship today (`agent-gateway` #413, `d1-proxy`
#450, `mcp-server` #409) is auxiliary control-plane surface; **none is the
AI-proxy ingress.**

**The framing correction that matters.** The issue treats "no Cloudflare
execution target for the governed path" as one gap. It is two, with different
requirements, and conflating them is how you end up building the wrong thing:

1. **Tethered egress (the closed loop).** An agent running in a Cloudflare
   Container (#415/#472) must reach a governed gateway **without leaving
   Cloudflare**. This needs *one* reachable governed endpoint per deployment,
   ideally near the agent's container, tolerant of a warm-up, carrying a
   minutes-long run's worth of traffic. It does **not** need global anycast p50.
   This is what actually gates #471–#475.
2. **A global public multi-tenant AI-proxy ingress on Cloudflare.** This needs
   edge-global placement, scale-to-zero, and a low added-latency budget on
   every request from every customer.

**#424 already decided (2).** Its verdict: "No-go — for migrating the
high-throughput production data plane to Containers today", with the hybrid
edge-Worker + origin as the shape for high-throughput serving. #470 must not
quietly reverse that. What #470 decides is **(1)**, and the correct answer to
(1) is not forced to be the same as the answer to (2).

---

## 1. The governed path, enumerated

Option A's real price is reimplementing *this list*, and the decision cannot be
costed without it. This is the ordered traversal of a single
`POST /v1/chat/completions`, grounded in the tree at `HEAD`.

### 1a. Ingress, before any AI logic

`FerroGateway::handle_request_filter` (`gateway/handlers.rs:20`):

| # | Step | Seam |
|---|---|---|
| 1 | request-id mint | `state.next_request_id()` |
| 2 | W3C trace context: validate `traceparent` (version/len/hex/all-zero rules), derive `trace_id`, bound `tracestate` to 512 B | `gateway/mod.rs:120` `ingress_trace_context` |
| 3 | `/control/v1` → `/admin/v1` alias canonicalisation, before anything reads the path (#453) | `ferrogate_admin::control_plane::canonicalize_alias_path` |
| 4 | network access: IP allow/deny + unauthenticated per-source rate limit | `state.check_network_access` (`state.rs:4700`) |
| 5 | CORS preflight for `/admin/*` | `responses::write_cors_preflight_response` |
| 6 | CSRF / confused-deputy guard on admin mutations (`Sec-Fetch-Site`, else `Origin`) | `handlers.rs:95` |
| 7 | pre-request plugin hooks | `state.run_pre_request_hooks` (`state_tools.rs:404`) |
| 8 | fixed API operation contract: documented-path → method-not-allowed | `gateway::api_contract` |
| 9 | health/readiness short-circuit; shared control-plane sync | `gateway/local.rs:256,270` |
| 10 | route-group dispatch (35 groups) | `gateway/route_groups.rs:34` |
| 11 | custom-domain static-site resolution (#265) | `try_custom_domain_site_serve` |
| 12 | dynamic route match → upstream → endpoint selection → target URI rewrite | `state.match_runtime_route`, `select_runtime_upstream_endpoint` |

### 1b. The AI request itself

`FerroGateway::handle_ai_request` (`gateway/chat.rs:136`), which serves **both**
`/v1/chat/completions` and `/v1/responses`:

| # | Step | Seam / line |
|---|---|---|
| 13 | **authenticate** across four key sources — external auth service, durable/virtual key, static config key, and the zero-config auth-disabled wildcard — each with its own scope semantics (`WILDCARD_SCOPE` for static config keys, empty-set-is-not-admin for durable keys) | `auth.rs:383` |
| 14 | scope check for the endpoint's scope (`chat.completions` / `responses.create`) | `auth.rs:383` |
| 15 | **`finalize_auth`**: resolve effective quota over the scope chain (org→team→project→workspace→key, `min` per dimension, recording which scope won), `quota_scope_disabled` deny, monthly-budget check *against the winning scope's aggregate spend*, prepaid-wallet balance check, then per-window RPM consumption | `auth.rs:660` |
| 16 | agent-run-id header parse/derive; four workflow headers + the "version/node/iteration require workflow-id" coherence rule | `chat.rs:2612` |
| 17 | gateway-config profile resolution (`x-ferrogate-config`), incl. per-api-key allow and disabled/not-found/not-allowed codes | `state.resolve_gateway_config_profile` |
| 18 | draining check (`node_draining`) | `state.is_draining()` |
| 19 | body read under `limits.inference_body_max_bytes`, `payload_too_large` + close | `gateway/body.rs:15` |
| 20 | JSON parse → typed parse → `validate_request_metadata` bounds (#171) | `chat.rs:2754` |
| 21 | per-key model allow/deny | `auth.can_use_model` |
| 22 | model registry resolve, distinguishing `model_disabled` from `model_not_found` | `state.resolve_model` |
| 23 | external RBAC authorize (`model:{name}`) | `auth.rs:764` |
| 24 | tenant model visibility | `state.can_tenant_use_model` |
| 25 | **usage estimation** — real BPE via `tiktoken-rs` (`cl100k_base` / `o200k_base`) with a `chars/4` fallback, plus message overhead, `max_tokens` and `n` (#282) | `crates/ferrogate-cli/src/tokenizer.rs` |
| 26 | candidate route computation under the tenant's region allowlist, cost-ranked | `state.candidate_model_routes` |
| 27 | canary rollout: sticky bucket by api-key→org→project→model, promote canary route (#276) | `state_rollout.rs` |
| 28 | region fail-closed (`region_not_allowed`, #173) | `chat.rs:2886` |
| 29 | guardrail envelope normalisation (protocol-aware segmentation) | `ferrogate_guardrails::normalize_request` |
| 30 | shadow/mirror spawn — sampled, budget-capped, metered-not-billed (#276) | `chat.rs:243` |
| 31 | **workflow policy**: node exists / is a model node / edge allowed / model+provider allowed / iteration cap / model-call cap / token budget / timeout — 13 distinct denial codes | `chat.rs:3158` |
| 32 | workflow provider constraint applied to the candidate list | `chat.rs:3345` |

Then, **per candidate route** (fallback loop, `chat.rs:334`):

| # | Step | Seam / line |
|---|---|---|
| 33 | provider exists | `state.providers` |
| 34 | provider circuit breaker | `state.provider_circuit_allows` |
| 35 | per-key provider allow/deny | `auth.can_use_provider` |
| 36 | **guardrail, Request stage** — policy selection by org/project/workspace/key/service-account/gateway-config/model/provider scope, streaming mode, shadow vs enforce, deterministic checks + external detectors (Presidio, LLM Guard, Workers AI Llama Guard, custom HTTP), merge of enforcement, evidence rows | `chat.rs:429` → `state_quota_and_policy.rs:386` |
| 37 | **policy engine** deny (`PolicyDecision::Deny`) | `chat.rs:497` |
| 38 | **cache gating** (`ai_cache_enabled` per key/model/provider/profile) + exact cache key + semantic-cache context (#273) | `chat.rs:521`, `state_routing.rs:281` |
| 39 | cache lookup → on hit: cache-hit metric, request log with `cache_status:"hit"`, raw response, **return** | `chat.rs:555-607` |
| 40 | API-key monthly token-budget reservation against the durable counter (RAII, `Drop` releases) | `state_quota_and_policy.rs:366` |
| 41 | TPM window consume, once per logical request | `state_routing.rs:802` |
| 42 | **prepaid-wallet credit hold** against `balance − outstanding_reservations` (#169 concurrent-overdraft fix), RAII | `state_wallets.rs:190` |
| 43 | provider request preparation: adapter translation across **8 canonical provider adapter families** (`openai-compatible`, `anthropic`, `gemini`, `grok`, `openrouter`, `azure-openai`, `bedrock`, `vertex` — `ferrogate-providers/src/types.rs:263-315`) implemented by 11 adapter modules, secret resolution, **AWS SigV4 signing** (`ferrogate-providers/src/sigv4.rs`, 1,183 lines) or Vertex OAuth | `chat.rs:3467` |
| 44 | trace-context header injection + provider-attempt identity | `chat.rs:3494`, `ProviderAttempt::for_request` |
| 45 | dispatch with per-attempt retry, retryable-status classification, fallback-route escalation, bounded body read, transport-failure classing (#384) | `gateway/dispatch.rs:57` |
| 46 | streaming: SSE normalisation (`responses_stream.rs`, `messages_stream.rs`), usage extraction from the last usage frame, guardrail stream capture with an overflow/timeout budget (`guardrail_stream_buffer_limit_exceeded`) | `chat.rs:1469-1630` |
| 47 | **billing event** — real usage if the provider reported it, else the estimate, per provider attempt, with latency and request metadata; a failed billing write **fails the request** (`502`) | `chat.rs:1834` → `state_billing_metering.rs:22` |
| 48 | token reservation settle; wallet hold capture/release | `chat.rs:1906` |
| 49 | **guardrail, Response stage** — Deny (rewrite body to the error envelope) or Redact (rewrite body), with an admin audit event either way | `chat.rs:1919` |
| 50 | request log with per-key body-recording gating and 16 KB truncation | `chat.rs:2013` |
| 51 | cache store (exact + semantic mirror) on success only | `chat.rs:2051` |
| 52 | circuit-breaker success/failure record; guardrail-match metric; admin audit events | `state.record_provider_{success,failure}` |

### 1c. How big this is, in numbers

- **~19,800 lines** of governed-path Rust in `ferrogate-cli` alone — inline
  `#[cfg(test)]` modules included, since they live in the same files —
  across `chat`, `embeddings`, `images`, `messages`, `messages_stream`,
  `responses_stream`, `dispatch`, `body`, `shadow`, `handlers`, `route_groups`,
  `api_contract`, `auth`, `metering`, `tokenizer`, `semantic_cache`,
  `network_access`, `state_quota_and_policy`, `state_billing_metering`,
  `state_rollout`, `state_guardrail_evidence`, `state_wallets`), on top of
  `ferrogate-guardrails` (~10.5k), `ferrogate-providers` (~8.5k) and
  `ferrogate-policy` (~3.6k).
- **55 distinct static client-visible error codes**, now enumerated rather than
  estimated: `GOVERNED_ERROR_VOCABULARY` in
  `crates/ferrogate-cli/src/gateway/governed_decision.rs` lists every code
  `chat.rs` and `auth.rs` can emit — **44 at admission, 9 in the dispatch loop,
  2 on the admin gate** — and a source scan
  (`governed_decision_test.rs`) fails the build if a code appears in either file
  without an entry. The earlier "at least 41 … across 28 error-writing call
  sites" was a lower bound counted by hand; this is the actual set, and it can no
  longer drift. On top of it sit the dynamic guardrail codes carried on a
  `GuardrailMatch`, which are not static literals and are not in the table.
  Each code is a governed outcome with a status, a stable string, an audit
  consequence and, in several cases, a money consequence.
- **The sequence already exists four times in-tree.** `chat.rs` (chat +
  responses), `embeddings.rs`, `images.rs` and `messages.rs` each independently
  re-walk steps 33-52 — same order, same seams, four copies, one language, one
  process. That is not a criticism of those files; it is the measurement that
  makes §3 concrete.

---

## 2. The options considered

- **Option A — Workers-native ingress.** Reimplement steps 13-52 as a Worker
  (TypeScript against `fetch` + D1/KV/DO bindings). True edge, no container, no
  cold container on the path, scale-to-zero. Cost: a **second implementation of
  every governed decision above**, in a second language, against a second state
  layer.
- **Option B — Pingora in a Cloudflare Container**, fronted by a thin Worker
  that routes to it. **One** data-plane implementation; the repo-root
  `Dockerfile` deploys essentially unchanged (#424 §1). Cost: container cold
  start, Worker→DO→container hops on every request, per-instance cost, no
  autoscaling.
- **Option C — hybrid**: the Worker owns auth/quota/cache/meter and forwards
  only provider dispatch; Pingora is retained for self-hosted. Cheap at the
  edge; needs a crisp contract for which decisions live where.
- **Option A′ — Workers-native ingress hosting the *same* Rust decision core,
  compiled to `wasm32`.** Not in the issue; named here because it is the only
  version of A that does not create a second implementation, and because it is
  the thing that could legitimately overturn this decision later (§7).

---

## 3. Policy divergence is the deciding factor

This is not an abstract risk in this repository. It is a recurring, documented
failure mode with four distinct shapes, and every one of them happened
*within a single language and a single process*.

**#383 — one module forgot a contract its siblings honoured.** Streaming
per-check guardrail evidence never appeared against live Supabase
(`buffer_error=false, shadow=false, rejected=false`) while every earlier
non-streaming stage of the same scenario persisted fine. The cause, recorded on
the regression test that now pins it
(`crates/ferrogate-storage/src/async_postgres_test.rs:43-57`): *"`guardrail_evidence.rs`
was the one module whose four transactions never pinned"* `search_path`, so its
rows resolved against the connection-default schema while "the audit-event and
request-log rows for the same request" landed in the configured one. Nothing
failed loudly — the writer runs detached and only `warn!`s — so **evidence was
silently lost**, and "only a live-Supabase scenario could see it". The contract
was invisible at the call site, so a sibling could omit it and still compile,
still pass unit tests, and still return `Ok`.

**#476 vs #469 — the same money decision made twice, with different rigour.**
#469 fixed the *offline reconciler* to accept spec-valid overpayment
(`settled >= expected`) instead of demanding an exact match. #476 then found the
*online* path — `finalize_settlement` — captured the tenant's wallet hold on a
merchant-reported `success: true` **without ever comparing the reported settled
amount to the owed amount**, falling back to the owed amount when the header
omitted it. #476 states the diagnosis exactly: *"The two paths make the same
money decision with different rigour — the online path trusts a
counterparty-supplied field, the offline path verifies against the chain."*
Note the asymmetry: #469 failed **closed** (funds stranded); #476 failed
**open** (underpayment captured full value). The lesson is not that two
implementations differ; it is that **you do not get to choose the direction in
which they differ**, and one of the two directions loses money silently.

**#188 / #397 — write-succeeds, runtime-ignores.** A control-plane surface
accepts a write that the runtime never consults. #188: `StoredQuotaPolicy` had
no `asset_storage_quota_bytes`, so the enforcement path read only the plan
default and a per-tenant override was unrepresentable. #397: a channel-move on a
static site "returns 200 but changes nothing served", because `serve_site_file`
resolves through the manifest and never consults the channel. The operator sees
success; the governed behaviour is unchanged.

**And the in-repo baseline (§1c).** Steps 33-52 already exist four times in
`ferrogate-cli`, in the same language, same process, same reviewers. Keeping
those four in agreement is ongoing work. Option A proposes a **fifth copy, in a
different language, on a different runtime, with a different state layer,
reviewed by different people, deployed on a different cadence.** The prior on
that staying identical is poor, and #476 tells us what the failure looks like
when the diverging decision is about money.

### Three divergence traps that are not hypothetical

These are the specific places where an independently-written Worker would
diverge **silently** — no error, no alarm, just a different answer:

1. **The tokenizer is on the money path.** `estimate_chat_completion_usage`
   drives the TPM pre-check, the monthly-budget reservation, the prepaid-wallet
   hold **and** the route cost ranking, using `tiktoken-rs`' real BPE
   (`cl100k_base` / `o200k_base`) with a documented `chars/4` fallback. A Worker
   using any other tokenizer — a JS tiktoken build, a different fallback
   threshold, a different `max_tokens`/`n` overhead formula — reserves a
   different number of credits for the identical request. Nothing errors; the
   two hosts simply admit and charge differently.
2. **The cache key encodes a security invariant.** `ai_response_cache_key`
   (`state_routing.rs:281`) hashes an ordered struct that includes the full
   tenant tuple, the provider/model triple, the request body **and
   `guardrail_policy_fingerprint`** — the last one exists specifically so that
   "any guardrail-policy change … rotates this fingerprint, so entries cached
   under the old policy can no longer be served" (#233). An edge cache that
   reproduces the key "close enough" but computes the fingerprint differently
   will serve, under a tightened redaction rule, content that rule was activated
   to suppress. The failure is invisible: a cache hit looks like a cache hit.
3. **Serving from cache *is* a governed decision.** On a hit, today's path
   (`chat.rs:555-607`) records a cache-hit metric and a request log with
   `cache_status:"hit"`, and returns — **before** the token reservation, the TPM
   consume and the wallet hold (which begin at `chat.rs:612`). So an edge cache
   that answers without consulting the origin silently skips: the request log
   row, the cache-hit metric, and — for anyone who later moves a quota check
   above the cache — whatever else has moved. "The Worker just caches" is not a
   transport optimisation; it is a decision to bypass steps 39-52.

### The rule this record adopts

> **Any component that makes a governed decision must either (a) be the only
> implementation of that decision, (b) be provably directional — able only to
> deny where the authority would also deny, never to allow or to author a
> metered amount — or (c) be proven equivalent to the authority by a shared
> fixture suite that fails CI on divergence.**
>
> An option that satisfies none of these three joins the #383 / #476 list. That
> is the criterion the options are graded against.

---

## 4. Cold start, CPU and latency

Every row is labelled. **Verified** = quoted from the CF docs (§11, fetched
2026-07-25). **Assumed** = a reasoned inference we have not measured.
**Unknown** = we could not determine it and it needs a live measurement.

### 4a. Option A — is a Worker big enough to run the governed path?

| Fact | Value | Status |
|---|---|---|
| CPU time per invocation, Workers Paid | **30 s default, configurable to 5 min** (`limits.cpu_ms`, max `300000`) | **Verified** |
| CPU time per invocation, Workers Free | 10 ms | **Verified** |
| Wall-clock duration, HTTP-triggered | "No limit"; a Worker streaming a response body stays active | **Verified** |
| `waitUntil()` after response | up to 30 s | **Verified** |
| Worker script size | 10 MB gzipped / 64 MB uncompressed (Paid) | **Verified** |
| **Startup time** (global scope must parse+execute) | **1 s**, both plans; violation is a *deploy* rejection (`10021`) | **Verified** |
| Memory per isolate | 128 MB (JS heap + WASM allocations) | **Verified** |
| Subrequests per invocation (Paid) | 10,000 (configurable up to 10 M); Free 50 | **Verified** |
| Simultaneous open connections | 6 per invocation, incl. `fetch`/KV/R2/D1/`connect()` | **Verified** |
| Worker invocations per request (service bindings) | max 32 | **Verified** |
| Cost of the governed path's CPU (BPE tokenisation of a large prompt + N regex detectors + policy scope matching) | not measured | **Unknown** |

**Reading.** The CPU ceiling is *not* the binding constraint for Option A — 30 s
default and 300 s max is enormous next to a request that today does BPE
tokenisation plus regex evaluation. The real Option-A constraints are the ones
nobody quotes: **1 s startup** (a WASM tokenizer with embedded `cl100k_base` +
`o200k_base` vocabularies must instantiate lazily inside the handler, not at
global scope), **128 MB per isolate** (shared across concurrent requests on that
isolate), **10 MB gzipped bundle**, and **6 simultaneous connections** (a
request that fans out to a policy read, a quota counter, a guardrail detector
and the provider is close to that ceiling before any fallback route). None of
these is disqualifying; all of them are unmeasured, and the honest statement is
that **Option A's runtime feasibility is plausible and unproven**.

### 4b. Option B — what does a Container cold start actually cost?

| Fact | Value | Status |
|---|---|---|
| Container cold start | "Container cold starts can often be in the **1-3 second range**, but this is dependent on image size and code execution time, among other factors" | **Verified** |
| FerroGate's own boot time inside that (config load, control-plane connect, sweeper spawn) | not measured | **Unknown** |
| Request path | Worker → Durable Object → container process on `defaultPort`; HTTP only, "end-users cannot make non-HTTP TCP or UDP requests" | **Verified** |
| DO/container co-location | "Durable Objects and their associated Container instances are **not guaranteed to run in the same location**" | **Verified** |
| Keeping an instance warm | without `sleepAfter` or a manual stop the instance keeps running; `onActivityExpired()` can be overridden | **Verified** |
| Always-on guarantee | none — "Cloudflare does not guarantee that any instance will run for any set period of time"; hosts restart, `SIGTERM` then `SIGKILL` after 15 min, "rebooted elsewhere shortly after" | **Verified** |
| Autoscaling | "**Not today**, though Cloudflare plans to add built-in autoscaling in a future release"; scaling is manual via explicit IDs or a fixed-N `getRandom` | **Verified** |
| Placement | instances are selected "regardless of location" — locality is a listed current limitation; a woken instance may land in a different region than the caller | **Verified** |
| Disk | "All disk is ephemeral" | **Verified** |
| Whether DO active-duration billing accrues for the full lifetime of a streamed response through a container | not documented by CF; #424 §7 estimated ~$307/mo at 100 M req × 2 s and flagged it for measurement | **Unknown** (still) |
| Container↔`outboundByHost` shim round-trip latency | not documented by CF | **Unknown** |
| Warm-start amortisation: starting the gateway container at run admission takes the 1-3 s off the request path for an agent run | a scheduling inference from the verified `/container/start` control surface (#415), not a measurement — see §12 and #424 §9 P9 | **Assumed** |

**Is the cold start on the request path?** *It depends on which gap you are
closing, and this is the crux of the framing correction.*

- **For the tethered agent loop (gap 1): no, not necessarily — and this is
  designable, not hopeful.** The control plane already starts the agent's
  container explicitly through `POST /container/prepare` / `/container/start`
  (#415, `workers/agent-gateway/src/container.ts`). A gateway container for that
  tenant can be started **at run admission, in parallel with the agent's own
  container**, and both are warm before the agent issues its first token. The
  cold start is then paid **once per run, off the request path**, and amortised
  over a minutes-to-hours job (#474). A 1-3 s warm-up in front of a coding-agent
  run is noise; the same 1-3 s in front of an interactive chat completion is not.
- **For a global public ingress (gap 2): yes, and it is disqualifying at the
  tail.** With no autoscaling, location-blind instance selection, no always-on
  guarantee and a DO in the path of every streamed response, a cold or
  remotely-placed instance puts seconds on a p99 that is supposed to be tens of
  milliseconds of gateway overhead. This is precisely why #424 said no-go for
  the high-throughput data plane, and nothing found here changes that.

**The measured figure the issue's acceptance asks for cannot be produced in this
environment** (no Docker, no live Cloudflare account — see §10). #424 §9 already
specifies the runbook that produces it (P5 cold start, P8 warm p50/p99 vs
direct-origin baseline, DO duration on streams, shim latency). This record does
not duplicate it; it inherits it and adds one step (§10).

---

## 5. State access

The governed path needs config, policy, quota counters, wallets, and durable
writes (billing events, request logs, guardrail evidence, audit events).

**From a Container (Option B): nothing changes.** The binary keeps its existing
`deadpool`/`tokio-postgres` control plane, or the D1 `ControlPlaneStore` backend
(#419/#420/#449/#450) with the per-tenant proxy bindings from #455. Cloudflare
bindings that a container process cannot hold directly (KV, R2, Secrets Store,
Workers AI) are reached through **Outbound Workers** — a documented first-class
platform feature, decided and quantified in #424 §6: the container issues a plain
HTTP request to a virtual hostname, an `outboundByHost` handler runs *in the
Workers runtime, outside the sandbox*, with `env` access to every declared
binding, and "no token is ever passed into the sandbox". **New control-plane
machinery required: zero.**

**From a Worker (Options A/C): a new state layer per governed datum.**

| Governed datum | Today | From a Worker | Note |
|---|---|---|---|
| config / policy / guardrail policies / model registry | in-process snapshot, hot-reloadable | D1 or KV read per request | D1: 1,000 queries per Worker invocation (Paid), 6 simultaneous connections, 10 GB max DB, single-threaded per DB — **verified** |
| RPM / TPM / monthly-token counters | `ClusterCounterBackend` — in-memory or Redis (`state.rs:5405`) | a third variant: Durable Object (single-threaded, strongly consistent, globally addressable) or D1 | The seam already exists; adding a variant is **additive and does not fork the decision** |
| prepaid wallet reservations (CAS) | `state_wallets.rs:190`, atomic against `balance − outstanding` | DO or the #450 D1 proxy `/d1/query` atomic family (#454/#455) | Money path; must be one implementation |
| billing events / request logs / evidence / audit | storage repositories, outbox-swept | D1 writes, or forward to the origin | |
| existing Postgres control plane | resident pool | **Hyperdrive** — "maintains the underlying database connection pool", supports "any Postgres or MySQL database" | **Verified**; means Option A is not forced onto D1 |

**Which option makes the control-plane story simpler? Option B, unambiguously,
and not by a small margin.** Option B needs **no new backend at all**. Option A
needs a Worker-side reimplementation of the quota scope-chain resolution, the
wallet CAS, the counter windows and the evidence writers — and crucially, the
quota counters and the wallet are the *same physical counters* the origin uses,
so if both hosts are ever live at once they must agree on the semantics
byte-for-byte or the tenant is double-charged or double-admitted. That is the
#476 shape with a network partition added.

One conclusion is worth extracting independently of the A/B/C choice: **adding a
Durable Object variant to `ClusterCounterBackend` is a good idea under every
option.** It is a new *backend* for an existing decision, not a new
*implementation* of the decision, and it gives a Cloudflare-resident deployment
strongly-consistent counters without Redis. That is the cheap, safe, always-right
move.

---

## 6. Decision

**Option B — Pingora in a Cloudflare Container is the governed data plane for
on-Cloudflare deployments — fronted by a Worker that is contractually forbidden
from making governed decisions.** Option A is rejected. Option C **as stated in
the issue** is rejected, because each of the four things it assigns to the
Worker — auth, quota, cache, meter — is a governed decision by the §3 rule; a
narrowed, non-governing version of C's Worker is adopted as the *shell* of B.

Rationale, in order of weight:

1. **B is the only option with one implementation of the governed path.** §1
   enumerates ~19,800 lines and 41+ error codes of governed decisions, already
   duplicated four times in one language, and §3 shows this repo losing evidence
   (#383) and money (#476) to divergence between *sibling paths in the same
   process*. A cross-language, cross-runtime fifth copy is the largest
   divergence surface anyone has proposed here, and it would sit directly on the
   metering and guardrail paths — the two things the product exists to guarantee.
2. **The cold start, which is the headline objection to B, is not on the request
   path for the workload that actually gates #471-#475.** The tethered agent
   loop starts its containers explicitly (#415); the gateway container warms in
   parallel at run admission and is amortised over a minutes-long run (#474).
   The 1-3 s figure is verified; making it off-path is a scheduling decision we
   already own.
3. **B's control-plane story is free.** No new backend, no second quota
   implementation, no second wallet CAS. Bindings arrive through the documented
   Outbound Workers shim that #424 already adopted. The `Dockerfile` ships as-is.
4. **B keeps `cf://` secret resolution honest.** #423 decided that Secrets Store
   values reach a consumer *only* through a Worker binding, and documented the
   containerised-runtime recipe (deploy glue exports
   `FERROGATE_CF_SECRET_<NAME>`). B consumes that decision unchanged. Option A
   would need its own provider-credential path — and step 43 includes AWS SigV4
   signing and Vertex OAuth, so "its own credential path" means a second
   implementation of request signing. That is a security-critical divergence
   surface, not a convenience one.
5. **The costs of B are real, bounded and already documented.** #424 quantified
   them: no autoscaling (verified), 4 vCPU / 12 GiB per instance, location-blind
   placement, DO duration billing on streams (unverified, flagged). They bound
   *throughput and geography*, not correctness. They are why this record does
   **not** extend B to the global public ingress.

### The Worker shell contract (what the fronting Worker may and may not do)

The Worker in front of the container exists, and it is useful. Its contract:

**MAY:**
- Terminate TLS, own the custom domain, and route to the container instance
  (`getContainer`/`containerFetch`) — pure transport.
- Select the target instance and **pre-warm** it (start-on-admission, §4b).
- Serve `/healthz` and static assets that carry no tenant decision.
- Reject on facts that are *host-independent and fail-closed*: malformed
  requests, absent credentials, requests over the body cap, and an explicit,
  operator-managed **deny list** (revoked key ids, suspended tenants) that can
  only turn an origin ALLOW into a Worker DENY.
- Attach request-id / trace headers the origin will re-validate anyway.

**MUST NOT:**
- Decide `allow` for anything the origin has not also decided. A Worker verdict
  is never an authorisation, only a veto.
- Author, adjust or consume any metered amount — no token estimate, no wallet
  hold, no counter decrement, no billing event.
- Evaluate a guardrail policy for effect (it may *pre-warm* a detector's
  connection; it may not decide Deny/Redact).
- Serve a response from cache without the origin having seen the request
  (§3 trap 3). If edge caching is ever wanted, it arrives as a *feature of the
  governed path* — origin-authored `Cache-Control`/cache tags the Worker merely
  obeys — never as Worker-side logic that reconstructs `ai_response_cache_key`.

Every "MAY" item is directionally safe under the §3 rule; every "MUST NOT" item
is a governed decision. The **deny list is the only place the Worker makes a
call at all**, and it is fail-closed by construction — which is precisely why it
requires a conformance fixture (§8), just a directional one rather than an
identity one.

That contract is now executable rather than aspirational.
`workers/gateway-front/src/shell.ts` is the whole of the shell's governed
surface, and every fixture in the corpus is run through the real Worker in
workerd asserting the "MUST NOT" list as properties: never `allow`, never
`cache_hit`, never a non-empty `metered`, never a durable write or audit event,
never a deny code outside the shared vocabulary. The deny list is keyed on the
**SHA-256 of the presented secret** rather than on a key id, because mapping a
token to a key id is a control-plane read and would quietly make the shell a
second authenticator — the exact drift this contract exists to prevent.

---

## 7. What would change my mind

Stated concretely, so this is falsifiable rather than a preference:

1. **A′ becomes real: a host-agnostic decision core.** If the governed
   *decisions* (not their I/O) were extracted into crates that compile to
   `wasm32-unknown-unknown`, then a Worker could host the **same** code and
   Option A stops being a second implementation. Today that is blocked, and the
   blockage is measurable, not vague:
   - `ferrogate-policy` (the quota scope chain, workflow budget and x402 spend
     decisions) depends on `ferrogate-storage`, which pulls
     `deadpool-postgres`, `tokio-postgres`, `native-tls` and `tokio` — none of
     which target `wasm32`. The coupling is thin — six items across two non-test
     files: `QuotaScopeKind`, `StoredPlan`, `StoredQuotaPolicy` in `quota.rs:8`
     and `StoredWorkflowRunBudget`, `WorkflowBudgetDimension`,
     `WORKFLOW_RUN_BUDGET_EXHAUSTED` in `workflow_budget.rs:14,108` — so the fix
     is a **row-types crate split**, not a rewrite.
   - `ferrogate-guardrails` depends on `reqwest`, `rustls` and `tokio` for its
     external-detector adapters; the deterministic detectors themselves are
     `regex` + `serde_json` and would move cleanly behind a feature gate.
   - Unknown until built: the resulting WASM bundle against the **verified**
     10 MB gzip / 1 s startup limits, especially with embedded BPE vocabularies.

   If someone lands that split and demonstrates a bundle inside the limits with
   the §8 suite green, **Option A′ is better than B** — it has one
   implementation *and* edge placement. That is the future this record is trying
   not to foreclose.
2. **Cloudflare ships Container autoscaling with locality-aware routing** and a
   documented always-on guarantee. Two of the three current no-gos for extending
   B beyond the tethered loop are platform roadmap items ("Not today, though
   Cloudflare plans to add built-in autoscaling in a future release").
3. **Measurement contradicts the amortisation argument.** If the #424 §9 P5/P8
   runbook shows FerroGate's in-container boot is far worse than the 1-3 s
   platform figure (e.g. control-plane connect dominates), or DO duration
   billing on streams makes B's unit economics untenable even at agent-loop
   volumes, B needs re-costing.
4. **The product target changes.** If the goal becomes a global public
   multi-tenant edge AI proxy rather than the tethered agent loop, this decision
   does not scale to it — but the answer then is **#424's hybrid**, not Option A.
   Reaching for A because B does not scale globally would be solving a
   throughput problem with a correctness liability.

---

## 8. The governed-decision conformance suite

Required by the issue's acceptance if A or C is chosen. This record chooses
neither in full — but the adopted Worker shell (§6) still makes one class of
call, and A′ (§7) would make many. **The suite exists.** It is the mechanism
that would have caught #383 and #476, and it is the prerequisite for any future
work that puts a governed decision in a second host.

The repo already had the pattern to copy: `ferrogate-guardrails`' detector
conformance harness (`crates/ferrogate-guardrails/src/conformance.rs`,
`run_detector_conformance`, `ConformanceReport`, feature-gated `conformance`,
never in a production build). This is the same idea one level up — conforming a
*host* instead of a *detector*.

### 8a. Fixture format (language-neutral, committed, reviewed)

`tests/fixtures/governed-decisions/<case>.json` — JSON, because both hosts must
read it and neither may own it. The normative format and every rule below live
next to the corpus in
[`tests/fixtures/governed-decisions/README.md`](../tests/fixtures/governed-decisions/README.md);
a worked example:

```jsonc
{
  "id": "money/wallet-balance-exhausted",
  "schema": 1,                    // must equal GOVERNED_DECISION_SCHEMA
  "description": "…",             // what governed behaviour this pins; asserted non-trivial
  "world": {
    "config": { /* deserialised straight into the real Config — a fixture
                   cannot describe a world the product cannot be configured
                   into */ },
    "draining": false,
    "wallets": [ { "tenant_id": "tenant-1", "balance_credits": "0" } ],
    "quota_policies": [ /* StoredQuotaPolicy rows */ ]
  },
  "request": {
    "endpoint": "chat.completions",
    "headers": { "authorization": "Bearer secret-1" },
    "headers_bytes": { },         // legal HTTP bytes that are not UTF-8
    "body": { "model": "fast-chat", "messages": [ /* … */ ] },
    "body_over_limit": false,     // the Session-side read hit the cap, as a fact
    "now_unix": 1784937600
  },
  "expect": {                     // the authority's golden decision
    "schema": 1, "outcome": "deny", "status": 429,
    "code": "wallet_balance_exhausted",
    "metered": { "prompt_tokens": 0, "completion_tokens": 0,
                 "credits_reserved": "0", "credits_captured": "0" },
    "durable_writes": ["request_log"],   // ordered kinds, not payloads
    "audit_events": []
  },
  "worker_shell": {               // what the veto-only §6 shell may answer
    "deny_list": [],              // SHA-256 hex of revoked bearer secrets
    "expect": { "schema": 1, "outcome": "defer", "status": 0 }
  }
}
```

Two deliberate departures from the sketch the first slice published, both
because the sketch promised more than the code can truthfully emit:

- **`quota` and `guardrail` are not in the canonical record yet.** At admission
  there is no guardrail verdict and no reservation to report, so emitting
  permanently-null objects would be decoration. They join the record — with a
  `GOVERNED_DECISION_SCHEMA` bump, which every fixture declares and the runner
  asserts — when the dispatch seam lands (§8f). Populating
  `quota.scope_that_denied` additionally needs the winning scope plumbed
  through `AuthError`, which today carries only status/code/message across 40
  construction sites.
- **`provider_response` is absent.** Scripting a provider response only matters
  for dispatch-stage cases, which are not in the corpus yet; a field no runner
  reads is a promise, not a format.

Rules that make the corpus load-bearing rather than decorative — each one now a
test, not an intention:

- **Amounts are decimal strings parsed as integers**, never floats and never
  compared lexically — the #469 discipline, applied to the fixture format
  itself so a suite cannot re-introduce the bug it exists to prevent.
  `parse_amount` rejects `"1.0"`, `"1e3"`, `"-1"`, `" 1"` and `""`.
- **Golden, committed, reviewed.** Expected values are generated from the
  authoritative Pingora path but **checked in**, so a behaviour change appears
  as a reviewable diff. This is the anti-#383 mechanism: a contract that is
  invisible at the call site becomes visible in a golden file.
- **Coverage gate.** Every vocabulary entry marked `FixtureCoverage::Required`
  must appear as some fixture's expected code; a code with no fixture **fails
  the suite**. 36 of the 44 admission codes are marked required and fixtured.
- **The vocabulary is scanned out of the source**, not maintained by hand. A new
  governed code in `chat.rs` or `auth.rs` with no vocabulary entry fails
  `governed_decision_test.rs`, forcing an explicit stage and coverage decision
  before it can ship. A vocabulary entry that no longer matches any code in
  either file fails too, so a rename cannot leave the table claiming coverage of
  something that cannot happen.
- **Money cases are mandatory, not optional.** The admission-stage members are
  fixtured and asserted by name: `wallet_balance_exhausted`,
  `monthly_budget_exceeded`, `token_budget_exceeded`, `rate_limit_exceeded`,
  `quota_scope_disabled`. The settlement cases (exact / overpaid / underpaid),
  the concurrent reservation against one balance, and the fail-closed
  `governance_counter_unavailable` are dispatch-stage or fault-injected and are
  enumerated with reasons rather than quietly dropped (§8f).

### 8b. Runner A — the authority (Rust, in-process)

`crates/ferrogate-cli/src/gateway/governed_decision_conformance_test.rs` loads
every fixture, materialises an `AppState` from `world`, drives
`decide_ai_request(…)`, and asserts the canonical serialisation of the resulting
`GovernedDecisionRecord { schema, outcome, status, code, metered,
durable_writes, audit_events }` is **byte-identical** to the committed golden.
Canonical means sorted keys at every depth and credit amounts as decimal
strings; `serde_json`'s map is a `BTreeMap` in this workspace, so the sort is
structural rather than hand-rolled.

**Correction to the first slice.** That slice said "this seam does not exist
today … there is no point where the decision is a value rather than a side
effect." That was too strong, and the sharper version is what made the
extraction tractable: `AiRequestRejection` and `AiWorkflowRejection` were
already values, returned by `build_ai_ingress_plan`, `build_ai_request_plan` and
`enforce_ai_workflow_policy`. What did not exist was a **canonical,
serialisable decision type and a single place that delivers it** — the four
admission rejection paths each open-coded their own request-log row and their
own `write_json_error`, which is why the decision could not be observed,
compared, or fixtured.

What landed:

- `decide_ai_request(state, headers, body, endpoint, ctx, now_unix) ->
  Result<AiRequestPlan, GovernedDecision>` — steps 13-32 in production order,
  with **no Session I/O**. Reading the body is I/O and stays in the handler;
  its over-cap outcome is handed to the decision as a *fact* (`AiRequestBody`),
  which is what lets the corpus drive the real function without a Pingora
  `Session`.
- `FerroGateway::deliver_governed_decision` — the one place an admission
  decision becomes bytes, replacing four open-coded blocks.
- The step order is unchanged and load-bearing: authenticate before reading the
  body, so an unauthenticated oversized request is still `missing_api_key` and
  not `payload_too_large`.

Crucially the handler and the corpus call the **same** functions. A conformance
runner that drove a test-only replica of the decision would prove that two
replicas agree, which is not the property under test.

### 8c. Runner B — the candidate host (the veto-only Worker shell)

`workers/gateway-front/` is the §6 Worker shell, and
`POST /__conformance/decide` (404 unless `CONFORMANCE=1`, never set in
production) takes a fixture verbatim and returns the canonical record the shell
produces. `workers/gateway-front/test/` boots the **real Worker in workerd** via
`@cloudflare/vitest-pool-workers` + Miniflare — the same runtime
`wrangler dev --local` uses — with no Docker, no Cloudflare account and no
network.

The corpus is not copied into the Worker. workerd has no filesystem, so the
repo-root fixtures are inlined by Vite at build time from the same paths Runner
A reads. A copy would make the suite prove that two copies agree.

The shell's entire governed surface is one file (`src/shell.ts`), on purpose:
anything the runner cannot see is something nobody is checking. It vetoes on
four host-independent facts — absent credential, body over the cap, body that is
not JSON, and a presented secret on the operator deny list matched **by SHA-256
of the secret** rather than by key id, because resolving a token to a key id is
a control-plane read and would make the shell a second authenticator.

One thing is deliberately *not* there: typed request validation. An edge
`invalid_request` is not host-independent — it needs the origin's schema to
agree with it — so a disagreement would produce false rejections. A directional
contract permits that; users would not forgive it, and Runner A asserts the
shell never claims that code without a deny list.

### 8d. Assertions

- **Identity subset** — for any decision the candidate host *owns*: canonical
  JSON must be **byte-identical** to Runner A's. Any difference fails.
- **Directional subset** — for a host whose contract is veto-only (the §6
  Worker shell): assert
  `worker.outcome ∈ { Defer, authority.outcome, Deny(any) }`, **and**
  `worker.metered == ∅` (it may never author an amount), **and** a Worker deny
  must carry a code from the shared vocabulary. `Defer` — "I made no governed
  call; ask the authority" — is not producible by the origin and exists so the
  shell can say nothing without saying "allow". This is how a fail-closed
  pre-filter is proven fail-closed rather than asserted to be.
- The predicate is implemented **twice**, in Rust and in TypeScript. Two
  implementations of the *check* is fine: a disagreement fails loudly and
  neither can silently pass. Two implementations of the *decision* is the thing
  this record exists to prevent.
- Runner A additionally checks that each fixture's declared Worker-shell answer
  is itself directionally legal, so the corpus cannot contain an expectation
  that is already a divergence; Runner B then checks that the Worker actually
  produces it.

### 8e. Where it runs

`.github/workflows/governed-decision-conformance.yml`, wired into `ci.yml` and
into the `rust-ci` aggregate so it blocks: `runner-a-authority` runs
`cargo test -p ferrogate-cli --bin ferrogate governed_decision`,
`runner-b-worker-shell` runs `npm ci && npm run typecheck && npm test` in
`workers/gateway-front`. A live-network variant remains the test gate's to own,
as with every other live proof in this repo. `tools/ferrogate-test/` is
untouched: the suite belongs next to the code it conforms, and the cross-host
driver turned out to be the corpus itself rather than a third program.

### 8f. What the suite does not cover, and why that boundary is where it is

The corpus covers the **admission** half of the governed path — steps 13-32 of
§1, which is where 44 of the 55 static governed codes live, including every
money decision taken before dispatch. The dispatch half (33-52) is still a
sequence of side effects: 23 of the 25 remaining `write_json_error` sites in
`chat.rs` are inside the per-candidate loop.

This is a narrower slice than "extract the decision out of 28 `write_json_error`
sites", and the narrowing is a judgement, not an omission:

1. **The two halves are not the same refactor.** Admission is a pure function of
   (config, control-plane state, headers, body) and ends in a single verdict.
   The dispatch loop interleaves decisions with irreversible effects — a TPM
   consume, a wallet hold with RAII release semantics, a provider round trip, a
   billing write whose failure *fails the request* — across a fallback loop that
   may run several times. Its "decision" is not one value but an ordered
   sequence of effects, and modelling it needs a design (an effect log, or an
   injectable dispatcher) rather than a lift.
2. **A hot-path rewrite with no incremental proof is exactly the risk this
   record is about.** Extracting admission first gives the corpus, the
   vocabulary gate and both runners real work to do today; the dispatch
   extraction then lands against a suite that already exists to catch it.
3. **The boundary is enforced in code, not in prose.** Every dispatch-stage code
   carries `FixtureCoverage::PendingDispatchSeam` with a written reason; a test
   asserts that excuse is only ever used by dispatch-stage codes, and another
   pins the size of the uncovered set at 17 so it cannot grow unnoticed. Eight
   admission codes are also uncovered — five need a backend fault the fixture
   world cannot inject (store, counter backend, external auth service), three
   need seeded workflow-run state — and each carries its reason too.

So the corpus is allowed to be incomplete. It is not allowed to be *quietly*
incomplete, and that distinction is the whole of the mechanism.

---

## 9. Tethered egress, end to end

The acceptance box asks for this stated end to end. Under the decision:

1. A caller submits a long-running agent job (#474, still to be built) to the
   control plane.
2. The control plane starts **two** things in parallel through the #413
   agent-gateway Worker: the agent's sandbox container
   (`POST /container/prepare` + `/container/start`, #415) and — if not already
   warm — the tenant's **gateway container** running the Pingora binary. The
   1-3 s cold start (verified) is paid here, concurrently, before the agent
   emits its first token.
3. The agent container starts with **`enableInternet = false`** — the
   `AgentSandbox` subclass pins it false, and the Worker rejects
   `enableInternet=true` with an empty allowlist (422 `invalid_spec`), with the
   Rust client refusing it client-side too (#415, defense in depth).
4. Its egress allowlist contains **exactly** the gateway container's hostname
   (plus whatever #475 concludes for GitHub). The agent's LLM base URL points at
   that hostname. Traffic therefore goes agent container → Cloudflare edge →
   fronting Worker → DO → gateway container — **entirely inside Cloudflare**, no
   public-internet round trip per token, which is the round trip the issue
   identifies as defeating "fully deployed to Cloudflare".
5. The gateway container runs the **same** `handle_ai_request` path as every
   self-hosted FerroGate: §1's steps 13-52, one implementation, identical codes,
   identical meters, identical evidence. Provider egress leaves from the gateway
   container, where the credentials live — the agent never holds a provider key.
6. Metering, guardrails and audit are therefore complete **by construction**,
   not by reconciliation.

**The honest gap in this story is #471, and it is not closed by this decision.**
Steps 3-4 are exactly the "cooperative, not enforced" tether #471 is about: if
the allowlist mechanism does not in fact prevent the agent process from reaching
`api.anthropic.com`, the loop leaks. What #470 contributes is that **when the
tether holds, the traffic lands on the authoritative governed path rather than
on a second implementation of it** — so #471's job is a network-enforcement
problem, not simultaneously a policy-equivalence problem. Under Option A it
would have been both.

**Update (#471 landed).** Cloudflare's egress controls turn out to be a real
network control, not a convention: with `enableInternet = false` "only traffic
you explicitly allow … can leave the container", only ports 80/443 and
Cloudflare-resolver DNS survive, and `deniedHosts` "overrides everything else in
the chain" — all verified from the CF docs on 2026-07-25 and tabulated, with the
unverified assumptions labelled, in
[`cloudflare-container-isolation.md`](cloudflare-container-isolation.md)
§"What Cloudflare actually enforces for egress". Step 4's allowlist is now
constrained to an operator-authorized host set (empty ⇒ sealed), the posture type
cannot express open internet, and the Worker attests the posture it applied or
the start fails. Step 6's "by construction, not by reconciliation" stands **for
traffic that traverses the tether**; the residual, configuration-shaped risk is
covered by the reconciliation detector rather than assumed away.

---

## 10. What this record does not settle

Stated explicitly, because a decision record that hides its gaps is worse than
no decision record.

**Could not be verified in this environment** (no Docker, no live Cloudflare
account, no Workers Paid plan):

- The **measured cold-start and p50/p99 added-latency figures** the issue's
  acceptance asks for. #424 §9 (P1-P8) is the runbook; it remains
  **pending-execution**. This slice adds **P9: warm-start amortisation** to that
  runbook — start a gateway container at agent-run admission, measure the
  interval between `/container/start` returning and the first
  `/v1/chat/completions` completing, and report how much of the 1-3 s the
  parallel start actually hides. §4b's central claim stands or falls on P9. See
  §12 for why this box cannot be closed by any developer environment.
- FerroGate's **own** in-container boot time (config parse, control-plane
  connect, sweeper spawn) as a component of the cold start.
- Whether **DO active-duration billing** accrues for the full lifetime of a
  streamed response routed through a container. #424 §7 flagged this as the
  sharpest cost risk and it is **still undocumented by Cloudflare**.
- **Container↔`outboundByHost` shim latency** — not published by CF.
- The **CPU cost of the governed path in a Worker isolate** (BPE tokenisation +
  regex detectors + policy scope matching), and therefore whether Option A/A′
  fits inside the 128 MB isolate and 1 s startup limits with realistic prompt
  sizes.
- Whether a `wasm32` build of the decision core fits the verified 10 MB gzip
  limit. Not attempted; it requires the §7 crate split first.

**Deliberately out of scope:**

- Option A′'s crate split (`ferrogate-policy` → row-types) — named as the
  mind-changer in §7, not designed here.
- The **dispatch-stage** decision seam (steps 33-52) and the fixtures that
  depend on it. Scoped, argued and enforced in code rather than dropped — §8f.
- The global public-ingress topology — owned by #424.
- Container egress *enforcement* — owned by #471, on which the §9 story depends.
- Binding `workers/gateway-front` to a real container origin — owned by #472.
  `forwardToOrigin` returns 501 until then, because a shell that cannot reach
  the authority must not invent one.

The `decide_ai_request` extraction is **no longer out of scope** — it landed
(§8b). The first slice listed it here as a prerequisite it was not doing, which
is precisely the gap code review called.

---

## 11. Verified sources

Cloudflare developer docs, all fetched **2026-07-25**:

- Workers limits (CPU 30 s default / 5 min max via `limits.cpu_ms`; Free 10 ms;
  no wall-clock limit for HTTP; `waitUntil` 30 s; 128 MB per isolate; Worker
  size 10 MB gzip / 64 MB uncompressed; **1 s startup**; subrequests 10,000
  Paid / 50 Free; 6 simultaneous connections; 100/500 Workers per account):
  <https://developers.cloudflare.com/workers/platform/limits/>
- Workers TCP sockets (`connect()` from `cloudflare:sockets`; **no inbound TCP**,
  "coming soon"; sockets cannot be created in global scope or shared across
  requests; Cloudflare IPs/localhost/private IPs blocked; port 25 blocked;
  Postgres users steered to Hyperdrive):
  <https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/>
- Service bindings ("zero overhead or added latency"; "both Workers run on the
  same thread of the same Cloudflare server"; still count toward subrequests;
  max 32 Worker invocations per request):
  <https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/>
- Containers platform details (cold start "**1-3 second range**"; Worker → DO →
  container; DO and container "not guaranteed to run in the same location"; all
  disk ephemeral; `SIGTERM` then `SIGKILL` after 15 min; no non-HTTP TCP/UDP
  ingress): <https://developers.cloudflare.com/containers/platform-details/>
- Containers FAQ (no guaranteed run duration; "rebooted elsewhere shortly
  after"; autoscaling "**Not today**"): <https://developers.cloudflare.com/containers/faq/>
- Containers scaling and routing (manual scaling by explicit ID; `getRandom`
  needs a fixed instance count; instances selected "regardless of location" as a
  current limitation): <https://developers.cloudflare.com/containers/scaling-and-routing/>
- D1 limits (10 GB max DB Paid; 50,000 DBs/account; **1,000 queries per Worker
  invocation** Paid / 50 Free; 6 simultaneous D1 connections per invocation;
  100 bound params; 100 KB max statement; 30 s query duration; single-threaded
  per database): <https://developers.cloudflare.com/d1/platform/limits/>
- Durable Objects (globally-unique name addressable from anywhere;
  "single-threaded and cooperatively multi-tasked"; storage "strongly consistent
  yet fast to access"; provisioned near first request; location hints):
  <https://developers.cloudflare.com/durable-objects/what-are-durable-objects/>
- Hyperdrive ("maintains the underlying database connection pool"; "supports any
  Postgres or MySQL database"; default-on query caching):
  <https://developers.cloudflare.com/hyperdrive/>

Inherited (verified 2026-07-24, recorded in
[`cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md) §10): Containers
pricing and instance tiers, Containers limits, the Container class interface,
Outbound Workers / `outboundByHost` binding access and credential injection,
Workers + DO pricing, and the Cloudflare API rate limits.

**Explicitly not documented by Cloudflare** (and therefore not asserted
anywhere above as fact): DO duration billing behaviour for streamed responses
through containers; container↔shim round-trip latency; any latency figure for
routing to a remotely-placed container instance.

---

## 12. The acceptance boxes, and the one that no developer environment can close

Stated box by box, because the first slice's failure was not a wrong argument —
it was answering a checklist with prose.

| AC | State |
|---|---|
| 1. Decision record picking A/B/C, incl. policy-divergence reasoning | Met — §3, §4, §5, §6. |
| 2. Conformance suite over shared governed-decision fixtures | Met for the admission half, with the remainder enumerated in code (§8, §8f). |
| 3. **Measured** cold-start + p50/p99 added latency | **Cannot be met by any developer environment.** See below. |
| 4. Tethered-egress story end to end | Met — §9. |

### AC3 is environment-blocked, not developer-blocked

Producing it requires, simultaneously: Docker (to build and run the container
image), a **live Cloudflare account on the Workers Paid plan** (Containers are
not on the free plan), a deployed Container application, and a load generator
placed to measure p50/p99 from a realistic client position. No developer
environment in this repository has any of the four, and no amount of code makes
one appear.

**Where the runbook lives:** #424 §9 —
[`docs/cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md) §9, "PoC
runbook", still marked **pending execution**. P5 is cold start, P8 is warm
p50/p99 against the P2 direct-origin baseline, and **P9: warm-start
amortisation** is appended there by this slice (start a gateway container at
agent-run admission; measure the interval between `/container/start` returning
and the first `/v1/chat/completions` completing; report how much of the verified
1-3 s the parallel start actually hides). §4b's central claim — that the cold
start is off the request path for the tethered loop — stands or falls on P9.

The first #470 slice described P9 in this record's §10 but never actually
appended it to the #424 runbook; that document received only a see-also
cross-reference. The step now exists where an operator executing the runbook
will find it, which is the whole point of pointing at a runbook item.

**No number in this record is a measurement that was not measured.** The 1-3 s
container cold start is a labelled vendor quote (§4b, source in §11). The
amortisation claim is labelled **Assumed**. Every unknown is labelled
**Unknown**. That discipline is the reason this section can say "cannot be
produced" rather than producing something.

**Recommendation to the maintainer: split AC3 into its own issue.** It is an
operator task with a written runbook, a different set of credentials and a
different definition of done from the engineering work #470 gates. Leaving it on
#470 makes the code work — the seam, the corpus, the runners, and the #471-#475
slices behind them — hostage to an account provisioning decision. As written it
cannot be closed by a document, and it should not be closed by one.

## Test coverage

The admission-stage extraction is a refactor: `decide_ai_request` and
`deliver_governed_decision` preserve the existing step order, codes, statuses
and request-log rows, so the standing AI-proxy suites
(`crates/ferrogate-cli/tests/ai_proxy_*.rs`, `proxy_runtime`) are the regression
net for "nothing changed". What is new:

- **`gateway/governed_decision_test.rs`** — the source scan that keeps
  `GOVERNED_ERROR_VOCABULARY` honest in both directions (no emitted code without
  an entry; no entry without an emitting code), canonical serialisation,
  decimal-string amount parsing, and the directional predicate: a veto-only host
  may defer or deny, never allow, never serve from cache, never author a metered
  amount, never deny outside the shared vocabulary.
- **`gateway/governed_decision_conformance_test.rs`** (Runner A) — the whole
  corpus through the real seam, byte-identical to the goldens; the coverage
  gate; the mandatory money cases asserted by name; the pending set pinned so it
  cannot grow unnoticed.
- **`workers/gateway-front/test/`** (Runner B) — the same corpus through the
  real Worker in workerd, asserting the §8d directional properties. No Docker,
  no Cloudflare account, no network.
- Both run in CI and block:
  `.github/workflows/governed-decision-conformance.yml`.

What it *specifies* to be tested when the gated work begins:

- The dispatch-stage seam and its fixtures (§8f), including the settlement money
  cases and the fail-closed `governance_counter_unavailable`.
- §10's P9 (warm-start amortisation), appended to the #424 §9 runbook.

**Not testable in any developer environment** (no Docker, no live Cloudflare
account, no Workers Paid plan): every measurement in §10 and §12 — cold start,
added latency, DO duration billing on streams, shim latency, and any WASM bundle
size for Option A′.
