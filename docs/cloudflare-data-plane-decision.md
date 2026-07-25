<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, decision record for the
  Cloudflare execution target of the LLM data plane (issue #470): the governed
  request path enumerated, Workers-native vs Container-hosted vs hybrid, the
  policy-divergence argument, and the governed-decision conformance suite.
-->

# Cloudflare execution target for the LLM data plane (decision #470)

**Status: decided, not implemented.** Issue #470 freezes this before anyone
builds; #471, #472, #473, #474 and #475 are gated behind it. Nothing in this
slice ships a Worker or touches the proxy.

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
- **At least 41 distinct static client-visible error codes** are emitted from
  `chat.rs` alone, across 28 error-writing call sites, plus the dynamic
  guardrail codes carried on a `GuardrailMatch`; `auth.rs` adds `missing_api_key`,
  `invalid_api_key`, `api_key_disabled`, `api_key_expired`, `scope_denied`,
  `quota_scope_disabled`, `monthly_budget_exceeded`, `rate_limit_exceeded`,
  `quota_resolution_unavailable` and more. Each one is a governed outcome with a
  status code, a stable code string, an audit consequence and, in several cases,
  a money consequence.
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
| Warm-start amortisation: starting the gateway container at run admission takes the 1-3 s off the request path for an agent run | a scheduling inference from the verified `/container/start` control surface (#415), not a measurement — see P9 in §10 | **Assumed** |

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
still requires a conformance fixture (§8), just a directional one rather than an
identity one.

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
call, and A′ (§7) would make many, so the suite is specified here and is a
**prerequisite for any future work that puts a governed decision in a second
host**. It is also the mechanism that would have caught #383 and #476.

The repo already has the pattern to copy: `ferrogate-guardrails`' detector
conformance harness (`crates/ferrogate-guardrails/src/conformance.rs`,
`run_detector_conformance`, `ConformanceReport`, feature-gated `conformance`,
never in a production build). This is the same idea one level up — conforming a
*host* instead of a *detector*.

### 8a. Fixture format (language-neutral, committed, reviewed)

`tests/fixtures/governed-decisions/<case>.json` — JSON, because both hosts must
read it and neither may own it:

```jsonc
{
  "id": "quota/tpm-exhausted-on-second-request",
  "world": {                    // the control-plane snapshot, not a live DB
    "api_keys": [ /* … */ ],
    "quota_policies": [ /* org/project/workspace/key rows */ ],
    "plans": [ /* … */ ],
    "guardrail_policies": [ /* revisions + checks + scope */ ],
    "models": [ /* logical → routes, pricing, region */ ],
    "providers": [ /* kind, base_url, region */ ],
    "wallets": [ { "tenant": "…", "balance": "1000", "outstanding": "0" } ],
    "counters": { "tpm:key-1:2026-07-25T00:01": 4000 },
    "clock_unix": 1784937600
  },
  "request": {
    "method": "POST", "path": "/v1/chat/completions",
    "headers": { "authorization": "Bearer …", "x-ferrogate-config": "…" },
    "body": { "model": "gpt-4o", "messages": [ /* … */ ], "stream": false }
  },
  "provider_response": { /* scripted, so dispatch is deterministic */ },
  "expect": {
    "outcome": "deny",                    // allow | deny | cache_hit
    "status": 429,
    "code": "tpm_limit_exceeded",
    "quota": { "scope_that_denied": "project", "consumed_tokens": 0 },
    "guardrail": { "stage": null, "effect": null, "policy_revision": null },
    "metered": { "prompt_tokens": 0, "completion_tokens": 0,
                 "credits_reserved": "0", "credits_captured": "0" },
    "durable_writes": ["request_log"],    // ordered kinds, not payloads
    "audit_events": []
  }
}
```

Rules that make the corpus load-bearing rather than decorative:

- **Amounts are decimal strings parsed as integers**, never floats and never
  compared lexically — the #469 discipline, applied to the fixture format
  itself so a suite cannot re-introduce the bug it exists to prevent.
- **Golden, committed, reviewed.** Expected values are generated from the
  authoritative Pingora path but **checked in**, so a behaviour change appears
  as a reviewable diff. This is the anti-#383 mechanism: a contract that is
  invisible at the call site becomes visible in a golden file.
- **Coverage gate.** Every code in the governed vocabulary (the 41+ from
  `chat.rs`, plus `auth.rs`'s) must appear in ≥1 fixture; a code with no fixture
  **fails the suite**. Adding a new governed outcome therefore forces a fixture,
  which forces both hosts to agree before it ships.
- **Money cases are mandatory, not optional**: exact / overpaid / underpaid
  settlement, wallet insufficient, concurrent reservation against the same
  balance, counter-backend unavailable (which must fail *closed* with
  `governance_counter_unavailable`, not silently allow).

### 8b. Runner A — the authority (Rust, in-process)

A `#[cfg(test)]`/feature-gated harness in `ferrogate-cli` that loads a fixture,
materialises an `AppState` from `world`, and drives the governed decision to a
typed `GovernedDecision { outcome, status, code, quota, guardrail, metered,
durable_writes, audit }`, serialised canonically (sorted keys, integers as
strings).

**Prerequisite, stated plainly: this seam does not exist today.** `handle_ai_request`
writes its rejections straight into the Pingora `Session`
(28 `write_json_error`/`write_json_error_and_close` sites in `chat.rs`), so there is no point where the
decision is a value rather than a side effect. The suite requires extracting
`decide_ai_request(...) -> GovernedDecision` from the response-writing, leaving
the handler as `match decide(...) { … write … }`. That refactor is worth doing on
its own merits — it is what would let the four sibling surfaces (§1c) share one
decision function instead of four copies — but it is **not** in this slice, and
nothing else in §8 can be built before it.

### 8c. Runner B — the candidate host (Worker, local)

`wrangler dev --local` (workerd/Miniflare, no account needed) exposing a
`POST /__conformance/decide` route that exists **only** in a conformance build:
it takes the same fixture JSON, seeds its own state layer (D1/DO/KV) from
`world`, and returns the same canonical `GovernedDecision`.

### 8d. Assertions

- **Identity subset** — for any decision the candidate host *owns*: canonical
  JSON must be **byte-identical** to Runner A's. Any difference fails.
- **Directional subset** — for a host whose contract is veto-only (the §6
  Worker shell): assert
  `worker.outcome ∈ { authority.outcome, Deny(any) }`, **and**
  `worker.metered == ∅` (it may never author an amount), **and** a Worker deny
  must carry a code from the shared vocabulary. This is how a fail-closed
  pre-filter is proven fail-closed rather than asserted to be.
- **Divergence report**, not a bare assert — mirroring `ConformanceReport`:
  which behaviours were *exercised* as well as which held, so a suite that
  silently stops covering the guardrail stage is itself a failure.

### 8e. Where it runs

A CI job that runs Runner A (`cargo test`) and Runner B (`wrangler dev --local`)
over the same corpus directory and diffs the two canonical outputs. The natural
home for the cross-host driver is the existing compliance surface in
`tools/ferrogate-test/` (untouched by this slice); a live-network variant is the
test gate's to own, as with every other live proof in this repo.

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

---

## 10. What this record does not settle

Stated explicitly, because a decision record that hides its gaps is worse than
no decision record.

**Could not be verified in this environment** (no Docker, no live Cloudflare
account, no Workers Paid plan):

- The **measured cold-start and p50/p99 added-latency figures** the issue's
  acceptance asks for. #424 §9 (P1-P8) is the runbook; it remains
  **pending-execution**. This record adds one step to it — **P9: warm-start
  amortisation.** Start a gateway container at agent-run admission, measure the
  interval between `/container/start` returning and the first
  `/v1/chat/completions` completing, and report how much of the 1-3 s the
  parallel start actually hides. §4b's central claim stands or falls on P9.
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
- The `decide_ai_request` extraction (§8b) — a prerequisite for the suite, worth
  doing independently, not in this slice.
- The global public-ingress topology — owned by #424.
- Container egress *enforcement* — owned by #471, on which the §9 story depends.

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

## Test coverage

No runtime behaviour changes in this slice, so there is nothing new to test —
this is a decision record. What it *specifies* to be tested, when the gated work
begins:

- §8's governed-decision fixture corpus with the vocabulary coverage gate, run
  against Runner A (Rust, in-process) and any future second host.
- §8b's `decide_ai_request` extraction is the prerequisite; until it exists the
  suite cannot be built, and that is stated rather than assumed.
- §10's P9 (warm-start amortisation), appended to the #424 §9 runbook.

**Not testable locally** (no Docker, no live Cloudflare account, no Workers Paid
plan): every measurement in §10 — cold start, added latency, DO duration
billing on streams, shim latency, and any WASM bundle size for Option A′.
