<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Token4AI Cloud, FerroGate AI Gateway, Cloudflare integration research
  spike + developer-docs reference (issue #421): MCP, R2/Workers/Pages static
  hosting, managed agents, Secrets Store, D1, Workers AI Llama Guard, deploy
  topology, and the shared API-token auth model. AI Gateway was evaluated and
  dropped as redundant; the rationale is recorded here.
-->

# Cloudflare Integration Reference

This document is the durable capture of the Cloudflare developer-docs survey that
scoped the FerroGate Cloudflare initiative (research spike issue #421 and its
sibling sub-issues). It is the single source implementers of the sibling issues
should consult for API shapes, auth scopes, product limits, and the FerroGate
plug-in seams each Cloudflare (CF) area targets.

This is a *reference*, not a design decision: the deploy-topology decision lives
in [`docs/cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md) (#424),
which §8 summarises. Every plug-in-seam `file:line` citation below was verified
against the current `main` tree while writing this doc; several sibling issues
have since landed (R2 `AssetObjectStore` trait, the `cf://` `CloudflareSecretResolver`,
the D1 control-plane backend, the Workers AI Llama Guard detector), so seams that
this doc originally called "planned" are now marked **exists today**.

## Contents

- [1. AI Gateway — evaluated and dropped](#1-ai-gateway--evaluated-and-dropped)
- [2. MCP (Model Context Protocol)](#2-mcp-model-context-protocol)
- [3. Static hosting: R2, Workers Static Assets, Pages](#3-static-hosting-r2-workers-static-assets-pages)
- [4. Managed agents](#4-managed-agents)
- [5. Secrets Store](#5-secrets-store)
- [6. D1](#6-d1)
- [7. Workers AI Llama Guard (optional guardrail detector)](#7-workers-ai-llama-guard-optional-guardrail-detector)
- [8. Deploy topology](#8-deploy-topology)
- [9. Cross-cutting: one API-token auth model](#9-cross-cutting-one-api-token-auth-model)
- [10. FerroGate plug-in seams](#10-ferrogate-plug-in-seams)

---

## 1. AI Gateway — evaluated and dropped

**Decision: the Cloudflare AI Gateway integration was evaluated during this spike
and DROPPED as redundant.** It is recorded here so the decision is not
re-litigated by a later implementer.

### What AI Gateway is

Cloudflare AI Gateway is a proxy that sits *in front of* upstream model providers
and adds caching, rate limiting, request logging/analytics, retries/fallback, and
unified billing. It exposes a provider-native "compat" surface
(`https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/{provider}/...`),
a normalized unified endpoint, BYOK key storage, and `cf-aig-*` request headers.

### Why it was dropped

FerroGate **is itself the AI gateway.** Every capability AI Gateway offers is a
first-class FerroGate responsibility already:

- **Caching / rate limiting / retries / fallback** — owned by FerroGate's Pingora
  data plane and provider/upstream layer.
- **Logging / analytics / billing** — owned by FerroGate's observability +
  billing pipeline (`docs/analytics-warehouse.md`, the billing ledger stores).
- **Provider routing / BYOK** — owned by FerroGate's provider adapters and
  secret-resolver (§5, §10.5).

Layering FerroGate on top of AI Gateway would double the proxy hop, split the
source of truth for cost/latency/logs across two systems, and add a second set of
limits (e.g. the unified-billing endpoint's ~200 req / 60 s throttle) for no net
capability. There is therefore **no FerroGate plug-in seam for AI Gateway** — §10
does not list one.

### Scope-table footnote (important)

The foundation client's required-scope set (`crates/ferrogate-cloudflare/src/scopes.rs:33`)
still enumerates an **AI Gateway (Read, Edit)** permission group from before this
drop decision. The scopes table in §9 matches the code exactly (the code is the
source of truth for the preflight), so it keeps that row. Granting an unused
permission group is harmless; pruning it from the preflight set is a code
follow-up, not a docs change.

> Note: FerroGate's optional Llama Guard guardrail detector (§7) talks to
> **Workers AI** (`/ai/run`), **not** AI Gateway — it has no AI-Gateway
> dependency, consistent with this drop.

---

## 2. MCP (Model Context Protocol)

Cloudflare hosts a managed MCP catalog and offers MCP server hosting via the
Agents SDK. For FerroGate this is **pure configuration** against the existing MCP
host — no new transport code (§10.6).

### Managed catalog

- Managed first-party servers are exposed under **`*.mcp.cloudflare.com`** (a
  curated catalog: docs, Workers bindings, observability, etc.). FerroGate
  consumes them as ordinary MCP upstreams.

### Hosting your own

- **Agents SDK hosting** — an MCP server authored with the Cloudflare Agents SDK
  deploys as a Worker (backed by a Durable Object for session state), giving a
  hosted `*.workers.dev` / custom-domain MCP endpoint.

### Transports

- **Streamable HTTP** — the current transport (single endpoint, POST for the
  request, optional streamed response). FerroGate's default.
- **SSE** — the legacy transport, still accepted by many servers.

FerroGate models both (`McpTransport::StreamableHttp` / `::Sse`, plus `::Stdio`
for local servers — `crates/ferrogate-mcp/src/config.rs:25`).

### Auth

- **OAuth** — the managed catalog and many hosted servers use an OAuth
  authorization-code flow (issuer + client id/secret + scopes). FerroGate models
  this with `McpOauthConfig` (`crates/ferrogate-mcp/src/config.rs:60`) and the
  `McpAuthType::Oauth` / `PerUserOauth` auth modes.
- **Bearer** — a static bearer token in an `Authorization` header for simpler
  servers (`McpAuthType::SharedHeaders`).

Registering a Cloudflare-hosted MCP server is done by adding an `McpServerConfig`;
there is even a dedicated `validate_cloudflare_mcp_servers` validation pass
(`crates/ferrogate-cli/src/config/validate.rs:155`).

---

## 3. Static hosting: R2, Workers Static Assets, Pages

Three CF options for serving FerroGate-hosted static assets/sites.

### R2 (object storage)

- **S3-compatible API** with SigV4 auth (the same signer FerroGate already uses
  for its asset bucket). Access via **R2 API tokens** (scoped Access Key ID /
  Secret) or an account API-token with **Workers R2 Storage** permission.
  Endpoint form: `https://<account_id>.r2.cloudflarestorage.com`.
- Objects served **public** (managed `r2.dev` domain, dev-only) or via a
  **custom domain** routed through a Worker/CDN for production.
- Best fit for FerroGate because the asset path is already an S3-compatible
  bucket client (§10.2) — R2 is close to a drop-in endpoint/credential swap.

### Workers Static Assets

- Assets attach to a Worker and upload via a **3-step flow**: (1) create an
  assets *upload session* declaring the file manifest (path → hash/size),
  (2) upload the file bodies (batched by hash), (3) deploy the Worker script that
  references the completed asset manifest. Requires **Workers Scripts Edit**.
- Good when assets must be co-served with Worker logic (routing, auth, headers).

### Pages

- Git-or-direct-upload static hosting with a **deployments** model (each publish
  is an immutable deployment; preview + production aliases). Managed via the Pages
  REST API (`/accounts/{account_id}/pages/projects/.../deployments`). Requires
  **Cloudflare Pages Edit**.

### Recommendation matrix

| Need | R2 | Workers Static Assets | Pages |
|------|----|-----------------------|-------|
| FerroGate-managed byte store, S3-compatible | **Best** (reuses SigV4 bucket client, §10.2) | No (Worker-bound) | No |
| Large / many objects, presigned upload+read | **Best** | Weak (manifest-oriented) | Weak |
| Assets co-served with edge logic (auth, routing) | Via fronting Worker | **Best** | Limited |
| Turnkey site with preview/prod deployments | No | Partial | **Best** |
| Custom domain, production TLS | Yes (custom domain) | Yes (Worker route) | Yes (built-in) |
| Closest to current FerroGate code | **Yes** — endpoint swap | Larger change | Larger change |

**Recommendation:** default to **R2** for the FerroGate asset object-store backend
(minimal change over the current S3-compatible bucket client); reach for Workers
Static Assets or Pages only when edge logic or turnkey deployment semantics are
required.

---

## 4. Managed agents

Running FerroGate-managed agents *on* Cloudflare.

### The stack

- **Agents SDK → Durable Objects** — an agent is a Durable Object (DO) instance:
  single-threaded, addressable, stateful. The Agents SDK wraps a DO with
  agent-runtime conveniences.
- **Workflows** — durable, multi-step, retryable execution (steps survive
  restarts). Has a **REST lifecycle**: create instance, get status, pause/resume,
  terminate under `/accounts/{account_id}/workflows/{name}/instances`.
- **Containers / Sandboxes** — heavier isolation for arbitrary code / tool
  execution, fronted by a Worker.

### Key constraint: no public lifecycle REST API for DO / Agents / Containers

Durable Objects, Agents, and Containers have **no public REST API to
create/start/stop instances**. Their lifecycle is only reachable *from inside a
Worker* (bindings). Therefore FerroGate must **deploy a fronting Worker** that
exposes the lifecycle operations it needs (spawn/kill/exec an agent or container)
as HTTP endpoints, and call *that* Worker. Only **Workflows** offers a public REST
lifecycle directly.

### Deploy path

- Deploy the fronting Worker (and any DO/Container definitions) via **script PUT**
  (`PUT /accounts/{account_id}/workers/scripts/{name}` with the module + metadata,
  multipart) or via **Wrangler**. Requires **Workers Scripts Edit** (and Write for
  Workflows-bearing scripts).

### Pricing (shape, not quotes)

- Workers: per-request + CPU-time (Standard) pricing.
- Durable Objects: request + duration + storage.
- Workflows: billed on the underlying Worker invocations/CPU of each step.
- Containers: instance-time + resources.

FerroGate's agent-worker abstraction already treats isolation backends as a
replaceable registry, so a Cloudflare-managed backend registers alongside the
existing Firecracker/Docker/local-process tiers — see §10.4.

---

## 5. Secrets Store

Account-level secret storage, consumed by Workers as bindings and manageable via
REST.

### REST CRUD

- Stores and secrets are CRUD-managed under
  `/accounts/{account_id}/secrets_store/stores` and
  `.../stores/{store_id}/secrets`. Requires the **Secrets Store** permission group
  (Read for reads, Write for create/update/delete).

### Scopes

- A secret is scoped to a store; a Worker binds a specific secret by name. Values
  are write-only via the management API (you set, you cannot read back plaintext
  through REST — reads happen through the Worker binding).

### Beta caps

- **1 store per account** (`CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT = 1`,
  `crates/ferrogate-secrets/src/cloudflare.rs:37`).
- **100 secrets per store** (`..._MAX_SECRETS_PER_ACCOUNT = 100`, `:39`).
- **1024 bytes** per secret value (`..._MAX_VALUE_BYTES = 1024`, `:41`).

### Multi-tenant limitation

The single-store / 100-secret / 1024-byte caps mean Secrets Store **cannot** hold
per-tenant provider keys at FerroGate scale during beta. It is viable only for a
small set of *FerroGate-operator* secrets, not tenant fan-out (see the #418
tenancy split, `docs/cloudflare-secrets-tenancy.md`). FerroGate's secret-resolver
already ships a `cf://` scheme (§10.3) that resolves through Secrets Store; the
caps gate any per-tenant use until GA.

---

## 6. D1

Cloudflare's managed SQLite (per-database) service.

### Provision / query REST

- Databases are provisioned and queried over REST (implemented in
  `crates/ferrogate-cloudflare/src/d1.rs`):
  - `POST /accounts/{account_id}/d1/database` — create; `GET .../d1/database` — list;
    `GET|DELETE .../d1/database/{uuid}` — fetch/delete.
  - `POST /accounts/{account_id}/d1/database/{uuid}/query` — run SQL, returning
    result sets.
- Requires the **D1** permission group (Read for query/read, Edit for
  create/schema).

### Per-tenant model

- FerroGate uses **one D1 database per tenant** (isolation + independent limits).
  Databases are cheap to create but each is a distinct `database_id` FerroGate
  tracks in its control plane (`CloudflareD1StorageOptions`,
  `crates/ferrogate-storage/src/control_plane_store_d1/client_config.rs:73`).

### Limits

- Per-database size and row-count ceilings, and per-query result-size limits (D1
  is SQLite semantics behind a REST facade — large scans are not its strength).
- The public HTTP query API has **no multi-statement-with-params transaction and
  no `RETURNING`**, which blocks atomic control-plane transitions.

### REST rate limit → proxy-Worker recommendation (implemented)

The D1 REST query API is rate-limited, adds a round-trip per query, and lacks
atomic multi-statement transactions. For hot / atomic paths FerroGate fronts D1
with a **proxy Worker** (`workers/d1-proxy/`) that holds a **native D1 binding**
and can run `prepare().bind()` / `batch()` (atomic) / `RETURNING`, exposed as a
bearer-authenticated HTTP API. The Rust client for it is
`crates/ferrogate-cloudflare/src/d1_proxy.rs` (issue #450); it decodes into the
same `D1QueryResult` type as the REST client. This mirrors the DO/Container
fronting-Worker pattern (§4).

---

## 7. Workers AI Llama Guard (optional guardrail detector)

An **optional, opt-in** content-moderation detector (issue #422) that FerroGate
composes with its native guardrail rules. **It does NOT depend on AI Gateway**
(which was dropped, §1) — it calls Workers AI directly.

### Shape

- Talks to Cloudflare **Workers AI** at `POST accounts/{account_id}/ai/run/{model}`
  over the shared `CloudflareClient` (issue #405). Default model
  `@cf/meta/llama-guard-3-8b`
  (`crates/ferrogate-guardrails/src/adapters/workers_ai_llama_guard.rs:110`); any
  `@cf/meta/llama-guard-*` model is accepted.
- Sends a chat-style `messages` array; parses Llama Guard's `safe` / `unsafe\nS2,S9`
  verdict + hazard categories into a `DetectorResult`.

### Where it sits

- It is ONE `GuardrailDetector` (`crates/ferrogate-guardrails/src/contract.rs:255`)
  among others (`custom_http`, `presidio`, `llm_guard`). FerroGate — not Llama
  Guard — decides flag-vs-block by composing the verdict with policy rules; the
  detector never decides enforcement on its own.
- **Content-moderation, not prompt-injection.** Llama Guard classifies against a
  fixed hazard taxonomy; operators needing prompt-injection coverage keep the
  native rules and/or the self-hosted LLM-Guard adapter.
- **Opt-in / graceful disable:** it is constructed only from an explicit
  `WorkersAiLlamaGuardConfig` plus a live `CloudflareClient`, so it simply cannot
  exist unless the operator has configured the `[cloudflare]` block.
- **Fail-open vs. fail-closed** is owned by the *policy* (`on_error` actions), not
  the detector — consistent with every other remote detector.

### Scope note

Workers AI `/ai/run` needs a **Workers AI (Read)** permission group *only if this
optional detector is enabled*. It is intentionally **absent** from the mandatory
foundation preflight set (`scopes.rs`, §9) because the detector is opt-in — the
scopes table reflects that.

### AI Gateway is NOT required

Cloudflare docs let Workers AI be routed *through* AI Gateway, but FerroGate
deliberately does not: the detector hits the Workers AI `/ai/run` path directly,
so it inherits no AI-Gateway limits or second hop (§1).

---

## 8. Deploy topology

*Where the FerroGate runtime itself runs* relative to Cloudflare compute is
decided in [`docs/cloudflare-deploy-topology.md`](cloudflare-deploy-topology.md)
(#424). Summary of the options and the load-bearing constraint:

- **(a) Containers-hosted** — the FerroGate binary runs inside Cloudflare
  Containers, fronted by a Worker + Durable Object.
- **(b) Edge-Worker + origin (hybrid)** — a thin CF Worker at the edge
  (auth pre-check / cache / routing / guardrail pre-check) forwards to a FerroGate
  origin on Containers or external VMs/k8s.
- **(c) Status quo** — FerroGate on VMs/k8s (`deploy/kubernetes/`,
  `charts/ferrogate`, `docs/cluster-deployment.md`), consuming CF products only as
  upstreams via REST + FerroGate-deployed fronting Workers.

### Why Pingora cannot run on Workers (structural, not incremental)

Plain Workers **cannot host the FerroGate data plane**:

- Workers are V8 isolates (JS/WASM). Pingora is a **native** Rust proxy: it owns
  its tokio runtime, binds OS listen sockets, manages upstream connection pools,
  and calls native TLS. None of that exists in an isolate — "porting" means
  rewriting the data plane against `fetch` semantics and losing Pingora entirely.
- The Postgres pool (`deadpool` / `tokio-postgres`) needs long-lived raw TCP
  sockets and a resident pool; isolates offer neither the socket model nor the
  resident process lifetime.
- Resident background loops have no home in a per-request isolate.

Workers therefore appear only as the **thin edge layer** of the hybrid and the
**fronting/binding layer** for Containers (§4), never as the FerroGate runtime
itself. The #424 decision is **hybrid edge-Worker now, Containers beachhead
next**; read that doc for the cost model, bindings-vs-REST access decision, and
PoC runbook.

---

## 9. Cross-cutting: one API-token auth model

All FerroGate Cloudflare access uses a **single Cloudflare account API token**
(scoped to the FerroGate account) presented as `Authorization: Bearer <token>`.
R2 may additionally use its S3-style Access Key ID / Secret for the SigV4 bucket
path. There is no per-product credential sprawl: one token, the union of the
permission groups below.

### Required token-scopes table

This table is the **authoritative** required-scope list and **matches the
foundation client's preflight set byte-for-byte**. Source of truth:
`REQUIRED_TOKEN_PERMISSION_GROUPS` at
**`crates/ferrogate-cloudflare/src/scopes.rs:33`**, asserted by
`CloudflareClient::preflight` at **`crates/ferrogate-cloudflare/src/client.rs:273`**
(an under-scoped token surfaces as `CloudflareError::MissingScope`, whose message
names these groups via `required_group_names()`,
`crates/ferrogate-cloudflare/src/error.rs:119`). Rows and access levels below are
copied verbatim from the code, in code order.

| Permission group | Access | FerroGate use (`used_by` in code) |
|------------------|--------|-----------------------------------|
| AI Gateway | Read, Edit | AI Gateway management + inference proxying |
| Secrets Store | Read, Write | `cf://` secret backend (#417) |
| D1 | Read, Edit | D1-backed state |
| Workers Scripts | Edit | Worker deployment |
| Workers R2 Storage | Read, Edit | R2 object storage |
| Cloudflare Pages | Edit | Pages deployment |
| Workflows (Workers Scripts) | Write, Edit | Workflows orchestration |

Notes:

- **AI Gateway** row is retained because the code still lists it (§1): the table
  matches `scopes.rs`, not the current integration set. The integration is dropped;
  the granted scope is harmless and pruning it is a code follow-up.
- **Workflows** has no standalone permission group for the deploy path — managing
  Workflows requires **Workers Scripts Write/Edit** (the Workflow ships inside a
  Worker script), which is why the code names it `Workflows (Workers Scripts)`.
- **Workers Static Assets** (when used instead of R2/Pages) is covered by the
  **Workers Scripts Edit** row (assets attach to a Worker deploy).
- R2's optional S3 Access Key path is a *credential form*, not an extra permission
  group; the account-token equivalent is the **Workers R2 Storage** row.
- **Workers AI** (for the optional Llama Guard detector, §7) is deliberately
  **not** in this set — it is opt-in, so the code does not require it at preflight.

The #405 client preflight asserts a valid, account-scoped token and fails closed
at startup when the token is missing/invalid; per-group enforcement surfaces via
`MissingScope`.

---

## 10. FerroGate plug-in seams

Each Cloudflare area plugs into an existing FerroGate seam. Citations are against
current `main` and were grep-verified while writing. AI Gateway has **no seam**
(dropped, §1).

### 10.1 R2 → asset object-store seam

- **Seam (exists today):** `AssetObjectStore` trait —
  `crates/ferrogate-cli/src/gateway/asset_bucket.rs:165`; concrete
  `AssetBucketClient` (S3-compatible, SigV4) — `:137` (`impl AssetObjectStore for
  AssetBucketClient` at `:258`); `AssetBucketConfig` — `:38`. Presigned
  upload/read: `crates/ferrogate-cli/src/gateway/asset_presign.rs`.
- **Fit:** R2 is an `AssetBucketConfig` pointed at the R2 S3 endpoint (R2 is
  S3-compatible), or a second `AssetObjectStore` impl. The trait extraction (#411)
  has landed, so the seam is fully in place.

### 10.2 Secrets Store → secret-resolver seam

- **Seam (exists today):** `SecretResolver` trait —
  `crates/ferrogate-secrets/src/lib.rs:142`; `SecretRef` enum with the
  `CfSecret { .. }` (`cf://<store>/<name>`) variant — `:62` / `:76`;
  `SecretResolverRegistry` (scheme dispatch, `.with_cloudflare(..)`) — `:255` / `:278`.
- **Concrete resolver (exists today):** `CloudflareSecretResolver` —
  `crates/ferrogate-secrets/src/cloudflare.rs:139` (`impl SecretResolver` at `:356`),
  built on the shared `ferrogate_cloudflare::CloudflareClient`. Beta caps (§5) bound
  it to operator, not per-tenant, secrets.

### 10.3 Managed agents → agent-worker isolation-backend seam

- **Seam (exists today):** `IsolationBackendLifecycle` trait —
  `crates/ferrogate-runtime/src/isolation.rs:266`; `FrameworkAdapter` trait —
  `crates/ferrogate-runtime/src/framework_adapter.rs:521`; replaceable backend
  registry `registered_isolation_backends` —
  `crates/agent-worker/src/backends.rs:121` (tiers, e.g.
  `docker_registered_backend` at `:252`, `firecracker_registered_backend` at `:1261`).
- **Fronting-Worker dispatch:** managed external actions flow through
  `GatewayExternalActionTransportRequest` —
  `crates/agent-worker/src/external_actions.rs:39` — the natural attach point for a
  Cloudflare fronting-Worker call.
- **Control-plane record:** `StoredManagedWorkerTemplate` —
  `crates/ferrogate-storage/src/lib.rs:1001` (`ManagedWorkerTemplateRepository` at
  `:761`).
- **Fit:** a Cloudflare-managed backend registers as a new
  `RegisteredIsolationBackend` alongside Firecracker/Docker/local-process; the
  "no public lifecycle REST" constraint (§4) is satisfied by pointing its dispatch
  at a FerroGate-deployed fronting Worker. **Seams exist today; a CF backend impl
  does not yet.**

### 10.4 D1 → control-plane store seam

- **Seam (exists today):** the repository trait family `Repository<T>` —
  `crates/ferrogate-storage/src/lib.rs:738`; backend selector enum
  `RuntimeControlPlaneBackend` with the `CloudflareD1(Arc<D1ControlPlaneStore>)`
  variant — `:10416` / `:10419`; provider kind `StorageProviderKind::CloudflareD1`
  — `:307`.
- **Concrete store (exists today):** `D1ControlPlaneStore` —
  `crates/ferrogate-storage/src/control_plane_store_d1/mod.rs:359`, reached over the
  rate-limited REST client (`ferrogate-cloudflare/src/d1.rs`) and, for atomic hot
  paths, the proxy-Worker client (`d1_proxy.rs`, §6). The Postgres reference impl
  `PostgresControlPlaneStore` is at `crates/ferrogate-storage/src/lib.rs:1330`.

### 10.5 MCP → upstream registration seam

- **Seam (exists today):** `McpServerConfig` —
  `crates/ferrogate-mcp/src/config.rs:80` (transport `McpTransport` at `:25`,
  `McpOauthConfig` at `:60`); Cloudflare-specific validation
  `validate_cloudflare_mcp_servers` —
  `crates/ferrogate-cli/src/config/validate.rs:155` (general
  `validate_mcp_servers` at `:2769`); registration `upsert_mcp_server` —
  `crates/ferrogate-cli/src/state.rs:674`.
- **Fit:** a Cloudflare managed (`*.mcp.cloudflare.com`) or self-hosted MCP server
  is an `McpServerConfig` with `transport: streamable_http` and either `oauth` or a
  bearer header — **pure configuration, no new transport code.**

### 10.6 Workers AI Llama Guard → guardrail detector seam

- **Seam (exists today):** `GuardrailDetector` trait —
  `crates/ferrogate-guardrails/src/contract.rs:255`; concrete
  `WorkersAiLlamaGuardDetector` / `WorkersAiLlamaGuardConfig` —
  `crates/ferrogate-guardrails/src/adapters/workers_ai_llama_guard.rs:156` / `:119`
  (`impl GuardrailDetector` at `:418`).
- **Wiring:** constructed opt-in from a `[cloudflare]` block at
  `crates/ferrogate-cli/src/state.rs:6389` (`WorkersAiLlamaGuardDetector::new`).
- **Fit:** the detector returns a verdict; policy composition decides enforcement
  (§7). No AI Gateway dependency.

### Seam summary

| CF area | FerroGate seam | Exists today? |
|---------|----------------|---------------|
| AI Gateway | — (dropped, §1) | n/a — no seam |
| R2 static hosting | `AssetObjectStore` trait + `AssetBucketClient` | Yes |
| Secrets Store | `SecretResolver` / `SecretRef::CfSecret` + `CloudflareSecretResolver` | Yes |
| Managed agents | isolation-backend registry + fronting-Worker transport | Seam yes; CF backend no |
| D1 | `RuntimeControlPlaneBackend::CloudflareD1` + `D1ControlPlaneStore` | Yes |
| MCP | `McpServerConfig` registration | Yes (config-only) |
| Workers AI Llama Guard | `GuardrailDetector` + `WorkersAiLlamaGuardDetector` | Yes (opt-in) |

---

## References

- Research spike: issue #421 (this document is its capture). Siblings: foundation
  client #405; asset object-store extraction #411; `cf://` secret backend #417/#423;
  Secrets Store tenancy #418; D1 backend #420/#440/#449/#450; Workers AI Llama Guard
  #422; managed agents #419; deploy topology #424.
- Deploy topology (running FerroGate ON Cloudflare — Containers vs edge-Worker+origin
  vs status quo, bindings-vs-REST): `docs/cloudflare-deploy-topology.md` (#424).
- Related CF decision docs: `docs/cloudflare-agent-gateway.md` (#413),
  `docs/cloudflare-secrets-resolution.md` (#423),
  `docs/cloudflare-secrets-tenancy.md` (#418), `docs/cloudflare-d1-backend.md`,
  `docs/cloudflare-mcp-hosting.md`.
- FerroGate architecture context: `docs/agentic-gateway-architecture.md`,
  `docs/agent-worker-protocol.md`, `docs/durable-storage.md`.
