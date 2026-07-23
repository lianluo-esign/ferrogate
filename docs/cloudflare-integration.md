<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Token4AI Cloud, FerroGate AI Gateway, Cloudflare integration research
  spike + developer-docs reference: AI Gateway, MCP, R2/Workers/Pages static
  hosting, managed agents, Secrets Store, D1, and the shared API-token auth model.
-->

# Cloudflare Integration Reference

This document is the durable capture of the Cloudflare developer-docs survey that
scoped the FerroGate Cloudflare initiative (epic issue #421 and its sibling
sub-issues). It is the single source implementers of the sibling issues should
consult for API shapes, auth scopes, product limits, and the FerroGate plug-in
seams each Cloudflare (CF) area targets.

The research is considered substantially complete; this document *curates* it
into reference form. Every plug-in-seam `file:line` citation below is grounded in
the current `main` codebase (verified while writing this doc). Where a seam does
not yet exist — because a sibling issue such as #411 plans to extract it — that is
called out explicitly with a pointer to the current code it would extract from.

## Contents

- [1. AI Gateway](#1-ai-gateway)
- [2. MCP (Model Context Protocol)](#2-mcp-model-context-protocol)
- [3. Static hosting: R2, Workers Static Assets, Pages](#3-static-hosting-r2-workers-static-assets-pages)
- [4. Managed agents](#4-managed-agents)
- [5. Secrets Store](#5-secrets-store)
- [6. D1](#6-d1)
- [7. Cross-cutting: one API-token auth model](#7-cross-cutting-one-api-token-auth-model)
- [8. FerroGate plug-in seams](#8-ferrogate-plug-in-seams)

---

## 1. AI Gateway

Cloudflare AI Gateway is a proxy in front of upstream model providers that adds
caching, rate limiting, logging, and unified billing.

### REST surfaces

Two distinct data-plane surfaces:

- **Compat (provider-native) surface** — one path per provider under the gateway,
  e.g. `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/openai/...`.
  The request/response body is the *provider's own* shape (OpenAI, Anthropic,
  Gemini, etc.). FerroGate keeps its existing per-provider adapters and only
  rewrites the base URL — see the seam in §8.1.
- **Unified surface** — a single normalized endpoint
  (`.../{account_id}/{gateway_id}/compat/chat/completions` and the unified
  provider-routing/BYOK entrypoint) that accepts one OpenAI-shaped request and
  fans out to any configured upstream. Subject to a **200 requests / 60 s**
  throttle on the unified-billing path.

### `cf-aig-*` headers

Behaviour is controlled per-request with response/request headers, including:

- `cf-aig-authorization` — bearer for an *authenticated* gateway.
- `cf-aig-cache-ttl`, `cf-aig-skip-cache`, `cf-aig-cache-key` — cache control.
- `cf-aig-metadata` — arbitrary JSON metadata stamped onto the log entry.
- `cf-aig-custom-cost` — override the billed cost for a request.
- `cf-aig-collect-log` / log-related toggles — per-request log opt-out.

FerroGate would attach these on the outbound request built by the provider
adapter (§8.1) without touching per-provider body translation.

### BYOK and management REST

- **BYOK (Bring Your Own Keys)** — provider keys can be stored on the gateway so
  clients authenticate only to the gateway; FerroGate can alternatively keep
  holding keys itself and pass them through on the compat surface.
- **Management REST** — gateways are CRUD-managed under
  `/accounts/{account_id}/ai-gateway/gateways` (list/create/update/delete gateway,
  read logs, manage evaluations/datasets). Requires the **AI Gateway** permission
  group (Read for reads, Edit for management).

### Limits

- **10 gateways** (default plan) / **20 gateways** (higher tier).
- Log storage caps per gateway (log retention/row caps enforced by CF; treat
  logs as bounded, not a durable store).
- **200 req / 60 s** throttle on the unified-billing endpoint.

---

## 2. MCP (Model Context Protocol)

Cloudflare hosts a managed MCP catalog and offers MCP server hosting via the
Agents SDK.

### Managed catalog

- Managed servers are exposed under **`*.mcp.cloudflare.com`** (a curated catalog
  of first-party Cloudflare MCP servers — docs, Workers bindings, observability,
  etc.). These are consumed as ordinary MCP upstreams.

### Hosting your own

- **Agents SDK hosting** — an MCP server can be authored with the Cloudflare
  Agents SDK and deployed as a Worker (backed by a Durable Object for session
  state), giving a hosted `*.workers.dev` / custom-domain MCP endpoint.

### Transports

- **Streamable HTTP** — the current transport (single endpoint, POST for
  request, optional streamed response). This is FerroGate's default.
- **SSE** — the legacy transport, still accepted by many servers.

FerroGate already models both (`McpTransport::StreamableHttp` / `::Sse`).

### Auth

- **OAuth** — the managed catalog and many hosted servers use an OAuth
  authorization-code flow (issuer + client id/secret + scopes). FerroGate models
  this with `McpOauthConfig`.
- **Bearer** — a static bearer token in an `Authorization` header for simpler
  servers.

Registering a Cloudflare-hosted MCP server in FerroGate is *pure configuration*
against the existing MCP host — no new transport code — see §8.6.

---

## 3. Static hosting: R2, Workers Static Assets, Pages

Three CF options for serving FerroGate-hosted static assets/sites.

### R2 (object storage)

- **S3-compatible API** with SigV4 auth (the same signer FerroGate already uses
  for its asset bucket). Access via **R2 API tokens** (scoped Access Key ID /
  Secret) or account API-token with **Workers R2 Storage** permission.
- Objects served **public** (managed `r2.dev` domain, meant for dev only) or via
  a **custom domain** routed through a Worker/CDN for production.
- Best fit for FerroGate because the existing asset path is already an
  S3-compatible bucket client (§8.2) — R2 is close to a drop-in endpoint swap.

### Workers Static Assets

- Assets are attached to a Worker and uploaded via a **3-step flow**: (1) create
  an assets *upload session* declaring the file manifest (path -> hash/size),
  (2) upload the file bodies (batched by hash), (3) deploy the Worker script that
  references the completed asset manifest. Requires **Workers Scripts Edit**.
- Good when assets must be co-served with Worker logic (routing, auth, headers).

### Pages

- Git-or-direct-upload static site hosting with a **deployments** model (each
  publish is an immutable deployment; preview + production aliases). Managed via
  the Pages REST API (`/accounts/{account_id}/pages/projects/.../deployments`).
  Requires **Cloudflare Pages Edit**.

### Recommendation matrix

| Need | R2 | Workers Static Assets | Pages |
|------|----|-----------------------|-------|
| FerroGate-managed byte store, S3-compatible | **Best** (reuses SigV4 bucket client, §8.2) | No (Worker-bound) | No |
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

- **Agents SDK -> Durable Objects** — an agent is a Durable Object (DO) instance:
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
existing Firecracker/Docker/local-process tiers — see §8.4.

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

- A secret is scoped to a store; a Worker binds a specific secret. Values are
  write-only via API (you set, you cannot read back the plaintext through the
  management API).

### Beta caps

- **1 store per account.**
- **100 secrets per store.**
- **1024 bytes** per secret value.

### Multi-tenant limitation

The single-store / 100-secret / 1024-byte caps mean Secrets Store **cannot** hold
per-tenant provider keys at FerroGate scale during beta. It is viable only for a
small set of *FerroGate-operator* secrets, not tenant fan-out. FerroGate's own
secret-resolver seam (§8.3) would add a `cf://`-style scheme that resolves through
Secrets Store, but the caps gate any per-tenant use until GA.

---

## 6. D1

Cloudflare's managed SQLite (per-database) service.

### Provision / query REST

- Databases are provisioned and queried over REST:
  `/accounts/{account_id}/d1/database` (create/list) and
  `.../database/{database_id}/query` (execute SQL, returning result sets).
  Requires the **D1** permission group (Read for query/read, Edit for
  create/schema).

### Per-tenant model

- A natural FerroGate model is **one D1 database per tenant** (isolation +
  independent limits). Databases are cheap to create but each is a distinct
  `database_id` FerroGate must track in its control plane.

### Limits

- Per-database size and row-count ceilings, and per-query result-size limits
  (D1 is SQLite semantics behind a REST facade — large scans are not its
  strength).

### REST rate limit -> proxy-Worker recommendation

The D1 **REST query API is rate-limited** and adds a round-trip per query. For
hot paths FerroGate should front D1 with a **proxy Worker** (Worker + D1 binding)
that batches/serves queries at the edge, rather than calling the REST query API
directly per request. This mirrors the DO/Container fronting-Worker pattern (§4).

---

## 7. Cross-cutting: one API-token auth model

All FerroGate Cloudflare access uses a **single Cloudflare account API token**
(scoped to the FerroGate account) presented as `Authorization: Bearer <token>`.
R2 may additionally use its S3-style Access Key ID / Secret for the SigV4 bucket
path. There is no per-product credential sprawl: one token, the union of the
permission groups below.

### Required token-scopes table

The table below is the authoritative list of permission groups the **#405
foundation client preflight** must verify. Columns: FerroGate CF area · CF
product · permission group(s) · read/edit.

| FerroGate CF area | CF product | Permission group(s) | Read/Edit |
|-------------------|-----------|---------------------|-----------|
| AI Gateway (proxy + management REST) | AI Gateway | AI Gateway | Read + Edit |
| Secrets Store (operator secrets) | Secrets Store | Secrets Store | Read + Write |
| D1 (per-tenant DBs) | D1 | D1 | Read + Edit |
| Managed agents deploy (fronting Worker / script PUT) | Workers | Workers Scripts | Edit |
| Static hosting — R2 object store | R2 | Workers R2 Storage | Read + Edit |
| Static hosting — Pages | Pages | Cloudflare Pages | Edit |
| Managed agents — Workflows lifecycle | Workflows | Workers Scripts (Workflows requires Workers Scripts) | Write + Edit |

Notes:

- **Workflows** has no standalone permission group of its own for the deploy
  path: managing Workflows requires **Workers Scripts Write/Edit** (the Workflow
  ships inside a Worker script), which is why the row references Workers Scripts.
- **Workers Static Assets** (when used instead of R2/Pages) is covered by the
  **Workers Scripts Edit** row (assets attach to a Worker deploy).
- R2's optional S3 Access Key path is a *credential form*, not an extra permission
  group; the account-token equivalent is **Workers R2 Storage Read/Edit** above.

The #405 client preflight should assert the token carries every group in this
table (with the listed read/edit level) and fail closed at startup otherwise.

---

## 8. FerroGate plug-in seams

Each Cloudflare area plugs into an existing FerroGate seam. Citations are against
current `main`. Where a seam is *planned* (not yet extracted), it says so.

### 8.1 AI Gateway -> provider/upstream adapter seam

- **Seam:** `ProviderAdapter` trait — `crates/ferrogate-providers/src/types.rs:351`
  (dispatched via `AdapterRegistry::adapter_for` at
  `crates/ferrogate-providers/src/registry.rs:31`).
- **Base-URL override point:** `ProviderConfig.base_url` —
  `crates/ferrogate-providers/src/types.rs:15`.
- **Outbound dispatch:** `dispatch_provider_request` —
  `crates/ferrogate-cli/src/gateway/dispatch.rs:57`.
- **Fit:** the compat surface only needs the base URL rewritten to
  `gateway.ai.cloudflare.com/v1/{account}/{gateway}/{provider}` and the
  `cf-aig-*` headers attached on the `ProviderHttpRequest`; per-provider body
  translation is unchanged. **This seam exists today.**

### 8.2 R2 -> asset object-store seam

- **Current concrete:** `AssetBucketClient` / `AssetBucketConfig` (S3-compatible,
  SigV4) — `crates/ferrogate-cli/src/gateway/asset_bucket.rs:46` and `:34`.
  Presigned upload/read path: `crates/ferrogate-cli/src/gateway/asset_presign.rs`.
- **Planned seam:** there is **no `AssetObjectStore` trait yet** — sibling issue
  **#411** plans to extract one from `AssetBucketClient`. R2 would then be a second
  implementation (or, more cheaply, an endpoint/credential swap on the existing
  SigV4 client, since R2 is S3-compatible).
- **Fit:** until #411 lands, R2 support is an `AssetBucketConfig` pointed at the R2
  S3 endpoint; after #411 it is a trait impl.

### 8.3 Secrets Store -> secret-resolver seam

- **Seam:** `SecretResolver` trait — `crates/ferrogate-secrets/src/lib.rs:92`;
  `SecretRef` enum — `:37`; `SecretResolverRegistry` (scheme dispatch) — `:196`.
- **Fit:** add a `cf://` (or `cfsecrets://`) variant to `SecretRef` and a
  `CloudflareSecretResolver` implementing `SecretResolver`, wired into the
  registry alongside `env://` and `vault://`. **The resolver seam exists today**;
  the `cf://` scheme does not yet (would be added here). Note the beta caps (§5)
  bound this to operator, not per-tenant, secrets.

### 8.4 Managed agents -> agent-worker isolation-backend seam

- **Seam:** `IsolationBackendLifecycle` trait —
  `crates/ferrogate-runtime/src/isolation.rs:256`; `FrameworkAdapter` trait —
  `crates/ferrogate-runtime/src/framework_adapter.rs:521`; replaceable backend
  registry — `registered_isolation_backends` at
  `crates/agent-worker/src/backends.rs:110` (individual tiers, e.g.
  `docker_registered_backend` at `:165`, `firecracker_registered_backend` at
  `:1174`).
- **Fronting-Worker dispatch:** managed external actions already flow through a
  gateway transport — `GatewayExternalActionTransportRequest/Response` in
  `crates/agent-worker/src/external_actions.rs` (import at `:39`), which is the
  natural place a Cloudflare fronting Worker call would attach.
- **Control-plane record:** `StoredManagedWorkerTemplate` —
  `crates/ferrogate-storage/src/lib.rs:986` (repository trait at `:746`).
- **Fit:** a Cloudflare-managed backend registers as a new
  `RegisteredIsolationBackend` alongside Firecracker/Docker/local-process, and the
  "no public lifecycle REST" constraint (§4) is satisfied by pointing its dispatch
  at a FerroGate-deployed fronting Worker. **The backend-registry and transport
  seams exist today;** a Cloudflare backend impl does not yet.

### 8.5 D1 -> control-plane store seam

- **Seam:** the repository trait family (`Repository<T>` and the typed repos) —
  `crates/ferrogate-storage/src/lib.rs:723`; Postgres implementation
  `PostgresControlPlaneStore` — `:1315`; backend selector enum
  `RuntimeControlPlaneBackend` (`Memory` | `Postgres`) — `:10357`.
- **Fit:** a D1-backed control plane would be a third `RuntimeControlPlaneBackend`
  variant implementing the same repository traits, with queries routed through a
  proxy Worker (§6) rather than the rate-limited REST query API. **The store seam
  and backend enum exist today;** a D1 variant does not yet.

### 8.6 MCP -> upstream registration seam

- **Seam:** `McpServerConfig` — `crates/ferrogate-mcp/src/lib.rs:202` (transport
  `McpTransport` at `:147`, `McpOauthConfig` at `:182`); config validation/registration
  path — `crates/ferrogate-cli/src/config/validate.rs:2859` and state registration
  `crates/ferrogate-cli/src/state.rs:669`.
- **Fit:** a Cloudflare managed (`*.mcp.cloudflare.com`) or self-hosted MCP server
  is registered as an `McpServerConfig` with `transport: streamable_http` and
  either `oauth` or a bearer header — **pure configuration, no new transport
  code.** **This seam exists today.**

### Seam summary

| CF area | FerroGate seam | Exists today? |
|---------|----------------|---------------|
| AI Gateway | `ProviderAdapter` + `base_url` + dispatch | Yes |
| R2 static hosting | `AssetBucketClient` (trait `AssetObjectStore` planned by #411) | Concrete yes; trait no |
| Secrets Store | `SecretResolver` / `SecretRef` (`cf://` scheme new) | Seam yes; scheme no |
| Managed agents | agent-worker isolation-backend registry + fronting-Worker transport | Seam yes; CF backend no |
| D1 | control-plane `Repository` traits + `RuntimeControlPlaneBackend` | Seam yes; D1 variant no |
| MCP | `McpServerConfig` registration | Yes (config-only) |

---

## References

- Epic: issue #421 (this document is its capture); foundation client: #405; asset
  object-store extraction: #411; managed-agent siblings: #419.
- FerroGate architecture context: `docs/agentic-gateway-architecture.md`,
  `docs/agent-worker-protocol.md`, `docs/durable-storage.md`.
