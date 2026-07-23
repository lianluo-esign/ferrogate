<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: The FerroGate agent-gateway Worker (issue #413): the no-first-party-REST
  constraint, the fronting-Worker architecture, the control-route contract, and how
  #412 / #414 / #426-428 build on it.
-->

# The FerroGate agent-gateway Worker (issue #413)

This is the durable design note for the **agent-gateway Worker** — the required
front for **all** Cloudflare (CF) agent operations FerroGate drives. It records
the hard constraint that forces the architecture, the Worker's shape, the
control-route contract, and how the sibling issues build on it.

## 1. The constraint: no first-party REST API for an agent instance

Cloudflare exposes **no first-party REST API** to
create / start / stop / invoke / inspect / destroy an **individual** agent
(Durable Object) instance. This is verified, not assumed:

- Durable Objects, the Agents SDK, and Containers/Sandboxes are only reachable
  **from inside a Worker** via runtime **bindings**. There is no public
  `POST /accounts/{id}/durable_objects/.../instances/{name}/start`-style
  endpoint.
- The Durable Objects REST API that *does* exist is **read-only at instance
  granularity** (list namespaces/objects, inspect) — it cannot drive lifecycle.
- The only CF agent-adjacent product with a public lifecycle REST API is
  **Workflows** (`/accounts/{id}/workflows/{name}/instances` — create / status /
  pause / resume / terminate). That is the province of the sibling issue **#414**,
  and it is a *different* execution model (durable multi-step), not a general
  agent-instance controller.

**Therefore:** every agent operation FerroGate performs — address an instance by
name, invoke a method, read status, cancel, destroy — must be fronted by a
Worker **we write and deploy**. There is no way around this; downstream issues
must design against it rather than expecting a REST endpoint to appear.

## 2. Architecture: the fronting Worker

Source: [`workers/agent-gateway/`](../workers/agent-gateway/).

```
FerroGate (Rust)                          Cloudflare edge
────────────────                          ───────────────
CloudflareControlSurface (#412 seam)
   │  WorkerGatewayControlSurface (#413)
   │    HTTP + Bearer                      ┌───────────────────────────┐
   ├────────────────────────────────────► │ agent-gateway Worker      │
   │   POST /control/start                 │  (fetch handler)          │
   │   POST /control/invoke                │   • DIY auth gate         │
   │   POST /control/cancel                │   • /control/* routes ──┐ │
   │   POST /control/destroy               │   • routeAgentRequest   │ │
   │   GET  /control/status                │        /agents/:a/:n/.. │ │
   │                                       │                         ▼ │
GatewayWorkerDeployer (#413)               │   getAgentByName(ns,name) │
   │  PUT /accounts/{id}/workers/scripts   │        │  DO RPC          │
   ├────────────────────────────────────► │        ▼                  │
   │  (module + metadata + DO migration)   │   AgentGateway (DO, SQLite)│
   │  DELETE …/scripts/{name}  (teardown)  └───────────────────────────┘
```

- **`AgentGateway`** — a Durable Object agent class (Agents SDK `Agent`), one
  addressable stateful instance per run. State lives in the DO's embedded
  **SQLite** DB, so the class is registered with a **`new_sqlite_classes`**
  migration (not `new_classes`).
- **`routeAgentRequest(request, env, options)`** — path-routes
  `/agents/:agent/:name/...` to the DO, DIY-gated in
  `onBeforeRequest` / `onBeforeConnect`.
- **Explicit control routes** (`/control/*`) — each addresses an instance **by
  name** via `getAgentByName(ns, name)` and invokes a DO RPC method. This is the
  lifecycle surface FerroGate calls.
- **Tethered egress enforcement point** — because *every* agent operation passes
  through this Worker's auth gate, it is the single choke point at which
  FerroGate enforces authN/Z on CF-hosted agent traffic.

### Auth (DIY)

Cloudflare fronts the DO but does not authenticate the caller for us, so auth is
**do-it-yourself**. The baseline is a **bearer token** compared (constant-time)
against the `GATEWAY_CONTROL_TOKEN` secret in `onRequest` / `onBeforeRequest` /
the control routes. The credential comes from FerroGate's secret seam (#405
token resolver / #417 Secrets Store). Documented stronger alternatives, swappable
at the same gate:

- **mTLS** — client-cert on a custom domain (reuses FerroGate's self-hosted mTLS
  posture).
- **Cloudflare Access** — validate the `Cf-Access-Jwt-Assertion` JWT.

### SDK pin + migration caveat

The Agents SDK is **pre-1.0**; `agents` and `wrangler` are pinned **exactly** in
`workers/agent-gateway/package.json`. The DO migration has two forms across
wrangler/SDK versions (`[[migrations]]` + `new_sqlite_classes` vs. the newer
top-level `exports`/`[migrations]` mechanism); the exact form must be **verified
against the pinned SDK at deploy time**. See the Worker README's "SDK migration
caveat".

## 3. Control-route contract

All routes require `Authorization: Bearer <GATEWAY_CONTROL_TOKEN>`.
`runRef` is the agent instance **name** (the `runId` given to `start`).
`GET /healthz` is the only unauthenticated route.

| Verb | Route | Body / query | Returns |
|------|-------|--------------|---------|
| start   | `POST /control/start`   | `{ sessionId, runId, workerTemplateId, frameworkAdapter, capabilityEnvelopeId }` | `{ runRef, status }` |
| invoke  | `POST /control/invoke`  | `{ runRef, workloadRef, args[] }` | `{ runRef, status, exitCode, message }` |
| cancel  | `POST /control/cancel`  | `{ runRef, reason }` | `{ runRef, status }` |
| destroy | `POST /control/destroy` | `{ runRef }` | `{ runRef, status }` |
| status  | `GET  /control/status`  | `?runRef=NAME` | `{ runRef, status, message }` |

`status` ∈ `queued | running | completed | failed | stopped | cleaned_up`,
mirroring the Rust `CloudflareRunStatus`.

## 4. Deploy / teardown (Rust)

Two options, both covered by the Rust pipeline in
[`crates/ferrogate-runtime/src/cloudflare_gateway_deploy.rs`](../crates/ferrogate-runtime/src/cloudflare_gateway_deploy.rs):

1. **Workers Script API** — `PUT /accounts/{account_id}/workers/scripts/{name}`
   as `multipart/form-data`: a `metadata` JSON part (`main_module`, the DO
   `bindings`, the `new_sqlite_classes` migration, compat date/flags) plus the
   module part. Teardown is `DELETE …/scripts/{name}`.
   `GatewayWorkerSpec` builds the metadata + multipart body + content type
   **deterministically** so the exact request is unit-tested against a mocked
   #405 transport. Requires the **Workers Scripts Edit** token scope.
2. **`wrangler deploy`** shell-out — the documented CLI fallback
   (`GatewayWorkerSpec::wrangler_deploy_command`), used when a live multipart PUT
   is not wired (the shared `ReqwestTransport` hard-codes a JSON content type, so
   a live multipart upload needs a multipart-aware transport or Wrangler).

Every CF call flows through the **#405 `HttpTransport` seam**, so the whole
pipeline is mockable with no network. The **live** deploy + a live control
round-trip need a real CF account/token and are the **test agent's** to prove.

## 5. How the sibling issues build on this

- **#412 — control seam.** `crates/ferrogate-runtime/src/cloudflare_worker.rs`
  defines the synchronous `CloudflareControlSurface` seam and the
  `CloudflareAgentControlClient` that maps the managed-worker scheduler lifecycle
  onto it. #413 supplies the **real** implementation,
  `WorkerGatewayControlSurface`
  ([`cloudflare_gateway_control.rs`](../crates/ferrogate-runtime/src/cloudflare_gateway_control.rs)),
  mapping start/exec/stop/cleanup/status onto the control routes above. The seam
  is sync; the production transport bridges to the async #405 client via a
  `block_on` bridge (`BlockingHttpControlTransport`).
- **#414 — Workflows REST.** The *other* `CloudflareControlSurface` impl, using
  the public Workflows lifecycle REST API. It coexists with #413: operators pick
  the hosting model per worker template. #414 does **not** remove the need for
  #413 — Workflows is a different execution model and does not expose arbitrary
  agent-instance control.
- **#426–428 (agent lifecycle / memory / schedule verbs).** These extend the
  control-route contract (§3) with additional DO RPC methods on `AgentGateway`
  (e.g. memory read/write, schedule set/cancel) and the matching Rust mappings.
  They design against the constraint in §1: any new agent operation is a new
  control route on this Worker, never a new CF REST endpoint.
- **#409 — hosted MCP.** Shares the Workers Script deploy plumbing
  (`GatewayWorkerDeployer` / the Script PUT + DELETE path).

## 6. What is proven vs. live-only

- **Proven offline (this issue):** the Worker source (coherent + deployable),
  the deploy/teardown request construction (script name, metadata, DO SQLite
  migration, multipart body) against a mocked #405 transport, the teardown
  DELETE, and the control-surface verb→route→auth→status mapping against a
  scripted transport (plus the block-on bridge).
- **Live-only (test agent):** an actual `wrangler deploy` / Script PUT onto a
  real account, and a live authenticated control round-trip against the deployed
  Worker. These require a real CF account/token and network, absent from the dev
  sandbox.
