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
| start (lazy create + `onStart(props)`) | `POST /control/start`   | `{ sessionId, runId, workerTemplateId, frameworkAdapter, capabilityEnvelopeId, props }` | `{ runRef, status }` |
| invoke  | `POST /control/invoke`  | `{ runRef, workloadRef, args[] }` | `{ runRef, status, exitCode, message }` |
| cancel (fiber-cancel) | `POST /control/cancel`  | `{ runRef, reason }` | `{ runRef, status }` |
| destroy (`this.destroy()`) | `POST /control/destroy` | `{ runRef }` | `{ runRef, status }` |
| status (custom RPC) | `GET  /control/status`  | `?runRef=NAME` | `{ runRef, status, message, resolvedModel }` |

`status` ∈ `queued | running | completed | failed | stopped | cleaned_up`,
mirroring the Rust `CloudflareRunStatus`. `props` carries the per-run
model/tools/prompt + placement (see §3a). There is deliberately **no** stop /
pause / resume / getStatus route — those primitives do not exist on Cloudflare
(§3a).

## 3a. Run verbs → Cloudflare primitives (issue #414)

FerroGate's run-lifecycle verbs do **not** map onto a conventional
start/stop/pause lifecycle API — Cloudflare's actual agent primitives are
**narrower**. Issue #414 pins the mapping to that reality so downstream code
stops assuming verbs that do not exist.

| FerroGate verb (scheduler / surface) | Cloudflare primitive (reality) | Gateway route / mechanism |
|---|---|---|
| **create / instantiate** | **LAZY** — the first `getAgentByName(ns, name)` (or `routeAgentRequest`) for a name *creates* the instance; the same name always resolves to the same instance. There is no explicit "create". | `POST /control/start` (`getAgentByName` addresses the run by name — first addressing instantiates it) |
| **start** | `onStart(props)` runs **automatically** on every cold start / wake — it is not caller-invoked. | delivered as the `props` field of `POST /control/start`; the Worker's `onStart(props)` reads model/tools/prompt |
| **exec / invoke** | agent RPC method | `POST /control/invoke` |
| **stop / pause / resume / restart** | **do NOT exist.** Hibernation is automatic (~70–140s idle → zero compute, state retained; wakes on the next HTTP/WS/alarm/email). | *no route.* Modeled entirely client-side as **hibernate + re-address**: `stop_run` is a local no-op returning `Stopped`; "resume/restart" is just re-addressing the agent by name (which wakes it). |
| **getStatus** | **does NOT exist** as a primitive. | `GET /control/status` — a **custom** `status()` RPC we expose on the agent, not a built-in `getStatus`. |
| **cancel** | only via **fibers** (`startFiber().cancel`, `abortSubAgent`). | `POST /control/cancel` — the fiber-cancel route (distinct from "stop") |
| **destroy / delete** | `this.destroy()` — drops the DO's tables, deletes alarms, clears storage. | `POST /control/destroy` |

### RPC vs. path routing (per verb)

Every control verb uses **DO RPC** via `getAgentByName(ns, name).method(...)` (the
`/control/*` routes), because lifecycle operations must target one named instance
and return a structured result. `routeAgentRequest` **path routing**
(`/agents/:agent/:name/...`) is reserved for *in-agent* HTTP/WS traffic (the
agent's own request handler), not lifecycle control.

### The no-stop / no-getStatus constraint (do not design against it)

There is **no** `stop`, `pause`, `resume`, `restart`, or `getStatus` primitive on
Cloudflare. Concretely:

- **"Stop" is hibernation.** To "stop" an agent you simply stop addressing it; it
  hibernates automatically. FerroGate's `stop_run` therefore performs **no HTTP
  request** — it returns `Stopped` locally. On the completion/failure path the
  scheduler's stop is exactly this hibernation no-op; the subsequent
  `destroy` (cleanup) is what actually tears the instance down.
- **"Resume/restart" is re-addressing.** `getAgentByName(ns, name)` wakes a
  hibernated instance; persistent state is retained across hibernation, so a woken
  agent reads its already-resolved run config from state (props are **not**
  re-delivered).
- **Status is custom.** `run_status` calls our own `status()` RPC; do not expect a
  platform `getStatus`.
- **Cancel is fibers, not stop.** Actively aborting in-flight work is a *separate*
  operation from a terminal stop. The Rust client routes a natural terminal
  reason (`completed`/`failed`) to the hibernation no-op, and any operator cancel
  reason to the `cancel_run` fiber-cancel route — all through the unchanged #412
  `AgentWorkerControlClient` seam, so `ManagedWorkerScheduler` drives it as-is.

### Run parameterization: `props` (transient) vs. state (persistent)

Per-run initialization is delivered as **`props`**, not persistent state:

- **`props`** (`CloudflareRunProps` in Rust → `RunProps` in the Worker): the
  run's runtime-selectable dials — **model**, **tools**, **system prompt**, plus
  `locationHint` (`wnam`/`enam`/`weur`/…), `jurisdiction` (`eu`/`fedramp`), and
  `routingRetry`. Cloudflare has **no deploy-time `model` field**: the agent
  chooses its model/tools/prompt *in code* inside `onStart(props)`, so those
  become selectable per run without redeploying the Worker.
- **State**: the agent's persistent DO SQLite rows. `onStart` reads the transient
  props and writes the *resolved* selections into state, so they survive
  hibernation and are available to every later invoke without props being re-sent.

FerroGate injects per-run props through a **`CloudflareRunPropsResolver`** on the
`CloudflareAgentControlClient`, which maps the scheduler's `IsolationPrepareRequest`
(e.g. its `worker_template_id`) onto the props. The scheduler seam itself is left
unchanged — the resolver is the only new injection point — and the props ride the
`props` field of `POST /control/start` into `onStart(props)`.

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
