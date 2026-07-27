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
  pause / resume / terminate). It is a *different* execution model (durable
  multi-step), not a general agent-instance controller, so it does not remove
  this constraint. (An earlier revision of this note called Workflows "the
  province of #414". It is not: **#414 is the verb→primitive mapping and the
  per-run `props` parameterization on top of THIS Worker** — see §3a. No
  Workflows-backed control surface exists or is planned here.)

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
| start (lazy create; props resolved into state) | `POST /control/start`   | `{ sessionId, runId, workerTemplateId, frameworkAdapter, capabilityEnvelopeId, props }` | `{ runRef, status }` — or 409 `run_conflict` / 422 on a refused placement dial |
| invoke  | `POST /control/invoke`  | `{ runRef, workloadRef, args[] }` | `{ runRef, status, exitCode, message }` |
|         |                         |                                   | *(every verb below `start` returns 404 `not_found` for a `runRef` with no bound run)* |
| cancel (**cooperative** abort — NOT fibers, see §3a) | `POST /control/cancel`  | `{ runRef, reason }` | `{ runRef, status, aborted, detail }` |
| destroy (`this.destroy()`) | `POST /control/destroy` | `{ runRef }` | `{ runRef, status }` |
| status (custom RPC) | `GET  /control/status`  | `?runRef=NAME` (percent-encoded) | `{ runRef, status, message, resolvedModel, resolvedLocationHint, recordedRoutingRetry, cancelRequested }` |

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
| **start** | `onStart()` runs **automatically** on every cold start / wake — it is not caller-invoked, and the pinned SDK calls it with **no arguments**, so it cannot carry per-run props. | `POST /control/start` carries `props`; `start()` resolves model/tools/prompt into persistent state itself (see below). `onStart()` stays the argument-less wake hook. |
| **exec / invoke** | agent RPC method | `POST /control/invoke` |
| **stop / pause / resume / restart** | **do NOT exist.** Hibernation is automatic (~70–140s idle → zero compute, state retained; wakes on the next HTTP/WS/alarm/email). | *no route.* Modeled entirely client-side as **hibernate + re-address**: `stop_run` is a local no-op returning `Stopped`; "resume/restart" is just re-addressing the agent by name (which wakes it). |
| **getStatus** | **does NOT exist** as a primitive. | `GET /control/status` — a **custom** `status()` RPC we expose on the agent, not a built-in `getStatus`. |
| **cancel** | Cloudflare documents **fibers** (`startFiber().cancel`, `abortSubAgent`) — but the pinned `agents@0.0.109` **ships no fiber API at all** (`grep -ri fiber node_modules/agents/` finds nothing). | `POST /control/cancel` — a **cooperative** cancel: abort an `AbortSignal` the workload observes + set a durable latch that refuses later `invoke`s. Distinct from "stop". See the caveat below. |
| **destroy / delete** | `this.destroy()` — drops the DO's tables, deletes the alarm, clears storage, then aborts the object. | `POST /control/destroy` — calls `this.destroy()`. Because the abort also tears down the RPC channel the call arrived on, a completed destroy surfaces as a rejected RPC with reason `"destroyed"`, which the route maps back to the `cleaned_up` envelope. |

**Why `destroy` must be the SDK call and not `ctx.storage.deleteAll()` (issue
#482).** `deleteAll()` alone looks equivalent — it wipes the object's SQLite
database — but it leaves the Durable Object's **alarm armed**: Cloudflare only
made `deleteAll()` delete the alarm from compatibility
date `2026-02-24`, and this Worker deploys `compatibility_date = "2025-06-01"`
with no `delete_all_deletes_alarm` flag. Nothing later cleans that alarm up
either: the SDK's `_scheduleNextAlarm()` only ever calls `setAlarm()`, and with
zero schedule rows left it returns without calling `deleteAlarm()`. So a run
destroyed while carrying a #426 schedule wakes back up after its own cleanup and
bills compute — and in-flight work and WebSockets are never aborted
(`ctx.abort()` is skipped).

An earlier draft of this paragraph said `deleteAll()` "clears the synced state, so
a following `status` still answers 404". **Measured, it does not.** Run the
mutation (replace `await this.destroy()` in `destroyRun()` with
`await this.ctx.storage.deleteAll()`) and the follow-up status answers **200
`{"status":"cleaned_up"}`**: `status()` returns `not_found` only when the
in-memory `this.state.runId` is `null`, and `deleteAll()` reaches storage, not the
resident object. Without `ctx.abort()` nothing evicts that object, so it keeps
answering out of memory. Three observables move under this mutation, not one —
the status code, the `/schedule/list` reply (400 `no such table:
cf_agents_schedules`, because the dropped tables are never rebuilt either), and
the pending alarm. Only the last is the harm #482 names; the first two say the
object never went away.

The **stranded alarm is the whole of it**; the schedule rows are not a second
problem. `AgentGateway` is registered under `new_sqlite_classes` (see
`wrangler.toml`), and on a SQLite-backed Durable Object `deleteAll()` removes the
entire contents of the object's private SQLite database — SQL data *and*
key-value data, atomically. `cf_agents_schedules` therefore does **not** survive
`deleteAll()`, and the "surviving row re-arms the alarm on the next wake" story an
earlier draft of this section told is **false** for this deployment. The table
DROPs inside `destroy()` are redundant with its own `deleteAll()` here; what makes
`destroy()` the required call is the `deleteAlarm()` and the `ctx.abort()` that
`deleteAll()` alone does not do.

**Do not reimplement the teardown as `deleteAll()` + `ctx.abort()`.** It measures
green — the whole Worker suite stays at `109 passed` under it — and the reason is
a commit-timing artefact, not a property you can rely on. At this compatibility
date the alarm's *survival* of `deleteAll()` only becomes visible to a later read
once the I/O turn commits; a `ctx.abort()` in that same turn breaks the output
gate (`workerd/api/actor-state.c++:1178: broken.outputGateBroken`, printed on
every destroy in this suite) and the survival never lands, so the alarm reads
`null` for the wrong reason. (That is the inference the two runs below force —
workerd's own source is not vendored here, so it is not read off it.) Put one macrotask
(`await new Promise((r) => setTimeout(r, 0))`) between the two and the alarm is
back: `1 failed | 108 passed`, the single red being the #482 guard. Add
`deleteAlarm()` in front of that same sequence and it is green again
(`109 passed`) — which is what `deleteAlarm()` buys: an outcome that does not
depend on when the abort happens to land. All four runs are recorded in
`destroy-alarm.test.ts`'s header.

`workers/agent-gateway/test/destroy-alarm.test.ts` pins exactly that one
discriminator: after a destroy the platform reports **no** pending alarm, while a
sibling run that was not destroyed still has one. Its schedule-list test is a
post-condition, not a second discriminator: it *does* red under the `deleteAll()`
mutation, but on `status === 200` (the route 400s with `no such table`), never on
the count — see the file's own header.

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
- **Cancel is cooperative, and it is not a stop.** Actively aborting in-flight
  work is a *separate* operation from a terminal stop. The Rust client routes a
  **terminal** stop to the hibernation no-op and an **operator cancel** to
  `cancel_run` — decided by the scheduler's typed `ManagedWorkerStopKind`, never
  by parsing the reason string (an operator cancel whose reason happened to read
  `"completed"` previously sent no control call at all). Both go through the
  unchanged #412 `AgentWorkerControlClient` seam, so `ManagedWorkerScheduler`
  drives it as-is.

  **What cancel can and cannot do.** The pinned Agents SDK has no fiber API, so
  `POST /control/cancel` does two things: it aborts an `AbortSignal` that the
  agent's `dispatchWorkload` observes (in-flight work rejects at its next
  observation point), and it sets a **durable** `cancelRequested` latch so a
  later `invoke` — including one after hibernation dropped the in-memory abort
  handle — is refused. The response's `aborted` field says which happened:
  `true` = in-flight work on that instance was signalled, `false` = nothing was
  running there and only the latch was set.

  It therefore **cannot** stop a workload that ignores the signal, or one
  executing outside the agent's Durable Object (a container, a sub-request
  already in flight). Any caller for whom "stopped" must be a *guarantee* has to
  verify and escalate. The #428 cost governor's `KillMode::Cancel` does exactly
  that: cancel → re-read `run_status` → `cleanup_run` (`this.destroy()`) unless
  the run actually reached a terminal state. A cooperative cancel is an
  optimization on the way to a destroy, never a substitute for one.

### Run parameterization: `props` (transient) vs. state (persistent)

Per-run initialization is delivered as **`props`**, not persistent state:

- **`props`** (`CloudflareRunProps` in Rust → `RunProps` in the Worker): the
  run's runtime-selectable dials — **model**, **tools**, **system prompt**, plus
  the placement dials `locationHint`, `jurisdiction` and `routingRetry` (each
  honored, refused or recorded-only per the table below — none is silently
  inert). Cloudflare has **no deploy-time `model` field**: the agent
  chooses its model/tools/prompt *in code* inside `onStart(props)`, so those
  become selectable per run without redeploying the Worker.
- **State**: the agent's persistent DO SQLite rows. `start` reads the transient
  props and writes the *resolved* selections into state, so they survive
  hibernation and are available to every later invoke without props being re-sent.

FerroGate injects per-run props through a **`CloudflareRunPropsResolver`** on the
`CloudflareAgentControlClient`, which maps the scheduler's `IsolationPrepareRequest`
(e.g. its `worker_template_id`) onto the props. The scheduler seam itself is left
unchanged — the resolver is the only new injection point — and the props ride the
`props` field of `POST /control/start`.

**The props are resolved in `start()`, NOT by calling `onStart(props)`.** The
pinned `agents@0.0.109` rebinds `this.onStart` in its constructor to a
zero-argument wrapper (`agents/dist/chunk-3IQQY2UH.js:316-317`) that invokes the
user hook with no arguments, so anything handed to it is silently discarded —
which is exactly what happened: every `resolved*` field fell back to its initial
value while the control plane reported the run as parameterized. `onStart()`
remains the (argument-less) wake hook; a woken agent reads its already-resolved
configuration from state.

### Placement dials: honored, refused, recorded — never silently inert

| dial | disposition | why |
|---|---|---|
| `locationHint` (`wnam`/`enam`/`weur`/…) | **HONORED** — passed to `getAgentByName(ns, name, { locationHint })` on `POST /control/start`. An unrecognized value is refused (422 `unsupported_location_hint`). | It is consumed by `namespace.get(id, options)` when the instance is first created and is identity-neutral (`idFromName` never sees it), so applying it at start is complete: later calls resolve the same object without repeating it. |
| `jurisdiction` (`eu`/`fedramp`) | **REFUSED** — a start carrying it fails closed with 422 `jurisdiction_unsupported`. | It is applied as `namespace.jurisdiction(j).idFromName(name)` — it changes the Durable Object's **identity**. FerroGate addresses a run by name from call sites that share no per-run state (the scheduler client, #428's kill switch, the #426/#427 schedule and memory clients), so honoring it on `start` alone would leave the run reachable from the starter and invisible to everyone else — including the over-budget kill path. A jurisdiction belongs on the **deployment** (one gateway Worker per jurisdiction). Recording it and reporting it back as if honored is the #188 "endpoint returns 200 while the runtime ignores the value" failure mode applied to a compliance control. |
| `routingRetry` | **RECORDED ONLY** — persisted as `recordedRoutingRetry` and returned by `GET /control/status`; the Worker performs no retry. | Retrying a control call is FerroGate's transport concern (it owns the timeout, backoff and idempotency). A second retry loop inside the Worker would multiply rather than bound the attempts. |

### Lifecycle guards

- **An unknown `runRef` is refused, not created.** Addressing a name always
  yields a Durable Object stub and Cloudflare has no existence check, so every
  verb but `start` returns **404 `not_found`** when no run is bound to the
  instance. Before this, `POST /control/destroy {"runRef":"typo"}` answered 200
  `cleaned_up`, FerroGate recorded `IsolationLifecycleEvidence` for a run that
  never existed, and a token holder could mint unbounded instances. The refusal
  happens before the first `setState`, so nothing is persisted for the addressed
  name. On the Rust side it is `CloudflareControlSurfaceError::RunNotFound`.
- **The run identity is bound once.** A `start` that disagrees with the bound
  `runId`/`sessionId`/`capabilityEnvelopeId`, or targets a terminal or cancelled
  run, is refused with **409 `run_conflict`**; an identical re-start is
  idempotent (a safe transport retry) and does not re-resolve props.
- **Terminal states are not rewritten.** `cancel` on a `completed`/`failed`/
  `cleaned_up` run reports that status with `aborted: false` instead of flipping
  it to `stopped`.

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
- **#414 — lifecycle mapping + run parameterization.** Not a second control
  surface: it pins each FerroGate run verb to the *actual* Cloudflare primitive
  on the #413 Worker (§3a), threads the per-run `props` (model/tools/prompt +
  placement) into the run's resolved configuration, and supplies the lifecycle
  guards — cooperative cancel, `this.destroy()`, `not_found` on an unknown
  `runRef`, and the start state machine.
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
