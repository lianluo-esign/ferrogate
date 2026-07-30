<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: FerroGate agent-gateway Worker — deploy + SDK-migration caveat (issue #413).
-->

# FerroGate agent-gateway Worker (issue #413)

The **required front for ALL Cloudflare agent operations**. Cloudflare exposes
**no first-party REST API** to create / start / stop / invoke / inspect / destroy
an individual agent (Durable Object) instance — the DO REST API is read-only at
instance granularity. Therefore every agent operation FerroGate drives must be
fronted by a Worker we write and deploy. This is that Worker.

See `docs/cloudflare-agent-gateway.md` for the full architecture and how #412 /
#414 / #426-428 build on it.

## What it contains

- **`AgentGateway`** — a Durable Object agent class (Agents SDK `Agent`),
  registered with a **`new_sqlite_classes`** DO migration (the SDK stores agent
  state in an embedded per-instance SQLite DB).
- **`routeAgentRequest(request, env, options)`** — path-routes
  `/agents/:agent/:name/...` to the DO, DIY-gated in
  `onBeforeRequest` / `onBeforeConnect`.
- **Explicit control routes** (`/control/*`) — each addresses an instance **by
  name** via `getAgentByName(ns, name)` and invokes an RPC method
  (`start` / `invoke` / `cancel` / `destroy` / `status`).
- **DIY auth** — bearer token compared (constant-time) against the
  `GATEWAY_CONTROL_TOKEN` secret in `onRequest` / `onBeforeRequest` / the control
  routes. mTLS and Cloudflare Access are documented stronger alternatives.

## Control-route contract

| Verb | Route | Body / query | Returns |
|------|-------|--------------|---------|
| start (lazy create; props resolved into state) | `POST /control/start`   | `{ sessionId, runId, workerTemplateId, frameworkAdapter, capabilityEnvelopeId, props }` | `{ runRef, status }`; 409 `run_conflict` on a re-bind, 422 on a refused placement dial |
| invoke  | `POST /control/invoke`  | `{ runRef, workloadRef, args[] }` | `{ runRef, status, exitCode, message }` |
| cancel (**cooperative** abort — NOT fibers) | `POST /control/cancel`  | `{ runRef, reason }` | `{ runRef, status, aborted, detail }` |
| destroy (`this.destroy()`) | `POST /control/destroy` | `{ runRef }` | `{ runRef, status }` |
| status (custom RPC) | `GET  /control/status`  | `?runRef=NAME` | `{ runRef, status, message, resolvedModel, resolvedLocationHint, recordedRoutingRetry, cancelRequested }` |

Every verb except `start` returns **404 `not_found`** when no run is bound to the
addressed instance: naming an instance always yields a Durable Object stub, so
without this a typo'd `runRef` answered 200 and FerroGate recorded lifecycle
evidence for a run that never existed.

`runRef` is the agent instance name (the `runId` supplied to `start`). All
routes require `Authorization: Bearer <GATEWAY_CONTROL_TOKEN>`. `GET /healthz`
is the only unauthenticated route.

`props` (`RunProps`) is the transient per-run init — `model`, `tools`,
`systemPrompt`, `locationHint`, `jurisdiction`, `routingRetry`. `start()` reads
them to pick the run's model/tools/prompt in code (Cloudflare has no deploy-time
model field) and writes the resolved selections into persistent state. Props are
distinct from that state.

They are resolved in `start()`, **not** by calling `onStart(props)`: the pinned
`agents@0.0.109` rebinds `this.onStart` to a zero-argument wrapper, so props
handed to it are silently dropped.

Placement dials are each honored, refused or recorded — never silently inert:

| dial | disposition |
|---|---|
| `locationHint` | **honored** — passed to `getAgentByName(ns, name, { locationHint })` at start (identity-neutral, so start is the complete place to apply it). An unknown value is refused 422. |
| `jurisdiction` | **refused** (422 `jurisdiction_unsupported`) — it changes the Durable Object's *identity*, so a run started with one would be unreachable from every FerroGate caller that does not also carry it, including the #428 over-budget kill switch. It belongs on the deployment, not on a run. |
| `routingRetry` | **recorded only** — reported by `status`; retrying a control call is FerroGate's transport concern. |

There is deliberately **no** stop / pause / resume / restart / getStatus route:
Cloudflare has no such primitive. An idle agent **hibernates** automatically
(zero compute, state retained) and wakes on the next request, so FerroGate models
"stop" as hibernate + re-address entirely client-side. `status` is a custom RPC,
not a platform `getStatus`.

**`cancel` is COOPERATIVE, not a fiber cancel.** Cloudflare documents fibers
(`startFiber().cancel` / `abortSubAgent`) as the cancellation primitive, but the
pinned SDK ships none (`grep -ri fiber node_modules/agents/` finds nothing).
`POST /control/cancel` therefore aborts an `AbortSignal` that the agent's
`dispatchWorkload` observes — in-flight work rejects at its next observation
point — and sets a durable latch that refuses any later `invoke`. The response's
`aborted` field says whether in-flight work was actually signalled (`true`) or
only the latch was set (`false`). It **cannot** stop a workload that ignores the
signal or one running outside the Durable Object, so a caller that needs a
guarantee must verify and escalate to `destroy`; #428's `KillMode::Cancel` does
exactly that.

**So a signalled cancel does not report `stopped`.** Signalling is not stopping,
and only the workload knows which happened: when `cancel` aborted something in
flight it sets the latch and leaves the status alone, and the `invoke` path
writes `stopped` once the workload has actually unwound. (A cancel with nothing
in flight writes `stopped` straight away — there is nothing left to wait for.) A
workload that ignores the signal therefore keeps reporting `running`, which is
exactly what makes `KillMode::Cancel`'s verify-then-escalate step do something:
while `cancel` wrote `stopped` unconditionally, the verification read back the
status the cancel had just written and the destroy never fired.

**A cancelled run refuses further work.** `invoke` on a latched run returns
**409 `run_cancelled`** — a refusal envelope, not an `InvokeResult` — so a caller
cannot record it as an execution. A second *concurrent* invoke on the same
instance is refused the same way (409 `invoke_in_flight`): one workload per
instance at a time is what keeps the single abort handle meaningful. See
[`../../docs/cloudflare-agent-gateway.md`](../../docs/cloudflare-agent-gateway.md)
§3a for the full verb→primitive→route mapping.

**`destroy` calls the SDK primitive, alarm and all.** `destroyRun()` signals any
in-flight workload, writes the `cleaned_up` status its envelope reports, and then
calls the SDK's `this.destroy()`, which DROPs the four `cf_agents_*` tables,
calls `ctx.storage.deleteAlarm()`, clears storage and finally aborts the object
with reason `"destroyed"`. Because that abort also tears down the RPC channel the
destroy call arrived on, a *completed* destroy surfaces to the route as a
rejected RPC carrying that reason, which is mapped back onto the `cleaned_up`
envelope. The `deleteAlarm()` is load-bearing rather than decorative: at this
deployment's `compatibility_date = "2025-06-01"`, `ctx.storage.deleteAll()` does
**not** clear the Durable Object's alarm (Cloudflare made it do so only from
compatibility date `2026-02-24`), so a destroy that called `deleteAll()` alone
would leave a #426 schedule's alarm pending — it fires, the Durable Object is
re-instantiated, and a run marked `cleaned_up` wakes up and bills compute. Issue
#482; regression-tested in `test/destroy-alarm.test.ts`.

One measured qualification, because it is the trap a reimplementation falls
into: `deleteAll()` followed by a *same-turn* `ctx.abort()` also leaves no alarm,
and the whole Worker suite stays green under it. That is a commit-timing
artefact — the abort breaks the output gate before the alarm's survival of
`deleteAll()` commits — not a second safe teardown. Insert one macrotask before
the abort and the alarm is back. What `deleteAlarm()` buys is an outcome that
does not depend on that ordering. The four runs are tabulated in
`test/destroy-alarm.test.ts`'s header and in `docs/cloudflare-agent-gateway.md`
§3a.

The Rust side (`crates/ferrogate-runtime/src/cloudflare_gateway_control.rs`)
maps `CloudflareControlSurface` verbs onto exactly these routes.

## Memory routes (issue #427)

`src/memory.ts` adds a governed read/write/query surface over the agent's
per-instance memory layers (synced JSON state, embedded SQLite, chat history),
all POST + bearer-gated, with the instance name in the body:

| Route | Body | Layer |
|-------|------|-------|
| `POST /memory/state/get`   | `{ instance }` | 1 — synced state read |
| `POST /memory/state/set`   | `{ instance, state }` | 1 — validated whole-object replace (422 on violation) |
| `POST /memory/sql/query`   | `{ instance, sql, params? }` | 2 — embedded SQLite (507 `sqlite_full` on SQLITE_FULL) |
| `POST /memory/chat/get`    | `{ instance, limit? }` | 3 — chat history read |
| `POST /memory/chat/prune`  | `{ instance, maxMessages? }` | 3 — eviction to the `MEMORY_MAX_PERSISTED_MESSAGES` cap |
| `POST /memory/semantic/query` | `{ instance, query, topK? }` | Vectorize pilot — **beta, default OFF** (501 while disabled) |

Instance names are minted by the Rust naming scheme
(`fg.{tenant}.{session}.{run}`, see
`crates/ferrogate-runtime/src/cloudflare_agent_memory.rs`), so per-instance DO
isolation is tenant isolation. Full details:
[`../../docs/cloudflare-agent-memory.md`](../../docs/cloudflare-agent-memory.md).

## Schedule routes (issue #426)

`src/schedule.ts` adds a governed surface over the agent's **in-DO SQLite
scheduler** (`this.schedule(...)` → rows in `cf_agents_schedules`, multiplexed
through the DO's single alarm; they survive hibernation). Cloudflare has **no
external enqueue primitive** — scheduling is in-agent only — so these routes
RPC into the named agent. All POST + bearer-gated, instance name in the body:

| Route | Body | Effect |
|-------|------|--------|
| `POST /schedule/create` | `{ instance, task: { taskId, kind, delaySeconds?/at?/cron?/everySeconds?, data? } }` | cancel-before-recreate, then schedule (`once`/`cron`/`interval`); 422 `invalid_task`, 429 `schedule_limit` |
| `POST /schedule/list`   | `{ instance, taskId?, kind? }` | list schedule rows (optionally filtered) |
| `POST /schedule/cancel` | `{ instance, taskId \| scheduleId }` | cancel all rows for a FerroGate task, or one raw SDK row |

Key decisions (see
[`../../docs/cloudflare-agent-scheduling.md`](../../docs/cloudflare-agent-scheduling.md)):

- **Pinned callback** — every schedule fires the agent's `runScheduledTask`
  dispatcher (`SCHEDULE_DISPATCH_METHOD`); callers can never schedule arbitrary
  agent methods. Firings are logged to `fg_schedule_task_runs` (readable via
  `/memory/sql/query` — how a live test proves hibernation survival).
- **Duplicate guard** (github.com/cloudflare/agents #1049) — every create
  cancels existing rows keyed by `taskId` first, so create is idempotent and
  interval rows can never accumulate.
- **`scheduleEvery` is absent from the pinned `agents` 0.0.109** (verified
  against `node_modules`): `interval` tasks are emulated as delayed one-shots
  that re-arm themselves in the dispatcher. The host seam still probes for a
  native `scheduleEvery` so an SDK upgrade is picked up defensively.
- `SCHEDULE_MAX_TASKS_PER_INSTANCE` (wrangler var, default 100) caps concurrent
  schedule rows per instance.

The Rust side (`crates/ferrogate-runtime/src/cloudflare_agent_schedule.rs`,
`AgentScheduleClient`) maps `schedule_create` / `schedule_list` /
`schedule_cancel` onto exactly these routes.

## Container / Sandbox routes (issue #415)

`src/container.ts` adds the **Cloudflare Containers / Sandbox isolation tier** —
"just another sandbox", per-tenant isolated, for agent runs that must execute
arbitrary / untrusted code. Cloudflare exposes **no public container lifecycle
REST API** (`this.ctx.container.start/exec/signal/monitor/destroy`, or the
`@cloudflare/sandbox` `getSandbox(...).exec/runCode/…`, are only reachable from
Worker code), so these routes are the sole tethered path FerroGate drives the
tier through. All POST + bearer-gated, instance name in the body:

| Route | Body | Effect |
|-------|------|--------|
| `POST /container/prepare`   | `{ instance, container: { image, tier, workspacePath? } }` | validate + pin image/tier (create is lazy); 422 `invalid_spec` |
| `POST /container/start`     | `{ instance, entrypoint?, env?, enableInternet?, egressAllowlist? }` | launch; **egress deny-by-default** |
| `POST /container/exec`      | `{ instance, step: { mode: "command"\|"code", command?/language?+source?, timeoutMillis? } }` | run a command or code step, capture stdout/stderr/exit |
| `POST /container/stop`      | `{ instance, signal }` | SIGTERM/SIGKILL |
| `POST /container/logs`      | `{ instance, tail? }` | recent instance logs |
| `POST /container/artifacts` | `{ instance, path? }` | list files under the workspace |
| `POST /container/cleanup`   | `{ instance }` | destroy the instance |

Key decisions (see
[`../../docs/cloudflare-container-isolation.md`](../../docs/cloudflare-container-isolation.md)):

- **Egress deny-by-default** — `enableInternet` starts `false`; a request with
  `enableInternet=true` and an EMPTY `egressAllowlist` is rejected (422). The
  Rust client blocks it client-side too; the Worker re-enforces (defense in
  depth). This mirrors the #117 function-egress broker.
- **Optional binding, fail closed** — the `CONTAINER_SANDBOX` DO binding is
  OPTIONAL (like the semantic-memory pilot's VECTORIZE/AI). Absent it, every
  verb returns `container_unbound` (HTTP 501). The low-level SDK surface is
  declared **structurally** in `container.ts`, so `tsc` needs neither
  `@cloudflare/sandbox` nor `@cloudflare/containers` as a build dependency.
- **Workers Paid only**; instances scale to zero; tiers `lite`→`standard-4`
  (≤ 4 vCPU / 12 GiB). `CONTAINER_MAX_OUTPUT_BYTES` (wrangler var, default
  1 MB) caps captured stdout/stderr.

The Rust side (`crates/ferrogate-runtime/src/cloudflare_container.rs`,
`ContainerControlClient`) maps `prepare` / `start` / `exec` / `stop` /
`collect_logs` / `collect_artifacts` / `cleanup` onto exactly these routes; the
agent-worker `IsolationBackendLifecycle` backend
(`crates/agent-worker/src/cloudflare_container_backend.rs`) drives that client.
The **live sandbox round-trip** (run a code step, capture stdout/exit) needs a
real `CONTAINER_SANDBOX` binding + network and is the test gate's to prove.

## Deploy

```sh
npm ci                            # installs the PINNED agents + wrangler versions
wrangler secret put GATEWAY_CONTROL_TOKEN   # seed the DIY auth secret
wrangler deploy                   # PUT the script + DO migration
```

Teardown: `wrangler delete` (or the Rust pipeline's script DELETE).

FerroGate can also deploy without the Wrangler CLI via the Workers **Script PUT**
API (`PUT /accounts/{account_id}/workers/scripts/{name}`) — see the Rust deploy
pipeline in `crates/ferrogate-runtime/src/cloudflare_gateway_deploy.rs`.

## Pinned versions

- `agents` (Agents SDK) — **pre-1.0**, pinned exactly in `package.json`
  (`0.0.109`). The pre-1.0 API surface (`routeAgentRequest`, `getAgentByName`,
  `Agent`) can change between patch releases, so the pin is exact, not a range.
- `wrangler` — pinned exactly (`4.107.1`). **Do not float this range** (#468); see
  below.
- `@cloudflare/workers-types` — pinned exactly (`4.20260702.1`), the last release
  of the v4 line.
- `@cloudflare/vitest-pool-workers` — pinned exactly (`0.18.1`), the last release
  whose bundled `wrangler` dependency is `4.107.1`.

### Why the Cloudflare toolchain is held on `workers-types` v4 (#468)

`agents@0.0.109` → `partyserver` declares a **hard** peer on
`@cloudflare/workers-types@^4`, and it still does on `partyserver@0.5.8` (latest
at the time of writing) — the whole `partyserver` line is v4-only. `wrangler`
crossed to `@cloudflare/workers-types@^5` in **4.108.0**; `4.107.1` is the last
release whose `peerOptional` is still `^4` (`^4.20260702.1`). Those two ranges
are simultaneously satisfiable only below that boundary, so the tree is pinned
to the v4 side of it:

| package | pin | reason |
| --- | --- | --- |
| `@cloudflare/workers-types` | `4.20260702.1` | last v4 release; satisfies `partyserver`'s `^4.20240729.0` **and** `wrangler@4.107.1`'s `^4.20260702.1` |
| `wrangler` | `4.107.1` | last release with a v4 `peerOptional`; `4.108.0`+ demands v5 |
| `@cloudflare/vitest-pool-workers` | `0.18.1` | pins `wrangler` as a **hard dependency**, so it, not the devDependency, decides which `wrangler` lands in the tree — `0.18.8` pins `wrangler@4.114.0` and reintroduces the v5 peer |

`wrangler` was previously `^4.114.0`, i.e. floating. That float is what made the
lockfile unregenerable: a `^` range silently walked the tree across the v4→v5
`workers-types` boundary and produced an unsatisfiable peer graph. All three
packages are therefore pinned exactly, not ranged.

With these pins `npm ci` installs from a clean checkout with **no
`--legacy-peer-deps`**, and every entry in `package-lock.json` carries
`resolved` + `integrity`.

**Unpinning is a coupled move.** Going to `wrangler@4.108.0`+ /
`@cloudflare/workers-types@^5` requires a `partyserver` (hence `agents`) release
that accepts the v5 peer. None exists yet. Bump all four together or not at all.

## SDK migration caveat (exports vs. legacy `migrations`)

The DO class must be registered so the runtime knows to create it with a
SQLite backend. Two forms exist across wrangler/SDK versions:

1. **`[[migrations]]` array with `new_sqlite_classes`** (used in `wrangler.toml`
   here) — accepted by wrangler 4.x. Use `new_sqlite_classes`, **not**
   `new_classes` (the Agents SDK requires the SQLite storage backend).
2. **Top-level `exports` / newer `[migrations]` mechanism** — some Agents SDK
   templates surface DO classes this way.

**Verify against the pinned `agents` version at deploy time.** If `wrangler
deploy` reports an unknown migration key or "class not exported", switch the
`wrangler.toml` migration block to the form the pinned SDK documents. This is
called out here because the SDK is pre-1.0 and the two forms are not
interchangeable across all versions.

## Not runnable in the FerroGate sandbox

This Worker needs a real Cloudflare account/token and network to deploy and to
prove a live control round-trip. In the offline dev sandbox only
`npm run typecheck` (tsc) can be attempted. `npm ci` needs registry access but no
Cloudflare account, so a clean checkout can reach the typecheck offline-of-CF
(#468). The live deploy + round-trip are the test agent's to prove.
