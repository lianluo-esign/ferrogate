# Cloudflare Agent Scheduling & Durable-Dispatch Bridge (issue #426)

FerroGate drives a Cloudflare agent's scheduling as a **governed FerroGate
operation**. Cloudflare exposes **no external enqueue endpoint** — scheduling
is in-agent only (`this.schedule(...)` inside the Durable Object) — so every
schedule create/list/cancel goes through the authenticated `/schedule/*`
routes of the agent-gateway Worker (issue #413), never as a direct call into
the agent (the *tethered principle*).

Code map:

- Worker routes + verbs + dispatcher: `workers/agent-gateway/src/schedule.ts`
  (dispatched from `src/index.ts`; shared bearer auth in `src/auth.ts`)
- Rust client: `crates/ferrogate-runtime/src/cloudflare_agent_schedule.rs`
  (`AgentScheduleClient`; reuses the #427 `AgentInstanceIdentity` naming
  scheme and the #413/#414 `GatewayControlTransport` seam)

## Verified platform facts (pinned Agents SDK `agents@0.0.109`)

Checked directly against the pinned package dist in
`workers/agent-gateway/node_modules` — the SDK is pre-1.0, so these are the
facts for THIS pin, not the current docs:

| Fact | 0.0.109 reality |
|---|---|
| `this.schedule(when, callback, payload)` | **Three arguments — no `opts` parameter.** `when` = number (seconds delay → row type `delayed`) \| `Date` (one-shot → `scheduled`) \| cron string (minute precision, auto-rescheduled by the alarm handler → `cron`). `callback` must be an existing method NAME on the agent class (the SDK throws otherwise). Payload is `JSON.stringify`ed into the row — the 2 MB DO SQLite value limit applies. |
| `scheduleEvery()` | **Does not exist in this pin** (zero occurrences in the package dist). Sub-minute intervals are therefore *emulated* (below). The Worker probes for a native `scheduleEvery` at runtime so an SDK upgrade is picked up defensively. |
| Management | `getSchedule(id)` (async), `getSchedules(criteria)` (**synchronous** in this pin), `cancelSchedule(id)` (async — returns `true` even for a missing id, so the Worker checks existence first to report real cancel counts). There is no `getScheduleById`/`listSchedules` spelling in this pin. |
| Persistence | Rows in `cf_agents_schedules` (`id, callback, payload, type, time, delayInSeconds, cron, created_at`), multiplexed through the DO's **single alarm** (`_scheduleNextAlarm`). Rows **survive hibernation/restart**; the constructor runs the alarm handler on wake, so schedules need **no re-establishment in `onStart`**. |
| Duplicate bug | github.com/cloudflare/agents issue #1049: repeated `scheduleEvery()` calls create duplicate interval rows. Guarded here by **cancel-before-recreate** (below) on *every* create, so the guard holds on this pin's emulation and on any future native path. |
| Intra-agent queue | The pin also ships `queue()/dequeue()/getQueue()` over a `cf_agents_queues` table — an *immediate* intra-agent work queue, not a timer. Out of scope for #426; noted for the matrix below. |

## Route surface

All POST + bearer-gated (`GATEWAY_CONTROL_TOKEN`, same constant-time check as
`/control/*` and `/memory/*`); the body carries the instance name minted by
the Rust naming scheme (`fg.{tenant}.{session}.{run}` — per-instance DO
isolation is tenant isolation; the Worker never derives names itself):

| Route | Body | Rust verb |
|---|---|---|
| `POST /schedule/create` | `{ instance, task: { taskId, kind, delaySeconds?/at?/cron?/everySeconds?, data? } }` | `schedule_create` |
| `POST /schedule/list`   | `{ instance, taskId?, kind? }` | `schedule_list` |
| `POST /schedule/cancel` | `{ instance, taskId \| scheduleId }` | `schedule_cancel` |

Task kinds: `once` (exactly one of `delaySeconds` / ISO-8601 `at`), `cron`
(SDK cron expression, minute precision), `interval` (`everySeconds >= 1`).
Error vocabulary → HTTP: `invalid_task` → 422 (validation aborts, nothing is
scheduled), `schedule_limit` → 429 (per-instance row cap,
`SCHEDULE_MAX_TASKS_PER_INSTANCE`, default 100), `schedule_error` → 400.

### Governance decisions

1. **Pinned callback.** Every schedule fires ONE agent method —
   `runScheduledTask` (`SCHEDULE_DISPATCH_METHOD`). Callers can never name an
   arbitrary agent method; otherwise a schedule could invoke `destroyRun`,
   `cancel`, or any RPC verb with an attacker-chosen payload. The FerroGate
   `taskId`/`kind`/`data` ride in a payload envelope the dispatcher unpacks.
2. **Cancel-before-recreate (the #1049 duplicate guard).** Every create first
   cancels all existing rows keyed by the task's `taskId`, then creates the
   replacement and reports `replaced`. Create is therefore idempotent for all
   kinds — re-issuing a schedule (e.g. after a FerroGate restart) can never
   accumulate duplicate interval rows.
3. **Interval emulation.** Because the pin has no `scheduleEvery`, `interval`
   tasks are created as a delayed one-shot whose dispatcher re-arms itself
   (`emulated: true` in the envelope). The SDK deletes a delayed row after it
   fires, so the re-arm creates exactly one successor; the re-arm ALSO runs
   the cancel-before-recreate guard defensively. Tick spacing is
   `everySeconds` from *dispatch completion* (slight drift, no overlap) —
   acceptable for heartbeat/refresh workloads; drift-free sub-minute fan-out
   belongs to the Queues tier below.
4. **Observable firings.** The dispatcher logs every execution into the
   instance's embedded SQLite (`fg_schedule_task_runs (task_id, kind,
   fired_at)`), readable through `/memory/sql/query` (#427). That is how a
   live test proves firings continued across a forced hibernation without any
   extra plumbing.

## Decision matrix: which durability tier for which workload

FerroGate's default is the **in-DO SQLite scheduler** — it is the only tier
that exists today end-to-end. The other tiers are documented targets with
proposed follow-up issues; #426 deliberately implements NO Queues/Workflows
consumers.

| Tier | Primitive | Durability & delivery | Sweet spot | Limits / cautions | FerroGate status |
|---|---|---|---|---|---|
| **SQLite scheduler** (default) | `this.schedule` rows + single DO alarm | Survives hibernation/restart; at-most-once per firing (no retry if the callback throws — the SDK logs and moves on) | Per-agent timed work: one-shots, minute-cron, self-re-arming intervals; anything that must wake THIS agent | Minute precision for cron; 2 MB payload; all firings serialize through one DO (single-writer); callback errors are swallowed by the SDK | **Implemented** (#426, `/schedule/*`) |
| **Queues** | Cloudflare Queues producer/consumer bindings | At-least-once delivery, batching, retries + DLQ | Cross-agent fan-out, high-volume async dispatch, work that must not be lost if one DO is busy/slow | Consumers are Worker-level (not per-agent) — a consumer must re-address the target agent by name; no timed delivery (pair with the scheduler for "at time T, enqueue") | **Future** (follow-up A below) |
| **Workflows** | Cloudflare Workflows (durable execution) | Durable multi-step runs: each step checkpointed, retried, resumable over days | Long multi-step jobs spanning agents/services, human-in-the-loop pauses, compensation logic | Separate deploy artifact + billing; step granularity is coarse; overkill for a simple timer | **Future** (follow-up B) |
| **Fibers** | Agent fiber handles (`startFiber` / cancel — the #414 cancel primitive) | In-memory, in-run concurrency; NOT durable — dies with the run/eviction | Parallel sub-work *inside* one live invocation, and cancellation of in-flight work | Never for future/cross-agent work; anything that must survive hibernation belongs in a tier above | **Cancel path wired** (#414 `/control/cancel`); fiber-parallel dispatch is the harness's concern |
| *(intra-agent queue)* | SDK `queue()` (`cf_agents_queues`) | Persisted FIFO, drained immediately by the same DO | "Run this next, in order" within one agent | No timing control; same single-writer bound | Not exposed; revisit if a consumer appears |

Chosen defaults: **scheduler for time, Queues for volume, Workflows for
sagas, fibers for in-run parallelism.** Concretely: if the work targets one
agent at a known time → SQLite scheduler. If it fans out or must survive a
busy/broken consumer → Queues. If it is a multi-step process with retries and
waits → Workflows. If it is concurrency inside a live run → fibers.

## Proposed follow-up issues (not implemented here)

- **A. Queues bridge** — `wrangler.toml` queue producer binding + a gateway
  consumer that re-addresses agents by instance name; Rust `queue_dispatch`
  verb; DLQ + retry policy mapped onto FerroGate's error vocabulary. Pairs
  with the scheduler for timed enqueue ("at T, push to queue Q").
- **B. Workflows bridge** — a FerroGate-owned Workflow class for cross-agent
  sagas (step = one governed gateway call), plus `/workflow/start|status`
  routes and a Rust client.
- **C. Native `scheduleEvery` adoption** — when the pinned SDK is upgraded to
  a version that ships `scheduleEvery`, drop the emulation (`emulated` flag),
  re-verify the #1049 dedup behavior live, and keep the cancel-before-recreate
  guard regardless.
- **D. Schedule reconciliation** — a FerroGate-side sweep that lists each
  live instance's schedules and prunes orphans for completed/destroyed runs
  (today `destroyRun`'s `deleteAll` clears them with the instance).

## What is proven where

Locally provable (and proven — see the #426 test evidence):

- Verb → route → body mapping, bearer auth, error mapping: Rust unit tests
  against a scripted transport (`cloudflare_agent_schedule_test.rs`, no
  network), Worker `tsc --noEmit`.
- Spec validation (task ids, kinds, interval/cron shapes) rejecting BEFORE
  any HTTP.
- The cancel-before-recreate contract (`replaced` reporting) at the wire
  level.

Live-Cloudflare-only (the test agent's to prove):

- Real DO alarm firing at the scheduled time; cron auto-reschedule.
- Schedule rows + firings surviving a **forced hibernation** (create →
  idle past hibernation → verify `fg_schedule_task_runs` grew via
  `/memory/sql/query`).
- Interval emulation re-arm cadence on a live DO, and the #1049 duplicate
  behavior under a real (future) `scheduleEvery`.
