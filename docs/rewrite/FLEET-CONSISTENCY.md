# FLEET-CONSISTENCY — one capability, five Workers, one answer

**Status: DERIVED FROM `src/` ON 2026-08-01 (wave 21).** Every cell below was
produced by scanning comment-stripped source across all five deployed Workers,
not by reading a design document. The scan is reproduced as an executable gate:
`apps/gateway/test/fleet-consistency.test.ts` (31 assertions, 3 `test.todo`),
mutation-proven eight ways in §7.

---

## 1. The defect class

A capability implemented in **more than one Worker**, where a control applied in
one Worker does not apply in the others. It has shipped **twice**, both times on
security or money, and both times every per-Worker suite stayed green because
every Worker was individually correct.

| # | Wave | The divergence | The exploit |
|---|---|---|---|
| 1 | 16 | Rust's `finalize_auth` (rate limit / monthly budget / wallet / quota) survived in `apps/gateway` and was lost in `apps/mcp` + `apps/agent-runtime` | "Call the other endpoint." A credential exhausted on `/v1/chat/completions` was ADMITTED on `/v1/agent-jobs` and MCP `tools/call`, and both spend real provider money |
| 2 | 20 | `DELETE /admin/v1/agent-upstreams/{id}` withdrew from the gateway's discovery surface; `apps/agent-runtime` resolved its A2A **dispatch** catalog from its own `AGENT_UPSTREAMS` var | An operator who withdraws a COMPROMISED upstream sees it gone from discovery and it stays reachable for dispatch |

**Correctness per Worker does not imply correctness of the fleet.** Nobody had
ever enumerated which capabilities exist in more than one Worker. §3 is that
enumeration.

### 1.1 The shape both defects share

Neither was a missing feature. In both cases the capability was IMPLEMENTED on
every Worker that needed it — and the two implementations **read different
sources of truth**. One was durable and mutated by the admin API; the other was
a deploy-time `[vars]` entry that only `wrangler deploy` can change.

> **A control that is DURABLE on one Worker and VAR-ONLY on another is the exact
> shape of both shipped defects.** That single sentence is the search key this
> whole document was built around, and it found three more instances.

---

## 2. Method

1. **Enumerate.** For each of the five Workers, walk `src/**/*.ts` and record
   the controls it implements: admission (rate limit, budget, wallet, quota),
   authn/authz ladders, tenant fencing, guardrails, upstream/catalog resolution,
   metering, caching, draining, secrets, sessions.
2. **Classify.** Each capability × Worker cell is
   `IMPLEMENTED-DURABLE` / `IMPLEMENTED-VAR-ONLY` / `IMPLEMENTED-IN-MEMORY` /
   `ABSENT` / `N-A`.
3. **Compare.** For every capability present on more than one Worker: *do they
   agree?* Same decision, same status, same code, same **source of truth**?
4. **Sharpen.** For every capability that is a CONTROL — something an operator
   applies to restrict or revoke — ask the harder question: *does applying it in
   one place apply it everywhere it is enforced?*

### 2.1 Why the scan strips comments, and why that mattered

Every probe runs against **comment-stripped** source, and that is load-bearing
rather than tidy. `apps/agent-runtime/src/middleware/auth.ts:445` states in
prose:

> *"The other two gates Rust runs ahead of it were already here: `403
> tenant_scope_denied` (the #515 identity seam) and the lifecycle-suspension
> ladder (`tenancy_suspended`)."*

**It is not there.** That Worker never reads the tenancy lifecycle authority in
any posture a real deployment uses (finding FC-2). A scan that read comments
would have believed the paragraph and reported the fleet consistent. The gate
pins this directly: the raw file contains the phrase, the stripped file does
not, and the probes only ever match quoted refusal codes or SQL fragments —
text that prose does not contain verbatim.

---

## 3. THE MATRIX — capability × Worker

Legend: **D** durable (a store the admin API mutates) · **V** deploy-time var
only · **M** in-memory / dev-table only · **—** absent · **n/a** the Worker has
no such concern.

`telemetry` is deliberately thin here and that is honest: it authenticates one
operator-issued collector token and owns no tenant state, so a control that
restricts a TENANT has nothing to apply to on that Worker.

| # | Capability / control | gateway | control-plane | mcp | agent-runtime | telemetry | Agree? |
|---|---|---|---|---|---|---|---|
| 1 | Credential resolution (`api_keys` / `static_api_keys`) | **D** | **D** | **D** | **D** | n/a | ✅ |
| 2 | 401-vs-403 taxonomy (suspended key ⇒ 401) | **D** | **D** | **D** | **D** | n/a | ✅ |
| 3 | Scope check (`403 scope_denied`) | **D** | **D** | **D** | **D** | n/a | ✅ |
| 4 | Admission: quota scope (`403 quota_scope_disabled`) | **D** | n/a | **D** | **D** | n/a | ✅ |
| 5 | Admission: monthly budget (`429`) | **D** | n/a | **D** | **D** | n/a | ✅ |
| 6 | Admission: prepaid wallet (`429`) | **D** | n/a | **D** | **D** | n/a | ✅ |
| 7 | Admission: RPM window (`429`) | **D** | n/a | **D** | **D** | n/a | ⚠️ **FC-5** |
| 8 | **Tenancy lifecycle / suspension** | **D** | **D** | **—** | **M** | n/a | ❌ **FC-2** |
| 9 | RBAC `rbac_action` | **D** | **D** | parsed, unread | parsed, unread | — | ⚠️ **FC-7** |
| 10 | Tenant fencing on reads/writes | **D** | **D** | **D** | **D** | n/a | ✅ |
| 11 | **Guardrail screening policy** | **D** | **D** (write half) | **V** | **V** | — | ❌ **FC-3** |
| 12 | **Agent-upstream catalog** | **D** | **D** (write half) | n/a | **D** | n/a | ✅ *(FC-4, closed 2026-08-01)* |
| 13 | MCP server catalog | n/a | **D** (write half) | **D** | n/a | n/a | ✅ |
| 14 | **Operator drain** | **V** | **D** (write half) | **—** | **—** | — | ❌ **FC-1** |
| 15 | Operator deny rules (`[[policies]]`) | **V** | — | — | — | — | ⚠️ **FC-6c** |
| 16 | Metering / usage rollup WRITE | **D** | — | — | — | n/a | ✅ (single writer by design) |
| 17 | Monthly-spend rollup READ | **D** | — | **D** | **D** | n/a | ✅ |
| 18 | Response cache | **V** | n/a | n/a | n/a | n/a | ✅ single-Worker |
| 19 | Pre-auth network gate (IP allowlist, unauth flood) | **V** | — | — | — | — | ✅ single-Worker |
| 20 | Secrets resolution (`@ferrogate/secrets`) | ✔ | ✔ | ✔ | — | — | ✅ (see §6.4) |
| 21 | Self-hosted-worker transport identity | **D** | **D** (write half) | n/a | **D** | n/a | ✅ |
| 22 | Session / OAuth state | n/a | **D** (console) | **D** (per-user MCP) | n/a | n/a | ✅ distinct concerns |
| 23 | Provider circuit breaker / shadow budget | **D** | n/a | n/a | n/a | n/a | ✅ single-Worker |

**Five cells diverge. Four are controls an operator applies. Three of those four
are money or security.**

---

## 4. FINDINGS, ranked by blast radius

### FC-1 — THE OPERATOR DRAIN IS APPLIED IN ONE WORKER AND ENFORCED IN ANOTHER

**Blast radius: whole fleet. Money + availability. The API is a no-op.**

*What the operator believes happened.* They call
`POST /admin/v1/drain {"draining": true}` before a migration or during an
incident. The control plane answers
`200 {"object":"drain","draining":true,"reason":…}`. The fleet has stopped
accepting new billable work.

*What actually happens.* `apps/control-plane/src/routes/admin_config_ops.ts::setAdminDrain`
writes the durable `runtime-state/drain` document — and **nothing reads it**
except the control plane's own `GET /admin/v1/drain`, which faithfully echoes
back the state that changed nothing. The gateway's drain is
`apps/gateway/src/routes/readiness.ts::drainStatus`, a synchronous read of the
deploy-time `GATEWAY_DRAIN` var; `apps/gateway/src/routes/drain.ts::nodeDrainGate`
refuses five spend-producing operations off THAT value. `apps/mcp` and
`apps/agent-runtime` have no drain gate on either source, so even a deployment
drained the working way (a `wrangler versions` var flip) keeps admitting MCP
`tools/call` and `/v1/agent-jobs`.

*How a tenant exploits the difference.* They do not need to. The failure is
against the operator: they watch the load balancer take the node out of
rotation, believe the deployment is quiescing, and it is spending the whole
time. During an incident this is the difference between "we stopped the
bleeding" and "we thought we did".

*Why it was invisible.* Three suites, three green. `apps/control-plane` proves
the document is written; `apps/gateway/test/routes/drain.test.ts` proves the var
is honoured on all five operations and flips it both ways inside one isolate.
Neither can see that the two halves are different variables.

*What makes it especially sharp.* `readiness.ts` carries the marker
`PORT-TODO(L: inventory-request-path §readiness)`, which says the proper fix is
*"a `DRAIN` DO/KV binding plus the operator route that writes it, which is a
control-plane slice, not a routing one."* **That control-plane slice has since
been written.** Both halves now exist. They were never joined.

*The fix.* `drainStatus` reads the durable `runtime-state/drain` document from
`CONTROL_DB` with the var as the fallback — byte for byte the precedence
`apps/gateway/src/routes/agent-upstreams.ts` already establishes for the
upstream registry (durable when a control database is bound, var otherwise,
fail-closed on a read error and specifically NOT back to the var). Then
`apps/mcp` and `apps/agent-runtime` refuse their spend-producing operations with
the identical `503 node_draining` and the identical message text.

*Gate.* `describe("FC-1 …")` — 4 assertions + 1 `test.todo`. RED when a Worker
joins drain state to drain enforcement (M1), and RED when a Worker grows a drain
refusal without being classified (M8).

---

### FC-2 — TENANT SUSPENSION DOES NOT REACH TWO OF THE THREE WORKERS THAT SPEND

**Blast radius: every suspended tenant. Security + money. This is the wave-16
admission bypass wearing a different control.**

*What the operator believes happened.* A tenant is compromised, delinquent, or
abusive. They suspend it in the control plane. Its credentials stop working.

*What actually happens.*

| Worker | Behaviour |
|---|---|
| `apps/gateway` | `403 tenancy_suspended`, resolved from `tenants.status` on the control database, **including suspended ancestors** in the tenant → project → workspace chain, and `503 lifecycle_status_unavailable` rather than an admission if the lookup fails (`middleware/auth.ts:269`, `adapters.ts:603`) |
| `apps/control-plane` | `403 tenancy_suspended` from its own durable lifecycle store |
| `apps/agent-runtime` | **Can NAME the refusal and cannot produce it.** `middleware/auth.ts:114` renders `tenancy_suspended` — but the only port that returns that outcome is `inMemoryApiKeyPort` (`ports.ts:598`, reading the `FG_DEV_API_KEYS` var). `d1ApiKeyPort` (`durable/adapters.ts`), the port every real deployment uses, returns exactly `unknown` / `key_suspended` / `resolved` / `unavailable` and **never** `tenancy_suspended` |
| `apps/mcp` | **No lifecycle check in any posture.** `src/auth.ts` documents its whole 401-vs-403 taxonomy and tenancy suspension is not a row in it |

*How a tenant exploits the difference.* Identically to wave 16: **call the other
endpoint.** The suspended tenant's key is not revoked, only its tenancy is — so
the credential still resolves. `/v1/chat/completions` is 403. MCP `tools/call`
and `POST /v1/agent-jobs` admit it, run the admission ladder against quota and
wallet that were never zeroed, and spend.

*Why it was invisible.* Because `apps/agent-runtime` has a passing suspension
test — driven through the dev in-memory table. The durable path it actually
deploys with was never exercised for this outcome. That is the
`lifecycle-tenancy-scenario-neverrun` failure mode this project has been bitten
by before, one Worker over.

*The fix.* Both Workers consult the same authority the gateway does —
`tenants.status` on the control database, ancestors included — **before** the
admission ladder. Ordering is not cosmetic: `finalize_auth` runs the lifecycle
gate ahead of quota/wallet resolution precisely so a suspended tenant never
reaches the step that authorizes spend. A lookup failure is `503`, never an
admission: fail-open here makes "flap the control plane" a suspension bypass.

*Gate.* `describe("FC-2 …")` — 4 assertions + 1 `test.todo`, including the
computed exploit set `["mcp","agent-runtime"]`. RED when the gateway stops
reading the authority (M2) and RED when another Worker starts (M2 inverse).

---

### FC-3 — AN ACTIVATED GUARDRAIL POLICY BINDS ONE WORKER AND NO OTHER

**Blast radius: every tenant. Data exfiltration / prompt injection.**

*What the operator believes happened.* They author a guardrail policy revision
and call `POST /admin/v1/guardrail-policies/{policy_id}/activate`. Screening is
live.

*What actually happens.* Only `apps/gateway` merges the durable
`guardrail_policy_revisions` + `guardrail_policy_bindings` rows into its
detector source (`src/guardrails/d1.ts` + `config.ts::guardrailPolicySourceFromEnv`).
The other two screening surfaces read a **deploy-time var**:

* `apps/mcp` screens MCP tool arguments and tool results from
  `FG_DEV_MCP_GUARDRAILS`, committed as `""` in `wrangler.toml` — which parses
  to `{}`, which matches nothing, which allows everything;
* `apps/agent-runtime` screens A2A messages from `FG_DEV_A2A_GUARDRAILS`, not
  committed at all.

Both files say so themselves. `apps/mcp/src/ports.ts:1704` is explicit: *"the
real enforcement policy is tenant-scoped control-plane state and this var is
DEV/TEST ONLY."* The honesty is not the problem; the gap is.

*How a tenant exploits the difference.* Move the payload to a surface the policy
does not reach. A secret pattern or keyword the gateway blocks in a chat
completion travels intact inside an MCP `tools/call` argument, inside a tool
RESULT flowing back, or inside an A2A `message:send` body. The activated
revision never sees it.

*The fix.* Both Workers resolve their detector policy from the same
`guardrail_policy_revisions` + `guardrail_policy_bindings` rows the gateway
merges, keeping the var as the no-control-database fallback — the same
precedence FC-1 and FC-4 use. The snapshot can be memoized per isolate exactly
as `guardrails/config.ts` already does.

*Gate.* `describe("FC-3 …")` — 3 assertions + 1 `test.todo`, including the
disjointness of the durable set and the var set. RED when the gateway drops the
durable read (M3).

---

### FC-4 — AGENT-UPSTREAM WITHDRAWAL, BOTH DOORS **— CLOSED 2026-08-01**

This is shipped defect #2 and the wave-20 integrate step reported it half
closed. **It was closed during this audit** by the concurrent slice that landed
`apps/agent-runtime/src/agents/registry.ts` and rewired `resolveDeps` from
`inMemoryAgentUpstreamPort` to `agentUpstreamPortFromEnv`. Both reach paths —
gateway DISCOVERY (`GET /.well-known/agent.json`) and agent-runtime DISPATCH
(`POST /v1/agents/{name}`, the `message:*` verbs) — now read the same
`control_plane_resources` rows of kind `agent-upstreams`, with the var surviving
only as the no-control-database fallback on both.

The row is kept because the gate is now a **forward** gate rather than a record
of a divergence: it asserts both Workers name the same collection constant and
the same table, and that `resolveDeps` MOUNTS the durable port rather than
merely containing a module that could. A registry module that exists and is not
wired is this repo's dominant defect; the mount assertion is what distinguishes
the two.

*Gate.* `describe("FC-4 …")` — 4 assertions. RED when either Worker re-derives
the collection constant (M4).

**Plus, added by the wave-21 INTEGRATE step, the one gate this section was still
missing: the EFFECT, on both doors, in a single assertion path.**
`apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` (5
assertions) stores a row, requires BOTH reach paths to hold it, issues ONE
`DELETE`, and requires BOTH to have lost it — inside one `it()`. Discovery is
driven behaviourally over `SELF` into the deployed gateway; dispatch calls
`d1AgentUpstreamPort` — `apps/agent-runtime`'s REAL production lookup, imported
as a leaf (that module has exactly one import and it is `import type`, which the
gate itself asserts off the source text) — against the same `CONTROL_DB` handle.

The reason it earns its place next to two already-green per-Worker suites is
what it does under mutation. Giving `d1AgentUpstreamPort` a process-lifetime
memo — the regression its own docblock warns about, "no cache, deliberately" —
leaves **`apps/gateway/test/routes/agent-upstream-withdrawal.test.ts` at 14/14
GREEN** and takes this file to **2 RED**, on the line

> `still DISPATCHABLE after withdrawal: expected 'https://attacker.example/a2a'
> to be undefined`

which is shipped defect #2 reproduced verbatim: one door shut, one door open,
the per-Worker suite blind. (The agent-runtime durable spec catches that
particular mutation too — 5 RED — but it cannot catch a regression on the
gateway's door, and the gateway's suite cannot catch one on agent-runtime's.
Only a test that holds both can fail for "the withdrawal was partial".)

---

### FC-5 — THE SHARED RPM COUNTER IS A DEPLOY-TIME UNCOMMENT IN TWO FILES

**Blast radius: every rate-limited credential. A 3× quota bypass, silent.**
**Not a live defect — a live trap. Gate is GREEN and stays that way.**

`RateLimiterDurableObject` is DEFINED by `apps/gateway` and BORROWED by
`apps/mcp` and `apps/agent-runtime` through `script_name = "ferrogate-gateway"`,
so `idFromName("key:<id>")` addresses the same instance from all three and a
credential at 60 rpm is charged ONE window across `/v1/chat/completions`,
`tools/call` and `/v1/agent-jobs`. That sharing IS the wave-16 fix.

Neither borrower can commit its stanza live: workerd refuses to start on a
cross-script DO binding under `wrangler dev --local` and
`@cloudflare/vitest-pool-workers` (`binding "RATE_LIMIT" refers to a service
"core:user:ferrogate-gateway", but no such service is defined`), so both stanzas
are written out and commented for deploy time, and `counterFromEnv` /
`limiterForEnv` degrade to a per-isolate `InMemoryRequestCounter` locally. Four
of five admission legs stay durable while it is commented.

The danger is what that leaves lying around for the next person who meets the
boot error: **define a private `RateLimiterDurableObject` in the app that
fails.** It compiles, it deploys, every suite passes — and it hands that Worker
its own full RPM quota. The wave-16 bypass, restored quietly, with a green
board. The `wrangler.toml` comment names this outcome; nothing enforced it.

*Gate.* `describe("FC-5 …")` — 5 assertions. RED when a borrower declares the
class in its live config or in a migration (M5b, 2 RED) and RED when the
deploy-time stanza loses `script_name` (M5a). This is the highest-value gate in
the file precisely because there is nothing wrong today.

---

### FC-6 — CONTROLS THAT ARE LEGITIMATELY SINGLE-WORKER

Manufacturing a consistency requirement between Workers that never shared a
concern is noise, and noise trains readers to skip the file. These are recorded
as single-Worker BY DESIGN, with the reason, and pinned so that the day a second
Worker grows one the divergence question gets **asked** — which is the step that
was skipped both times a bypass shipped.

* **FC-6a — pre-auth network gate** (`GATEWAY_IP_ALLOWLIST`, trusted-proxy hops,
  unauthenticated flood limit). The gateway is the only public ingress; the
  other four are reached through it or through an operator credential.
* **FC-6b — response cache.** Nothing else in the fleet serves a cacheable
  body.
* **FC-6c — operator deny rules (`[[policies]]`) — with a caveat, and the caveat
  is an OPEN QUESTION, not a finding.** Rust evaluated
  `policy_engine.evaluate(request, model, provider)` from `chat.rs` only, so a
  MODEL/PROVIDER-scoped deny rule being inference-only is **parity, not drift**.
  But `expandPolicyRule` treats an empty `models`/`providers` list as a
  WILDCARD, so

  ```toml
  [[policies]]
  organization_ids = ["tenant_x"]
  effect = "deny"
  ```

  reads to an operator as *"deny tenant_x everything"* and stops nothing on MCP
  `tools/call` or A2A dispatch. Rust had the same shape, so this is a
  **product** question (should a subject-only deny be fleet-wide?) rather than a
  port regression. Recorded here so it is decided rather than inherited.
* **FC-6d — provider circuit breaker and shadow budget.** Only the gateway
  dispatches to providers.
* **FC-6e — metering WRITE.** `usage_monthly_rollups` has exactly one writer
  (the gateway, through `@ferrogate/storage`) and three readers (all three
  admission ladders). A single writer is the correct design for a rollup and is
  recorded so a second one is a deliberate decision rather than an accident;
  spend originating in agent runs reaches the ledger because those runs dispatch
  inference **through** the gateway.

---

### FC-7 — `rbac_action` IS CARRIED BY FOUR WORKERS AND CONSULTED BY TWO

**Blast radius: zero today. Pre-armed for tomorrow.**

`apps/mcp/src/contract.ts:253` and `apps/agent-runtime/src/contract.ts:328` both
parse `rbac_action` off the shared contract table into their `ApiOperation` and
**never read it again**. Only `apps/gateway` and `apps/control-plane` call an
authorizer.

That is harmless today and only today: all 12 operations in
`docs/openapi/runtime-api-contract.json` carrying an `rbac_action` are
`/admin/v1/guardrail-*` or `/admin/v1/investigations` paths, which those two
Workers do not serve. The day one lands on a data-plane path it is silently
unenforced on two of five Workers — both shipped defects' shape, pre-armed and
waiting.

*Gate.* `describe("FC-7 …")` — 4 assertions, including "every rbac-guarded
operation is on an `/admin/v1/` path". RED the moment an `rbac_action` appears
on a data-plane operation (M6).

---

## 5. The ledger is a RATCHET, deliberately

The tables the gate asserts are the **measured** state of the fleet, not the
desired one. That means `fleet-consistency.test.ts` goes RED in **both**
directions:

* a **new** divergence — a control that stops being enforced on one Worker, or a
  Worker that starts resolving a shared control from a private source — is RED.
  This is the property both shipped defects needed and neither had;
* a divergence being **closed** is *also* RED, which forces this document and
  the gate's tables to be updated in the same commit as the fix.

The second half is the point. A finding without a gate rots back within two
waves. A gate whose ledger can drift away from the code rots the same way, one
level up — it keeps asserting a fleet that no longer exists, and reads as
coverage. FC-4 is the proof the ratchet works: it was an open divergence when
this audit started and a closed one four hours later, and the gate caught the
transition rather than sleeping through it.

---

## 6. Honest scope notes

**6.1 This is a source-text gate, and that is forced, not chosen.** The five
Workers are separately bundled and no app may import another's module graph —
that coupling is what `wrangler deploy` would reject and what the repo's package
boundaries forbid. Reading the other Workers as TEXT through `?raw` is the only
way a workerd test with no filesystem can see them at all. It is the same
technique `admission-consistency.test.ts` and `env-var-drift.test.ts` already
use.

**6.2 It does not replace a behavioural suite and does not try to.** Each
Worker's own refusals are still driven over `SELF` by its own tests. This file
asserts the one property none of those can see, because each of them is looking
at one Worker.

**6.3 Non-vacuity is asserted before anything else.** Several recorded tables
are `[]`, so a glob that silently resolved to nothing would let the whole file
pass while reading no code. Two guards run first: every Worker must contribute
modules, and a **canary token** must still be found on every Worker after
comment stripping. Mutation M7 (making `stripComments` eat string literals)
turns the canary RED **first**, ahead of the eight probe failures it also
causes — so a stripper regression can never present as "the fleet is
consistent."

**6.4 One cell is a genuine unknown, recorded as such.** `apps/agent-runtime` is
the only credential Worker with no `@ferrogate/secrets` consumer. Its
worker-plane transport secret arrives through the control database rather than
a secrets resolver, which is defensible and is not obviously wrong — but it was
not traced end to end in this pass and is not gated. Row 20 of §3 says `—`
rather than claiming a verdict.

**6.5 The three `test.todo`s are deliberate and are the FC-1/FC-2/FC-3 fixes.**
Each carries the exact change and the exact assertion that replaces it, so the
open findings stay visible in every run rather than living only here. This is
the pattern MOUNT-SEAMS §3.2 established when a delivering agent cannot write a
green assertion for a defect it is not allowed to fix.

---

## 7. Mutation proof

Every gate was proven by breaking the thing it watches, confirming the edit
landed by grepping the file back **off disk**, running the file, requiring RED,
restoring, and requiring GREEN. All eight mutations changed BEHAVIOUR — no
semantic no-ops, no parse errors, no chained harness building its own Worker.

Baseline, before any mutation: **31 passed | 3 todo (34)**.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M1** | `apps/gateway/src/routes/drain.ts` gains a `"runtime-state"` reference — the FC-1 fix arriving | `72:const MUTATION_DRAIN_COLLECTION = "runtime-state";` | **2 RED** — *only the control plane owns the drain DOCUMENT*; *no Worker joins the two, which is the defect* |
| **M2** | `LIFECYCLE_TENANT_SQL` drops the `status` column — the gateway stops reading the suspension authority | `603:… "SELECT id FROM tenants WHERE id = ?1"` | **2 RED** — *only the gateway reads the DURABLE lifecycle authority*; *names the spend Workers a suspension cannot stop* |
| **M3** | `apps/gateway/src/guardrails/d1.ts` renames both durable tables (11 occurrences) | 7 × `mutated_policy_bindings`, 0 × original | **1 RED** — *only gateway and control-plane touch the durable policy tables* |
| **M4** | `apps/agent-runtime` re-derives the collection constant as `"a2a-upstreams"` | `127:export const AGENT_UPSTREAM_COLLECTION = "a2a-upstreams";` | **1 RED** — *they name the SAME collection and the SAME table* |
| **M5a** | The commented deploy stanza in `apps/agent-runtime/wrangler.toml` loses `script_name` | 0 × `script_name = "ferrogate-gateway"` | **1 RED** — *both borrowers keep the deploy-time stanza, pointed at the gateway script* |
| **M5b** | `apps/agent-runtime` DEFINES the limiter class: `new_sqlite_classes = ["AgentRunState", "WorkerPlane", "RateLimiterDurableObject"]` | `58:new_sqlite_classes = […, "RateLimiterDurableObject"]` | **2 RED** — *only apps/gateway DEFINES the limiter class*; *neither borrower declares the class in its LIVE config* |
| **M6** | `rbac_action: "inference.chat.create"` added to `/v1/chat/completions` in the contract | 1 × `"inference.chat.create"` | **1 RED** — *every rbac-guarded operation is on an admin path the two enforcers serve* (`expected [ '/v1/chat/completions' ] to deeply equal []`) |
| **M7** | `stripComments` regresses to eating string literals (the VACUITY probe) | `.replace(/"[^"]*"/g, '""')` present | **9 RED**, canary FIRST — *still finds a known token on every Worker after comment stripping* |
| **M8** | `apps/mcp` grows a `"node_draining"` refusal — the other half of the FC-1 fix | `const MUTATION_DRAIN_CODE = "node_draining";` | **2 RED** — *only the gateway can refuse with node_draining*; *two of the three spend Workers have no drain gate at all* |

Restored after each: **31 passed | 3 todo (34)**. `git status` clean of every
mutation.

### 7.1 Two more, run by the wave-21 INTEGRATE step against FC-4's fix

The integrate step does not take a delivering agent's mutation table on trust,
and these two are the ones that matter for a SECURITY fix:

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M9** | `apps/agent-runtime/src/ports.ts` drops the durable mount and keeps only the var fallback — the pre-wave-21 posture, i.e. the fix removed | `1224: upstreams: /*MUT-A3L2*/ ((_e: unknown, p: AgentUpstreamPort) => p)(`, and `grep -c 'agentUpstreamPortFromEnv('` → **0** | **10 RED of 13** in `test/durable/agent-upstream-withdrawal.spec.ts` — including a `422` that names `durable-and-var.upstream.invalid` AFTER the delete, the resurrection stated exactly. **The app's own default project stayed 434/434 GREEN**, which is why the seam is ESC |
| **M10** | `d1AgentUpstreamPort` gains a process-lifetime memo — the regression its docblock names | `287: const memo = MUT_FLEET_MEMO.get(agentId);` | **2 RED** in `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` (*still DISPATCHABLE after withdrawal*) while the gateway's own withdrawal suite stayed **14/14 GREEN** — the fleet property, isolated |

Both restored; the named files re-run GREEN (13/13 and 5/5) and `git diff` is
clean of both markers.

---

## 8. What the next wave should do with this

1. **FC-1 first.** It is the only finding where the operator's action is a
   complete no-op, and it is the cheapest: `drainStatus` gains a durable read
   with the var as fallback, following the precedence `agent-upstreams.ts`
   already proves. The two other spend Workers then honour the same answer.
2. **FC-2 next.** Highest security value. It is the wave-16 bypass in a second
   control, and the fix is mechanical: the lifecycle gate the gateway already
   has, ahead of the admission ladder both other Workers already have.
3. **FC-3 after that.** Larger, because the detector snapshot has to be
   projected per isolate on two more Workers, but the design is settled — the
   gateway's `loadGuardrailPolicyStore` is the template.
4. **FC-6c is a product decision, not an engineering task.** Route it to
   whoever owns the deny-rule semantics before someone "fixes" it into a
   fleet-wide deny and changes behaviour Rust never had.
5. **Never delete FC-5.** It guards a thing that is not broken, which is exactly
   why it will look deletable.
