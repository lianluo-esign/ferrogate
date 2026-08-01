# FLEET-CONSISTENCY — one capability, five Workers, one answer

**Status: DERIVED FROM `src/` ON 2026-08-01 (wave 21), MECHANISED AND FULLY
CLOSED IN WAVE 22.** All five divergences the matrix found (FC-1 · FC-2 · FC-3 ·
FC-4 · FC-5) are closed; FC-5 was never a live defect and its gate stays. Both
gate files are green with no `test.todo` — see §9.7.
Every cell below was produced by scanning comment-stripped source across all
deployed Workers, not by reading a design document. Two executable gates hold it:

* `apps/gateway/test/fleet-consistency.test.ts` — the **LEDGER**. Records each
  finding as an exact table of Workers, fails in both directions, mutation-proven
  eight ways in §7. Right shape for a finding.
* `apps/gateway/test/fleet-control-matrix.test.ts` — the **MECHANICAL GATE**
  (wave 22, §9). Names no Worker anywhere: the fleet, the role sets, every
  control's source-of-truth class and the whole refusal table are COMPUTED, and
  the assertions are properties over those computations. Right shape for the
  CLASS — it re-derives itself when a Worker or a control is added, which is
  precisely when a hand list stops being true and does not stop being green.

Read the **Gate** column of §3 to see which cells each one holds, and §9.4 for
the ten that neither holds mechanically — those are the cells that rot first.

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

The **Gate** column is the wave-22 addition and is the column to read first.
`MECH` means the cell is derived and asserted MECHANICALLY by
`apps/gateway/test/fleet-control-matrix.test.ts` — no Worker is named in that
file, so the cell re-derives itself when a Worker is added, when a control moves
its source of truth, or when a refusal changes status or wording. `LEDGER` means
the cell is held only by `apps/gateway/test/fleet-consistency.test.ts`, whose
tables are hand-written lists of Workers. `INSPECTION` means nothing but this
document holds it.

> **The `LEDGER` and `INSPECTION` cells are the ones that will rot first, and
> they will rot silently.** A hand list stays green while the fleet changes
> underneath it; it only fails when someone edits the thing it happens to name.
> §9.4 lists them in one place so the next wave can convert them rather than
> rediscover them.

| # | Capability / control | gateway | control-plane | mcp | agent-runtime | telemetry | Agree? | Gate |
|---|---|---|---|---|---|---|---|---|
| 1 | Credential resolution (`api_keys` / `static_api_keys`) | **D** | **D** | **D** | **D** | n/a | ✅ | MECH §4.1 (wire answer); `api_keys` declared a non-control in §4.3 |
| 2 | 401-vs-403 taxonomy (suspended key ⇒ 401) | **D** | **D** | **D** | **D** | n/a | ✅ | MECH §4.1 — `invalid_api_key` / `api_key_disabled` / `api_key_expired` must carry one status fleet-wide |
| 3 | Scope check (`403 scope_denied`) | **D** | **D** | **D** | **D** | n/a | ✅ | MECH §4.1 |
| 4 | Admission: quota scope (`403 quota_scope_disabled`) | **D** | n/a | **D** | **D** | n/a | ✅ | MECH §3 `admission` (all five properties) + §4.2 wording |
| 5 | Admission: monthly budget (`429`) | **D** | n/a | **D** | **D** | n/a | ✅ | MECH §4.2 — emitters must equal the computed SPEND set |
| 6 | Admission: prepaid wallet (`429`) | **D** | n/a | **D** | **D** | n/a | ✅ | MECH §4.2 |
| 7 | Admission: RPM window (`429`) | **D** | n/a | **D** | **D** | n/a | ⚠️ **FC-5** | MECH §3 `rpm-counter` + §3.6 (one definer, borrowers pinned to `script_name`) |
| 8 | **Tenancy lifecycle / suspension** | **D** | **D** | **D** | **D** | n/a | ✅ *(FC-2, closed 2026-08-01)* | MECH §3 `tenant-lifecycle` — the authority is the `status` COLUMN, not the `tenants` table |
| 9 | RBAC `rbac_action` | **D** | **D** | parsed, unread | parsed, unread | — | ⚠️ **FC-7** | LEDGER (hand-listed) |
| 10 | Tenant fencing on reads/writes | **D** | **D** | **D** | **D** | n/a | ✅ | INSPECTION |
| 11 | **Guardrail screening policy** | **D** | **D** (write half) | **D** | **D** | — | ✅ *(FC-3, closed 2026-08-01)* | MECH §3 `guardrail-binding` |
| 12 | **Agent-upstream catalog** | **D** | **D** (write half) | n/a | **D** | n/a | ✅ *(FC-4, closed 2026-08-01)* | MECH §3 `agent-upstream-catalog` + behavioural `routes/agent-upstream-fleet-withdrawal.test.ts` |
| 13 | MCP server catalog | n/a | **D** (write half) | **D** | n/a | n/a | ✅ | INSPECTION (single reader today) |
| 14 | **Operator drain** | **D** (+ V override) | **D** (write + read) | **D** | **D** | — | ✅ *(FC-1, all three legs closed 2026-08-01)* | MECH §3 `drain` + §5 behavioural |
| 15 | Operator deny rules (`[[policies]]`) | **V** | — | — | — | — | ⚠️ **FC-6c** | MECH §3 `operator-deny-rules` (single-Worker pin) |
| 16 | Metering / usage rollup WRITE | **D** | — | — | — | n/a | ✅ (single writer by design) | INSPECTION (`usage_monthly_rollups` declared a non-control in §4.3) |
| 17 | Monthly-spend rollup READ | **D** | — | **D** | **D** | n/a | ✅ | MECH §3.4b — `usage_monthly_rollups` is an authority of `admission`, so every spend Worker must read it |
| 18 | Response cache | **V** | n/a | n/a | n/a | n/a | ✅ single-Worker | LEDGER |
| 19 | Pre-auth network gate (IP allowlist, unauth flood) | **V** | — | — | — | — | ✅ single-Worker | LEDGER |
| 20 | Secrets resolution (`@ferrogate/secrets`) | ✔ | ✔ | ✔ | — | — | ✅ (see §6.4) | INSPECTION — and §6.4 records it as an unresolved question, not a verdict |
| 21 | Self-hosted-worker transport identity | **D** | **D** (write half) | n/a | **D** | n/a | ✅ | INSPECTION (declared a non-control in §4.3) |
| 22 | Session / OAuth state | n/a | **D** (console) | **D** (per-user MCP) | n/a | n/a | ✅ distinct concerns | INSPECTION |
| 23 | Provider circuit breaker / shadow budget | **D** | n/a | n/a | n/a | n/a | ✅ single-Worker | INSPECTION |

**No cell diverges. All five divergences the wave-21 matrix found are CLOSED,
and four of the five (FC-1 · FC-2 · FC-3 · FC-4) are gated MECHANICALLY; FC-5
is a live trap rather than a divergence and is gated too. Thirteen of the
twenty-three rows are gated MECHANICALLY; ten are not, and §9.4 names them —
those ten are the rot risk this document now carries.**

---

## 4. FINDINGS, ranked by blast radius

### FC-1 — THE OPERATOR DRAIN **— CLOSED 2026-08-01, ALL THREE LEGS**

**Blast radius: whole fleet. Money + availability. The API was a no-op.**

#### What it was

*What the operator believed happened.* They call
`POST /admin/v1/drain {"draining": true}` before a migration or during an
incident. The control plane answers
`200 {"object":"drain","draining":true,"reason":…}`. The fleet has stopped
accepting new billable work.

*What actually happened.* `apps/control-plane/src/routes/admin_config_ops.ts::setAdminDrain`
wrote the durable `runtime-state/drain` document — and **nothing read it**
except the control plane's own `GET /admin/v1/drain`, which faithfully echoed
back the state that changed nothing. The gateway's drain was
`apps/gateway/src/routes/readiness.ts::drainStatus`, a synchronous read of the
deploy-time `GATEWAY_DRAIN` var; `apps/gateway/src/routes/drain.ts::nodeDrainGate`
refused five spend-producing operations off THAT value. `apps/mcp` and
`apps/agent-runtime` had no drain gate on either source, so even a deployment
drained the working way (a `wrangler versions` var flip) kept admitting MCP
`tools/call` and `/v1/agent-jobs`.

*How a tenant exploited the difference.* They did not need to. The failure was
against the operator: they watched the load balancer take the node out of
rotation, believed the deployment was quiescing, and it was spending the whole
time. During an incident this is the difference between "we stopped the
bleeding" and "we thought we did".

*Why it was invisible.* Three suites, three green. `apps/control-plane` proved
the document is written; `apps/gateway/test/routes/drain.test.ts` proved the var
is honoured on all five operations and flips it both ways inside one isolate.
Neither could see that the two halves were different variables.

#### What is closed

All three spend Workers now read the durable document **per request** and refuse
the spend-producing operations with the same `503 node_draining` (status, code
and message byte for byte). ONE admin write shuts all three doors.

| leg | module | mount | gate |
|---|---|---|---|
| `apps/mcp` | `src/drain.ts` | `src/http.ts::authenticateRequest` (a REQUIRED `SpendDeclaration` at all 5 authenticated surfaces) | `test/drain.test.ts`, `test/drain-fleet.test.ts` |
| `apps/agent-runtime` | `src/drain.ts` | `src/middleware/auth.ts::bearerAuth`, keyed on `DRAIN_GUARDED_OPERATION_IDS` (5 of 15) | `test/durable/drain.spec.ts` |
| `apps/control-plane` | `src/store/runtime_state.ts` | `routes/admin_config_ops.ts` builds the document with `drainDocument` and reads it back with the enforcers' `parseDrainDocument` | `test/drain.test.ts` |
| **`apps/gateway`** (wave-22 INTEGRATE, the third and last leg) | `src/routes/readiness.ts::resolveDrainState` — `readDurableDrain` + `combineDrain`, the same parse and the same precedence the other two state | `src/routes/drain.ts::nodeDrainGate` (the 5 spend operations) AND `/readyz` through `readinessResponse`, both via the ONE resolver | `test/fleet-control-matrix.test.ts` §5 (behavioural, over `SELF`), `test/fleet-consistency.test.ts` FC-1, `test/env-var-drift.test.ts` |

**THE FLEET GATES** are two, because no one of them can see what the other does.
`apps/mcp/test/drain-fleet.test.ts` issues one admin write and requires the MCP
and agent-runtime doors to shut in a single `it()` — the shape
`agent-upstream-fleet-withdrawal.test.ts` established — and additionally holds
the gateway's leg as TEXT (same table, same `resource_kind`, same `resource_id`,
imported from `apps/control-plane`'s own WRITER so a rename on either side is
red). `apps/gateway/test/fleet-control-matrix.test.ts` §5 holds the gateway's
leg BEHAVIOURALLY, over `SELF`, because that bundle is that Worker and the mcp
bundle is not.

Observed **RED** on the unfixed tree (`apps/mcp tools/call while draining:
expected 200 to be 503`; and, for the gateway leg, §5.1 *expected `{status:400,
code:"invalid_request"}` to deeply equal `{status:503, code:"node_draining"}`*),
GREEN after, and each mount re-proven by mutation — §7.2 and §7.4.

#### Decisions taken

- **Precedence: `durable OR deploy-var`, never "latest wins."** The durable
  document is the runtime operator API; `GATEWAY_DRAIN` remains a DEPLOY-TIME
  override and is declared only in `apps/gateway/wrangler.toml`. Either source
  drains; neither cancels the other. Under "latest wins" a stale var would
  silently un-drain a deployment an operator just drained by API, or a
  `{"draining": false}` call would re-admit traffic to a deployment drained at
  deploy time for a migration — FC-1 again, wearing the other half's clothes.
  Stated once in `combineDrain`, tested directly (`apps/mcp/test/drain.test.ts`
  §"the precedence rule").
- **Fail closed, with an HONEST code.** A durable lookup that FAILS refuses with
  `503 drain_state_unavailable`, not `node_draining`: refusing is
  non-negotiable (a control that admits when its backend is unavailable
  recreates the bypass), but claiming the node is draining while
  `GET /admin/v1/drain` says otherwise is the incident-time lie this repo
  refused to ship as `applied: true`. An UNBOUND control database is a
  different fact and is not a refusal — such a deployment has no control plane
  and already fails closed on every authenticated surface.
- **`/healthz` 200, `/readyz` 503 `operator_drain`.** Liveness must not flip:
  an orchestrator would RESTART the node and destroy the in-flight work the
  drain exists to let finish. Readiness must flip, or the probe tells a load
  balancer to keep sending traffic that every spend request then refuses. The
  durable read therefore happens on `/readyz` and NOWHERE upstream of
  `/healthz`.
- **The drain is DEPLOYMENT state, so `setAdminDrain` is platform-operator
  only.** The contract gives it `admin.write`, which a tenant administrator can
  hold; harmless while nothing read the row, and a cross-tenant denial of
  service now that every Worker resolves it by primary key. Two independent
  defences: `403 tenant_scope_denied` at the route, and `tenant_id: null`
  pinned by `drainDocument` with every enforcer IGNORING a tenant-attributed
  drain document.
- **What a drain does NOT stop**, because that is the point of draining: MCP
  `tools/list` / `resources/list` / `initialize` (discovery — a client must be
  able to learn where to fail over), the MCP identity operations (`revoke` in
  particular must work during a credential incident), agent-job READS and
  `cancelAgentJob`, and all six `auth.kind: "internal"` worker-plane callbacks
  (in-flight work reporting back; refusing them would strand every running job).

#### The last leg, as landed (wave-22 INTEGRATE)

`apps/gateway/src/routes/readiness.ts::drainStatus` WAS
`env?.GATEWAY_DRAIN?.trim().toLowerCase() === "true"` and nothing else, so
`POST /admin/v1/drain` shut MCP and agent-runtime and left
`/v1/chat/completions` serving. That file was outside the owned scope of the
slice that closed the other two legs, so the integrate step closed it.

*What changed.* `drainStatus` KEPT its identity as the deploy-time half — the
var decision table is worth testing on its own and `test/routes/drain.test.ts`
holds every spelling of it — and a new `resolveDrainState` reads the durable
`runtime-state/drain` document from `CONTROL_DB` and ORs the two with a
`combineDrain` restated byte-for-byte from `apps/mcp/src/drain.ts`. It is the
same durable-plus-var shape `apps/gateway/src/routes/agent-upstreams.ts` already
establishes for the upstream registry: fail-closed on a read error, and
specifically NOT back to the var. `readinessResponse` and `nodeDrainGate` became
`async`, which reached `readyzHandler`; both already ran in async contexts.

*Three decisions inside it.*

- **`/readyz` reads the document; `/healthz` does not.** Readiness must flip or
  the probe keeps telling a load balancer to send traffic every spend request
  then refuses. Liveness must NOT flip or an orchestrator restarts the node and
  destroys the in-flight work the drain exists to let finish. Identical split to
  `apps/mcp` and `apps/agent-runtime`.
- **The amplification objection the old PORT-TODO raised was answered, not
  inherited.** It said a per-request durable drain would have to happen on an
  ANONYMOUS endpoint and would be a free amplification target. Three things
  bound it: the read is ONE primary-key row on an indexed table (D1 is a
  replicated SQLite read — none of the single-object serialization a DO drain
  would have had); `/readyz` sits behind the pre-auth network gate; and the read
  that actually stops spend happens after `contractAuth` and after admission,
  where the caller has already paid for several control-database lookups. Only
  the five guarded operations pay it — every other operation costs nothing.
- **A bound-but-failing control database is `503 drain_state_unavailable`, not
  `node_draining`,** and `/readyz` reports `readiness_reason:
  "drain_state_unavailable"` rather than `operator_drain`. Refusing is
  non-negotiable; claiming the node is draining while `GET /admin/v1/drain` says
  otherwise is the incident-time lie this repo refused to ship. An UNBOUND
  database leaves the var as the only source, which is the no-control-plane
  posture the whole Worker already degrades to.

*Gate.* `describe("FC-1 the operator drain, all three legs joined")` in
`apps/gateway/test/fleet-consistency.test.ts` — 7 assertions, no `test.todo`.
The two that RECORDED the divergence are inverted into the two that record its
absence, in the same commit as the fix, which is the ratchet in §5. Plus
`test/env-var-drift.test.ts`'s *"FC-1's durable drain needed NO new binding —
wave 22 is wrangler-INERT"*, which asserts the deploy-config claim rather than
writing it in a commit message.

---

### FC-2 — TENANT SUSPENSION REACHED ONE OF THE THREE WORKERS THAT SPEND **— CLOSED 2026-08-01**

**Blast radius: every suspended tenant. Security + money. This is the wave-16
admission bypass wearing a different control.**

*What the operator believes happened.* A tenant is compromised, delinquent, or
abusive. They suspend it in the control plane. Its credentials stop working.

*What actually happened, before this wave.*

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

*The fix, as landed.* Both Workers consult the same authority the gateway does —
the `status` COLUMN of `tenants` on the control database, ancestors included —
**before** the admission ladder. Ordering is not cosmetic: `finalize_auth` runs
the lifecycle gate ahead of quota/wallet resolution precisely so a suspended
tenant never reaches the step that authorizes spend. A lookup failure is `503`,
never an admission: fail-open here makes "flap the control plane" a suspension
bypass.

| leg | module | mount |
|---|---|---|
| `apps/mcp` | `src/lifecycle.ts` (`TenancyLifecycleGatePort`) | `src/ports.ts::resolvePorts` — `lifecycle = durableLifecycle(env)`, consumed by `src/http.ts::authenticateRequest` ahead of `ports.admission.admit` |
| `apps/agent-runtime` | `LIFECYCLE_*_SQL` + `tenancyGatedApiKeyPort` in `src/ports.ts` | `resolveDeps` composes the gate OVER whichever credential port was chosen — the durable one AND the dev one alike, which is the whole point: the shipped defect was a lifecycle outcome only the dev table could produce |

Two decisions worth recording. **The gate wraps the CREDENTIAL PORT rather than
sitting beside it** on agent-runtime, so it cannot be bypassed by a future
caller that resolves a key some other way — the mistake the original defect was
made of. And **`disabled` / `deleted` / `suspended` all collapse onto
`403 tenancy_*` with the tier named**, matching what `apps/gateway` already
answered, because a client that fails over from one spelling to another is
looking at two products.

*Gates.* `describe("FC-2 …")` in `fleet-consistency.test.ts` — 5 assertions, no
`test.todo`, including the computed exploit set now required to be EMPTY and a
MOUNT assertion on both composition roots (a lifecycle module that exists and is
not wired is this repo's dominant defect). RED when the gateway stops reading
the authority (M2) and RED when a spend Worker stops (§9.5 M2, §7.5 below).

**THE FLEET GATE** is `apps/mcp/test/fleet-tenancy-suspension.test.ts`: ONE
suspension through the control plane, then all three spend doors required to
shut with the SAME status and code, in one `it()` — plus the inverse (lifting
re-opens all three), the fail-closed 503, and the property that a suspended KEY
stays `401 invalid_api_key` on all three rather than being swallowed by the new
`403`.

---

### FC-3 — AN ACTIVATED GUARDRAIL POLICY BOUND ONE WORKER **— CLOSED 2026-08-01**

**Blast radius: every tenant. Data exfiltration / prompt injection.**

*What the operator believes happened.* They author a guardrail policy revision
and call `POST /admin/v1/guardrail-policies/{policy_id}/activate`. Screening is
live.

*What actually happened, before this wave.* Only `apps/gateway` merges the durable
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

*The fix, as landed.* Both Workers resolve their detector policy from the same
`guardrail_policy_revisions` + `guardrail_policy_bindings` rows the gateway
merges, with the var surviving only as the no-control-database fallback — the
same precedence FC-1 and FC-4 use. Five decisions in it are worth recording,
because each was a place the obvious choice was the wrong one.

**1. The shared half is a LIBRARY, not a third copy.** No app may import another
app's module graph (§6.1), so "MCP and agent-runtime read the policy the same
way" is only expressible in a package both already depend on:
`packages/guardrails/src/binding.ts` owns the projection, detector construction,
scope selection, aggregation and the fail-closed postures. Writing that twice,
once per app, would have recreated the divergence the finding is about — two
implementations, one of which drifts.

**2. The SQL is restated per Worker anyway, and that is deliberate.** The
statements live in each app (`apps/mcp/src/guardrails.ts`,
`apps/agent-runtime/src/guardrails.ts`) and are handed to the library, which
defaults to its own identical constants. Two things depend on it: an operator
grepping *"who reads `guardrail_policy_bindings`"* must find every reader — before
this wave `apps/mcp` and `apps/agent-runtime` were absent from that grep and the
answer was correct — and `fleet-control-matrix.test.ts` derives each control's
source-of-truth class from the SQL literals in each Worker's own `src/`, so a
Worker reaching the rows only through a helper is still scored VAR-ONLY. The
drift that convention costs is bought back by assertion: the fleet gate requires
each Worker's constants to equal the library's, character for character. (One
byte of this is load-bearing and was found the hard way: the scanner reads a
literal that carries the verb, so `"SELECT …" + "FROM x"` hides the table. The
statements are written as ONE literal each.)

**3. The snapshot is REVALIDATED, not memoized.** `guardrails/config.ts`
snapshots once per isolate, which is defensible on the gateway. It is not here:
the promise FC-3 makes to an operator is *"you activate a policy and the very
next request is screened by it"*, and a process-lifetime memo silently downgrades
that to *"…once this isolate recycles"* — the same class of half-applied control,
and the exact regression FC-4's fleet gate catches by mutation on the sibling
capability. So every screened request re-reads the binding POINTERS (one indexed
scan of the smallest table in the schema) and recompiles only when
`(policy_id, active_revision, generation)` moved. Revisions are immutable, so an
unchanged pointer set provably denotes an unchanged policy set and the compiled
detectors — with their semaphore and circuit state — are reused. `generation` is
in the fingerprint and is not redundant: an archive-then-restore returns
`active_revision` to where it was while advancing it.

**4. Scope classes were NOT merged, and merging them would have been a
regression.** `scopeMatches` requires a policy's `managed_action` selector and
the request's managed-action context to be both present or both absent, because
Rust's MCP tool guardrail passes `managed_action: Some(ManagedActionContext {
class: Mcp, … })` (`server/managed_action_guardrail.rs:148`) while its A2A ingress
passes `managed_action: None` (`server/local.rs:9993`). A model-content policy
therefore does not police an MCP tool call and vice versa — that is parity, and a
"fix" that made one revision cover both would change behaviour Rust never had.
FC-3 was never "one scope should cover everything"; it was that a
correctly-scoped activated revision reached one Worker and no other. Both
directions are pinned.

**5. Where the projection is narrower than the gateway's engine, it is narrower
CLOSED.** `redact` and `quarantine` become `deny` `guardrail_invalid_redaction`,
because an MCP tool argument and an A2A message have no document to patch — which
is the gateway's own "a redact with no patch downgrades to deny" branch reached
unconditionally. `require_approval` fails closed (#200). Shadow mode still never
enforces, and `shadow_after_complete` on a streamed response still does not, both
verbatim from the engine.

*The streamed A2A leg was strengthened at the same time, and had to be.* The
response stage of `message:stream` previously `tee()`d the body, buffered the
whole teed branch and evaluated it — so a match could only be RECORDED, after
every byte had already reached the caller. On the leg an exfiltration payload
actually travels, that is a guardrail that takes notes.
`apps/agent-runtime/src/agents/stream-screen.ts` now screens FRAME BY FRAME:
only the frame being assembled is held, each complete frame is evaluated before
any of its bytes are handed on, a frame that passes is enqueued byte for byte
(so `ROUTE-MAP.md`'s framing requirement still holds), and a refused frame is
never delivered — the stream is cut with one terminal
`event: ferrogate.guardrail_blocked` frame carrying the operator's code and the
upstream connection is cancelled. **The HTTP status was committed as 200 before
the block and cannot be retracted, so that terminal frame is the only in-band
signal and clients must handle it**; that contract is written out in full in the
module's own header.

*Gates.* Three, because no one of them can see what the others do.

| Gate | What it holds |
|---|---|
| `apps/mcp/test/fleet-guardrail-activation.test.ts` (16, **rewired wave 23**) | THE FLEET EFFECT. Activates through `apps/control-plane`'s REAL writer (`projectGuardrailRevision` + the generation-guarded `projectGuardrailActivation`), then requires the GATEWAY's real durable reader, the DEPLOYED MCP Worker over `SELF`, and the DEPLOYED agent-runtime Worker (`agentRuntimeApp.fetch(request, env)` + its `resolveDeps` composition root) to agree — inside one `it()`, with `FG_DEV_MCP_GUARDRAILS` pinned EMPTY for the whole file so nothing can be explained by the var. **Until wave 23 the A2A leg imported `screenA2aAgainstDurablePolicies` as a LEAF and could not see the mount** — see §7.6 |
| `apps/agent-runtime/test/durable/guardrail-policy-activation.spec.ts` (7) | THE A2A DOOR, behaviourally, in the durable harness where `CONTROL_DB` is bound and no `FG_DEV_*` exists. Ordered: a refusal is `403` with the operator's code and the egress gate is never reached, versus `422 egress_host_not_governed` naming the upstream host when nothing screened |
| `apps/agent-runtime/test/stream-screen.test.ts` (12) | THE INCREMENTAL CONTRACT: clean prefix byte for byte, refused frame and everything after it never delivered, one detector call per FRAME, upstream cancelled, and all three failure postures closed |
| `describe("FC-3 …")` in `fleet-consistency.test.ts` (4) | THE SOURCE-TEXT FORWARD GATE: all four Workers read the durable tables, they name the same two, both borrowers MOUNT the durable screening in their composition root, and the var survives only as the fallback |

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

**6.5 The remaining `test.todo`s are deliberate and are the open FC fixes.**
Each carries the exact change and the exact assertion that replaces it, so the
open findings stay visible in every run rather than living only here. This is
the pattern MOUNT-SEAMS §3.2 established when a delivering agent cannot write a
green assertion for a defect it is not allowed to fix.

**EVERY `test.todo` IN THE LEDGER IS GONE** (2026-08-01). FC-1's went when two
of its three legs landed and was replaced by two POSITIVE assertions recording
the third; the wave-22 integrate step closed that third leg, which turned both
of them RED — exactly as intended — and they are now inverted into assertions
that the leg is joined. FC-2's went the same way in the same wave. A `todo`
cannot go red when the thing it describes lands; a measured table can, and that
is the whole ratchet.

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

### 7.2 FC-1's fix, mutation-proven (2026-08-01)

**M1 and M8 above are SUPERSEDED by the fix they anticipated.** They were
mutations that simulated FC-1's fix ARRIVING, against a ledger that recorded the
divergence; the fix has now landed for two of the three legs, so the tables
those two mutations turned red no longer exist in that form. They are left in
place as the record of what the audit measured, not as live gates.

These are the mutations run against the FIX. Each one changed BEHAVIOUR, was
confirmed by grepping the file back **off disk**, and was restored.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M11** | `apps/mcp/src/http.ts` resolves the drain and then IGNORES the answer | `236: await resolveDrain(spend.env); // MUTATION-FC1-MCP` | **3 RED** in `apps/mcp/test/drain-fleet.test.ts` — *both doors are OPEN before the drain, and BOTH are shut after it*; *the REST tool transport shuts on the same one write*; *lifting the drain re-opens both doors* |
| **M12** | `apps/agent-runtime/src/middleware/auth.ts` resolves the drain and drops the refusal | `510: // MUTATION-FC1-AR: resolve the drain and then IGNORE the answer` | **4 RED** in `apps/agent-runtime/test/durable/drain.spec.ts` — including *REFUSES the A2A ingress too, not just the job verb* |
| **M13** | `apps/agent-runtime/src/routes/health.ts` drops the durable term from the readiness conjunction | `168: const draining = !runtimeEnabled(env); // MUTATION-FC1-READYZ` | **1 RED** — */readyz answers 503 not_ready with readiness_reason operator_drain* |
| **M14** | `apps/mcp/src/routes/index.ts` calls `resolveDrain` on `/readyz` and discards it | `274: await resolveDrain(c.env as DrainBindings); // MUTATION-FC1-MCP-READYZ` | **1 RED** in `apps/mcp/test/drain.test.ts` — same probe assertion, on the other Worker |
| **M15** | `apps/control-plane/src/routes/admin_config_ops.ts` drops the platform-operator fence on `setAdminDrain` | `248: if (false as boolean) { // MUTATION-FC1-CP` | **1 RED** in `apps/control-plane/test/drain.test.ts` — *REFUSES a tenant-scoped admin with 403 tenant_scope_denied* |

The FLEET gate was additionally observed RED **before** any mount existed —
`apps/mcp tools/call while draining: expected 200 to be 503` — which is the
observation a test written after a fix can never make.

### 7.3 Six run against FC-3's fix

Each changed BEHAVIOUR — no semantic no-ops — was confirmed by grepping the file
back **off disk**, and was restored and re-verified GREEN.

Baseline before any mutation: `apps/mcp` fleet gate **15 passed**, the
agent-runtime A2A spec **7 passed**, the stream contract **12 passed**.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M16** | `apps/mcp/src/ports.ts` drops the durable wrapper from `resolvePorts` — the pre-wave posture, i.e. the fix removed | `1823: const guardrails = /*MUT-FC3-M1*/ deterministicManagedActionGuardrails(`, and `grep -c 'durableManagedActionGuardrails('` → **0** | **2 RED** — *ONE managed-action activation shuts the MCP door AND is live on the gateway, same code*; *the SAME activation screens a matching tool RESULT* |
| **M17** | `apps/agent-runtime/src/ports.ts` drops the durable wrapper from `resolveDeps` | `1554: guardrails: /*MUT-FC3-M2*/ ((_e: unknown, p: GuardrailPort) => p)(`, and `grep -c 'durableA2aGuardrailPort('` → **0** | **3 RED** in the A2A spec — including *ONE activation refuses the payload with the OPERATOR's code, before the forward* |
| **M18** | `compileActivatedPolicies` DROPS an uncompilable policy instead of failing it closed — the fail-OPEN direction | `676: /*MUT-FC3-M3*/ continue;` | **1 RED on each Worker** — *a detector that cannot BUILD fails the policy CLOSED, not open*. The narrowest and most valuable of the six: everything else stays green |
| **M19** | `activatedGuardrailPolicies` becomes a process-lifetime memo (constant fingerprint) — the FC-4 regression, on this capability | `355: const fingerprint = "MUT-FC3-M4";` | **5 RED** in the fleet gate + **3 RED** in the A2A spec. This is what a plain per-isolate snapshot would have shipped, and it is why the pointer revalidation is not an optimisation |
| **M20** | `agents/ingress.ts` refuses with its own `guardrail_blocked` instead of the operator's `PolicyAction.code` | `299: /*MUT-FC3-M5*/ "guardrail_blocked",` | **3 RED** — the "same code on every door" property, isolated from the "it refuses at all" property |
| **M21** | `stream-screen.ts` enqueues each frame BEFORE screening it — forward-then-scan, which is what the previous buffering shape effectively did | `156: controller.enqueue(encoder.encode(frame)); /*MUT-FC3-M6*/` | **8 RED of 12** — including *delivers the clean prefix, never the refused frame, never anything after* and *NEVER echoes the matched text* |

Both gates were also observed RED **before** any mount existed — the MCP fleet
gate at *"expected a JSON-RPC error object: expected undefined to be defined"*
and the A2A spec at *"expected 422 to be 403"* with the body naming
`guardrail-probe.upstream.invalid`, i.e. the payload had cleared every content
control and was at the point of being forwarded. That is the observation a test
written after a fix can never make.

---

### 7.4 FC-1's THIRD leg, mutation-proven by the wave-22 INTEGRATE step

The integrate step does not take a delivering agent's mutation table on trust,
and it wrote this leg itself, so it proved it itself. Each mutation changed
BEHAVIOUR, was confirmed by grepping the file back **off disk**, was run, was
restored, and the baseline re-confirmed.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M22** | `apps/gateway/src/routes/readiness.ts::resolveDrainState` performs the durable read and then IGNORES it (`combineDrain(NOT_DRAINING, …)`) — the var-only posture, i.e. the fix removed at the DECISION rather than at the read | `319: await readDurableDrain(env?.CONTROL_DB); // MUTATION-W22-FC1-GW: resolve and IGNORE` | **2 RED** — `fleet-control-matrix.test.ts` §5.1 (*the operator drained the fleet and the gateway kept accepting billable work*, `{status:400,code:"invalid_request"}` vs `{status:503,code:"node_draining"}`) and §5.2. **Every source-text gate stayed GREEN**, which is the finding: the file still NAMES `"runtime-state"`, so §3.3/§3.4, the ledger and `drain-fleet.test.ts` all pass a Worker that reads the document and throws the answer away. That is precisely why §5 is behavioural, and it is the strongest argument in this document for never gating a control on source text alone |
| **M23** | The same file's `RESOURCE_TABLE` and `DRAIN_COLLECTION` are pointed at private names — the pre-wave-22 posture reconstructed at the AUTHORITY | `119: export const RESOURCE_TABLE = "mut_w22_private_drain";`, `121: … = "mut-w22-runtime";`, and `grep -c '"runtime-state"'` → **0** | **13 RED** across three gateway files + **1 RED** in `apps/mcp/test/drain-fleet.test.ts` (*the THIRD enforcer reads the SAME document*). Includes §3.3 *DURABLE on agent-runtime, control-plane, mcp and VAR on gateway*, §3.4, all four of §5, the three inverted ledger assertions and the wrangler-inertness gate. §5.3 goes red too and honestly: with the table renamed the durable read FAILS, and the fail-closed posture answers `503 drain_state_unavailable` rather than `node_draining` — a different fact, deliberately given a different code |
| **M24** | `apps/mcp/src/http.ts` computes the drain refusal and discards it | `235: const refusal = /*MUT-W22-FC1-MCP*/ ((_r: unknown) => null)(` | **3 RED** in `test/drain-fleet.test.ts` — *both doors are OPEN before the drain, and BOTH are shut after it*; *the REST tool transport shuts on the same one write*; *lifting the drain re-opens both doors*. `test/drain.test.ts` also red-adjacent; the FLEET file is the one that names the fleet |
| **M25** | `apps/agent-runtime/src/middleware/auth.ts` does the same | `515: const refusal = /*MUT-W22-FC1-AR*/ ((_r: unknown) => null)(` | **5 RED of 94** in the durable harness — the four `drain.spec.ts` cases including *REFUSES the A2A ingress too, not just the job verb*, plus a fail-closed dispatch case |

### 7.5 FC-2 and FC-3, re-proven by the same step

Not a re-run of the delivering agents' tables — different mutation SITES, chosen
to break the MOUNT rather than the module, because "a module that exists and is
not wired" is this repository's dominant defect and the one a delivering agent's
own table is least likely to attack.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M26** | `apps/mcp/src/ports.ts::resolvePorts` binds `ALWAYS_ADMIT_LIFECYCLE` instead of `durableLifecycle(env)` — the module intact, the mount gone | `1831: const lifecycle = /*MUT-W22-FC2-MCP*/ ALWAYS_ADMIT_LIFECYCLE;`, `grep -c 'durableLifecycle(env)'` → **0** | **8 RED of 12** in `test/fleet-tenancy-suspension.test.ts` — including *shuts all three doors with the SAME status and code after ONE suspension*, *computes an EMPTY exploit set*, the ancestor case, the fail-closed 503 and *resolvePorts binds the durable lifecycle gate in the posture this Worker deploys* |
| **M27** | `apps/agent-runtime/src/ports.ts::resolveDeps` drops the `tenancyGatedApiKeyPort` wrap | `1501: : /*MUT-W22-FC2-AR*/ resolvedApiKeys;`, `grep -c 'tenancyGatedApiKeyPort(resolvedApiKeys'` → **0** | **6 RED** in `test/durable/lifecycle.spec.ts` AND **7 RED** in the mcp FLEET gate. The second number is the one that matters: the fleet gate fails for a regression on ANOTHER Worker, which is the property no per-Worker suite has |
| **M28** | `apps/mcp/src/ports.ts` drops the `durableManagedActionGuardrails` wrapper | `1823: const guardrails = /*MUT-W22-FC3-MCP*/ deterministicManagedActionGuardrails(`, `grep -c 'durableManagedActionGuardrails('` → **0** | **2 RED** in `test/fleet-guardrail-activation.test.ts` — *ONE managed-action activation shuts the MCP door AND is live on the gateway, same code*; *the SAME activation screens a matching tool RESULT* |
| **M29** | `apps/agent-runtime/src/ports.ts` drops the `durableA2aGuardrailPort` wrapper | `1554: guardrails: /*MUT-W22-FC3-AR*/ ((_e: unknown, p2: GuardrailPort) => p2)(`, `grep -c 'durableA2aGuardrailPort('` → **0** | **3 RED** in `test/durable/guardrail-policy-activation.spec.ts` + **1 RED** in `fleet-consistency.test.ts` (*both borrowers MOUNT the durable screening in their composition root*). **The mcp FLEET gate stayed 15/15 GREEN** — see the gap below |

**One gap, found by M29 and stated rather than smoothed over.**
`apps/mcp/test/fleet-guardrail-activation.test.ts` reaches agent-runtime by
importing its *screening function* as a leaf, not by driving its
`resolveDeps` — so it proves the FUNCTION honours an activation and cannot see
whether the deployed Worker still MOUNTS it. Removing that mount leaves the
fleet gate fully green. The regression is caught, twice — by the A2A durable
spec (3 RED) and by the ledger's mount assertion (1 RED) — so it is gated; but
the file whose NAME says "fleet" is not the file that catches it. The
equivalent for FC-1 does not have this shape (`drain-fleet.test.ts` drives
agent-runtime's real resolver against the real database and the gateway's leg is
held behaviourally in the gateway's own bundle), and the equivalent for FC-2
does not either (M27 turned the fleet gate red). This one is the outlier and it
should be closed by driving `resolveDeps` in the fleet file.

### 7.6 That gap, CLOSED (wave 23) — and re-proven from both sides

`apps/mcp/test/fleet-guardrail-activation.test.ts` now reaches agent-runtime the
way FC-2's fleet gate does. The leaf import of
`screenA2aAgainstDurablePolicies` is GONE. Two paths replace it, and neither can
be satisfied by a module that exists and is not wired:

 - **the composition root** — `resolveDeps(env)` from
   `apps/agent-runtime/src/ports.ts`, called exactly as
   `middleware/auth.ts::depsOrThrow` calls it per request, with every A2A
   assertion in the file going through the `deps.guardrails` port it returns;
 - **the deployed Worker** — `agentRuntimeApp.fetch(request, env)` against a
   real `api_keys` credential and a real durable `agent-upstreams` row, over the
   bare invoke verb AND `message:send` AND `message:stream`, with the ordered
   `403`-with-the-operator's-code versus `422 egress_host_not_governed`-naming-
   the-host observation the durable spec established.

The env agent-runtime is invoked with is built ONCE for the file, deliberately:
the durable snapshot is memoized against env identity, so a fresh object per
call would hand every assertion a cold cache and quietly retire the property
FC-3 actually promises (an activation takes effect on the next request through a
WARM isolate, because the binding POINTERS are revalidated — the property M19
attacks). One `it()` states it directly: resolve the deps, screen and get
`allow`, activate, screen through the **same** deps object and get the
operator's code.

Baseline: **16 pass** (was 15). No assertion was weakened or deleted; the
response-leg screening the wire cannot reach offline is still asserted, now
through the mounted port instead of the bare function.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M30** (= M29's site, re-run against the rewired file) | `apps/agent-runtime/src/ports.ts::resolveDeps` drops the `durableA2aGuardrailPort` wrapper — the module intact, the mount gone | `1554: guardrails: /*MUT-W23-FC3-AR*/ ((_e: unknown, p2: never) => p2)(`, `grep -c 'durableA2aGuardrailPort('` → **0** | **3 RED of 16**, in the file whose name says fleet: *ONE model-content activation shuts the A2A door AND is live on the gateway, same code*; *the A2A door is the DEPLOYED Worker's, not a screening function called directly*; *a detector that cannot BUILD fails the policy CLOSED, not open*. Under wave 22 this same mutation left the file **15/15 GREEN** |
| **M31** | `apps/agent-runtime/src/agents/ingress.ts` evaluates the request-stage guardrail and DISCARDS the verdict — the M22 shape, at the decision rather than the mount | `291: if (/*MUT-W23-FC3-ING: evaluate and DISCARD*/ false && requestVerdict.outcome === "deny") {` | **1 RED of 16**, and it is the interesting one: **every port-level assertion in the file stayed GREEN** and only the wire assertion (`403` with the operator's code, all three verbs) went red — `422 egress_host_not_governed` naming `fleet-guardrail-probe.upstream.invalid`, i.e. the payload passed every content control and was at the point of forward. A port-only gate would have passed a Worker that screens and throws the answer away |

Both source files were restored and verified byte-identical by `sha256sum`, and
`grep -c MUT-W23` over both returns 0.

M31 is M22's warning arriving on a second capability, and it is the argument for
why this file now has BOTH shapes rather than either: M30 is invisible to the
wire assertions (the mount is gone, but the fallback still allows and the
dispatch still reaches the forward — indistinguishable from the control case at
the port), and M31 is invisible to the port assertions (the port is mounted and
honours the activation; the route asks and discards). Neither half subsumes the
other.

---

## 8. What the next wave should do with this

1. **FC-1 — DONE (wave 22, all three legs).** Nothing left. The one thing to
   carry forward is a DEPLOY hazard rather than a code one:
   `apps/agent-runtime`'s two `[[d1_databases]]` stanzas are still committed
   COMMENTED OUT for a measured test-harness reason (§FC-5's sibling problem),
   so a deployment that leaves them commented drains two Workers of three — the
   defect reintroduced by configuration. `CLOUD-VERIFICATION.md` **B11** and
   **V-FC1** carry it.
2. **FC-2 — DONE (wave 22).** Highest security value, and the fix was the
   mechanical one: the lifecycle gate the gateway already had, composed over the
   credential port both other Workers already had, ahead of their admission
   ladders.
3. **FC-3 — DONE (wave 22).** §4 records the five decisions inside it. The one
   worth carrying forward: the gateway still snapshots its own guardrail source
   ONCE per isolate (`guardrails/config.ts`), while the two Workers closed here
   revalidate the binding pointers per request. That asymmetry is now the only
   place in the fleet where "when does an activation take effect" has two
   answers, and it should be collapsed onto the revalidating one rather than the
   reverse.
4. **FC-6c is a product decision, not an engineering task.** Route it to
   whoever owns the deny-rule semantics before someone "fixes" it into a
   fleet-wide deny and changes behaviour Rust never had.
5. **Never delete FC-5.** It guards a thing that is not broken, which is exactly
   why it will look deletable.
6. **The FC-3 fleet gate's leaf-import gap — DONE (wave 23).** §7.6. The one
   thing to carry forward is the RULE the gap taught, not the fix: a fleet gate
   that reaches another Worker by importing one of its FUNCTIONS proves the
   function and nothing about the deployment. Reach a sibling Worker through its
   composition root (`resolveDeps`) or its entrypoint
   (`app.fetch(request, env)`) — never through a leaf — and pair the two, because
   §7.6 M30/M31 show each is blind to what the other catches. `drain-fleet.test.ts`
   (FC-1) and `fleet-tenancy-suspension.test.ts` (FC-2) are the two worked
   examples; every future fleet gate copies one of them.
7. **THE SUITE ITSELF IS NOT DETERMINISTIC AT FULL SCALE — open, and it is a
   GATE defect, not a product one.** Chasing a once-observed failure of
   `apps/gateway/test/metering/durable.test.ts` *"does not double-charge the SAME
   request id"* did not reproduce that test (0 failures in 20 isolated runs, 12
   `test/metering` runs, 10 `test/assets`+`test/metering` runs, 16 whole-suite
   runs and 1 whole-workspace `bun run test`) but did surface something larger:
   **5 of 15 full `apps/gateway` runs failed, in a DIFFERENT file each time**,
   all inside one ~10-minute window when another process held the machine at
   load ≈ 5, and all 10 runs outside that window were green. The signature is
   always the same shape — one file, a whole CLUSTER of assertions, and always
   the ones that assert a RECORDED SIDE EFFECT (a meter charge, a durable row's
   field, a refusal driven by seeded policy), while the status/`ok` assertions in
   the same tests pass:

   | Run | File | Failures | Shape |
   |---|---|---|---|
   | 2 | `test/assets/egress.test.ts` | 7 of 24 | every test asserting a NON-ZERO `meter.charges`; the one asserting ZERO passed |
   | 3 | `test/assets/content-gate.test.ts` | 7 | **`expect(result.ok).toBe(false)` got `true`** — the per-`asset_type` content-type allowlist ADMITTED a disallowed content type |
   | 4 | `test/metering/agent-run-correlation.test.ts` | 1 | `events` had length 1 but `agent_run_id` was `undefined` — the row present was not the row the request wrote |
   | 1 | one file (6) and one workflow cluster (~40) | | same shape |

   Run 3's entry is the one to look at first: if it is a harness artefact it is
   benign, and if it is a real intermittent admission it is a live content-gate
   bypass. It did not reproduce in 10 targeted `test/assets` runs. It is outside
   the wave-23 owned scope and is recorded here rather than fixed or explained
   away. **Do not read "6,986 green" as a reproducible fact until this is
   closed** — a suite that fails one run in three under contention cannot
   distinguish a regression from a bad afternoon, which is the same class of
   problem as a green suite that cannot fail.

---

## 9. THE MECHANICAL GATE (wave 22) — `apps/gateway/test/fleet-control-matrix.test.ts`

**66 assertions. Baseline on 2026-08-01: 62 pass, 4 RED, and all four RED are
FC-1's third leg.** Six mutations, all restored, in §9.5.

### 9.1 Why a second fleet file, when §7 already mutation-proved the first

`fleet-consistency.test.ts` is the LEDGER and stays. It records each finding as
an exact table and fails in both directions, which is what makes a finding and
its document move in one commit. That is the right shape for a finding.

It is the wrong shape for a CLASS, for one reason: **every table in it is a
hand-written list of Workers.** `expect(appsMatching(PROBE.emitsNodeDraining))
.toEqual(["gateway"])` is true until someone adds a sixth Worker, at which point
it is *still* green about the five it knows and blind to the new one. Wave 21
enumerated 23 capabilities and found 5 divergences BY INSPECTION; inspection
does not survive the next refactor.

So the new file names **no Worker anywhere**. It computes:

* **the fleet**, from `apps/{*}/wrangler.toml` — a `*` in the APP position, so a
  sixth Worker enters every table below the moment it exists (`apps/cli` is
  excluded by having no `wrangler.toml`, not by name);
* **the role sets**, from behaviour: `CREDENTIAL` = the Workers that can answer
  `401 invalid_api_key`, `SPEND` = the Workers that carry the wave-16 ladder's
  `403 quota_scope_disabled`, `SCREENING` = the Workers that call a guardrail
  detector. A new Worker that ports the ladder joins `SPEND` automatically and
  is instantly required to honour the drain, the suspension and the quota;
* **the source-of-truth class of every control on every Worker**, from the SQL
  that Worker issues (resolved through its own table constants) and the vars it
  reads;
* **the whole refusal table** — every `(status, code, message)` any Worker can
  emit, in all three spellings the repo uses.

### 9.2 The five properties, demanded uniformly of every control

The registry supplies TOKENS only — durable authority, deploy-time var,
in-memory fallback, enforcement point, and which computed role set must enforce
it. It contains no list of Workers and no expected verdict. Every row is then
held to the same five:

| | Property | What it catches |
|---|---|---|
| **3.1** | the probes are live | a renamed table or refusal code, which would otherwise make every assertion below compare empty sets and pass |
| **3.2** | every Worker the ROLE SET requires actually enforces it | FC-2's original shape: a spend Worker with no lifecycle gate at all |
| **3.3** | every enforcer resolves it from the SAME class | **the one sentence all four shipped defects share** — DURABLE on one Worker and VAR-ONLY or IN-MEMORY on another is a hard failure, and the message prints the whole row |
| **3.4 / 3.4b** | a control APPLIED durably is OBSERVED by every enforcer, and by ALL of its authorities | FC-1 exactly (the admin API writes `runtime-state/drain`, the gateway refuses off `GATEWAY_DRAIN`); 3.4b catches the finer form where one of several authority tables is privatised |
| **3.5** | the refusal is the same wire answer everywhere | a 429 on one surface and a 403 on another is the same admission bug wearing a different response |

Plus §3.6, the FC-5 trap (one definer of `RateLimiterDurableObject`, every other
SPEND Worker pinned to the deploy-time `script_name` stanza), computed over
whichever Workers §2 put in SPEND.

### 9.3 The ratchets — new controls are DISCOVERED, not declared

* **§4.1** groups every refusal code the fleet declares and forbids two statuses
  for one code. It found two live disagreements on its first run, both
  legitimate and both now PINNED to their exact spelling so a change is red:
  `governance_counter_unavailable` (429 at the gateway's asset-download site per
  `server/assets.rs:1114`, 503 on every inference path) and `invalid_request`
  (422 on the admin plane, 400 on the data plane). Anything NOT on that
  two-entry list must agree, so a new shared code fails closed.
* **§4.2** requires the admission ladder's emitters to equal the computed SPEND
  set and its wording to be identical across it.
* **§4.3** is the new-control ratchet: **every table two or more Workers touch
  must be a registered control or an explicitly declared non-control.** A shared
  table is a shared source of truth by definition, and "does a change to it
  apply everywhere?" is the question nobody asked before either bypass shipped.
  The declared-non-control list is the only hand-written list in the file and
  its polarity is deliberate — the default for anything new is FAIL. It has
  already earned its place: `tenant_databases` appeared as a new mcp read during
  this wave and the gate demanded the decision (it is routing, not a control —
  the day it grows a `status` column it becomes one).
* **§4.4** is the inverse, against the registry rotting into fiction: every
  authority table a control claims must be issued by some Worker.

### 9.3.1 One deliberate widening, and why it is not a hole

A correct fix can move the `SELECT` out of the Worker: `apps/mcp` and
`apps/agent-runtime` resolve the activated guardrail revision through
`@ferrogate/guardrails`, so the statement lives in `packages/`. A scan of
`apps/{*}/src` alone scores both VAR-ONLY — **inventing the exact divergence the
file exists to detect, on the commit that closes it.** A gate that cries wolf on
a fix is a gate that gets deleted.

Scanning `packages/` instead would be worse: every Worker that IMPORTS a package
would score durable whether or not it MOUNTS the port, and "a module that exists
and is not wired" is this repository's dominant defect. So the evidence demanded
is on the WORKER — it names the authority table as a literal, in a file that
also evidences a control-database read, **and that file issues no SQL of its
own**. A module with its own SQL is scored on that SQL and nothing else, so
pointing a `SELECT` at a private table cannot be masked by an untouched
`const X_TABLE = "…"` sitting next to it. Mutation **M1** is that case, and it is
RED.

### 9.4 What is NOT mechanically gated — the cells that will rot first

Ten of the twenty-three rows. Listed here rather than left implicit, because an
ungated cell that nobody has written down is indistinguishable from a gated one:

| Row | Capability | Held by | Why it is not MECH yet |
|---|---|---|---|
| 9 | RBAC `rbac_action` | LEDGER (`fleet-consistency.test.ts` FC-7) | the property is about the CONTRACT table, not about a source of truth; convertible |
| 10 | Tenant fencing | INSPECTION | every Worker fences, but the fence is a SQL predicate rather than an authority, so §3's classifier cannot see it. **This is the most valuable conversion left** — a fence that weakens on one Worker is a cross-tenant read |
| 13 | MCP server catalog | INSPECTION | one reader today; the day a second Worker resolves it, §4.3 will demand it be registered |
| 16 | Metering WRITE | INSPECTION | declared a non-control in §4.3 (single writer by design) |
| 18, 19 | Response cache, pre-auth network gate | LEDGER | pinned single-Worker in FC-6a/FC-6b |
| 20 | Secrets resolution | INSPECTION | §6.4 records it as an unresolved question, not a verdict — gating it would pin an answer nobody has established |
| 21 | Self-hosted-worker transport identity | INSPECTION | declared a non-control in §4.3 |
| 22 | Session / OAuth state | INSPECTION | genuinely distinct concerns on the two Workers |
| 23 | Provider circuit breaker | INSPECTION | single-Worker by design |

### 9.5 Mutation proof

Baseline before every mutation: **62 passed | 4 failed (66)**. Each mutation was
applied, grepped back **off disk** to confirm the edit landed, run, restored,
and the baseline re-confirmed. All six change BEHAVIOUR. M1 and M2 were re-run
against the final classifier after §9.3.1's widening landed.

| # | Mutation | Confirmed off disk | Result |
|---|---|---|---|
| **M1** | `apps/mcp/src/admission/quota.ts` points its quota `SELECT` at a private table (`FROM mcp_private_quota_policies`) while leaving the `QUOTA_POLICY_TABLE` constant intact | `358: … FROM mcp_private_quota_policies …/*MUT-M1*/`, and `grep -c "FROM quota_policies"` → **0** | **+2 RED** — §3.4b on BOTH `admission` and `quota-plan`: *`mcp does not read quota_policies`* |
| **M2** | `apps/agent-runtime/src/ports.ts` drops the `status` column from `LIFECYCLE_TENANT_SQL` — the FC-2 fix removed | `715: … = "SELECT id FROM tenants WHERE id = ?1"; /*MUT-M2*/` | **+2 RED** — §3.3 *DURABLE on control-plane, gateway, mcp and IN-MEMORY on agent-runtime*, and §3.4 naming agent-runtime |
| **M3** | `apps/mcp/src/admission/gate.ts` answers the wallet refusal `403` with different wording | `101: status: 403,` + `message: "prepaid credit balance is empty"` | **+2 RED** — §4.1 (status disagreement, discovered without the registry) and §4.2 (wording) |
| **M4** | `apps/agent-runtime/src/ports.ts` issues SQL against `stored_assets`, a gateway-only table | `717: export const MUT_M4_SQL = "SELECT id FROM stored_assets …"; /*MUT-M4*/` | **+1 RED** — §4.3, the new-control ratchet: *a source of truth is shared by two Workers and nobody has asked whether a change to it applies to both* |
| **M5** | `stripComments` regresses to eating string literals (the VACUITY probe) | `152: .replace(/"[^"]*"/g, '""') /*MUT-M5*/` | **32 RED of 66**, and the CANARY fails FIRST — *comment stripping preserves every line of top-level code, on every Worker*. A stripper regression can never present as "the fleet is consistent" |
| **M6** | `apps/mcp/src/lifecycle.ts` stops naming the suspension refusal | `135: return "tenancy_inactive"; /*MUT-M6*/`, `grep -c '"tenancy_suspended"'` → **0** | **+1 RED** — §3.2 coverage: *these spend Workers cannot enforce it — an operator who applies it there changes nothing* — computed from the role set, not from a list |

§3.6 is not re-mutated here: it is carried over unchanged from the ledger's
`describe("FC-5 …")`, whose M5a/M5b in §7 broke exactly these assertions. Both
require editing a `wrangler.toml`, which this wave does not own.

`grep -rn "MUT-M[0-9]" apps/` is clean; every restore was verified by grepping
the ORIGINAL text back off disk, not by trusting the write.

### 9.6 How to read this suite RED at integrate time

**HISTORICAL — all of these are now GREEN; §9.7 records how.** Kept because
it is the record of a gate written to the INTENDED end state ahead of the fix,
which is the only way a gate is ever observed red for the right reason. As
written by the delivering agent, before the wave-22 integrate step:

| File | RED | Meaning |
|---|---|---|
| `fleet-control-matrix.test.ts` | **4** — §3 `drain` 3.3 + 3.4, §5.1, §5.2 | **FC-1's third leg is genuinely open.** `apps/mcp` and `apps/agent-runtime` now read the durable `runtime-state/drain` document; `apps/gateway` still refuses off the deploy-time `GATEWAY_DRAIN` var, so the fleet is DURABLE on two Workers and VAR on one — the defect shape, now inverted. §5.1 states it behaviourally: the operator's `POST /admin/v1/drain` is written, and `/v1/chat/completions` answers `400`, not `503 node_draining`. **These four go green when `drainStatus` gains the durable read with the var as fallback, and NOT before.** |
| `fleet-consistency.test.ts` | **5** — FC-2 ×3, FC-3 ×2 | **The ledger ratchet firing on a CLOSED divergence, exactly as §5 says it must.** FC-2 and FC-3 landed during this wave, so *"only the gateway reads the DURABLE lifecycle authority"* and *"only gateway and control-plane touch the durable policy tables"* are now false — which is the good news wearing a red. They belong to whoever lands those fixes, in the same commit. Do not "fix" them by widening the ledger without re-reading §3. |

Everything else in `apps/gateway` was green at that point: **2005 passed | 9
failed | 2 todo** across 114 files, plus 24/24 and 42/42 in the two escalated
harnesses.

### 9.7 The reds §9.6 predicted, resolved

The four `fleet-control-matrix.test.ts` reds and the five
`fleet-consistency.test.ts` reds §9.6 recorded were all real and are all closed.
The matrix's four went green when the gateway's `resolveDrainState` landed and
**not before**, exactly as §9.6 said they would. The ledger's five were the
ratchet firing on CLOSED divergences (FC-2 ×3, FC-3 ×2, plus FC-1's two
inverted assertions) and were resolved by rewriting the measured tables in the
same commit as the fix, which is what §5 demands. Both files are now GREEN with
no `test.todo`: **`fleet-consistency.test.ts` 35 passed (35)** and
**`fleet-control-matrix.test.ts` 66 passed (66)**.
