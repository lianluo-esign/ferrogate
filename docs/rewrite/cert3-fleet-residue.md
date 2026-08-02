# cert3 — the fleet, re-derived; and the unverifiable-locally residue

**Scope of this document.** Two areas, both certified by re-derivation from
`apps/*/src` and `crates/**` rather than by reading the previous wave's
conclusions: (1) the capability × Worker control matrix that
`FLEET-CONSISTENCY.md` records as 23 rows / 5 divergences / all closed, and
(2) the blockers `CLOUD-VERIFICATION.md` carries as B1–B11 and V-A3 / V-FC1 /
V-FC2 / V-FC3.

**Headline.** The five divergences wave 21 found and wave 22 closed ARE closed —
I re-derived each one independently and each holds. But the enumeration that
produced them is **incomplete in a specific, mechanical way**, and the gap is
not random: **the matrix's unit of analysis is the TABLE, and three live control
gaps sit in a COLUMN of a table that is already registered or already declared a
non-control.** The project learned this exact lesson once, for `tenants.status`
(FC-2), wrote it into the registry as a one-off comment — *"the CONTROL on
`tenants` is its `status` column"* — and did not generalise it. Re-running the
same search key one level down finds three more, one of which is a **CLASS A
regression on a control Rust implemented, mounted at three call sites, and
explicitly audited for exactly this failure mode**.

Verdict up front, in the terms of THE BAR:

| | |
|---|---|
| Merging `main-ts` → `main` | **GO**, unchanged. Nothing here is a reason to hold the merge. |
| Deleting `crates/**` | **NO-GO on a 3-item subset** — R1, R2, R5 below. Each is a control that WORKED in Rust and does not work in TS. R1 is the one that matters. |
| The other findings (R3, R4, R6, D1) | do not block; recorded so they are decided rather than inherited. |

---

## 0. What was actually run, and what was not

Executed this wave, offline, `--local` / vitest only. No `wrangler deploy`, no
live Cloudflare resource, no upstream LLM call, no `cargo`, no `git`, no writes
outside this file.

| What | Result |
|---|---|
| `apps/gateway/test/fleet-control-matrix.test.ts` | **66 passed (66)** — re-run 18 times, see §4.4 |
| `apps/gateway/test/fleet-consistency.test.ts` | **35 passed (35)** |
| both together | **101 passed (101)**, 3.96 s |
| `apps/mcp/test/{drain-fleet,fleet-tenancy-suspension,fleet-guardrail-activation}.test.ts` | **38 passed (38)** |
| `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` | **5 passed (5)** |

**NOT re-verified this wave, and therefore carried forward on the previous
wave's word:** the 6,986-test total, the 22/22 Playwright run, the 5/5
`wrangler dev --local` boots, the 200 seam rows, the 22 typecheck-clean
projects. Two reasons, both honest: the full sweep is expensive, and **other
agents were writing to this working tree while I ran** — `find apps packages
-name '*.ts' -newermt '2026-08-01 19:50'` returned four files mid-session
(`apps/agent-runtime/src/ports.ts`, `apps/agent-runtime/src/agents/ingress.ts`,
`apps/gateway/src/assets/service.ts`,
`apps/mcp/test/fleet-guardrail-activation.test.ts`). A whole-suite number
measured against a tree that is moving underneath it is not a number. §4.4
records the one place that concurrency visibly bit.

Everything in §1–§3 below is derived from source text I read directly, and every
claim names the file and the line so it can be checked without trusting me.

---

## 1. The matrix, re-derived

### 1.1 Method (deliberately different from wave 21's)

Wave 21 enumerated controls by walking each Worker's modules. I enumerated by
**four independent projections**, so a control invisible to one shows up in
another:

1. **Every refusal code** each Worker can emit
   (`grep -rhoE 'code: *"[a-z0-9_]+"'` per app), then asked of every code that
   appears on one spend Worker and not another: *why not?*
2. **Every table** each Worker issues SQL against
   (`grep -rhoE '(FROM|INTO|UPDATE|JOIN) +…'` per app), and for every table
   touched by ≥2 Workers, *do they read the same COLUMNS?*
3. **Every composition root**, read end to end
   (`apps/mcp/src/ports.ts::resolvePorts`,
   `apps/agent-runtime/src/ports.ts::resolveDeps`,
   `apps/gateway/src/assets/handlers.ts::assetDepsFromEnv`,
   `apps/gateway/src/guardrails/config.ts`), asking of every port: *what is it
   in the posture the Worker DEPLOYS in, not the posture the tests build?*
4. **The Rust side first, never the TS stub** — for every candidate, read
   `crates/**` and establish whether the control was IMPLEMENTED **and CALLED**
   before calling anything a regression.

Projection 3 is the one that found R1. It is not in wave 21's method and it is
the one that would have found the wave-16 bypass and FC-2 too.

### 1.2 The fleet is 5 Workers, and that is confirmed

`apps/{gateway,control-plane,mcp,agent-runtime,telemetry}/wrangler.toml` exist;
`apps/cli` has none. The mechanical gate's `*`-glob discovery of the fleet is
correct and is the right shape.

### 1.3 The five closed divergences — independently re-confirmed

I re-derived each rather than reading the ledger. All five hold:

| | Claim | What I checked | Verdict |
|---|---|---|---|
| **FC-1** drain | one write, three doors | `apps/gateway/src/routes/drain.ts::nodeDrainGate` mounted at `routes/index.ts:448` over 5 operation ids resolved from `c.get("operation")`; `apps/mcp/src/http.ts::authenticateRequest` requires a `SpendDeclaration`; `apps/agent-runtime/src/middleware/auth.ts:513` keyed on `DRAIN_GUARDED_OPERATION_IDS`. All three call `resolveDrainState`/`resolveDrain` per request, no memo. | **CLOSED**, and the guarded sets are RIGHT: agent-runtime owns 15 contract operations, exactly 5 of which start billable work (`createAgentRun`, `submitAgentJob`, `invokeAgent`, `sendAgentMessage`, `streamAgentMessage`) and exactly those 5 are guarded. |
| **FC-2** suspension | same authority, ahead of admission | `apps/agent-runtime/src/ports.ts` composes `tenancyGatedApiKeyPort` OVER the credential port (line ~1501); `apps/mcp/src/ports.ts::resolvePorts` binds `lifecycle = durableLifecycle(env)`; both read `tenants.status` with ancestors. | **CLOSED** — with a degraded-posture caveat, D1 below. |
| **FC-3** guardrail binding | one activation, three doors | `durableManagedActionGuardrails` (mcp) and `durableA2aGuardrailPort` (agent-runtime) both mounted in the composition root; pointer revalidation per request rather than a per-isolate memo. | **CLOSED.** The §7.5 M29 gap (fleet gate reached agent-runtime by leaf import) was **closed during this session** — `apps/mcp/test/fleet-guardrail-activation.test.ts` now imports `resolveDeps as resolveAgentRuntimeDeps` and drives the composition root. |
| **FC-4** upstream withdrawal | both doors | `agentUpstreamPortFromEnv` mounted in `resolveDeps`; var REPLACED not merged. | **CLOSED** |
| **FC-5** shared RPM counter | one definer | `apps/agent-runtime/wrangler.toml:192-195` and the mcp equivalent carry the commented `script_name = "ferrogate-gateway"` stanza; neither declares the class. | **NOT A DEFECT, and the trap gate is right.** See B10 in §3. |

### 1.4 THE SEARCH KEY, RUN ONE LEVEL DOWN

`FLEET-CONSISTENCY.md` §1.1 states the key that found everything so far:

> *A control that is DURABLE on one Worker and VAR-ONLY on another is the exact
> shape of both shipped defects.*

That key is applied at TABLE granularity. Run it at **COLUMN** granularity —
*"a control whose authority is a COLUMN of a table the fleet already shares"* —
and the gate cannot see it, **by construction**, for two independent reasons
visible in `fleet-control-matrix.test.ts` itself:

* `api_keys` / `static_api_keys` / `api_key_directory` are in the `NOT_A_CONTROL`
  set (line 1071–1073). Any control living in a COLUMN of `api_keys` is
  therefore exempt from the §4.3 new-control ratchet by name. → **R2**.
* `plans` is registered as an authority table of the `quota-plan` control
  (line 716–722), whose §3.2 coverage probe is the regex
  `/"quota_resolution_unavailable"/`. Every spend Worker emits that code, so
  `quota-plan` scores **fully covered on all five properties** — while three
  ENTITLEMENT columns of the very same table are read by nobody. → **R1**.

The registry knows this failure mode exists. It says so, once, for one row:

> `tenant-lifecycle` — *the authority is the `status` COLUMN, not the `tenants`
> table*

That sentence is the finding. It was applied to one row and not turned into a
property.

### 1.5 The re-derived matrix — deltas only

Rows 1–23 of `FLEET-CONSISTENCY.md` §3 are reproduced by my derivation with the
verdicts it states, except as noted. **Six rows are missing from it.** Legend as
in that document.

| # | Capability / control | gateway | control-plane | mcp | agent-runtime | Agree? | Class |
|---|---|---|---|---|---|---|---|
| **24** | **Plan tool entitlements** (`plans.mcp_enabled`, `extension_tools_enabled`, `self_hosted_workers_enabled`) | parsed, unread | parsed, unread | **M** (`InMemoryEntitlements`, every posture) | parsed, unread | ❌ **R1** | **A** |
| **25** | **Per-credential token budget** (`api_keys.monthly_token_budget`) | **D** | **D** | — | — | ❌ **R2** | **A** |
| **26** | **Guardrail evidence** (the record of what was screened and blocked) | **M** unconditional | — | — | — | ❌ **R5** | **A** |
| **27** | MCP audit trail (`ports.audit`) | **D** (`audit_events`) | n/a | **M** (`InMemoryAuditSink`) | n/a | ❌ **R4** | **A**(minor) |
| **28** | MCP asset catalog / `resources/read` | **D** (`stored_assets` + R2) | n/a | **M** (`InMemoryAssets`) | n/a | ❌ **R3** | **B** |
| **29** | Lifecycle DEGRADED-posture direction (control DB unbound) | fail **OPEN** | n/a | fail **CLOSED** | fail **OPEN** | ❌ **D1** | **A**(config) |

Two corrections to existing rows:

* **Row 9 (`rbac_action`)** understates it. `apps/mcp/src/auth.ts` performs the
  full durable Permission → Role → TenantRoleBinding walk (`ROLE_PERMISSIONS_SQL`,
  line 289) to populate `AuthContext.permissions`. That field has **exactly one
  consumer in the entire Worker**: `apps/mcp/src/ports.ts:1060`, inside
  `InMemoryEntitlements` — i.e. inside the dead gate of R1. So mcp's RBAC read is
  not merely "parsed, unread": it is a live, per-request D1 join whose only
  reader can never deny anything.
* **Row 1 (credential resolution) "✅ agree"** is true about the ANSWER and
  hides that the three spend Workers resolve credentials through **three
  different table sets and two different lookup keys**: gateway by `key_prefix`
  against `api_keys` on its bound `DB`; mcp by `key_hash` against
  `static_api_keys` → `api_key_directory` → the routed tenant `api_keys`;
  agent-runtime by `key_prefix` against `api_keys`. The consequence is bounded
  and documented (`apps/control-plane/src/store/api_keys.ts:315`: the revoke
  ordering is directory-then-tenant so a crash between legs fails closed) — but
  it fails closed only for the reader that checks the DIRECTORY, which is mcp
  alone. During that window the gateway and agent-runtime still admit the
  revoked credential. Narrow, real, and not currently written down.

---

## 2. Findings

### R1 — THE PLAN ENTITLEMENT GATE IS PARSED BY FOUR WORKERS AND ENFORCED BY NONE — **CLASS A**

**Blast radius: every tenant whose plan does not include MCP tools. Money +
capability. An operator control that silently does nothing.**

*What Rust did.* `crates/ferrogate-gateway/src/server/local.rs:137
::tool_execution_entitlement_denial` is a live, durable, mounted gate:
`StoredPlan.mcp_enabled` OR a bound role granting `mcp.execute`; denial is
`mcp_tools_disabled`. Its own docblock records that it was centralised
**precisely because** the same gate had already been missed twice:

> *"extended to the Extension backend in #183, and to the `/v1/mcp` JSON-RPC
> `tools/call` transport after a follow-up audit found it was a third call site
> executing the same underlying MCP tool with no equivalent gate. Centralized
> here — rather than re-implemented per call site — specifically because that's
> the exact failure mode that produced both bugs."*

It is called from two sites in the Rust request path
(`local.rs:3617`, `mcp_rpc.rs:567`), and `state_rbac.rs:11
::tenant_tool_entitlement_denied` is its durable half. This is not a Rust stub.
It is a control Rust implemented, mounted, lost twice, and hardened against
losing a third time.

*What TypeScript does.* `apps/mcp/src/ports.ts::resolvePorts` overrides seven
ports for the production posture — `guardrails`, `secrets`, `auth`, `approvals`,
`admission`, `lifecycle`, and (only when KV is bound) `credentials`/`cipher`.
`entitlements` is **not one of them**, in either posture. It is
`new InMemoryEntitlements()` from `inMemoryPorts()`, whose `deniedTenants` is a
`Set<string>` that nothing but a test ever writes to
(`apps/mcp/test/tools.test.ts:193`, the only write in the repo). Therefore
`toolExecutionDenial` returns `undefined` for every caller on every deployment
and `mcp_tools_disabled` is **unreachable in production**.

The columns are not missing — they are read and thrown away.
`plans.mcp_enabled`, `plans.extension_tools_enabled` and
`plans.self_hosted_workers_enabled` are parsed into a `StoredPlan` by
**four** Workers (`apps/gateway/src/ratelimit/quota.ts:379`,
`apps/mcp/src/admission/quota.ts:294`,
`apps/agent-runtime/src/admission/quota.ts:269`,
`apps/control-plane/src/store/quota_registry.ts:164`) and the resulting
`mcpEnabled` / `extensionToolsEnabled` / `selfHostedWorkersEnabled` fields have
**zero consumers anywhere in `apps/` or `packages/`** outside those parsers and
the control plane's own writer.

*The exploit.* An operator downgrades a tenant to a plan without MCP, or a plan
whose MCP entitlement was never granted (`mcp_enabled INTEGER NOT NULL DEFAULT
0` — the schema default is OFF). The admin API accepts it, the row is written,
the control plane echoes it back. `tools/call` keeps executing, keeps reaching
upstream MCP servers, and keeps spending. This is FC-1's shape — an operator
action that reports success and changes nothing — on a control that is also the
monetisation boundary.

*Why nothing caught it.* Because the port is individually correct, has a test,
and lives in a table (`plans`) the mechanical gate has already registered as an
authority of a DIFFERENT control that every spend Worker DOES enforce. §3.2 asks
*"does every Worker in the role set enforce `quota-plan`?"*, probes for
`"quota_resolution_unavailable"`, finds it on all three, and passes.

*The proof this is not a triage artefact.* `parity-audit-dead-packages.md:458`
already listed `entitlements` as *"❌ in-memory — no durable leg in any
posture"*, in a table where `auth`, `credentials`, `upstreams`, `approvals` and
`audit` sat beside it. Four of those six have since been closed. `entitlements`
was left, and no later wave re-triaged it, because it stopped appearing in the
search the later waves were running.

*Cost to close.* Low. mcp already binds the CONTROL database, already reads
`plans` (`admission/quota.ts:294`), and already performs the role walk
(`auth.ts:289`). The gate is a decision over two values it already has in hand.
`apps/gateway/src/assets/entitlements.ts` is the exact template — it is the same
Rust plan-OR-role walk, already ported, for `assets.host`.

---

### R2 — THE PER-CREDENTIAL TOKEN BUDGET STOPS ONE SPEND WORKER OF THREE — **CLASS A (narrow)**

**Blast radius: any credential an operator zeroed. Money.**

`crates/ferrogate-gateway/src/auth.rs:1344`, inside `authenticate_durable` —
the CREDENTIAL resolution step every handler in that one process shared:

```rust
if decision.monthly_token_budget == Some(0) {
    return Err(AuthError { status: TOO_MANY_REQUESTS, code: "token_budget_exceeded", … });
}
```

TS reproduces it on the gateway, verbatim and with the Rust reference in the
comment (`apps/gateway/src/keys/resolver.ts:322`, `null` correctly meaning
unlimited). `apps/mcp` and `apps/agent-runtime` **do not select the column at
all**: `apps/mcp/src/auth.ts:285 TENANT_KEY_SQL` and
`apps/agent-runtime/src/durable/adapters.ts:73 FIND_KEYS_BY_PREFIX_SQL` both
open the same `api_keys` row, both take `request_limit_per_minute` off it, and
neither takes `monthly_token_budget`. Neither Worker can emit
`token_budget_exceeded` — it is absent from both refusal-code sets.

So: an operator sets a key's token budget to zero — the documented kill switch
for a key that is burning money — and the key is refused on
`/v1/chat/completions` and **admitted on MCP `tools/call` and
`POST /v1/agent-jobs`**. Word for word the wave-16 bypass and FC-2, on a fifth
control.

**Scope it honestly.** Only the degenerate `== 0` leg is a fleet regression.
Rust's FULL committed-token enforcement (`sum_api_key_committed_tokens` →
`reserve_token_budget`) was per-HANDLER in Rust —
`server/{embeddings,images,messages}.rs` and `governed_decision.rs` — i.e. on
inference paths only. The TS gateway's `ratelimit/token-budget.ts` is a faithful
port of that and its absence from mcp/agent-runtime is **parity, not drift**.
The `== 0` refusal is the part that lived in the shared auth path, and that part
is lost on two Workers of three.

*Why nothing caught it.* `api_keys` is a **declared non-control**
(`fleet-control-matrix.test.ts:1071`), so §4.3 exempts every column of it, and
§4.1's refusal-code ratchet only fires when two Workers emit the SAME code with
different statuses — a code that one Worker cannot emit at all is invisible to
it.

---

### R5 — GUARDRAIL EVIDENCE IS NOT DURABLE ANYWHERE — **CLASS A (forensics)**

`apps/gateway/src/guardrails/config.ts:184` binds
`evidence: new InMemoryGuardrailEvidenceSink()` **unconditionally** — not
`?? `-guarded, not `CONTROL_DB`-conditional. There is no durable implementation
of `GuardrailEvidenceSink` in the repo and **no evidence table in
`sql/d1-ts/`** (`grep -rn guardrail_evidence sql/d1-ts/` → nothing).

Rust persisted it: `state_quota_and_policy.rs:935 ::record_guardrail_evaluation`
composes the evaluation into an admin audit event and routes it through
`record_admin_audit_event`, i.e. into durable storage, with a dedicated
`record_guardrail_evidence_persistence_failure` metric for when the queue is
full.

So on TS every guardrail decision — what was screened, what matched, what was
blocked, under which policy revision — dies with the isolate. The request-path
BEHAVIOUR is unaffected (the in-memory sink never fills across isolates, so
`guardrail_evidence_unavailable` cannot wrongly deny), which is exactly why it
is invisible: this is a **compliance and incident-response regression, not an
availability one**. For a product whose guardrail feature exists to be
auditable, "we blocked it and kept no record" is a material loss.

Note the asymmetry that makes this a fleet finding rather than a gateway one:
`apps/gateway/src/assets/handlers.ts:649` DOES bind a durable
`assetAuditSinkFromEnv` (`D1AssetAuditSink` → `audit_events`). The same Worker
persists asset audit and discards guardrail evidence.

---

### R4 — `apps/mcp` KEEPS NO DURABLE AUDIT TRAIL — **CLASS A (minor)**

`ports.audit` is `InMemoryAuditSink` in every posture (`resolvePorts` does not
override it), and it has **20 call sites** across `tools.ts` (9), `dispatch.ts` (7),
`identity/routes.ts` (3) and `identity/oauth.ts` (1) — including every tool execution,
every credential grant and every OAuth completion. All of it is per-isolate and
lost. The gateway writes `audit_events` durably; in Rust the two surfaces were
one process writing one log. Same class as R5, lower value, and it is the last
survivor of the `parity-audit-dead-packages.md` §7.2 table.

---

### R3 — `apps/mcp` `resources/read` SERVES NOTHING IN PRODUCTION — **CLASS B**

`ports.assets` is `InMemoryAssets` in every posture; `apps/mcp/src/ports.ts:673`
says so and explains why (the durable `stored_assets` + R2 read was deferred, no
new binding needed). `tools.ts:537` is the only consumer. Consequence: MCP
resource reads answer not-found on a real deployment. **Fails closed**, no money
and no data exposure, and the module docblock is honest about it. Recorded as a
capability gap rather than a control gap; it belongs in `MISSING-TRIAGE.md`
rather than here, and it does not block deleting `crates/`.

---

### D1 — THE SAME MISSING BINDING FAILS OPEN ON TWO WORKERS AND CLOSED ON THE THIRD — **CLASS A (configuration)**

With `CONTROL_DB` unbound (which is the **committed default** for
`apps/agent-runtime` — see B4):

| Worker | Lifecycle authority behaviour | Direction |
|---|---|---|
| `apps/mcp` | `durableLifecycle(env)` → `UnboundLifecycleGate.admit()` returns `"unavailable"` → `503 lifecycle_status_unavailable` (`src/lifecycle.ts:398`, `:415`) | **CLOSED** |
| `apps/agent-runtime` | `d1LifecycleRowSource(undefined, tenant).tenantRow()` → `if (control === undefined) return null` (`src/ports.ts`) — "no row" is indistinguishable from "not suspended" | **OPEN** |
| `apps/gateway` | `lifecycleRowSourceFromEnv` builds `D1LifecycleRowSource(undefined, tenantDb)` whenever EITHER handle exists — same shape | **OPEN** |

The drain has the same split by explicit decision:
`readDurableDrain(undefined)` returns `NOT_DRAINING`
(`apps/agent-runtime/src/drain.ts:177`), reasoned as *"an UNBOUND control
database is a different fact and is not a refusal"*. That reasoning is
defensible for the drain and is **not** defensible for the suspension authority,
and the two are currently on the same rule.

**The dangerous posture is the HALF-bound one, and it is not in
`CLOUD-VERIFICATION.md`.** A deployment that binds `DB` and forgets
`CONTROL_DB`, while the committed `FG_DEV_IN_MEMORY_PORTS = "1"` (B1) is left in
place, gets a `resolveDeps` that **succeeds** — `apiKeys` is durable,
`workerIdentities` falls back to the in-memory dev table instead of returning
`undefined` — so the Worker serves traffic with:

* tenant suspension silently inoperative (tenant tier reads `null`),
* the operator drain silently inoperative (`NOT_DRAINING`),
* guardrail screening silently inoperative (var-only, and `FG_DEV_A2A_GUARDRAILS`
  is not committed),
* agent-upstream withdrawal silently inoperative (var-only).

Four fleet controls off, no error, every local test green. B4/B11 describe only
the fully-unbound case and correctly call it fail-closed; the half-bound case is
the one that ships.

---

## 3. Weighing the gates honestly against M22

M22's lesson, in the document's own words: *neutralising the drain DECISION while
leaving the source text intact turned 2 behavioural assertions red and left
**every source-text gate GREEN**.* So the only honest coverage number is the
**behavioural** one.

### 3.1 The census

| File | Assertions | Behavioural (drives a Worker or a composition root) | Source-text |
|---|---|---|---|
| `apps/gateway/test/fleet-control-matrix.test.ts` | 66 | **3** (§5.1, §5.2, §5.3 — `SELF.fetch` into the deployed gateway) | 63 |
| `apps/gateway/test/fleet-consistency.test.ts` | 35 | **0** — it is the LEDGER, and §6.1 says so | 35 |
| `apps/mcp/test/drain-fleet.test.ts` + `fleet-tenancy-suspension.test.ts` + `fleet-guardrail-activation.test.ts` | 38 | **most** — `SELF` for the mcp door, the real Hono apps / `resolveDeps` for the other two | some |
| `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` | 5 | **5** | 0 |

**So of the 101 assertions in the two files `FLEET-CONSISTENCY.md` presents as
"the fleet gates", 3 are behavioural — the three M22 proved are the only ones
that can catch a Worker that reads the operator's document and discards the
answer.** The other 98 are exactly the class M22 showed stays green. That is not
an argument against them — a source-text ratchet is the right instrument for
"has a Worker been added", "has an authority moved", "has a code changed status"
— but the document's claim of "13 of 23 capabilities mechanically gated" should
be read as *13 of 23 mechanically WATCHED for source-text drift, 5 behaviourally
proven end to end*.

### 3.2 Which controls have a behavioural fleet proof

| Control | Behavioural fleet proof? |
|---|---|
| drain | ✅ `drain-fleet.test.ts` (mcp + agent-runtime, one write) + matrix §5.1–5.3 (gateway) |
| suspension | ✅ `fleet-tenancy-suspension.test.ts` — three doors, one write |
| guardrail binding | ✅ `fleet-guardrail-activation.test.ts` — now including agent-runtime's `resolveDeps` |
| agent-upstream withdrawal | ✅ `agent-upstream-fleet-withdrawal.test.ts` |
| admission ladder (quota/budget/wallet) | ⚠️ per-Worker suites + `admission-consistency.test.ts` (source-text). No single test applies one quota and observes three doors. |
| RPM counter (FC-5) | ❌ **impossible offline** — see B10 |
| **plan entitlements** | ❌ **no gate of any kind — R1** |
| **token budget** | ❌ **no gate of any kind — R2** |
| tenant fencing | ❌ INSPECTION only, as §9.4 admits. Spot-checked here: DO addressing is fenced by construction (`apps/agent-runtime/src/runs/addressing.ts:35` joins `tenantId`), and mcp's upstream catalog is fenced by an authenticated bound parameter. No defect found; still ungated. |

### 3.3 The gate's structural blind spot, stated as a property to add

Everything in §1.4 reduces to one missing assertion, which would have caught R1
and R2 and would keep catching this class:

> **Every COLUMN of a shared control table that any Worker PARSES must have at
> least one Worker that CONSUMES it in a decision** — or be listed as a
> deliberate non-decision, with the polarity of §4.3 (default FAIL).

`plans.mcp_enabled` → parsed 4×, consumed 0×. `api_keys.monthly_token_budget` →
parsed 1×, consumed 1×, absent from the two other Workers that open the same
row. Both are one query away from red.

### 3.4 One observation about the gate's reliability, recorded unresolved

While running `apps/gateway/test/fleet-control-matrix.test.ts` **alone**, I
observed it **RED twice in succession** on an unmodified tree —
`3 failed | 63 passed (66)`, the three failures being exactly §5.1, §5.2 and
§5.3, i.e. **the only three behavioural assertions in the file**. The clearest
of the three:

```
5.3 the deploy-time var keeps working — the durable read is an ADDITION
  expected { status: 400, code: "invalid_request" }
        to deeply equal { status: 503, code: "node_draining" }
  test/fleet-control-matrix.test.ts:1259
```

i.e. with `bindings.GATEWAY_DRAIN = "true"` set, the drain gate did not refuse at
all. It then passed **18 consecutive runs** afterwards (8 default reporter,
3 verbose, 1 with a cleared `node_modules/.vite`, plus 6 in pairings), and I
could not reproduce it.

**Most likely cause, and why I am not calling it a gate defect:** the two RED
runs fell inside the window in which concurrent agents were writing
`apps/gateway/src/assets/service.ts` and `apps/agent-runtime/src/ports.ts` (§0).
A transient mid-write tree explains a Worker bundle that failed to mount a
middleware. **Recorded rather than smoothed over** because the alternative
explanation — an intermittent failure in the only three assertions that hold the
fleet's most expensive fix — is the kind of thing this project has been bitten by
before, and because a reader who sees this file red once should know it has been
seen before and not yet explained. **Action: re-run it on a quiescent tree
before the cutover and confirm 20/20 green.**

---

## 4. The unverifiable-locally residue, triaged

For each blocker: **A** = a regression that blocks deleting `crates/`,
**DEPLOY** = a procedure item a human executes, **LIMIT** = a genuine platform
constraint. And, separately and more importantly: **can it silently produce a
security or money failure in production while the local tree is fully green?**

| # | What | Class | Silent in production? |
|---|---|---|---|
| **B1** | `FG_DEV_IN_MEMORY_PORTS = "1"` committed in mcp + agent-runtime | **DEPLOY** | **PARTLY — and worse than the row says.** On mcp the flag no longer disables auth/admission/lifecycle/guardrails (all four are bound in BOTH postures now), so its residual effect is the durable upstream catalog and the credential store — fail-closed. On **agent-runtime** it is the enabler of the half-bound posture in D1: with `CONTROL_DB` missing it turns a fail-CLOSED `resolveDeps` into a serving Worker with four fleet controls silently off. **This row should be re-written around agent-runtime, not mcp.** |
| **B2** | R2 bucket declared, none exists | DEPLOY | No — a declared-but-absent bucket fails the DEPLOY outright; a deleted stanza gives `503 asset_bucket_unavailable` across the whole family, mutation-proven. LOUD. |
| **B3** | account token lacks KV, mcp declares `MCP_OAUTH_KV` | LIMIT/DEPLOY | No — deploy fails rather than degrading. But note the consequence if the stanza is DROPPED for the run: `durableIdentityBound(env)` is false, `credentials` stays `InMemoryCredentialStore` and `cipher` stays an ephemeral per-isolate key, so stored MCP credentials do not survive isolate eviction. Fail-closed, and it must be **stated in the result** rather than assumed passed. |
| **B4** | agent-runtime declares no D1 (both stanzas committed commented) | **DEPLOY**, with an A-shaped edge | **YES, via D1.** Fully unbound is loud (`resolveDeps → undefined`, every authenticated surface refuses). Half-bound + B1 is silent and turns off suspension, drain, guardrails and upstream withdrawal on that Worker. **The most dangerous single row in this table.** |
| **B5** | Analytics Engine required for telemetry | DEPLOY | No — declared-but-unavailable fails the deploy. |
| **B6** | `FG_REQUIRE_PRODUCTION_MTLS = "0"` committed | **LIMIT**, mis-labelled as DEPLOY | **YES, bounded.** At `"0"` (`admitTransport` → `marker_contract`, `middleware/auth.ts:266`) every channel is admitted, including `symmetric_aead` and the bare unverified `mutual_tls` marker. It is **not** an authentication bypass — the six worker-plane callbacks still require the AEAD-sealed frame keyed on `self_hosted_worker_registrations`. It is transport-downgrade acceptance. And the remediation in `CLOUD-VERIFICATION.md` ("override to `1`") is only correct where the ZONE has Cloudflare mTLS configured: the kept PORT-TODO at `auth.ts:238` records that a Worker never sees the handshake, so `"1"` admits `verified_mutual_tls` only, which `request.cf.tlsClientAuth` can supply **exclusively on a properly configured zone** and never under `--local`. Reclassify this row from "flip a var" to "a platform limit with a zone precondition". |
| **B7** | `ADMIN_CONSOLE_JWT_SECRET` unset | DEPLOY | No — fail-closed and LOUD (`503 admin_console_unconfigured` on the whole console + both SSO callbacks). Correct as written. |
| **B8** | per-tenant IdP `env://` secrets must exist | DEPLOY | No — fails the login closed. The row's own caveat is right: indistinguishable from an IdP outage in the logs, so check it explicitly. |
| **B9** | two control migration files | DEPLOY | No — an unapplied `0002` makes every OIDC callback refuse. LOUD. |
| **B10** | cross-script `RATE_LIMIT` stanzas committed COMMENTED | **LIMIT + DEPLOY**, no mechanical backstop | **YES — MONEY.** Left commented, `counterFromEnv` degrades to a per-isolate `InMemoryRequestCounter`: a credential capped at 60 rpm is charged 60 on the gateway **plus 60 × N mcp isolates plus 60 × M agent-runtime isolates**, and nothing anywhere errors. The other four admission legs stay durable, so the deployment looks correct. workerd cannot resolve a `script_name` binding offline (`binding "RATE_LIMIT" refers to a service "core:user:ferrogate-gateway", but no such service is defined` — 0 collected tests if uncommitted), so this is **genuinely ungatable locally**, and `env-var-drift.test.ts` pinning the three rot modes of a COMMENT is the most that can be done. **Top of the honest-cost list.** |
| **B11** | the drain document needs the SAME control DB uuid on all three spend Workers | **DEPLOY** | **YES.** No stanza, no placeholder, nothing to typecheck: the drain's fleet-wideness is a function of three `database_id` values matching. Point two Workers at different control databases and each drains independently, every local test green, `GET /admin/v1/drain` cheerfully reporting `draining: true`. The row is correct and it is the second-most-silent item here. |

### 4.1 The verification steps

`V-A3`, `V-FC1`, `V-FC2`, `V-FC3` are all **well-formed and sufficient** — each
one applies ONE operator action and observes the doors that must shut, which is
the only shape that can prove a fleet property. Two gaps:

* **There is no `V-` step for R1 or R2**, because neither was known. Add:
  *set `plans.mcp_enabled = 0` for the tenant, then call MCP `tools/call` —
  expect `mcp_tools_disabled`*; and *set `api_keys.monthly_token_budget = 0`,
  then call all three spend Workers — expect `429 token_budget_exceeded` on all
  three.* Both currently FAIL. They should be added as failing rows rather than
  omitted.
* **There is no `V-` step for B10**, the one item with no mechanical backstop at
  all. Add: *drive N > 1 concurrent isolates on mcp against a 60-rpm credential
  and confirm ONE window is charged.* Without it the RPM ceiling is the only
  control in the fleet that will be neither locally gated nor live-verified.

### 4.2 The honest cost of local-only discipline — the silent list

Ranked. These four can produce a **security or money failure in production with
a fully green local tree**, and no amount of further offline work can close
them:

1. **B10 — the shared RPM counter.** Money. Silent. Ungatable offline by
   construction. A 3× (or N×) quota bypass wearing a green board.
2. **B4 + B1 half-bound agent-runtime (D1).** Security AND money. Silent. Four
   fleet controls off — suspension, drain, guardrails, upstream withdrawal — on
   a Worker that serves normally.
3. **B11 — three control-database uuids that must be equal.** Availability +
   incident response. Silent. The drain reports success and covers a subset.
4. **B6 — the mTLS posture.** Security, bounded by the AEAD frame. Silent.
   Zone-dependent, so it is a platform limit with a precondition rather than a
   var flip.

And the two that are **not** on this list although they look like they should
be: **B2** and **B5** both fail the DEPLOY rather than degrading, and **B7**
fails closed and loud. Those three are the shape the rest of the residue should
be pushed toward.

---

## 5. Verdict

**The fleet work of waves 21–22 is sound and I could not break any of it.** Every
one of the five closed divergences holds under independent re-derivation, the
guarded operation sets are correct rather than approximately correct, and the
mechanical gate is the right instrument for the class it watches.

**And the enumeration behind it is incomplete along a seam the gate cannot see.**
Three live control gaps (R1, R2, R5) sit one level below the granularity the
matrix operates at — inside a COLUMN of a table that is already registered or
already exempted. R1 is the material one: a control Rust implemented, mounted at
three call sites, and *specifically hardened against being missed a third time*,
which the TS port parses in four Workers and enforces in none, on the surface
that spends money and reaches third-party systems.

That is the answer to *"did the port LOSE anything that worked"*, and the answer
is yes, three times, in a place nobody had looked because the previous wave's
own success defined where to look.

**Recommendation.** Merge `main-ts` → `main`: **GO**. Delete `crates/**`:
**hold on R1, R2, R5** — R1 is a few hours' work against an existing template
(`apps/gateway/src/assets/entitlements.ts`), R2 is two SQL columns and one
branch each on two Workers, R5 is a table and a sink. Add the §3.3 column
property to `fleet-control-matrix.test.ts` in the same commit, or the next wave
re-derives this page instead of reading it. Re-run
`fleet-control-matrix.test.ts` 20× on a quiescent tree (§3.4) before the
cutover. And carry §4.2's four-item silent list into the live run as the thing
that verification is FOR — those four are what the local-only discipline
genuinely cannot buy.
