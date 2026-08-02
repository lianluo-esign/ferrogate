# FerroGate — triage of the 37 MISSING modules (wave 19)

**Baseline:** `main-ts`, 2026-08-01. Input: the 37-row `MISSING` list in
`docs/rewrite/MODULE-OWNERSHIP.md`. Every row was re-opened in `crates/**` and
judged on its own evidence.

## The rule this document applies

`MODULE-OWNERSHIP.md` was written under the old rule — **the Rust tree is the
specification, so every MISSING row is a blocker.** The project owner has since
stated that the Rust system is itself a half-finished product and that
TypeScript is the forward development platform. The bar is therefore no longer
"matches Rust"; it is "is the TypeScript system complete and correct on its own
terms". That splits the 37 rows three ways:

| Class | Meaning | Blocks cutover? |
|---|---|---|
| **A — REGRESSION** | The behaviour was COMPLETE, WIRED and REACHABLE in Rust and the TS port lost it. | **YES** |
| **B — RUST UNFINISHED** | Built but never wired: no production caller, no producer, orphaned behind a `pub use`. Copying it faithfully would port a design, not a behaviour. Product backlog on TS. | No |
| **C — DELIBERATE / OBSOLETE / PLATFORM** | Its purpose evaporates on Workers (AF_UNIX IPC, process spawn, filesystem), it is `#[cfg(test)]`-only, or it is an explicit product decision. | No |

Two tests decided most rows, and both are mechanical rather than editorial:

1. **Is there a production caller?** Not "is it exported" — `pub use` in a
   `lib.rs` is not a caller. Four modules in this list are reachable only from
   their own `#[cfg(test)]` siblings.
2. **Is the transport/execution model expressible on workerd?** `UnixStream` +
   `SO_PEERCRED`, `Command::new`, `std::fs::write` and `TcpStream` are not
   missing APIs; they are facilities the sandbox exists to deny.

---

## THE ANSWER

| Class | Modules | Rust lines | Share |
|---|---:|---:|---:|
| **STALE — already PORTED, row was wrong** | 9 | 5,896 | 21.3% |
| **A — REGRESSION (blocks)** | 8 | 3,391 | 12.3% |
| **B — Rust never finished (backlog)** | 15 | 6,664 | 24.1% |
| **C — deliberate / obsolete / platform** | 5 | 11,693 | 42.3% |
| **total** | **37** | **27,644** | 100% |

**CLASS A is NOT empty. It contains 4 capabilities across 8 modules — and 1,389
of its 3,391 lines are `extensions.rs`, of which only a small projection is
actually the regression (§A3).** None of the four is in the enterprise-identity,
coding-agent or external-action families that dominate the line count; those are
all B or C. The A list is at the bottom of this document with blast radius per
item.

Per-module ledger (the 37 rows, one line each):

| Class | Modules |
|---|---|
| STALE→PORTED (9) | `auth-service/{admin_console,sso,server,scim,saml,http,lib}.rs`, `storage/control_plane_store_d1/auth_quota.rs`, `gateway/server/managed_action_guardrail.rs` |
| **A (8)** | `gateway/budget_alerts.rs`, `gateway/function_egress.rs`, `gateway/function_egress_cloudflare.rs`, `runtime/function_egress.rs`, `runtime/function_token.rs`, `runtime/supabase_edge_function.rs`, `gateway/extensions.rs`, `gateway/client_action_time.rs` |
| B (15) | `runtime/coding_agent/*` (11), `runtime/cloudflare_agent_memory.rs`, `runtime/cloudflare_container_tether_audit.rs`, `mcp/mcp_worker_deploy.rs`, `runtime/egress_dispatch_stage.rs` |
| C (5) | `agent-worker/external_actions.rs`, `gateway/server/external_actions.rs`, `runtime/managed_external_action.rs`, `agent-worker/recorded_evidence.rs`, `cli/reference.rs` |

---

## PART 1 — STALENESS PASS (9 rows were already wrong when written)

`MODULE-OWNERSHIP.md` carries its own concurrency warning: the sweep ran while
wave-18 agents were creating `packages/identity`, `packages/sso` and
`apps/control-plane/src/session`. Nine rows are stale as a result. Eight are the
predicted enterprise-identity ones; **one more is stale for an unrelated reason
and was NOT predicted** (`managed_action_guardrail.rs`).

### 1.1 The enterprise-identity family — 8 rows, now real

`apps/control-plane/src/index.ts:103-112` mounts three surfaces outside
`registerRoutes` (they are not contract operations, so they cannot move the
anti-drift count):

```
MOUNTED_SESSION_ROUTES = mountAdminConsoleSession(app)      // session/index.ts
IDENTITY_APP           = createIdentityRoutes(...)          // @ferrogate/identity
MOUNTED_SSO_ROUTES     = mountSsoRoutes(app)                // identity/routes.ts
```

All **17 non-health paths** `crates/ferrogate-auth-service/src/server.rs` served
now exist in TS. Path-for-path:

| Rust `server.rs` path | TS mount |
|---|---|
| `/v1/admin/register` `/login` `/refresh` `/logout` `/me` | `apps/control-plane/src/session/routes.ts` (869 lines) |
| `/v1/admin/team` `/team/invite` `/team/members/{id}` | same |
| `/scim/v2/Users` `/Users/{id}` `/Groups` `/v1/admin/team/scim-token` | `packages/identity/src/routes.ts` → `scim/service.ts` |
| `/v1/admin/auth/sso/authorize` `/sso/callback` | `packages/identity/src/oidc/flow.ts` |
| `/v1/admin/auth/saml/authorize` `/saml/acs` `/v1/admin/team/sso-config` | `apps/control-plane/src/identity/routes.ts` → `packages/sso` |

Volume and depth, measured not asserted:

* `packages/sso/src` **2,256 lines**, `packages/identity/src` **2,982**,
  `apps/control-plane/src/session` **2,024**, `apps/control-plane/src/identity`
  **1,186** — **8,448 lines** against 5,896 lines of Rust.
* The security-critical half is really there:
  `packages/sso/src/redirect-binding.ts:139-185` verifies the detached
  HTTP-Redirect signature with `crypto.subtle.verify("RSASSA-PKCS1-v1_5", …)`
  against a certificate parsed in `x509.ts`, and the header states "There is no
  branch that returns normally without `crypto.subtle.verify`". This matches the
  Rust binding choice exactly — `saml.rs:9-14` implements **only** the
  HTTP-Redirect binding and says so, deliberately avoiding XML-DSig
  canonicalization. The TS is a parity port, not a narrower one.
* SCIM deprovisioning is behavioural, not shape-only:
  `packages/identity/src/scim/service.ts:206-234` handles `active:false` by
  deactivating the membership AND revoking gateway keys (`#517` — "revoking
  tokens alone leaves a deprovisioned user" with a live key), and `:275-301`
  parses all three `PATCH` spellings real IdPs send.
* The STORAGE half — the reason `MODULE-OWNERSHIP.md` said "not just a missing
  router" — exists: `apps/control-plane/src/session/store.ts:182-300`
  (`admin_users`, `admin_user_tenant_memberships`, `admin_user_refresh_tokens`)
  and `apps/control-plane/src/identity/adapters.ts:321-492`
  (`sso_provider_configs`, `sso_pending_flows`, refresh-token burn).
* Gated: `apps/control-plane/test/{console-session,identity-mount,sso-store-contract}.test.ts`.

| Row | Old class | Corrected |
|---|---|---|
| `ferrogate-auth-service/src/admin_console.rs` (1481) | MISSING | **PORTED** — `session/routes.ts`, `session/index.ts` (both cite the `.rs` path) |
| `ferrogate-auth-service/src/sso.rs` (970) | MISSING | **PORTED** — `packages/identity/src/oidc/flow.ts`, `index.ts` |
| `ferrogate-auth-service/src/server.rs` (622) | MISSING | **PORTED (partial)** — 17/17 identity paths; see §1.2 for the other 6 |
| `ferrogate-auth-service/src/scim.rs` (598) | MISSING | **PORTED** — `packages/identity/src/scim/service.ts` |
| `ferrogate-auth-service/src/saml.rs` (551) | MISSING | **PORTED** — `packages/sso/src/*` |
| `ferrogate-auth-service/src/http.rs` (487) | MISSING | **OBSOLETE-ON-CF** — hand-rolled bounded HTTP request/response reader; Hono + `Request`/`Response` are the platform equivalent. Error shapes cited by `packages/identity/src/errors.ts` |
| `ferrogate-auth-service/src/lib.rs` (117) | MISSING | **PORTED (subsumed)** — crate root is `mod`/`pub use` only (`lib.rs:33-60`); with every module owned, nothing remains |
| `ferrogate-storage/src/control_plane_store_d1/auth_quota.rs` (519) | MISSING | **PORTED** — quota/plan half already was; admin-user/SSO/refresh-token half is `session/store.ts` + `identity/adapters.ts` |

### 1.2 The 6 auth-service routes that are NOT identity — CLASS C

`server.rs` also served `/v1/auth/resolve-api-key`, `/v1/auth/authorize`,
`/v1/rbac/roles{,/id}`, `/v1/rbac/bindings{,/id}`, `/v1/tenants`. These are the
**REST indirection the gateway used to reach an out-of-process auth service** —
`lib.rs:9-11` says so outright: "the gateway should consume the REST API
decision output, not embed role, permission, or binding evaluation in the
request hot path." On Workers that indirection is the thing that disappears: the
TS gateway resolves keys directly from the D1 `api_key_directory` binding, and
RBAC/tenant CRUD are contract operations (`/admin/v1/roles`,
`/admin/v1/tenant-accounts`). **CLASS C — obsolete-on-CF, replacement cited.**

### 1.3 The unpredicted stale row — `server/managed_action_guardrail.rs`

Not part of the identity work, stale for a different reason: the sweep's
signature index missed it. `apps/mcp/src/ports.ts:507-511` says

> Clean-room port of `crates/ferrogate-gateway/src/server/managed_action_guardrail.rs`
> (`evaluate_managed_action_guardrail_async` + `payload_text`)

and `ports.ts:466-505` carries `ManagedActionGuardrailConfig`,
`guardrailPayloadText` and the deterministic detector binding that
`apps/mcp/src/tools.ts`'s chokepoint runs on `tools/call` and
`POST /v1/mcp/tool/execute`. Rust's own live caller is the same chokepoint
(`server/local.rs:3847` and `:4124`, inside `handle_tool_execute_with_backend`,
request + response stages). **Corrected: PORTED (partial).** The unported
remainder is `ManagedActionClass` derivation *from a
`ManagedExternalAction`* — which has no CF caller at all (§3.1), so the
remainder is C, not a gap.

> **Method note for future sweeps.** Both stale causes are the same failure:
> a signature index scored against file *names* and *rare identifiers* cannot
> see a port that renames (`payload_text` → `guardrailPayloadText`) or that
> lands mid-audit. The `.rs`-path citation convention is the control that
> caught all nine — 9/9 stale rows had a TS file naming the `.rs` path. Run the
> citation grep FIRST next time; it is one `grep -rl` and it is decisive.

---

## PART 2 — CLASS C: deliberate, obsolete, or a platform floor (5 modules, 11,693 lines)

These are 43% of the MISSING line count and none of them blocks.

### 3.1 The external-action capability boundary — 3 modules, 10,820 lines

| Module | Lines | Verdict |
|---|---:|---|
| `agent-worker/src/external_actions.rs` | 6,552 | **C** |
| `ferrogate-gateway/src/server/external_actions.rs` | 2,271 | **C** |
| `ferrogate-runtime/src/managed_external_action.rs` | 1,997 | **C** (typed contract for the two above) |

**Implemented?** Yes, thoroughly — not a stub. The gateway authorizer at
`server/external_actions.rs:101-311` resolves per-tenant RBAC fail-closed,
binds the action to a guardrail policy, resolves workspace→project attribution
(#519), pulls the run's real `trace_id` (#305), stamps the capability
fingerprint onto guardrail evidence (#306), and refuses rather than silently
narrowing when a project-scoped policy could not be selected. This is the most
carefully written code in the MISSING list.

**Reachable how? — the decisive fact.** The only production transport is an
**AF_UNIX socket** whose parent directory must be uid-owned and mode `0700`
(`server/external_actions.rs:466`, started at `server/mod.rs:395`; client at
`agent-worker/src/external_actions.rs:1158-1190`, kernel peer-authenticated via
`SO_PEERCRED` — the non-Linux `verify` at `:1300-1305` returns
`Err("… requires Linux SO_PEERCRED")`). The HTTP variant that would have made
this a remote protocol is `#[cfg(test)]` on **both** sides
(`server/external_actions.rs:831`; `agent-worker/src/external_actions.rs:1307`,
`:1324`). So the gate only ever protected an agent-worker process **co-located
on the same host as the gateway**.

And the thing being gated does not exist on workerd either:
`agent-worker/src/external_actions.rs` is the in-process action **executor** —
`execute_governed_cli_action` (`:1821`), `execute_governed_filesystem_action`
(`:2119`), `execute_governed_browser_action` (`:1785`),
`execute_governed_network_egress_action` (`:1749`), driving `std::fs`,
`TcpStream` and spawned processes. `MODULE-OWNERSHIP.md` already classes its
immediate siblings — `handler_runtime.rs`, `backends.rs`,
`firecracker_guest_exec.rs` — **OBSOLETE-ON-CF for exactly this reason**;
marking the executor they call MISSING was an inconsistency in that document.

**What TS does instead, and why it is not a downgrade.** `apps/agent-runtime/src/runs/governance.ts`
(header §1-4) keeps the DECISION at the API boundary — action identity,
capability envelope, isolation grant pinned to `enableInternet:false` +
`interceptHttps:true`, and a sealed-by-default egress allowlist — and the
per-action enforcement is the platform's: a `@cloudflare/sandbox` container
cannot reach the network at all. The Rust per-action broker exists *because* a
local process could.

**Backlog note (B, post-cutover):** the 9-variant typed `ManagedExternalAction`
is a better model than `requiredCapabilities: string[]` and should be revisited
if FerroGate ever adds an in-container action broker. It is a product decision,
not a port debt.

### 3.2 `agent-worker/src/recorded_evidence.rs` — 634 lines — CLASS C

Fully implemented and genuinely good: one redaction chokepoint (`redact_scoped`)
that every excerpt/metadata/argv builder in the crate delegates to, with a
deny-list pinned from the *other* side by
`recorded_evidence_test.rs` (it enumerates the header names the provider/secret
crates emit, so dropping an entry fails a test rather than passing one).

But every one of its seven callers is inside `agent-worker`:
`backends.rs`, `firecracker_guest_exec.rs`, `handler_runtime.rs`,
`external_actions.rs`, `handlers.rs`, `self_hosted_execution.rs`,
`x402_client.rs` — that is, the in-process executor (C, §3.1), the microVM
channel (already OBSOLETE-ON-CF), and x402 (already DELIBERATELY-DROPPED). **The
Rust gateway never calls it**; redaction was always the worker's job, done
before bytes crossed the wire. In the CF topology the executing thing is either
a platform sandbox or a customer-run self-hosted worker binary that still
carries this code. No TS surface observes raw upstream bytes to redact.

**Backlog trigger, stated precisely:** the day `apps/agent-runtime` grows an
in-Worker executor that records an excerpt of an upstream response, this
becomes a required port on day one. Until then there is nothing to protect.

### 3.3 `ferrogate-cli/src/reference.rs` — 239 lines — CLASS C

**The row is a category error.** `crates/ferrogate-cli/src/lib.rs:56-57`:

```rust
#[cfg(test)]
mod reference;
```

It is compiled **only under `cfg(test)`**. The shipped `ferrogate` binary cannot
render `docs/cli-reference.md` at all; the module is a drift test that
regenerates under `FERROGATE_REGENERATE_DOCS=1 cargo test`. It is build/docs
tooling, not product behaviour — the same category `MODULE-OWNERSHIP.md`'s own
method step 2 excludes as TEST-ONLY, missed because the filter keyed on path
patterns rather than on `cfg`. Nothing about it blocks a cutover.

---

## PART 3 — CLASS B: Rust was never finished (15 modules, 6,664 lines)

Every module here is *implemented and tested* and has **no production caller**.
Porting them would port a design that was never exercised.

### 4.1 The coding-agent five-phase contract (#472) — 11 modules, 5,098 lines

`credential_broker.rs` (1114), `materialize.rs` (793), `write_back.rs` (664),
`container_adapter.rs` (640), `run.rs` (356), `bootstrap.rs` (345),
`extract.rs` (301), `work_product_artifact.rs` (251), `mod.rs` (219),
`adapter.rs` (209), `error.rs` (206).

Three independent facts, any one of which is sufficient:

1. **The adapter is never constructed outside its own tests.**
   `ContainerCodingAgentAdapter` is declared at `container_adapter.rs:119` and
   implements the trait at `:248`; the only `::new(` call in the entire
   `crates/` tree is `container_adapter_test.rs:208`. There is no registry, no
   dispatcher, no config discriminant that selects it.
2. **Nothing outside the module tree references it**, with exactly one
   exception: `ferrogate-gateway/src/server/agent_jobs.rs:79` imports
   `coding_agent::WorkProductView` and calls
   `WorkProductView::from_timeline_events` at `:892`.
3. **That one exception is provably inert.** The projection filters timeline
   events on `WORK_PRODUCT_ARTIFACT_OBJECT = "coding_agent.work_product"`
   (`work_product_artifact.rs:62`) — and **no non-test Rust code anywhere writes
   an envelope with that `object`.** The producer is `extract.rs`, reached only
   through the adapter of fact (1). So `work_products` is `[]` on every
   `getAgentJobResult` a Rust deployment can serve.

The TS is therefore not behind: `apps/agent-runtime/src/runs/lifecycle.ts:430-500`
ports the filter, the skip-on-unparseable rule and — the security-relevant half —
re-derives `attribution_verified` against the **path** `run_id` rather than the
payload's, which is the exact property the Rust projection exists for. It
declines `repo_verified` and `published.matches_work_product` and says why:
"Inventing the derivation here would produce a verdict with nothing behind it,
which is strictly worse than not reporting one." Under-claiming beats
fabricating. **B — product backlog, gated on FerroGate deciding it wants a
coding-agent product at all.**

### 4.2 Four orphaned single modules — 1,566 lines

| Module | Lines | Evidence of orphanhood |
|---|---:|---|
| `ferrogate-runtime/src/cloudflare_agent_memory.rs` | 465 | `AgentMemoryClient` (`:249`) with `state_get`/`state_set`/`sql_query`/`chat_history_get`/`chat_history_prune`/semantic search is exported at `ferrogate-runtime/src/lib.rs:72` and **called by nothing**. The only symbol any other module uses is `AgentInstanceIdentity` — the *naming scheme* — imported by `managed_worker.rs:39`, `cloudflare_agent_cost.rs`, `cloudflare_agent_schedule.rs`, `cloudflare_container.rs`. The `/memory/*` URLs appear only in `cloudflare_agent_memory_test.rs:279-281`. |
| `ferrogate-runtime/src/cloudflare_container_tether_audit.rs` | 442 | `TetherAuditor`, `verdict_for`, `TetherVerdict`, `TetherReconciliation` are exported at `lib.rs:96-98` and have **zero callers** in `crates/`. Nothing ever runs the reconciliation. |
| `ferrogate-mcp/src/mcp_worker_deploy.rs` | 396 | `pub mod` at `ferrogate-mcp/src/lib.rs:80`; the only `McpWorkerDeployer::new` in the tree is `mcp_worker_deploy_test.rs:58`. No route, no command, no scheduler invokes a deploy. |
| `ferrogate-runtime/src/egress_dispatch_stage.rs` | 263 | `mod` at `lib.rs:23`, `pub use` at `:124`, and the **only** other mention in `crates/` is a doc comment at `x402_client.rs:762` saying the types "now live in" it. Extracted for a reuse that never happened; its one real consumer is the deliberately-dropped x402 loop. |

Notes that matter for the backlog, not for the gate:

* **Agent memory** — the server half (`/memory/*`) exists in the legacy
  `workers/agent-gateway/src/memory.ts`, so the *feature* was half-built: a
  Worker serving it and a Rust client nobody called. If TS wants durable agent
  memory it is a fresh design against a DO, not a port.
* **Tether-bypass detection (#471)** — worth flagging as the highest-value B
  item. The PREVENTION half IS in TS (`governance.ts` §4: sealed-by-default
  egress allowlist). The Rust DETECTION half exists precisely because
  prevention is only as good as its configuration — but it was never wired in
  Rust either, so TS lost nothing. Recommend it as the first post-cutover
  security item.

### 4.3 `ferrogate-gateway/src/extensions.rs` — 1,389 lines — **B in bulk, A in one corner**

Counted in CLASS A below because two contract operations regressed; recorded
here because the *module* is mostly a scaffold, and porting it wholesale would
be the wrong call.

**What the "plugin extension runtime" actually supports.** `build_builtin_extension`
(`:546-571`) and `build_tool_provider` (`:574-586`) accept exactly four
hard-coded ids and `bail!("unsupported builtin …")` on everything else:

| id | Behaviour |
|---|---|
| `tool.echo` | `Ok(json!({"echo": request.arguments}))` (`:664`) |
| `tool.health_check` | `Ok(json!({"status": "ok"}))` |
| `hook.noop` | no-op request hook |
| `event.audit_log` | appends to an in-process `Arc<Mutex<Vec<GatewayEvent>>>` |

The only id with real external reach is `mcp.http` (`:681-716`), an MCP
tools/list + tools/call client — **and that is ported**, as
`apps/mcp/src/jsonrpc.ts` (`tools/list` parsing, `:337-347`) plus the durable
upstream registry. There is no general HTTP-plugin runtime in Rust to lose;
"ExtensionRegistry" is a demo harness with one real backend. A tenant
configuring an arbitrary plugin gets `bail!` in Rust today. **B.**

---

## PART 4 — CLASS A: the regressions that block

**4 capabilities, 8 modules, 3,391 lines.** Ordered by blast radius.

### A1 — Budget-threshold alert delivery is silently dead

**Modules:** `ferrogate-gateway/src/budget_alerts.rs` (264).

**Rust: complete, wired, on the hot path.**
`state_billing_metering.rs:231` calls `dispatch_budget_threshold_alerts` from
the metering-record path (plus `:778`, `:905`, `:1048`), which reaches
`state_wallets.rs:643-656`: build `BudgetAlertWebhookPayload`, POST it, and
record the notification id regardless of delivery outcome so a threshold fires
at most once per billing period. The module signs the body with HMAC-SHA256 over
`"<timestamp>.<body>"` and sends `X-FerroGate-Signature` /
`X-FerroGate-Timestamp` (`budget_alerts.rs:24-38`) so a receiver can reject
replays. Nothing about it is a stub.

**TS: three of four parts present, and the missing part is the one that
notifies anyone.**
* Config ACCEPTS and VALIDATES the setting — `packages/config/src/schema/sections.ts:321`
  (`webhook_url`) and `packages/config/src/validate/sections.ts:143-146`
  (non-empty, must be `http(s)://`).
* The once-per-period arbiter is durable — `packages/storage/src/d1/budget-alerts-d1.ts`
  (`INSERT … ON CONFLICT DO NOTHING RETURNING id`).
* The thresholds are READ into the request path —
  `apps/gateway/src/ratelimit/quota.ts:344` parses `alert_threshold_pcts_json`
  into `EffectiveQuota.alertThresholdPcts`.
* **Nothing ever compares spend against them, and nothing ever POSTs.** The only
  hits for `alertThreshold` in `apps/gateway/src` are the four parse sites
  above; `webhookUrl` has zero implementation hits.

`packages/storage/src/budget-alerts.ts:22-31` documents this against itself:
"an operator who configures alert thresholds is never notified."

**Blast radius: money, silently.** The operator-visible contract is *accepted*
end to end — the config validates, the admin surface stores the thresholds —
and the notification never arrives. This is worse than an unimplemented feature,
because the system affirms the configuration. A tenant burns through a budget
and the first signal is the invoice. **This is the archetype the wave-15
admission bypass established: a control whose configuration is accepted and
whose enforcement was lost in the split.**

**To close:** compare committed spend to `alertThresholdPcts` in the metering
drain, claim the D1 idempotency row, `fetch()` the webhook with the same HMAC
scheme. No platform obstacle — `fetch` + `crypto.subtle.sign("HMAC")`.

### A2 — Brokered edge-function egress (`executeFunction`) — and the recorded reason is wrong

**Modules (5, 1,244 lines):** `ferrogate-gateway/src/function_egress.rs` (363),
`function_egress_cloudflare.rs` (222), `ferrogate-runtime/src/function_egress.rs`
(197), `function_token.rs` (200), `supabase_edge_function.rs` (262).

**Rust: complete, live, fail-closed, env-gated.**
`server/local.rs:3219` is the `POST /v1/functions/execute` handler. It branches
to the Cloudflare-Worker target when `FG_FN_TARGET_KIND=cloudflare_worker`
(`:3242`), otherwise to the Supabase path, and returns
`503 function_egress_disabled` when no signing secret is configured (`:3250`) —
fail closed, not fail open. The pipeline
(`function_egress.rs::prepare_brokered_invocation`) authorizes the target
against the tenant's allowlist, mints a short-lived scoped capability token
(`function_token.rs`), builds the governed HTTP request, and bounds the outcome.
Configuration is `FG_FN_JWT_SECRET` / `FG_FN_APIKEY` / `FG_FN_ALLOWLIST`
(`function_egress.rs:96-98`) and `FG_FN_TARGET_KIND` / `FG_FN_CF_WORKER`
(`function_egress_cloudflare.rs:75-101`).

**TS: `registerNotImplemented("executeFunction")` — one of only 3 declared gaps
in the 251-op contract.**

**The rationale recorded for that 501 misreads the Rust.**
`apps/gateway/src/routes/index.ts:278-287` says:

> "the Rust ran user functions in an out-of-process sandbox. On Workers that is
> `@cloudflare/sandbox`/containers, which `apps/agent-runtime` owns"

`handle_function_execute` sandboxes nothing. It is a **signed outbound HTTPS
call to an already-deployed remote function** (a Supabase Edge Function or a
Cloudflare Worker). That is `fetch` plus HMAC — squarely inside a Worker's
abilities, arguably *more* natural there than in Pingora. The 501 is not a
platform limit and the marker should not claim one. **A misfiled rationale is
how a blocker becomes invisible**, which is the failure mode this whole audit
series exists to catch.

**Blast radius:** bounded to operators who set `FG_FN_*` — the broker is
default-off in Rust, so an operator who never configured it loses nothing. For
one who did, `POST /v1/functions/execute` goes from brokering a signed call to
`501`. Ranked below A1 for that reason, but it is a contract operation that
served traffic and now does not.

### A3 — `/v1/tools` and `/v1/tools/execute` regress to 501 on the gateway

**Module:** `ferrogate-gateway/src/extensions.rs` (1,389 — see §4.3 for why the
rest of it is B).

**Rust:** `state_tools.rs:48-57` — `tools_for(tenant, api_key_id, route)` =
extension tools **+ the tenant's registered MCP servers' tools**; `tool_by_name`
(`:86`) additionally resolves built-in gateway tools such as `fetch_asset`
(#257). `handle_tool_execute_with_backend` (`local.rs:3573`) runs the full
chokepoint: capability → **input** managed-action guardrail (`:3847`) → approval
escalation → execute → **output** guardrail (`:4124`), with the action
fingerprint stamped onto every audit row (#306). With zero plugins configured
this endpoint still returned the tenant's MCP tool catalogue.

**TS:** both operations are `registerNotImplemented` at
`apps/gateway/src/routes/index.ts:257-276`.

**Why this is A and not B: the capability exists in the TS tree already.**
`apps/mcp` implements `tools/list` ("the tenant's allowlisted MCP tools plus the
built-in gateway tools", `tools.ts:204-210`), `fetch_asset` (`tools.ts`), and
`tools/call` through the same governed chokepoint with the ported managed-action
guardrail (`ports.ts:507-511`). What is missing is the **projection of that
catalogue onto the gateway's REST aliases** — the marker's stated blocker ("the
MCP server registry lives in `apps/mcp`") is now describing a package that
exists and is mounted.

**Blast radius:** an OpenAI-shaped client that discovers tools at
`GET /v1/tools` gets `501` instead of a list, and `POST /v1/tools/execute`
cannot run one. Same data and same dispatch are reachable at `POST /v1/mcp`
(`tools/list`) and `POST /v1/mcp/tool/execute`, so this degrades a client's
discovery path rather than removing the capability. **2 of 251 contract
operations; the third declared 501 is A2 above.**

### A4 — Signed client action-time tokens are issued by the CLI and ignored by the gateway

**Module:** `ferrogate-gateway/src/client_action_time.rs` (494).

**Rust: complete and on every request.** A Pingora `HttpModule`
(`:435-465`) built from `ServerTimeTokenSigner` in `state.rs`, used by
`server/handlers.rs` and `server/proxy.rs`. A request carrying
`x-ferrogate-action-id` MUST also carry a valid `x-ferrogate-time-token`
(HMAC-SHA256, 30 s TTL, ≤60 s cap, rotation via a trusted-key list); the
challenge is the safe `GET /healthz` preflight, and the response mints the next
token. Malformed id → 400; id without token → 400; unconfigured authority + an
id → error. A request that sends neither header is passed through untouched
(`:363-372`), so the feature is opt-in per client.

**TS: the signing half shipped, the verifying half did not.**
`apps/cli/src/action-identity.ts:19-22` defines both headers, the CLI transport
sends the action id and reads the returned token
(`apps/cli/src/ports.ts:354`), and `apps/gateway` **never reads either header**
— the only non-CLI hits in the tree are CLI tests. Recorded honestly at
`apps/gateway/src/index.ts:160-174`: "a CLI that signs an action-time token
today has it ignored rather than verified."

The unverified field is already modelled: `apps/agent-runtime/src/ports.ts:289-301`
declares `ActionIdentity { action_id, canonical_target_sha256, client_clock_unix,
server_time_token }` — and that interface has **zero references anywhere in the
tree** (`ActionIdentity` matches only its own declaration plus a prose mention in
`governance.ts:15`). So the shape of the claim exists, nothing reads it, and
nothing validates it. That is exactly the state in which a future handler starts
trusting it.

**Blast radius — stated accurately, because overstating it would be its own
failure.** There is **no exploitable gap today**: no TS surface consumes
`x-ferrogate-action-id`, so nothing downstream can be spoofed by an unverified
one, and the CLI degrades cleanly when no token comes back (`ports.ts:354-359`
omits the field). What is lost is a *false assurance*: FerroGate's own CLI
implements a replay/clock-attestation protocol that the server silently does not
enforce, and any future TS surface that starts trusting `action_id` inherits an
unauthenticated input. It is the lowest-severity A and the cheapest to close
(ordinary Hono middleware, ahead of `contractAuth`) — but it is a complete,
wired, live Rust behaviour that the port dropped, which is the definition of A.

---

## What the CLASS A list is NOT

Stated explicitly, because a triage that only adds blockers is not a triage:

* **Enterprise identity (SAML/OIDC/SCIM/console session) does not block.** It
  was the loudest finding in `MODULE-OWNERSHIP.md` — "enterprise tenants cannot
  log in at all" — and wave 18 closed it. 8,448 lines of TS, path-for-path, with
  real signature verification and the storage half. Verified in §1.1.
* **The 11-module coding-agent contract does not block.** Its adapter is
  constructed only by its own tests and nothing in Rust ever writes the artifact
  it projects; a Rust deployment returns the same empty array TS does (§4.1).
* **The 10,820-line external-action boundary does not block.** Its only
  production transport is an AF_UNIX socket with `SO_PEERCRED` peer
  authentication, gating an in-process executor that spawns processes and writes
  files. Neither exists on workerd, and the decision half is kept in
  `governance.ts` (§3.1).
* **`recorded_evidence.rs` does not block.** All seven callers are inside the
  worker executor; the Rust gateway never calls it, so no TS surface has raw
  bytes to redact (§3.2).
* **The CLI reference generator does not block.** It is `#[cfg(test)]` (§3.3).

## Recommended disposition

**Cutover is blocked on A1–A4 and nothing else in this list.** A1 is the only
one with an unbounded, silent, money-shaped failure and should be closed before
cutover regardless of schedule. A2 and A3 are contract operations and should be
closed or explicitly signed off as accepted 501s by the owner (A2's marker text
must be corrected either way — it currently claims a platform limit that does
not exist). A4 is a one-middleware fix.

Post-cutover backlog, ranked: tether-bypass detection (#471, security), the
typed 9-variant action model if an in-container broker is ever built, durable
agent memory as a fresh DO design, and the coding-agent product decision.
