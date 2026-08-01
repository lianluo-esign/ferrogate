# FerroGate — module ownership (Rust → TypeScript)

**Baseline:** `main-ts` working tree, 2026-08-01. Every non-test Rust source
module in `crates/**/src/**`, with the TypeScript that owns it. Derived by
walking the filesystem — `PORT-PLAN.md` is deliberately **not** an input, because
the map is the control that failed.

> **Concurrency note.** Wave-18 agents were creating `packages/identity/`,
> `packages/sso/` and `apps/control-plane/src/session/` while this audit ran.
> At scan time those held RED tests and port interfaces but **no implementation**
> (`packages/sso/src` did not exist; `packages/identity/src` held only
> `ports.ts`/`errors.ts`/`membership-role.ts`/`oidc/base64url.ts`). The rows below
> record the state this audit observed and are marked *in-flight* where work has
> started. A row does not become PORTED because a package directory appeared.

## Why this document exists

Two large gaps were found by accident, seventeen waves in, and they failed the
same way: **they were never in any wave task list, so no agent owned them and no
audit looked for them.**

* `ferrogate-cloudflare` — the 21st crate — appeared in NO row of `PORT-PLAN.md`.
* SAML / OIDC / SCIM / admin-console session do not exist in TypeScript at all.

A *wrong* row in a map is visible. A *missing* row is not. `PORT-PLAN.md` maps at
**crate** granularity, so the single row
`ferrogate-admin + ferrogate-auth-service + ferrogate-control-plane-client -> apps/control-plane`
looked satisfied while five of that crate's twelve modules had zero TypeScript.
This document maps at **module** granularity: the same failure now needs 363
separate omissions instead of one.

### The mechanical reason the audits could not see it

Every parity audit in waves 1-17 was driven by
`docs/openapi/runtime-api-contract.json` (251 operations) through `ROUTE-MAP.md`.
`crates/ferrogate-auth-service/src/server.rs` serves 34 routes, and **not one of**
**them is in that contract** — `scim`, `sso`, `saml`, `oidc`, `admin/login`,
`admin/register`, `admin/team` all test `False` against the contract document. An
audit that enumerates the contract is structurally incapable of noticing a surface
the contract never described. **Two independent controls (the crate map and the
operation contract) had the same blind spot, which is why nothing caught it.**

### Corollary: the contract half is in far better shape than the rest

Only **3 of the 251 contract operations** are declared unimplemented in TS
(`registerNotImplemented`): `listTools`, `executeTool`, `executeFunction` — and all
three are the same Rust module, `ferrogate-gateway/src/extensions.rs`. Every other
operation is mounted. **So the remaining risk is almost entirely in behaviour that
never had a contract row**: the auth-service surface, the coding-agent contract,
the external-action capability boundary, evidence redaction, agent memory, the
tether-bypass audit, brokered function egress, and the budget-alert webhook.

## Method

1. `find crates -path "*/src/*" -name "*.rs"` → **620** files.
2. Split test scaffolding — 253 by path pattern (`/tests/`, `tests.rs`,
   `*_test.rs`, `test_*.rs`) plus 4 `*_test_support.rs` helpers = **257 TEST-ONLY**,
   leaving **363 product modules** (275,295 lines; 220 over 300 lines).
3. For each product module, extract distinctive signatures (quoted string literals
   ≥6 chars plus `pub fn/struct/enum/trait/const/type` names, with the
   `#[cfg(test)]` tail cut), drop any signature hitting >25 TS files as too
   generic, and score the rest against an inverted token index over all 886 TS
   files (snake_case also tried as camelCase).
4. Independently extract every `crates/<crate>/src/<path>.rs` citation appearing in
   a TS doc comment (this repo's "Clean-room port of …" convention) — **73**
   product modules are cited by path. Citation coverage alone is only 20%, so it
   cannot be the primary control either.
5. Cross-check against the contract: 170 distinct contract paths, 153 present
   verbatim in `apps/*/src`; and `grep registerNotImplemented` for declared gaps.
6. Every module with low signature coverage, and every module over 300 lines with
   an ambiguous owner, was opened and probed by hand.

> **On the "479 non-test / 284 over 300 lines" figures in the wave brief:** the
> true mechanical counts are **620** `src` files, **363** non-test, **220**
> non-test over 300 lines (359 if test scaffolding is counted). The brief's
> numbers came from a different filter. This document enumerates all **620** so no
> filter choice can hide a row.

## Classes

| Class | Meaning |
|---|---|
| **PORTED** | A cited TS file implements the behaviour (not merely the name). |
| **OBSOLETE-ON-CF** | Its purpose evaporates on Workers — it wrapped a REST API that is now a native binding, or it is a process / thread / TLS / connection-pool helper. Replacement cited. |
| **DELIBERATELY-DROPPED** | x402 / Solana (owner directive 2026-07-24) or a Rust-only concern with a recorded decision. |
| **MISSING** | No TS equivalent and no recorded decision, **or** a recorded 501/PORT-TODO with no implementation. **These are the finds.** |
| **UNVERIFIED** | This pass did not prove presence. Deliberately NOT called PORTED. |
| **TEST-ONLY** | Rust test scaffolding, no product behaviour. |

Each PORTED/OBSOLETE row also carries an **evidence tier**:
`hand-verified` (opened and read this pass) · `cited-by-TS` (the TS owner names the
`.rs` path in its header) · `signature-derived` (≥45% of the module's rare
signatures resolve into the TS tree, but the body was not read).

## Summary

> ### ⚠️ SUPERSEDED IN PART — read `MISSING-TRIAGE.md` first
>
> **Wave 19 (2026-08-01) re-opened all 37 MISSING modules.** Two things changed:
>
> 1. **Nine rows were STALE and are corrected in place below** (each is marked
>    `CORRECTED wave 19`). Eight are the enterprise-identity family the
>    concurrency note predicted — `admin_console.rs`, `sso.rs`, `scim.rs`,
>    `saml.rs`, `server.rs`, `http.rs`, `lib.rs`, `auth_quota.rs`, all landed by
>    wave 18 in `packages/{sso,identity}` + `apps/control-plane/src/{session,identity}`
>    (8,448 lines of TS). The ninth was NOT predicted:
>    `server/managed_action_guardrail.rs` is ported at `apps/mcp/src/ports.ts:466-511`
>    and the signature index simply missed it.
> 2. **The remaining 28 are no longer all blockers.** Under the owner's ruling
>    that the Rust tree is itself half-finished, they triage to
>    **A=8 (regression, blocks) · B=15 (Rust never wired) · C=5 (platform /
>    `cfg(test)` / obsolete)**. The evidence per row — is there a production
>    caller, does the transport exist on workerd — is in
>    `docs/rewrite/MISSING-TRIAGE.md`.
>
> The `Ranked MISSING list` and `MISSING grouped by capability` sections below
> are preserved AS WRITTEN (they are the wave-18 record); they overstate the
> blocker set by 29 modules. Use the triage for the cutover decision.

| Class | Modules | Lines |
|---|---:|---:|
| PORTED (245 + 8 corrected) | 253 | 203,165 |
| OBSOLETE-ON-CF (24 + 1 corrected) | 25 | 20,164 |
| DELIBERATELY-DROPPED | 11 | 7,178 |
| MISSING (37 − 9 stale) | 28 | 21,748 |
| UNVERIFIED | 46 | 23,040 |
| **product total** | **363** | **275,295** |

Of the 28 real MISSING modules: **A 8 / 3,391 lines · B 15 / 6,664 · C 5 / 11,693**
(`MISSING-TRIAGE.md`).
| TEST-ONLY | 257 | 123,750 |
| **grand total** | **620** | **399,045** |

Evidence tiers across PORTED + OBSOLETE-ON-CF: **signature-derived** 131 · **hand-verified** 77 · **cited-by-TS** 61.

## Ranked MISSING list

> **HISTORICAL — wave-18 record, superseded by `MISSING-TRIAGE.md`.** Rows
> 4, 7, 12, 13, 14, 15, 16, 18 and 37 of this table were STALE when written and
> are corrected in the full table below. Of the 28 that survive, 20 are B or C
> and do not block cutover. The blocking set is
> `budget_alerts.rs` · the 5-module brokered edge-function egress ·
> `extensions.rs` (2 contract ops only) · `client_action_time.rs`.

**37 modules, 27,644 lines of Rust with no TypeScript implementation.**

| # | Rust module | Lines | What is lost, and its blast radius |
|---:|---|---:|---|
| 1 | `crates/agent-worker/src/external_actions.rs` | 6552 | **Largest single gap.** 6552 lines: the handler-facing gate every framework action (tools, MCP, CLI, REST, filesystem, browser automation, secrets, memory, network egress) must pass before executing. TS ports only the `parent_action_fingerprint` header slice and a coarse `CapabilityRequest{requiredCapabilities: string[]}`. The 9-variant typed `ManagedExternalAction` and its per-variant policy are absent. |
| 2 | `crates/ferrogate-gateway/src/server/external_actions.rs` | 2271 | 2271 lines: the GATEWAY side of the external-action authorization boundary (capability policy + timeline evidence + the shared authorization response). Counterpart of agent-worker::external_actions; same gap. |
| 3 | `crates/ferrogate-runtime/src/managed_external_action.rs` | 1997 | 1997 lines: the 9-variant typed action contract (Tool, McpTool, Cli, Filesystem, Browser, Rest, Secret, Memory, NetworkEgress) with per-variant policy fields. TS models it as `requiredCapabilities: readonly string[]`, which cannot express a per-variant decision. |
| 4 | `crates/ferrogate-auth-service/src/admin_console.rs` | 1481 | **1481 lines. The admin-console SESSION surface**: `POST /v1/admin/register`, `/login`, `/refresh`, `/logout`; `GET /v1/admin/me`; `GET /v1/admin/team`; `POST /v1/admin/team/invite`; `/v1/admin/team/members/{id}` role change + removal. Zero TS routes at scan; `apps/control-plane/src/session/` (store/tokens/credentials) was appearing in-flight but is not mounted on any route. Blast radius: the console has no way to authenticate a human at all; every `/admin/v1/**` op in TS assumes a bearer key that only this surface could mint for a person. |
| 5 | `crates/ferrogate-gateway/src/extensions.rs` | 1389 | 1389 lines. `ExtensionRegistry::from_config` — HTTP plugin extensions from `ExtensionConfig`, `statuses()`, `tools_for()/all_tools()`, the `pre_request`/`post_response` hooks, `emit(GatewayEvent)` — has no TS runtime. **This is the ONLY module behind all 3 of the 251 contract operations that TS declares unimplemented** (`listTools`, `executeTool`, `executeFunction`); every other op is mounted. Recorded (501, not silent). Blast radius: a tenant configures a plugin, sees it in the admin CRUD, and it never runs. |
| 6 | `crates/ferrogate-runtime/src/coding_agent/credential_broker.rs` | 1114 | 1114 lines: the phase-1 credential grant/revoke broker (clone credential minted, scoped, then revoked at `finalize`). The single highest-risk unported module in this family. |
| 7 | `crates/ferrogate-auth-service/src/sso.rs` | 970 | **970 lines. OIDC (Authorization Code + PKCE, RFC 7636) and SAML SSO flows plus the per-tenant SSO config endpoints (#160/#283).** Zero TS implementation at scan (see concurrency note): `sso`/`oidc` matched no implementation file under apps/ or packages/, only an unrelated MCP OAuth client; `packages/identity/src/oidc/` held one base64url helper and RED tests. Lost: `POST\|GET\|DELETE /v1/admin/team/sso-config`, `GET /v1/admin/auth/sso/authorize`, `GET /v1/admin/auth/sso/callback`, group->role mapping, `client_secret_ref` indirection, 10-minute flow TTL. Blast radius: enterprise tenants cannot log in at all. |
| 8 | `crates/ferrogate-runtime/src/coding_agent/materialize.rs` | 793 | 793 lines: which commit, cloned with which credential, revoked where. |
| 9 | `crates/ferrogate-runtime/src/coding_agent/write_back.rs` | 664 | 664 lines: who authorized the outward side effect, and where is the audit event. |
| 10 | `crates/ferrogate-runtime/src/coding_agent/container_adapter.rs` | 640 | 640 lines: `ContainerCodingAgentAdapter`, which drives git through #415 `/container/exec`. |
| 11 | `crates/agent-worker/src/recorded_evidence.rs` | 634 | 634 lines (#526): the single chokepoint that redacts raw observed bytes (HTTP status line, every header, body; worker stdout; guest frames) before they are RECORDED as evidence. No TS equivalent — `recorded_evidence` returns 0 hits across apps/ + packages/. Blast radius: evidence rows can carry unredacted upstream bytes. |
| 12 | `crates/ferrogate-auth-service/src/server.rs` | 622 | 622 lines: the auth-service router itself. **Its 34 routes are not in `docs/openapi/runtime-api-contract.json`** — grep for `scim`/`sso`/`saml`/`admin/login` in the 251-op contract returns False for all. This is the mechanical reason 17 waves of contract-driven parity audits could not see this crate: the contract they audit against never described it. |
| 13 | `crates/ferrogate-auth-service/src/scim.rs` | 598 | **598 lines. SCIM 2.0 user/group provisioning.** The "1 TS file" that made this look covered is `apps/gateway/src/keys/scopes.ts`, which merely contains the substring `scim` in an unrelated scope name — it is NOT a SCIM implementation. (`packages/identity/test/scim-*.test.ts` are RED tests written this wave; no `src/scim` implementation existed at scan.) Lost: `GET\|POST /scim/v2/Users`, `GET\|PATCH\|DELETE /scim/v2/Users/{id}`, `GET /scim/v2/Groups`, `POST /v1/admin/team/scim-token`. Blast radius: no IdP-driven deprovisioning, so a revoked employee keeps tenant access. |
| 14 | `crates/ferrogate-auth-service/src/saml.rs` | 551 | **551 lines. SAML 2.0 SP: AuthnRequest construction, ACS assertion verification against the IdP signing certificate, attribute mapping.** Zero TS implementation at scan; `packages/sso/` had RED tests and NO `src/` directory. Lost: `GET /v1/admin/auth/saml/authorize`, `GET /v1/admin/auth/saml/acs`. Blast radius: same as sso.rs; also the highest-risk surface to reimplement (signature verification). |
| 15 | `crates/ferrogate-gateway/src/server/managed_action_guardrail.rs` | 551 | 551 lines: derives the guardrail `ManagedActionClass`, canonical target string and scannable input text FROM a runtime external action, so managed actions get the same guardrail envelope as user traffic. Depends on `ManagedExternalAction::capability_action`, which is itself unported (see agent-worker::external_actions). |
| 16 | `crates/ferrogate-storage/src/control_plane_store_d1/auth_quota.rs` | 519 | 519 lines covering "admin users, **SSO**, refresh tokens, quota policies, plans" (#440). Quotas and plans are ported; the **admin-user / SSO-config / refresh-token tables are not** — `sso_config` = 0 TS hits. This is the STORAGE half of the same auth-service gap, and it is why that gap is not just a missing router. |
| 17 | `crates/ferrogate-gateway/src/client_action_time.rs` | 494 | 494 lines. The VERIFYING half of signed action-time tokens. Recorded as a PORT-TODO at apps/gateway/src/index.ts:161-173: "a CLI that signs an action-time token today has it ignored rather than verified." |
| 18 | `crates/ferrogate-auth-service/src/http.rs` | 487 | 487 lines: the crate HTTP layer (request/response shapes, cookie/session handling) the four surfaces above share. |
| 19 | `crates/ferrogate-runtime/src/cloudflare_agent_memory.rs` | 465 | 465 lines (#427): per-agent-instance memory — `state` get/set, SQL query, chat-history get/prune, the default-off Vectorize semantic-memory pilot, and the tenant-isolating instance naming scheme, all as governed calls to the agent-gateway Worker authenticated `/memory/*` routes. `agentMemory` = 0 TS hits and no `/memory/*` route exists in apps/agent-runtime. Blast radius: agents have no durable memory surface; chat history cannot be pruned per tenant. |
| 20 | `crates/ferrogate-runtime/src/cloudflare_container_tether_audit.rs` | 442 | 442 lines (#471): tether-bypass **detection** — reconciles provider-reported usage against gateway-metered usage per run and emits a typed fail-loud verdict "so a bypass that prevention did not catch is never silent". `tether` = 0 TS hits. The PREVENTION half (enableInternet:false + one-host allowlist) IS ported in governance.ts; the detection half that exists precisely because prevention is only as good as its configuration is not. Security-relevant. |
| 21 | `crates/ferrogate-mcp/src/mcp_worker_deploy.rs` | 396 | 396 lines (#409): uploads a tenants own hosted MCP-server Worker (Workers Script PUT + McpAgent DO binding + OAUTH_KV + SQLite DO migration). Recorded as a SCOPE-boundary PORT-TODO at apps/mcp/src/index.ts:39-47 — it belongs in apps/control-plane, not the data-plane ingress. Blast radius: tenants cannot get a hosted MCP server provisioned. |
| 22 | `crates/ferrogate-gateway/src/function_egress.rs` | 363 | 363 lines (#120): gateway-side TLS egress executor for BROKERED edge-function calls — the fail-closed pipeline that runs an already-governed EdgeFunctionHttpRequest and bounds the outcome. `brokered`, `edge_function`, `FunctionInvocation` all return 0 TS hits. |
| 23 | `crates/ferrogate-runtime/src/coding_agent/run.rs` | 356 | 356 lines: long-running filesystem-mutating execution to a terminal status. |
| 24 | `crates/ferrogate-runtime/src/coding_agent/bootstrap.rs` | 345 | 345 lines: which agent, which task, model traffic pointed where. |
| 25 | `crates/ferrogate-runtime/src/coding_agent/extract.rs` | 301 | 301 lines: what did it produce, and to which run_id does that belong (`id_is_consistent`). |
| 26 | `crates/ferrogate-gateway/src/budget_alerts.rs` | 264 | 264 lines: the outbound webhook POST that DELIVERS a budget-threshold alert (#170). Threshold detection + idempotency are ported; the dispatch is not. `webhookUrl` = 0 src hits, `budget_threshold` = 0. Blast radius: an operator configures `webhook_url` in config (the validator accepts it) and is never notified. |
| 27 | `crates/ferrogate-runtime/src/egress_dispatch_stage.rs` | 263 | 263 lines (#353): the TYPED discriminant recording how far an outbound dispatch got on the wire, so a payment attempt can tell "no request byte reached the upstream" from "the request may have reached the upstream". 0 TS hits for `dispatchStage` or the message text. Consumers are the x402 settlement loop (dropped) — but the same distinction gates retry safety for any at-most-once egress. |
| 28 | `crates/ferrogate-runtime/src/supabase_edge_function.rs` | 262 | 262 lines: the Supabase Edge Function target of the brokered-egress pipeline. (Supabase appears in TS only as a storage-provider enum.) |
| 29 | `crates/ferrogate-runtime/src/coding_agent/work_product_artifact.rs` | 251 | 251 lines. The TS carries the work-product envelope verbatim but explicitly declines to re-derive `product_id`, `repo_verified` and `published.matches_work_product` because the model has no port. Self-documented at lifecycle.ts:454-467: "`crates/ferrogate-runtime/src/coding_agent/` has NO TypeScript port anywhere in this tree — it is not in PORT-PLAN.md either." |
| 30 | `crates/ferrogate-cli/src/reference.rs` | 239 | 239 lines (#365): the generator that renders the FULL assembled command tree into the committed `docs/cli-reference.md`. `docs/cli-reference` = 0 TS hits. Blast radius: docs-only, but the committed reference can now drift from the tree silently. |
| 31 | `crates/ferrogate-gateway/src/function_egress_cloudflare.rs` | 222 | 222 lines: the Cloudflare-flavoured half of the same brokered-egress executor. 0 TS hits. |
| 32 | `crates/ferrogate-runtime/src/coding_agent/mod.rs` | 219 | The five-phase coding-agent adapter contract (#472): materialize -> bootstrap -> run -> extract -> write-back, plus the mandatory `finalize` that discharges phase-1 credential obligations. |
| 33 | `crates/ferrogate-runtime/src/coding_agent/adapter.rs` | 209 | 209 lines: the `CodingAgentAdapter` trait. |
| 34 | `crates/ferrogate-runtime/src/coding_agent/error.rs` | 206 | 206 lines. |
| 35 | `crates/ferrogate-runtime/src/function_token.rs` | 200 | 200 lines: the short-lived token minted for a brokered function invocation. |
| 36 | `crates/ferrogate-runtime/src/function_egress.rs` | 197 | 197 lines: runtime half of the brokered edge-function egress (#120). |
| 37 | `crates/ferrogate-auth-service/src/lib.rs` | 117 | 117 lines: crate root wiring the above together. |

### MISSING grouped by capability

| Capability | Modules | Lines | Status |
|---|---:|---:|---|
| Enterprise identity — OIDC / SAML / SCIM / admin-console session | 8 | 5,345 | IN FLIGHT (wave-18 tasks #132-#139): `packages/identity`, `packages/sso`, `apps/control-plane/src/session` — RED tests written, implementation not yet present at scan time. |
| Coding-agent five-phase contract (#472) | 11 | 5,098 | Self-documented as unported at `apps/agent-runtime/src/runs/lifecycle.ts:454-467`. NOT in any wave task list. |
| External-action capability boundary (typed 9-variant `ManagedExternalAction`) | 4 | 11,371 | TS models it as `requiredCapabilities: string[]`, which cannot express a per-variant decision. NOT in any wave task list. |
| Gateway plugin/extension runtime | 1 | 1,389 | Recorded as 501 on the 3 contract ops it owns. Marked, not silent. |
| Brokered edge-function egress (#120) | 6 | 1,507 | `executeFunction` is a recorded 501; the credential/token and dispatch-stage halves are not marked anywhere. |
| Evidence redaction + tether-bypass detection + agent memory | 3 | 1,541 | Security- and privacy-relevant. NOT in any wave task list. |
| Delivery + tooling | 4 | 1,393 | Two are marked (client_action_time, mcp_worker_deploy); the budget-alert webhook and the CLI reference generator are not. |

## UNVERIFIED list

Not a claim of absence — a claim that **this pass did not prove presence**. Each
needs a behaviour-level re-derivation before it may be relabelled PORTED. Listing
them is the point: an audit that reports only what it is sure of, and calls the
rest PORTED, is exactly the failure this document exists to end.

| Rust module | Lines | Nearest TS candidate |
|---|---:|---|
| `crates/ferrogate-runtime/src/managed_worker.rs` | 3612 | apps/control-plane/src/routes/admin_managed_worker.ts, apps/agent-runtime/src/workers/frame.ts |
| `crates/ferrogate-gateway/src/server/site_domains.rs` | 1370 | apps/control-plane/src/routes/site_domain.ts, apps/control-plane/src/site_domain_txt.ts, packages/storage/src/site-domain.ts |
| `crates/ferrogate-gateway/src/server/wallets.rs` | 1359 | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/wallets.ts |
| `crates/ferrogate-runtime/src/self_hosted_mtls.rs` | 1342 | apps/agent-runtime/src/middleware/auth.ts (test/mtls.test.ts) |
| `crates/ferrogate-gateway/src/server/sites.rs` | 1226 | apps/gateway/src/assets/service.ts, apps/gateway/src/assets/content-gate.ts |
| `crates/ferrogate-gateway/src/lifecycle.rs` | 1078 | apps/cli/src/config-gate.ts, apps/control-plane/src/adapters.ts |
| `crates/agent-worker/src/management.rs` | 956 | apps/agent-runtime/src/routes/* |
| `crates/agent-worker/src/handlers.rs` | 819 | apps/agent-runtime/src/routes/* |
| `crates/ferrogate-gateway/src/state_asset_lifecycle.rs` | 790 | packages/storage/src/d1/retention-d1.ts, apps/control-plane/src/routes/admin_request_log.ts |
| `crates/ferrogate-gateway/src/server/quota_policies.rs` | 723 | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/quota_policy.ts |
| `crates/ferrogate-cli/src/cli.rs` | 639 | apps/cli/src/commands/serve.ts, apps/cli/src/commands/config-commands.ts |
| `crates/ferrogate-gateway/src/state_guardrail_evidence.rs` | 612 | apps/agent-runtime/src/runs/model.ts, apps/gateway/src/metering/ports.ts |
| `crates/ferrogate-gateway/src/server/plans.rs` | 527 | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/admin_agent_schedule.ts |
| `crates/ferrogate-gateway/src/metering.rs` | 494 | packages/guardrails/src/adapters/llm_guard.ts, packages/guardrails/src/adapters/fixture.ts |
| `crates/ferrogate-gateway/src/server/asset_admission.rs` | 487 | apps/gateway/src/ratelimit/workflow.ts, apps/gateway/src/ratelimit/middleware.ts |
| `crates/ferrogate-runtime/src/capability_boundary.rs` | 467 | apps/agent-runtime/src/ports.ts (CapabilityRequest/GovernancePort), packages/config/src/validate/capability-target.ts |
| `crates/ferrogate-gateway/src/state_tools.rs` | 415 | apps/gateway/src/routes/index.ts, apps/mcp/src/index.ts |
| `crates/ferrogate-gateway/src/lib.rs` | 401 | — |
| `crates/ferrogate-gateway/src/server/handlers.rs` | 386 | apps/gateway/src/middleware/errors.ts, apps/gateway/src/index.ts |
| `crates/ferrogate-gateway/src/state_agent_cost_governor.rs` | 327 | apps/gateway/src/ratelimit/token-budget.ts, apps/gateway/src/metering/ports.ts |
| `crates/ferrogate-gateway/src/state_observability.rs` | 327 | packages/config/src/validate/sections.ts, packages/observability/src/index.ts |
| `crates/ferrogate-config/src/caddyfile/parser_support.rs` | 320 | packages/config/src/validate/helpers.ts, packages/observability/src/cloudflare.ts |
| `crates/ferrogate-runtime/src/cloudflare_worker_target.rs` | 307 | packages/config/src/schema/capability-target.ts |
| `crates/ferrogate-gateway/src/server/asset_inline_publish.rs` | 292 | — |
| `crates/ferrogate-gateway/src/server/api_key_tenancy.rs` | 274 | apps/control-plane/src/store/tenancy.ts, apps/control-plane/src/store/lifecycle.ts |
| `crates/ferrogate-gateway/src/server/asset_stream.rs` | 272 | — |
| `crates/ferrogate-gateway/src/server/asset_publish_gate.rs` | 260 | apps/gateway/src/assets/scan.ts, apps/gateway/src/assets/ports.ts |
| `crates/ferrogate-control-plane-client/src/resource.rs` | 254 | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts |
| `crates/ferrogate-gateway/src/server/proxy.rs` | 251 | apps/gateway/src/routes/reverse-proxy.ts, apps/gateway/src/index.ts |
| `crates/ferrogate-runtime/src/lib.rs` | 233 | — |
| `crates/ferrogate-control-plane-client/src/lib.rs` | 221 | — |
| `crates/ferrogate-gateway/src/server/billing_outbox.rs` | 198 | apps/gateway/src/metering/publisher.ts |
| `crates/ferrogate-cloudflare/src/resolver.rs` | 177 | packages/secrets/src/cloudflare.ts, packages/cloudflare/src/index.ts |
| `crates/ferrogate-control-plane-client/src/dispatch.rs` | 177 | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts |
| `crates/ferrogate-config/src/config/routing.rs` | 175 | — |
| `crates/ferrogate-cli/src/ctl/ops_cmd.rs` | 161 | packages/providers/src/models.ts, packages/config/src/schema/config.ts |
| `crates/ferrogate-gateway/src/service_storage.rs` | 143 | packages/config/src/schema/enums.ts, packages/storage/src/provider.ts |
| `crates/ferrogate-control-plane-client/src/evidence.rs` | 142 | apps/cli/src/registry.ts, apps/control-plane/src/routes/admin_request_log.ts |
| `crates/ferrogate-guardrails/src/adapters/fixture.rs` | 142 | packages/guardrails/src/adapters/fixture.ts, packages/guardrails/src/adapters/transport.ts |
| `crates/ferrogate-config/src/lib.rs` | 141 | — |
| `crates/ferrogate-gateway/src/state_rollout.rs` | 129 | apps/gateway/src/inference/ports.ts, apps/gateway/src/inference/shadow.ts |
| `crates/ferrogate-mcp/src/cloudflare.rs` | 110 | apps/mcp/src/transport.ts |
| `crates/ferrogate-cloudflare/src/lib.rs` | 101 | — |
| `crates/ferrogate-cli/src/ctl/confirmation.rs` | 70 | — |
| `crates/ferrogate-payments/src/lib.rs` | 67 | — |
| `crates/ferrogate-config/src/config/mod.rs` | 66 | — |

## Full table

### `crates/agent-worker` — 17 product modules (21,602 lines), 19 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `external_actions.rs` | 6552 | MISSING | hand-verified | apps/agent-runtime/src/runs/governance.ts (PARTIAL — action-identity slice only, 165 lines) | **Largest single gap.** 6552 lines: the handler-facing gate every framework action (tools, MCP, CLI, REST, filesystem, browser automation, secrets, memory, network egress) must pass before executing. TS ports only the `parent_action_fingerprint` header slice and a coarse `CapabilityRequest{requiredCapabilities: string[]}`. The 9-variant typed `ManagedExternalAction` and its per-variant policy are absent. |
| `backends.rs` | 3521 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/governance.ts (IsolationGrant) | Backend registry for Firecracker/Docker/local-process isolation. workerd exposes no /dev/kvm, no fork/exec, no namespaces; the one CF-native backend (@cloudflare/sandbox) is what IsolationGrant pins. PLATFORM LIMIT recorded in governance.ts §8.2/8.4. |
| `lifecycle.rs` | 1770 | PORTED | hand-verified | apps/agent-runtime/src/runs/lifecycle.ts |  |
| `handler_runtime.rs` | 1189 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/do.ts | In-process framework-handler execution. Execution on CF is always the Sandbox container or a leased self-hosted worker; this Worker owns run STATE + the governance DECISION only. |
| `firecracker_guest_exec.rs` | 1005 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/governance.ts | AF_VSOCK channel to a microVM guest agent. |
| `management.rs` | 956 | UNVERIFIED | hand-verified | apps/agent-runtime/src/routes/* | Worker management endpoints; overlaps `/v1/self-hosted-workers/*` (which IS ported, workers/plane.ts). |
| `handlers.rs` | 819 | UNVERIFIED | hand-verified | apps/agent-runtime/src/routes/* | Handler HTTP surface of the worker process. Some routes map onto the 15 agent-runtime contract ops; not individually re-derived in this pass. |
| `x402_client.rs` | 776 | DELIBERATELY-DROPPED | hand-verified | packages/payments (types only) | x402/Solana deprioritized (owner directive 2026-07-24; PORT-PLAN `ferrogate-payments` row). |
| `local_process_backend.rs` | 731 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/governance.ts | `unshare -U -r -m -n -p -f` namespaces. No syscall surface in workerd. |
| `self_hosted_execution.rs` | 661 | PORTED | hand-verified | apps/agent-runtime/src/workers/plane.ts, apps/agent-runtime/src/workers/callbacks.ts | The 6 internal-auth `/v1/self-hosted-workers/*` callbacks. |
| `events.rs` | 650 | PORTED | hand-verified | apps/agent-runtime/src/runs/events.ts |  |
| `main.rs` | 645 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/index.ts | clap CLI + SocketAddr listener for a standalone binary. The Worker entry replaces it. |
| `recorded_evidence.rs` | 634 | MISSING | hand-verified | — | 634 lines (#526): the single chokepoint that redacts raw observed bytes (HTTP status line, every header, body; worker stdout; guest frames) before they are RECORDED as evidence. No TS equivalent — `recorded_evidence` returns 0 hits across apps/ + packages/. Blast radius: evidence rows can carry unredacted upstream bytes. |
| `cloudflare_container_backend.rs` | 455 | PORTED | hand-verified | apps/agent-runtime/src/runs/governance.ts, apps/agent-runtime/src/ports.ts (IsolationGrant) | The only backend with a CF equivalent; enableInternet:false / interceptHttps:true pinned by test/isolation-grant.test.ts. |
| `state.rs` | 418 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/do.ts (Durable Object storage) | Process-local idempotency/lifecycle store; the DO replaces the process boundary it existed to defend. |
| `cloudflare_container_lifecycle.rs` | 410 | PORTED | hand-verified | apps/agent-runtime/src/runs/lifecycle.ts, apps/agent-runtime/src/runs/do.ts |  |
| `docker_backend.rs` | 410 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/governance.ts | Shells out to the `docker` CLI. A Worker cannot spawn a process. |

<details><summary>TEST-ONLY modules (19, 12,458 lines)</summary>

| Module | Lines |
|---|---:|
| `management_test.rs` | 2282 |
| `external_actions_target_test.rs` | 1559 |
| `recorded_evidence_scan_test.rs` | 955 |
| `backends_test.rs` | 935 |
| `external_actions_x402_test.rs` | 856 |
| `firecracker_guest_exec_test.rs` | 837 |
| `x402_client_test.rs` | 805 |
| `external_actions_recorded_evidence_test.rs` | 746 |
| `isolation_adversarial_test.rs` | 637 |
| `recorded_evidence_test.rs` | 566 |
| `recorded_evidence_scan_test_support.rs` | 538 |
| `external_actions_self_hosted_family_test.rs` | 364 |
| `self_hosted_execution_test.rs` | 334 |
| `cloudflare_container_lifecycle_test.rs` | 301 |
| `cloudflare_container_backend_test.rs` | 286 |
| `docker_backend_test.rs` | 168 |
| `local_process_backend_test.rs` | 132 |
| `worker_type_test.rs` | 117 |
| `external_actions_worker_type_test.rs` | 40 |

</details>

### `crates/ferrogate-admin` — 2 product modules (353 lines), 1 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `control_plane.rs` | 331 | PORTED | hand-verified | apps/control-plane/src/contract.ts, apps/control-plane/src/middleware/alias.ts | `/control/v1/*` -> `/admin/v1/*` alias canonicalization (ROUTE-MAP invariant 7). |
| `lib.rs` | 22 | PORTED | hand-verified | apps/control-plane/src/index.ts | Crate root re-export. |

<details><summary>TEST-ONLY modules (1, 474 lines)</summary>

| Module | Lines |
|---|---:|
| `control_plane_test.rs` | 474 |

</details>

### `crates/ferrogate-auth-service` — 12 product modules (5,986 lines), 7 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `admin_console.rs` | 1481 | PORTED | hand-verified (CORRECTED wave 19) | — | **1481 lines. The admin-console SESSION surface**: `POST /v1/admin/register`, `/login`, `/refresh`, `/logout`; `GET /v1/admin/me`; `GET /v1/admin/team`; `POST /v1/admin/team/invite`; `/v1/admin/team/members/{id}` role change + removal. Zero TS routes at scan; `apps/control-plane/src/session/` (store/tokens/credentials) was appearing in-flight but is not mounted on any route. Blast radius: the console has no way to authenticate a human at all; every `/admin/v1/**` op in TS assumes a bearer key that only this surface could mint for a person. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — apps/control-plane/src/session/routes.ts (869) + session/index.ts — mounted at index.ts:104.** |
| `sso.rs` | 970 | PORTED | hand-verified (CORRECTED wave 19) | — | **970 lines. OIDC (Authorization Code + PKCE, RFC 7636) and SAML SSO flows plus the per-tenant SSO config endpoints (#160/#283).** Zero TS implementation at scan (see concurrency note): `sso`/`oidc` matched no implementation file under apps/ or packages/, only an unrelated MCP OAuth client; `packages/identity/src/oidc/` held one base64url helper and RED tests. Lost: `POST\|GET\|DELETE /v1/admin/team/sso-config`, `GET /v1/admin/auth/sso/authorize`, `GET /v1/admin/auth/sso/callback`, group->role mapping, `client_secret_ref` indirection, 10-minute flow TTL. Blast radius: enterprise tenants cannot log in at all. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — packages/identity/src/oidc/flow.ts + index.ts — mounted via createIdentityRoutes (index.ts:107).** |
| `server.rs` | 622 | PORTED | hand-verified (CORRECTED wave 19) | — | 622 lines: the auth-service router itself. **Its 34 routes are not in `docs/openapi/runtime-api-contract.json`** — grep for `scim`/`sso`/`saml`/`admin/login` in the 251-op contract returns False for all. This is the mechanical reason 17 waves of contract-driven parity audits could not see this crate: the contract they audit against never described it. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — packages/identity/src/routes.ts + apps/control-plane/src/session/routes.ts — 17/17 identity paths; /v1/auth/*, /v1/rbac/*, /v1/tenants are OBSOLETE-ON-CF (direct D1 binding + contract ops).** |
| `scim.rs` | 598 | PORTED | hand-verified (CORRECTED wave 19) | — | **598 lines. SCIM 2.0 user/group provisioning.** The "1 TS file" that made this look covered is `apps/gateway/src/keys/scopes.ts`, which merely contains the substring `scim` in an unrelated scope name — it is NOT a SCIM implementation. (`packages/identity/test/scim-*.test.ts` are RED tests written this wave; no `src/scim` implementation existed at scan.) Lost: `GET\|POST /scim/v2/Users`, `GET\|PATCH\|DELETE /scim/v2/Users/{id}`, `GET /scim/v2/Groups`, `POST /v1/admin/team/scim-token`. Blast radius: no IdP-driven deprovisioning, so a revoked employee keeps tenant access. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — packages/identity/src/scim/service.ts (461) + scim/{filter,auth,resources}.ts.** |
| `saml.rs` | 551 | PORTED | hand-verified (CORRECTED wave 19) | — | **551 lines. SAML 2.0 SP: AuthnRequest construction, ACS assertion verification against the IdP signing certificate, attribute mapping.** Zero TS implementation at scan; `packages/sso/` had RED tests and NO `src/` directory. Lost: `GET /v1/admin/auth/saml/authorize`, `GET /v1/admin/auth/saml/acs`. Blast radius: same as sso.rs; also the highest-risk surface to reimplement (signature verification). **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — packages/sso/src/* (2256 lines incl. redirect-binding.ts:139-185 crypto.subtle.verify).** |
| `http.rs` | 487 | OBSOLETE-ON-CF | hand-verified (CORRECTED wave 19) | — | 487 lines: the crate HTTP layer (request/response shapes, cookie/session handling) the four surfaces above share. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — packages/identity/src/errors.ts — hand-rolled bounded HTTP reader replaced by Hono + platform Request/Response.** |
| `rbac.rs` | 402 | PORTED | hand-verified | apps/control-plane/src/routes/rbac.ts, apps/control-plane/src/store/rbac_registry.ts | `/v1/rbac/roles` + `/v1/rbac/bindings`; the durable write half landed in wave 17 (task #111). |
| `main.rs` | 223 | OBSOLETE-ON-CF | hand-verified | — | 223 lines: standalone binary entry (listener/bind). A Worker entry replaces it — but only once the surface it serves exists. |
| `membership_role.rs` | 183 | PORTED | hand-verified | apps/gateway/src/keys/scopes.ts, apps/gateway/src/keys/index.ts | owner/admin/member role ladder. |
| `api_key.rs` | 180 | PORTED | hand-verified | apps/gateway/src/keys/hash.ts, apps/control-plane/src/routes/admin_api_key.ts |  |
| `util.rs` | 172 | PORTED | hand-verified | apps/gateway/src/keys/hash.ts, apps/agent-runtime/src/durable/hash.ts | Hash/encode helpers. |
| `lib.rs` | 117 | PORTED | hand-verified (CORRECTED wave 19) | — | 117 lines: crate root wiring the above together. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — crate root is mod/pub use only (lib.rs:33-60); subsumed once every module is owned.** |

<details><summary>TEST-ONLY modules (7, 5,488 lines)</summary>

| Module | Lines |
|---|---:|
| `admin_console_test.rs` | 3780 |
| `credential_debug_test.rs` | 679 |
| `saml/tests.rs` | 283 |
| `membership_role_test.rs` | 271 |
| `rbac_test.rs` | 256 |
| `main_test.rs` | 113 |
| `hardening_test.rs` | 106 |

</details>

### `crates/ferrogate-billing` — 5 product modules (2,166 lines), 5 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `x402_inbound.rs` | 671 | PORTED | signature-derived | packages/billing/src/x402-inbound.ts, packages/payments/src/wire.ts | signature coverage 23/30. |
| `ledger.rs` | 450 | PORTED | signature-derived | packages/billing/src/ledger.ts, apps/gateway/src/metering/ledger.ts | signature coverage 17/18. |
| `service.rs` | 446 | PORTED | signature-derived | packages/billing/src/service.ts, packages/billing/src/ledger.ts | signature coverage 12/15. |
| `lib.rs` | 387 | PORTED | signature-derived | packages/billing/src/event.ts, packages/billing/src/usage.ts | signature coverage 23/27. |
| `pricing.rs` | 212 | PORTED | signature-derived | packages/billing/src/pricing.ts, apps/gateway/src/assets/egress.ts | signature coverage 14/26. |

<details><summary>TEST-ONLY modules (5, 1,324 lines)</summary>

| Module | Lines |
|---|---:|
| `x402_inbound_test.rs` | 393 |
| `service_test.rs` | 303 |
| `ledger_test.rs` | 302 |
| `lib_test.rs` | 216 |
| `pricing_test.rs` | 110 |

</details>

### `crates/ferrogate-cli` — 18 product modules (4,401 lines), 11 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `ctl/resource_cmd.rs` | 798 | PORTED | signature-derived | apps/cli/src/commands/ctl.ts, apps/cli/src/tree.ts | signature coverage 3/4. |
| `cli.rs` | 639 | UNVERIFIED | signature-derived | apps/cli/src/commands/serve.ts, apps/cli/src/commands/config-commands.ts | Not individually re-derived in this pass; signature coverage 31/72. |
| `admin_api.rs` | 636 | OBSOLETE-ON-CF | hand-verified | apps/control-plane (the Worker itself) | 636 lines: a `ferrogate admin-api serve` listener that terminates the consoles HTTPS and reverse-proxies `/admin/v1/*` to the gateway so admin traffic never rides the AI data-plane process. On CF the control plane IS a separate Worker; the process split it existed to create is structural. |
| `assets_cli.rs` | 504 | PORTED | hand-verified | apps/cli/src/commands/assets.ts |  |
| `lib.rs` | 333 | PORTED | cited-by-TS | apps/cli/src/config-gate.ts | TS owner cites `crates/ferrogate-cli/src/lib.rs` by path; no distinctive signatures. |
| `reference.rs` | 239 | MISSING | hand-verified | — | 239 lines (#365): the generator that renders the FULL assembled command tree into the committed `docs/cli-reference.md`. `docs/cli-reference` = 0 TS hits. Blast radius: docs-only, but the committed reference can now drift from the tree silently. |
| `storage.rs` | 188 | PORTED | signature-derived | packages/storage/src/provider.ts, packages/config/src/schema/enums.ts | signature coverage 4/8. |
| `ctl/context_cmd.rs` | 183 | PORTED | signature-derived | apps/cli/src/commands/context.ts, apps/cli/src/commands/ctl.ts | signature coverage 2/3. |
| `ctl/store.rs` | 175 | PORTED | cited-by-TS | apps/cli/src/toml.ts, apps/cli/test/contexts-toml.test.ts | TS owner cites `crates/ferrogate-cli/src/ctl/store.rs` by path; signature coverage 6/10. |
| `ctl/ops_cmd.rs` | 161 | UNVERIFIED | signature-derived | packages/providers/src/models.ts, packages/config/src/schema/config.ts | Not individually re-derived in this pass; signature coverage 2/6. |
| `ctl/dispatch.rs` | 146 | PORTED | signature-derived | apps/cli/src/diagnostics.ts, apps/cli/src/commands/ctl.ts | signature coverage 4/5. |
| `plans_cli.rs` | 82 | PORTED | signature-derived | apps/agent-runtime/src/admission/quota.ts, apps/cli/src/commands/plans.ts | signature coverage 8/10. |
| `billing.rs` | 75 | OBSOLETE-ON-CF | hand-verified | packages/billing/src/service.ts | 75 lines: `ferrogate billing serve` process wiring for a standalone billing listener. |
| `ctl/confirmation.rs` | 70 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `ctl/mod.rs` | 60 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |
| `completions.rs` | 54 | PORTED | hand-verified | apps/cli/src/commands/completions.ts |  |
| `command_tree.rs` | 47 | PORTED | signature-derived | apps/cli/src/tree.ts | signature coverage 1/2. |
| `main.rs` | 11 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |

<details><summary>TEST-ONLY modules (11, 2,671 lines)</summary>

| Module | Lines |
|---|---:|
| `ctl/resource_cmd_test.rs` | 693 |
| `assets_cli_test.rs` | 623 |
| `admin_api_test.rs` | 402 |
| `ctl/clock_guard_test.rs` | 280 |
| `ctl/fingerprint_parity_test.rs` | 158 |
| `reference_test.rs` | 138 |
| `ctl/store_test.rs` | 107 |
| `ctl/ops_cmd_test.rs` | 75 |
| `completions_test.rs` | 71 |
| `ctl/context_cmd_test.rs` | 64 |
| `ctl/dispatch_test.rs` | 60 |

</details>

### `crates/ferrogate-cloudflare` — 11 product modules (2,871 lines), 11 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `client.rs` | 551 | PORTED | cited-by-TS | packages/cloudflare/src/retry.ts, packages/cloudflare/test/client.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/client.rs` by path; signature coverage 16/22. |
| `r2.rs` | 534 | PORTED | cited-by-TS | packages/cloudflare/src/r2.ts, packages/cloudflare/test/r2.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/r2.rs` by path; signature coverage 11/19. |
| `r2_token.rs` | 395 | PORTED | cited-by-TS | packages/cloudflare/src/r2-token.ts, packages/cloudflare/test/r2-token.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/r2_token.rs` by path; signature coverage 11/17. |
| `d1_proxy.rs` | 260 | OBSOLETE-ON-CF | hand-verified | packages/storage/src/tenant-router.ts, packages/storage/src/tenant-rest.ts | 260 lines: the bearer-auth HTTP shim in front of D1 that existed because Rust had no D1 binding. A Worker binds D1 natively; the REST transport remains for cross-account/tenant routing. |
| `d1.rs` | 255 | PORTED | cited-by-TS | packages/cloudflare/src/d1.ts, packages/cloudflare/test/d1.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/d1.rs` by path; signature coverage 5/10. |
| `error.rs` | 252 | PORTED | cited-by-TS | packages/cloudflare/src/errors.ts, packages/cloudflare/test/errors.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/error.rs` by path; signature coverage 4/6. |
| `resolver.rs` | 177 | UNVERIFIED | signature-derived | packages/secrets/src/cloudflare.ts, packages/cloudflare/src/index.ts | Not individually re-derived in this pass; signature coverage 3/8. |
| `envelope.rs` | 148 | PORTED | cited-by-TS | packages/cloudflare/src/envelope.ts, packages/cloudflare/test/envelope.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/envelope.rs` by path; signature coverage 7/7. |
| `config.rs` | 115 | PORTED | signature-derived | packages/cloudflare/src/client.ts, packages/config/src/schema/entities.ts | signature coverage 8/12. |
| `lib.rs` | 101 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `scopes.rs` | 83 | PORTED | cited-by-TS | packages/cloudflare/src/scopes.ts, packages/cloudflare/test/scopes.test.ts | TS owner cites `crates/ferrogate-cloudflare/src/scopes.rs` by path; signature coverage 3/3. |

<details><summary>TEST-ONLY modules (11, 3,400 lines)</summary>

| Module | Lines |
|---|---:|
| `r2_test.rs` | 1081 |
| `r2_token_test.rs` | 496 |
| `backoff_test.rs` | 389 |
| `d1_proxy_test.rs` | 274 |
| `scopes_test.rs` | 263 |
| `d1_test.rs` | 248 |
| `error_test.rs` | 179 |
| `envelope_test.rs` | 143 |
| `resolver_test.rs` | 125 |
| `client_test.rs` | 115 |
| `config_test.rs` | 87 |

</details>

### `crates/ferrogate-config` — 22 product modules (11,684 lines), 8 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `config/validate.rs` | 4005 | PORTED | cited-by-TS | packages/config/test/validate-rule-identity.test.ts | TS owner cites `crates/ferrogate-config/src/config/validate.rs` by path; signature coverage 28/69. |
| `config/types.rs` | 3213 | PORTED | cited-by-TS | apps/gateway/src/guardrails/engine.ts, apps/gateway/src/guardrails/index.ts | TS owner cites `crates/ferrogate-config/src/config/types.rs` by path; signature coverage 121/226. |
| `config/signed_snapshot.rs` | 821 | PORTED | signature-derived | packages/config/src/signed-snapshot.ts, apps/mcp/src/ports.ts | signature coverage 26/33. |
| `caddyfile/parser.rs` | 797 | PORTED | signature-derived | packages/config/src/caddyfile/parser.ts, packages/config/src/loader.ts | signature coverage 30/31. |
| `config/loader.rs` | 435 | PORTED | signature-derived | packages/config/src/loader.ts, packages/config/src/index.ts | signature coverage 4/4. |
| `config/network_access.rs` | 371 | PORTED | signature-derived | apps/gateway/src/index.ts, packages/config/src/network-access.ts | signature coverage 3/5. |
| `x402_scope.rs` | 370 | PORTED | signature-derived | packages/config/src/x402-scope.ts, packages/config/src/validate/sections.ts | signature coverage 11/16. |
| `caddyfile/parser_support.rs` | 320 | UNVERIFIED | signature-derived | packages/config/src/validate/helpers.ts, packages/observability/src/cloudflare.ts | Not individually re-derived in this pass; signature coverage 1/3. |
| `config/asset_endpoint.rs` | 209 | PORTED | signature-derived | packages/config/src/asset-endpoint.ts, packages/config/src/validate.ts | signature coverage 9/12. |
| `config/routing.rs` | 175 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `x402.rs` | 167 | PORTED | cited-by-TS | packages/config/src/x402-scope.ts | TS owner cites `crates/ferrogate-config/src/x402.rs` by path; signature coverage 3/5. |
| `types.rs` | 156 | PORTED | signature-derived | packages/config/src/caddyfile/types.ts, packages/config/src/caddyfile/parser.ts | signature coverage 11/11. |
| `lib.rs` | 141 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `caddyfile/lexer.rs` | 138 | PORTED | signature-derived | packages/config/src/index.ts, packages/config/src/caddyfile/lexer.ts | signature coverage 1/2. |
| `config/provider.rs` | 69 | PORTED | signature-derived | — | signature coverage 1/1. |
| `config/mod.rs` | 66 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `config/secrets.rs` | 64 | PORTED | signature-derived | packages/config/src/index.ts, packages/config/src/secrets.ts | signature coverage 1/1. |
| `config/upstream.rs` | 47 | PORTED | signature-derived | packages/config/src/schema/entities.ts, packages/config/src/validate/entities.ts | signature coverage 1/1. |
| `config/snapshot.rs` | 44 | PORTED | signature-derived | apps/cli/src/config-gate.ts, apps/control-plane/src/routes/admin_config_ops.ts | signature coverage 1/1. |
| `diagnostic.rs` | 40 | PORTED | signature-derived | packages/config/src/caddyfile/parser.ts, packages/config/src/diagnostic.ts | signature coverage 1/1. |
| `loader.rs` | 22 | PORTED | signature-derived | packages/config/src/index.ts, apps/cli/src/ports.ts | signature coverage 2/3. |
| `caddyfile/mod.rs` | 14 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |

<details><summary>TEST-ONLY modules (8, 8,893 lines)</summary>

| Module | Lines |
|---|---:|
| `config/validation_tests.rs` | 4857 |
| `config/tests.rs` | 1771 |
| `config/signed_snapshot_test.rs` | 573 |
| `x402_scope_test.rs` | 562 |
| `caddyfile/parser_tests.rs` | 544 |
| `x402_test.rs` | 251 |
| `config/serde_tests.rs` | 232 |
| `config/routing_tests.rs` | 103 |

</details>

### `crates/ferrogate-control-plane-client` — 27 product modules (10,328 lines), 26 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `receipt.rs` | 2256 | PORTED | cited-by-TS | apps/cli/src/receipt.ts | TS owner cites `crates/ferrogate-control-plane-client/src/receipt.rs` by path; signature coverage 109/146. |
| `action_identity.rs` | 1159 | PORTED | signature-derived | apps/cli/src/action-identity.ts, apps/cli/src/receipt.ts | signature coverage 20/28. |
| `transport.rs` | 1122 | PORTED | signature-derived | apps/cli/src/paging.ts, apps/cli/src/ports.ts | signature coverage 27/46. |
| `parity.rs` | 446 | PORTED | signature-derived | apps/cli/src/parity.ts, apps/gateway/src/routes/index.ts | signature coverage 21/23. |
| `command.rs` | 390 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts | signature coverage 14/18. |
| `asset.rs` | 367 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/gateway/src/assets/handlers.ts | signature coverage 35/51. |
| `context.rs` | 355 | PORTED | signature-derived | apps/cli/src/context.ts, apps/cli/src/global-args.ts | signature coverage 15/21. |
| `billing.rs` | 351 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/wallets.ts | signature coverage 31/48. |
| `agent.rs` | 299 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/agent-runtime/src/runs/lifecycle.ts | signature coverage 35/53. |
| `catalog.rs` | 292 | PORTED | signature-derived | apps/cli/src/registry.ts, packages/config/src/schema/config.ts | signature coverage 37/52. |
| `ops.rs` | 260 | PORTED | cited-by-TS | apps/control-plane/src/routes/admin_config_ops.ts, apps/control-plane/src/routes/admin_overview.ts | TS owner cites `crates/ferrogate-control-plane-client/src/ops.rs` by path; signature coverage 21/34. |
| `organization.rs` | 257 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/quota_policy.ts | signature coverage 22/38. |
| `iam.rs` | 256 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/admin_virtual_key.ts | signature coverage 39/59. |
| `resource.rs` | 254 | UNVERIFIED | signature-derived | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts | Not individually re-derived in this pass; signature coverage 5/12. |
| `worker.rs` | 251 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/self_hosted_worker.ts | signature coverage 23/40. |
| `lib.rs` | 221 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; signature coverage 0/3. |
| `guardrail.rs` | 220 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/guardrail_policy.ts | signature coverage 19/31. |
| `registry_helpers.rs` | 219 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts | signature coverage 8/13. |
| `error.rs` | 202 | PORTED | signature-derived | apps/cli/src/errors.ts, apps/cli/src/receipt.ts | signature coverage 4/6. |
| `mcp.rs` | 197 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/mcp/src/index.ts | signature coverage 18/31. |
| `dispatch.rs` | 177 | UNVERIFIED | signature-derived | apps/cli/src/registry.ts, apps/cli/src/commands/ctl.ts | Not individually re-derived in this pass; signature coverage 6/43. |
| `output.rs` | 173 | PORTED | signature-derived | apps/cli/src/output.ts, packages/providers/src/anthropic.ts | signature coverage 4/5. |
| `auth.rs` | 161 | PORTED | signature-derived | apps/cli/src/context.ts, packages/secrets/src/cloudflare.ts | signature coverage 6/9. |
| `evidence.rs` | 142 | UNVERIFIED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/admin_request_log.ts | Not individually re-derived in this pass; signature coverage 8/18. |
| `args.rs` | 104 | PORTED | signature-derived | apps/cli/src/global-args.ts, apps/gateway/src/guardrails/ports.ts | signature coverage 3/4. |
| `version.rs` | 104 | PORTED | signature-derived | apps/cli/src/version.ts, apps/gateway/src/routes/service.ts | signature coverage 6/7. |
| `tool_approval.rs` | 93 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/admin_tool.ts | signature coverage 8/12. |

<details><summary>TEST-ONLY modules (26, 12,034 lines)</summary>

| Module | Lines |
|---|---:|
| `receipt_test.rs` | 2974 |
| `transport_test.rs` | 1943 |
| `action_identity_test.rs` | 1293 |
| `asset_test.rs` | 501 |
| `billing_test.rs` | 448 |
| `catalog_test.rs` | 423 |
| `parity_test.rs` | 393 |
| `ops_test.rs` | 355 |
| `organization_test.rs` | 354 |
| `guardrail_test.rs` | 342 |
| `context_test.rs` | 320 |
| `iam_test.rs` | 317 |
| `evidence_test.rs` | 286 |
| `agent_test.rs` | 277 |
| `worker_test.rs` | 268 |
| `mcp_test.rs` | 261 |
| `tool_approval_test.rs` | 204 |
| `registry_helpers_test.rs` | 163 |
| `resource_test.rs` | 156 |
| `command_test.rs` | 147 |
| `auth_test.rs` | 143 |
| `dispatch_test.rs` | 124 |
| `error_test.rs` | 106 |
| `args_test.rs` | 82 |
| `version_test.rs` | 78 |
| `output_test.rs` | 76 |

</details>

### `crates/ferrogate-core` — 1 product modules (265 lines), 0 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `lib.rs` | 265 | PORTED | signature-derived | packages/schemas/src/index.ts, packages/core/src/index.ts | signature coverage 14/16. |

### `crates/ferrogate-gateway` — 102 product modules (108,562 lines), 73 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `server/local.rs` | 12152 | PORTED | hand-verified | apps/gateway/src/routes/*, apps/gateway/src/inference/*, apps/gateway/src/middleware/* | 12152-line god-router; decomposed into the contract-driven Hono route modules. 54 data-plane ops certified in wave 17 (task #109). |
| `state.rs` | 7802 | PORTED | hand-verified | apps/gateway/src/adapters.ts, apps/gateway/src/ports.ts + the per-concern state_* ports | 7802-line god-object; decomposed across apps/gateway ports/adapters rather than mirrored 1:1. |
| `state_agent_runtime.rs` | 4743 | PORTED | cited-by-TS | apps/agent-runtime/src/runs/model.ts, apps/control-plane/test/audit-events-read.test.ts | TS owner cites `crates/ferrogate-gateway/src/state_agent_runtime.rs` by path; signature coverage 43/121. |
| `server/chat.rs` | 4313 | PORTED | cited-by-TS | packages/policy/src/workflow-graph.ts | TS owner cites `crates/ferrogate-gateway/src/server/chat.rs` by path; signature coverage 43/72. |
| `server/asset_bucket.rs` | 4258 | PORTED | cited-by-TS | apps/gateway/src/assets/sigv4.ts | TS owner cites `crates/ferrogate-gateway/src/server/asset_bucket.rs` by path; signature coverage 7/31. |
| `server/virtual_keys.rs` | 3037 | PORTED | hand-verified | apps/control-plane/src/routes/admin_virtual_key.ts, apps/control-plane/src/store/virtual_keys.ts |  |
| `responses.rs` | 2734 | PORTED | cited-by-TS | apps/agent-runtime/src/middleware/errors.ts, apps/control-plane/src/middleware/errors.ts | TS owner cites `crates/ferrogate-gateway/src/responses.rs` by path; signature coverage 46/179. |
| `state_mcp_identity.rs` | 2714 | PORTED | cited-by-TS | apps/mcp/src/durable.ts, apps/mcp/src/identity/oauth.ts | TS owner cites `crates/ferrogate-gateway/src/state_mcp_identity.rs` by path; signature coverage 48/112. |
| `server/assets.rs` | 2489 | PORTED | cited-by-TS | apps/gateway/src/assets/service.ts, apps/gateway/test/assets/governed-actions.test.ts | TS owner cites `crates/ferrogate-gateway/src/server/assets.rs` by path; signature coverage 28/52. |
| `server/asset_presign.rs` | 2403 | PORTED | signature-derived | apps/gateway/src/assets/service.ts, apps/gateway/src/assets/schemas.ts | signature coverage 33/45. |
| `server/external_actions.rs` | 2271 | MISSING | hand-verified | — | 2271 lines: the GATEWAY side of the external-action authorization boundary (capability policy + timeline evidence + the shared authorization response). Counterpart of agent-worker::external_actions; same gap. |
| `telemetry.rs` | 2070 | OBSOLETE-ON-CF | hand-verified | packages/observability/src/otlp.ts, apps/gateway/src/telemetry/emit.ts | 2070 lines, of which the bulk is a hand-rolled rustls TCP/TLS HTTP client used because Pingora could not borrow an async client. On Workers `fetch()` is the transport; the OTLP payload construction IS ported. |
| `acme.rs` | 1929 | OBSOLETE-ON-CF | hand-verified | Cloudflare-managed TLS / Cloudflare for SaaS; config surface at packages/config/src/schema/sections.ts | 1929 lines of ACME (http-01/dns-01) certificate issuance. Cloudflare terminates TLS; the caddyfile `acme` config block IS parsed + validated in TS. NOTE: no TS provisions a Cloudflare-for-SaaS custom hostname either (`custom_hostname` = 0 hits) — see site_domains. |
| `server/messages.rs` | 1804 | PORTED | hand-verified | apps/gateway/src/inference/anthropic.ts, apps/gateway/src/streaming/anthropic.ts | `/v1/messages`. |
| `state_billing_metering.rs` | 1794 | PORTED | cited-by-TS | apps/gateway/src/metering/outbox.ts | TS owner cites `crates/ferrogate-gateway/src/state_billing_metering.rs` by path; no distinctive signatures. |
| `server/agent_runs.rs` | 1718 | PORTED | cited-by-TS | packages/policy/src/workflow-budget.ts | TS owner cites `crates/ferrogate-gateway/src/server/agent_runs.rs` by path; signature coverage 17/57. |
| `server/agent_jobs.rs` | 1645 | PORTED | cited-by-TS | apps/agent-runtime/src/crypto.ts, apps/agent-runtime/src/runs/lifecycle.ts | TS owner cites `crates/ferrogate-gateway/src/server/agent_jobs.rs` by path; signature coverage 18/36. |
| `state_quota_and_policy.rs` | 1634 | PORTED | cited-by-TS | apps/gateway/src/guardrails/engine.ts, apps/gateway/src/guardrails/index.ts | TS owner cites `crates/ferrogate-gateway/src/state_quota_and_policy.rs` by path; signature coverage 25/39. |
| `server/rbac.rs` | 1616 | PORTED | hand-verified | apps/control-plane/src/routes/rbac.ts, apps/control-plane/src/store/rbac_registry.ts |  |
| `auth.rs` | 1588 | PORTED | cited-by-TS | apps/agent-runtime/src/admission/admit.ts, apps/agent-runtime/src/middleware/auth.ts | TS owner cites `crates/ferrogate-gateway/src/auth.rs` by path; signature coverage 36/54. |
| `extensions.rs` | 1389 | MISSING | hand-verified | apps/gateway/src/routes/index.ts:270-287 (registerNotImplemented x3) | 1389 lines. `ExtensionRegistry::from_config` — HTTP plugin extensions from `ExtensionConfig`, `statuses()`, `tools_for()/all_tools()`, the `pre_request`/`post_response` hooks, `emit(GatewayEvent)` — has no TS runtime. **This is the ONLY module behind all 3 of the 251 contract operations that TS declares unimplemented** (`listTools`, `executeTool`, `executeFunction`); every other op is mounted. Recorded (501, not silent). Blast radius: a tenant configures a plugin, sees it in the admin CRUD, and it never runs. |
| `server/site_domains.rs` | 1370 | UNVERIFIED | hand-verified | apps/control-plane/src/routes/site_domain.ts, apps/control-plane/src/site_domain_txt.ts, packages/storage/src/site-domain.ts | TXT-record verification + CRUD are ported. The certificate/custom-hostname PROVISIONING half that acme.rs served has no CF equivalent in the tree. |
| `server/wallets.rs` | 1359 | UNVERIFIED | signature-derived | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/wallets.ts | Not individually re-derived in this pass; signature coverage 5/24. |
| `server/embeddings.rs` | 1241 | PORTED | hand-verified | apps/gateway/src/inference/handlers.ts, apps/gateway/src/inference/schemas.ts | `/v1/embeddings` is one of the 31 gateway contract ops. |
| `server/sites.rs` | 1226 | UNVERIFIED | signature-derived | apps/gateway/src/assets/service.ts, apps/gateway/src/assets/content-gate.ts | Not individually re-derived in this pass; signature coverage 6/25. |
| `server/images.rs` | 1177 | PORTED | hand-verified | apps/gateway/src/inference/handlers.ts, apps/gateway/src/inference/schemas.ts | `/v1/images/generations`. |
| `server/route_groups.rs` | 1141 | PORTED | signature-derived | apps/control-plane/src/routes/index.ts, apps/control-plane/src/routes/admin_agent_upstream.ts | signature coverage 26/26. |
| `server/guardrail_policies.rs` | 1127 | PORTED | signature-derived | apps/control-plane/src/routes/guardrail_policy.ts, apps/cli/src/receipt.ts | signature coverage 27/45. |
| `lifecycle.rs` | 1078 | UNVERIFIED | hand-verified | apps/cli/src/config-gate.ts, apps/control-plane/src/adapters.ts | 1078 lines: process lifecycle + config reload + action-time preflight. Partly OBSOLETE-ON-CF (no process to reload), partly the unported client_action_time preflight. |
| `state_wallets.rs` | 999 | PORTED | signature-derived | packages/storage/src/wallet.ts, apps/mcp/src/admission/quota.ts | signature coverage 16/23. |
| `state_scheduler.rs` | 979 | PORTED | cited-by-TS | apps/control-plane/src/schedule/engine.ts | TS owner cites `crates/ferrogate-gateway/src/state_scheduler.rs` by path; signature coverage 9/21. |
| `server/agent_schedules.rs` | 963 | PORTED | cited-by-TS | apps/control-plane/src/routes/resource.ts, apps/control-plane/src/schedule/model.ts | TS owner cites `crates/ferrogate-gateway/src/server/agent_schedules.rs` by path; signature coverage 5/16. |
| `server/mod.rs` | 955 | PORTED | hand-verified | apps/gateway/src/routes/index.ts | Module declarations only. |
| `state_x402_settlement.rs` | 946 | DELIBERATELY-DROPPED | hand-verified | — | x402/Solana deprioritized (owner directive 2026-07-24). |
| `messages_stream.rs` | 943 | PORTED | cited-by-TS | apps/gateway/src/guardrails/stream.ts | TS owner cites `crates/ferrogate-gateway/src/messages_stream.rs` by path; signature coverage 21/25. |
| `server/x402_spend_policy.rs` | 939 | DELIBERATELY-DROPPED | hand-verified | apps/control-plane/src/routes/x402_spend_policy.ts (CRUD shell) | x402/Solana deprioritized; the policy CRUD shell exists, the settlement runtime does not. |
| `state_routing.rs` | 905 | PORTED | cited-by-TS | packages/providers/src/models.ts | TS owner cites `crates/ferrogate-gateway/src/state_routing.rs` by path; signature coverage 31/39. |
| `server/site_domain_verification.rs` | 864 | PORTED | cited-by-TS | apps/control-plane/src/routes/site_domain.ts, apps/control-plane/src/site_domain_txt.ts | TS owner cites `crates/ferrogate-gateway/src/server/site_domain_verification.rs` by path; signature coverage 4/11. |
| `state_x402_negotiation.rs` | 847 | DELIBERATELY-DROPPED | hand-verified | — | x402/Solana deprioritized. |
| `approval.rs` | 828 | PORTED | cited-by-TS | apps/mcp/src/approvals.ts | TS owner cites `crates/ferrogate-gateway/src/approval.rs` by path; signature coverage 6/22. |
| `server/mcp_rpc.rs` | 791 | PORTED | cited-by-TS | apps/mcp/src/jsonrpc.ts, apps/mcp/src/routes/ingress.ts | TS owner cites `crates/ferrogate-gateway/src/server/mcp_rpc.rs` by path; signature coverage 2/6. |
| `state_asset_lifecycle.rs` | 790 | UNVERIFIED | signature-derived | packages/storage/src/d1/retention-d1.ts, apps/control-plane/src/routes/admin_request_log.ts | Not individually re-derived in this pass; signature coverage 2/13. |
| `state_x402_reconciler.rs` | 789 | DELIBERATELY-DROPPED | hand-verified | — | x402/Solana deprioritized. |
| `server/governed_decision.rs` | 786 | PORTED | signature-derived | apps/gateway/src/ratelimit/workflow.ts, packages/policy/src/workflow-graph.ts | signature coverage 47/75. |
| `responses_stream.rs` | 770 | PORTED | cited-by-TS | apps/gateway/src/guardrails/stream.ts | TS owner cites `crates/ferrogate-gateway/src/responses_stream.rs` by path; signature coverage 15/24. |
| `server/admin_overview.rs` | 769 | PORTED | hand-verified | apps/control-plane/src/routes/admin_overview.ts |  |
| `server/quota_policies.rs` | 723 | UNVERIFIED | signature-derived | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/quota_policy.ts | Not individually re-derived in this pass; signature coverage 4/10. |
| `state_assets.rs` | 631 | PORTED | signature-derived | packages/storage/src/d1/assets-d1.ts, apps/gateway/src/assets/service.ts | signature coverage 5/7. |
| `state_guardrail_evidence.rs` | 612 | UNVERIFIED | signature-derived | apps/agent-runtime/src/runs/model.ts, apps/gateway/src/metering/ports.ts | Not individually re-derived in this pass; signature coverage 1/4. |
| `server/observed_agent_activity.rs` | 587 | PORTED | hand-verified | packages/storage/src/presence.ts, apps/control-plane/src/routes/admin_managed_worker.ts |  |
| `asset_scan.rs` | 567 | PORTED | signature-derived | apps/gateway/src/assets/scan.ts, apps/gateway/src/assets/ports.ts | signature coverage 18/34. |
| `model_routing.rs` | 564 | PORTED | signature-derived | apps/gateway/src/inference/candidates.ts, apps/gateway/src/inference/handlers.ts | signature coverage 3/3. |
| `server/managed_action_guardrail.rs` | 551 | PORTED | hand-verified (CORRECTED wave 19) | — | 551 lines: derives the guardrail `ManagedActionClass`, canonical target string and scannable input text FROM a runtime external action, so managed actions get the same guardrail envelope as user traffic. Depends on `ManagedExternalAction::capability_action`, which is itself unported (see agent-worker::external_actions). **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — apps/mcp/src/ports.ts:466-511 (evaluate_managed_action_guardrail_async + payload_text), run by the tools.ts chokepoint.** |
| `server/payment_attempts.rs` | 542 | DELIBERATELY-DROPPED | hand-verified | apps/control-plane/src/routes/payment_attempt.ts | x402/Solana deprioritized. |
| `asset_signature.rs` | 541 | PORTED | cited-by-TS | apps/gateway/src/assets/signature.ts, apps/gateway/test/assets/signature.test.ts | TS owner cites `crates/ferrogate-gateway/src/asset_signature.rs` by path; signature coverage 16/17. |
| `state_evidence_writer.rs` | 541 | OBSOLETE-ON-CF | hand-verified | `ctx.waitUntil` (19 src files), apps/gateway/src/metering/publisher.ts | Bounded MPSC background writer that existed solely to keep `block_in_place` off a Pingora worker thread (#309). Workers have no thread to park. |
| `server/plans.rs` | 527 | UNVERIFIED | signature-derived | apps/control-plane/src/middleware/errors.ts, apps/control-plane/src/routes/admin_agent_schedule.ts | Not individually re-derived in this pass; signature coverage 3/9. |
| `state_tenancy.rs` | 511 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/store/tenancy.ts | signature coverage 16/35. |
| `server/asset_security.rs` | 497 | PORTED | cited-by-TS | apps/gateway/src/assets/content-gate.ts | TS owner cites `crates/ferrogate-gateway/src/server/asset_security.rs` by path; signature coverage 6/25. |
| `client_action_time.rs` | 494 | MISSING | hand-verified | apps/cli/src/action-identity.ts (SIGNING half only) | 494 lines. The VERIFYING half of signed action-time tokens. Recorded as a PORT-TODO at apps/gateway/src/index.ts:161-173: "a CLI that signs an action-time token today has it ignored rather than verified." |
| `metering.rs` | 494 | UNVERIFIED | signature-derived | packages/guardrails/src/adapters/llm_guard.ts, packages/guardrails/src/adapters/fixture.ts | Not individually re-derived in this pass; signature coverage 3/7. |
| `server/asset_admission.rs` | 487 | UNVERIFIED | signature-derived | apps/gateway/src/ratelimit/workflow.ts, apps/gateway/src/ratelimit/middleware.ts | Not individually re-derived in this pass; signature coverage 2/15. |
| `server/dispatch.rs` | 484 | PORTED | hand-verified | apps/gateway/src/inference/dispatch.ts |  |
| `server/payments.rs` | 416 | DELIBERATELY-DROPPED | hand-verified | apps/control-plane/src/routes/payment_attempt.ts | x402/Solana deprioritized. |
| `state_tools.rs` | 415 | UNVERIFIED | signature-derived | apps/gateway/src/routes/index.ts, apps/mcp/src/index.ts | Not individually re-derived in this pass; signature coverage 7/21. |
| `lib.rs` | 401 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `server/handlers.rs` | 386 | UNVERIFIED | signature-derived | apps/gateway/src/middleware/errors.ts, apps/gateway/src/index.ts | Not individually re-derived in this pass; signature coverage 4/12. |
| `function_egress.rs` | 363 | MISSING | hand-verified | — | 363 lines (#120): gateway-side TLS egress executor for BROKERED edge-function calls — the fail-closed pipeline that runs an already-governed EdgeFunctionHttpRequest and bounds the outcome. `brokered`, `edge_function`, `FunctionInvocation` all return 0 TS hits. |
| `builtin_tools.rs` | 356 | PORTED | hand-verified | apps/mcp/src/tools.ts (`builtinTools()`, `BUILTIN_TOOL_PREFIX`, `fetch_asset`) |  |
| `state_agent_cost_governor.rs` | 327 | UNVERIFIED | signature-derived | apps/gateway/src/ratelimit/token-budget.ts, apps/gateway/src/metering/ports.ts | Not individually re-derived in this pass; signature coverage 3/15. |
| `state_observability.rs` | 327 | UNVERIFIED | signature-derived | packages/config/src/validate/sections.ts, packages/observability/src/index.ts | Not individually re-derived in this pass; signature coverage 8/29. |
| `server/mcp_ingress.rs` | 298 | PORTED | hand-verified | apps/mcp/src/routes/ingress.ts, apps/mcp/src/dispatch.ts |  |
| `server/asset_inline_publish.rs` | 292 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `server/api_key_tenancy.rs` | 274 | UNVERIFIED | hand-verified | apps/control-plane/src/store/tenancy.ts, apps/control-plane/src/store/lifecycle.ts | 274 lines (#340): the API-side half of the console project->workspace cascade. `api_key_tenancy` = 0 direct hits; `cascade` appears in the TS store. Not individually re-derived. |
| `server/asset_stream.rs` | 272 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; no distinctive signatures. |
| `budget_alerts.rs` | 264 | MISSING | hand-verified | packages/storage/src/budget-alerts.ts (detection half only) | 264 lines: the outbound webhook POST that DELIVERS a budget-threshold alert (#170). Threshold detection + idempotency are ported; the dispatch is not. `webhookUrl` = 0 src hits, `budget_threshold` = 0. Blast radius: an operator configures `webhook_url` in config (the validator accepts it) and is never notified. |
| `server/asset_publish_gate.rs` | 260 | UNVERIFIED | signature-derived | apps/gateway/src/assets/scan.ts, apps/gateway/src/assets/ports.ts | Not individually re-derived in this pass; signature coverage 2/6. |
| `state_x402_sweeper.rs` | 255 | DELIBERATELY-DROPPED | hand-verified | — | x402/Solana deprioritized. |
| `server/proxy.rs` | 251 | UNVERIFIED | signature-derived | apps/gateway/src/routes/reverse-proxy.ts, apps/gateway/src/index.ts | Not individually re-derived in this pass; signature coverage 4/11. |
| `semantic_cache.rs` | 233 | PORTED | cited-by-TS | apps/gateway/src/cache/config.ts, apps/gateway/src/cache/semantic.ts | TS owner cites `crates/ferrogate-gateway/src/semantic_cache.rs` by path; signature coverage 6/6. |
| `function_egress_cloudflare.rs` | 222 | MISSING | hand-verified | — | 222 lines: the Cloudflare-flavoured half of the same brokered-egress executor. 0 TS hits. |
| `server/shadow.rs` | 221 | PORTED | hand-verified | apps/gateway/src/inference/shadow.ts | Sampled, budget-capped fire-and-forget duplication (#276). |
| `server/mcp_identity.rs` | 220 | PORTED | cited-by-TS | apps/mcp/src/identity/routes.ts | TS owner cites `crates/ferrogate-gateway/src/server/mcp_identity.rs` by path; signature coverage 3/7. |
| `server/agent_cost_burn.rs` | 218 | PORTED | cited-by-TS | apps/control-plane/src/routes/admin_agent_cost_burn.ts, apps/control-plane/test/agent-cost-burn-read.test.ts | TS owner cites `crates/ferrogate-gateway/src/server/agent_cost_burn.rs` by path; signature coverage 6/9. |
| `server/api_contract.rs` | 215 | PORTED | cited-by-TS | apps/agent-runtime/src/contract.ts, apps/control-plane/src/contract.ts | TS owner cites `crates/ferrogate-gateway/src/server/api_contract.rs` by path; signature coverage 1/2. |
| `asset_registry.rs` | 202 | PORTED | cited-by-TS | apps/gateway/src/assets/registry.ts | TS owner cites `crates/ferrogate-gateway/src/asset_registry.rs` by path; signature coverage 6/6. |
| `server/billing_outbox.rs` | 198 | UNVERIFIED | hand-verified | apps/gateway/src/metering/publisher.ts | 198 lines. Outbox drain surface; the metering publisher is the nearest owner but the drain endpoint was not individually re-derived. |
| `state_rbac.rs` | 183 | PORTED | cited-by-TS | apps/gateway/test/rbac.test.ts | TS owner cites `crates/ferrogate-gateway/src/state_rbac.rs` by path; signature coverage 10/14. |
| `tokenizer.rs` | 180 | PORTED | hand-verified | apps/gateway/src/inference/estimate.ts | cl100k-style estimation. |
| `server/a2a.rs` | 179 | PORTED | hand-verified | apps/agent-runtime/src/agents/ingress.ts | Verified line-by-line: `collect_a2a_text` -> `a2aReplyText`, `a2a_message_count` -> `a2aMessageCount`, `a2a_input_envelope`/`a2a_output_envelope` -> `envelopeFromText("a2a", ...)` in ports.ts. |
| `state_observed_activity.rs` | 173 | PORTED | signature-derived | apps/control-plane/src/routes/admin_managed_worker.ts, apps/cli/src/registry.ts | signature coverage 1/2. |
| `server/asset_egress.rs` | 170 | PORTED | cited-by-TS | apps/gateway/src/assets/egress.ts | TS owner cites `crates/ferrogate-gateway/src/server/asset_egress.rs` by path; signature coverage 3/4. |
| `service_storage.rs` | 143 | UNVERIFIED | signature-derived | packages/config/src/schema/enums.ts, packages/storage/src/provider.ts | Not individually re-derived in this pass; signature coverage 4/10. |
| `state_rollout.rs` | 129 | UNVERIFIED | signature-derived | apps/gateway/src/inference/ports.ts, apps/gateway/src/inference/shadow.ts | Not individually re-derived in this pass; signature coverage 1/4. |
| `tenant_scope_reads.rs` | 115 | OBSOLETE-ON-CF | hand-verified | apps/gateway/src/tenancy/index.ts | 115 lines: a trait seam (#543) whose only job is to let a test produce a storage FAILURE inside a scope resolver. The TS store ports are already interfaces, so the seam is structural, not behavioural. |
| `server/usage_reports.rs` | 114 | PORTED | signature-derived | apps/gateway/src/assets/service.ts, apps/control-plane/src/routes/billing.ts | signature coverage 1/2. |
| `billing_client.rs` | 66 | PORTED | signature-derived | apps/gateway/src/metering/ports.ts, apps/gateway/src/metering/publisher.ts | signature coverage 3/3. |
| `state_payment_attempts.rs` | 66 | DELIBERATELY-DROPPED | hand-verified | apps/control-plane/src/routes/payment_attempt.ts | x402/Solana deprioritized. |
| `lifecycle_gate.rs` | 45 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |
| `server/admin_list_query.rs` | 41 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |
| `body.rs` | 27 | PORTED | signature-derived | apps/gateway/src/inference/handlers.ts | signature coverage 1/2. |
| `dashboard.rs` | 7 | PORTED | signature-derived | apps/control-plane/src/routes/admin_overview.ts | signature coverage 1/2. |

<details><summary>TEST-ONLY modules (73, 35,490 lines)</summary>

| Module | Lines |
|---|---:|
| `state_quota_and_policy_test.rs` | 2932 |
| `server/agent_jobs_test.rs` | 2338 |
| `auth_admission_test.rs` | 1625 |
| `state_x402_reconciler_test.rs` | 1529 |
| `state_routing_test.rs` | 1401 |
| `server/x402_spend_policy_test.rs` | 1339 |
| `server/asset_presign_test.rs` | 1292 |
| `state_x402_negotiation_test.rs` | 1231 |
| `state_mcp_identity_test.rs` | 1211 |
| `state_x402_settlement_test.rs` | 960 |
| `server/sites_test.rs` | 791 |
| `state_guardrail_evidence_test.rs` | 761 |
| `server/site_domain_verification_test.rs` | 745 |
| `server/observed_agent_activity_test.rs` | 644 |
| `state_x402_sweeper_test.rs` | 625 |
| `builtin_tools_test.rs` | 609 |
| `server/mcp_rpc_test.rs` | 605 |
| `auth_test.rs` | 595 |
| `server/asset_inline_publish_test.rs` | 591 |
| `server/external_actions_target_test.rs` | 542 |
| `state_asset_lifecycle_test.rs` | 520 |
| `server/assets_test.rs` | 519 |
| `server/asset_admission_test.rs` | 420 |
| `server/governed_decision_conformance_test.rs` | 419 |
| `server/asset_stream_test.rs` | 398 |
| `state_agent_cost_governor_test.rs` | 394 |
| `server/a2a_test.rs` | 384 |
| `function_egress_test.rs` | 372 |
| `state_wallet_settlement_test.rs` | 366 |
| `server/asset_security_test.rs` | 365 |
| `server/api_key_tenancy_test.rs` | 364 |
| `function_egress_cloudflare_test.rs` | 358 |
| `server/admin_overview_test.rs` | 358 |
| `state_billing_outbox_test.rs` | 323 |
| `server/messages_test.rs` | 321 |
| `server/embeddings_test.rs` | 315 |
| `server/agent_schedules_test.rs` | 310 |
| `server/asset_egress_test.rs` | 305 |
| `server/mcp_ingress_test.rs` | 303 |
| `server/payment_attempts_test.rs` | 301 |
| `model_routing_test.rs` | 295 |
| `state_observed_activity_test.rs` | 281 |
| `state_rollout_test.rs` | 280 |
| `state_assets_test.rs` | 270 |
| `server/governed_decision_test.rs` | 261 |
| `state_workers_ai_llama_guard_test.rs` | 260 |
| `tenant_scope_reads_fault.rs` | 256 |
| `state_tenant_identity_test.rs` | 253 |
| `server/shadow_test.rs` | 235 |
| `state_scheduler_lifecycle_test.rs` | 231 |
| `server/images_test.rs` | 228 |
| `server/rbac_test.rs` | 206 |
| `state_agent_runtime_workflow_gate_test.rs` | 205 |
| `server/chat_provider_attempt_test.rs` | 183 |
| `responses_debug_test.rs` | 179 |
| `server/guardrail_policies_test.rs` | 178 |
| `semantic_cache_test.rs` | 169 |
| `server/site_domains_test.rs` | 163 |
| `server/route_groups_test.rs` | 162 |
| `asset_registry_test.rs` | 160 |
| `metering_test.rs` | 156 |
| `server/agent_cost_burn_test.rs` | 153 |
| `client_action_time_test.rs` | 148 |
| `state_billing_metering_metrics_test.rs` | 144 |
| `lifecycle_admin_reload_test.rs` | 141 |
| `state_self_hosted_security_test.rs` | 113 |
| `server/api_contract_test.rs` | 109 |
| `service_storage_test.rs` | 74 |
| `server/admin_list_query_test.rs` | 62 |
| `state_debug_test.rs` | 60 |
| `lifecycle_gate_test.rs` | 56 |
| `state_reload_test.rs` | 21 |
| `server/mcp_identity_test.rs` | 17 |

</details>

### `crates/ferrogate-guardrails` — 14 product modules (6,959 lines), 8 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `policy.rs` | 1050 | PORTED | signature-derived | packages/guardrails/src/policy.ts, packages/guardrails/src/index.ts | signature coverage 43/51. |
| `deterministic.rs` | 966 | PORTED | signature-derived | packages/guardrails/src/deterministic.ts, packages/guardrails/src/index.ts | signature coverage 16/27. |
| `envelope.rs` | 937 | PORTED | signature-derived | packages/guardrails/src/envelope.ts, packages/guardrails/src/index.ts | signature coverage 28/33. |
| `custom_http.rs` | 679 | PORTED | signature-derived | packages/guardrails/src/custom_http.ts, apps/gateway/src/guardrails/detectors.ts | signature coverage 14/20. |
| `adapters/workers_ai_llama_guard.rs` | 641 | PORTED | cited-by-TS | packages/guardrails/src/adapters/workers_ai_llama_guard.ts, packages/guardrails/test/adapters.test.ts | TS owner cites `crates/ferrogate-guardrails/src/adapters/workers_ai_llama_guard.rs` by path; signature coverage 18/22. |
| `evaluation.rs` | 610 | PORTED | signature-derived | packages/guardrails/src/evaluation.ts, packages/guardrails/src/index.ts | signature coverage 18/37. |
| `conformance.rs` | 473 | PORTED | signature-derived | packages/guardrails/src/conformance.ts, packages/guardrails/src/index.ts | signature coverage 12/20. |
| `adapters/presidio.rs` | 398 | PORTED | signature-derived | packages/guardrails/src/adapters/presidio.ts, apps/gateway/src/guardrails/detectors.ts | signature coverage 14/19. |
| `adapters/llm_guard.rs` | 330 | PORTED | signature-derived | packages/guardrails/src/adapters/llm_guard.ts, packages/guardrails/src/adapters/presidio.ts | signature coverage 13/17. |
| `adapters/mod.rs` | 296 | PORTED | signature-derived | packages/guardrails/src/adapters/transport.ts, packages/guardrails/src/adapters/presidio.ts | signature coverage 14/17. |
| `contract.rs` | 288 | PORTED | cited-by-TS | apps/control-plane/src/routes/guardrail_policy.ts | TS owner cites `crates/ferrogate-guardrails/src/contract.rs` by path; signature coverage 32/33. |
| `adapters/fixture.rs` | 142 | UNVERIFIED | signature-derived | packages/guardrails/src/adapters/fixture.ts, packages/guardrails/src/adapters/transport.ts | Not individually re-derived in this pass; signature coverage 2/6. |
| `net.rs` | 87 | PORTED | signature-derived | packages/guardrails/src/net.ts, packages/guardrails/src/index.ts | signature coverage 3/3. |
| `lib.rs` | 62 | PORTED | signature-derived | apps/mcp/src/protocol.ts, apps/control-plane/src/store/d1.ts | signature coverage 1/1. |

<details><summary>TEST-ONLY modules (8, 3,566 lines)</summary>

| Module | Lines |
|---|---:|
| `deterministic_test.rs` | 828 |
| `lib_test.rs` | 604 |
| `adapters_test.rs` | 538 |
| `policy_test.rs` | 490 |
| `adapters/workers_ai_llama_guard_test.rs` | 340 |
| `evaluation_test.rs` | 323 |
| `envelope_test.rs` | 222 |
| `conformance_test.rs` | 221 |

</details>

### `crates/ferrogate-mcp` — 10 product modules (3,115 lines), 10 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `http_client.rs` | 621 | PORTED | cited-by-TS | apps/mcp/src/transport.ts | TS owner cites `crates/ferrogate-mcp/src/http_client.rs` by path; signature coverage 12/17. |
| `manager.rs` | 585 | PORTED | cited-by-TS | apps/mcp/src/session.ts | TS owner cites `crates/ferrogate-mcp/src/manager.rs` by path; signature coverage 18/24. |
| `mcp_worker_deploy.rs` | 396 | MISSING | hand-verified | — | 396 lines (#409): uploads a tenants own hosted MCP-server Worker (Workers Script PUT + McpAgent DO binding + OAUTH_KV + SQLite DO migration). Recorded as a SCOPE-boundary PORT-TODO at apps/mcp/src/index.ts:39-47 — it belongs in apps/control-plane, not the data-plane ingress. Blast radius: tenants cannot get a hosted MCP server provisioned. |
| `stdio_client.rs` | 394 | PORTED | cited-by-TS | apps/mcp/src/ports.ts | TS owner cites `crates/ferrogate-mcp/src/stdio_client.rs` by path; signature coverage 9/15. |
| `config.rs` | 345 | PORTED | cited-by-TS | apps/mcp/src/catalog.ts, apps/mcp/src/durable.ts | TS owner cites `crates/ferrogate-mcp/src/config.rs` by path; signature coverage 26/29. |
| `protocol.rs` | 336 | PORTED | cited-by-TS | apps/mcp/src/protocol.ts | TS owner cites `crates/ferrogate-mcp/src/protocol.rs` by path; signature coverage 28/39. |
| `tls.rs` | 153 | OBSOLETE-ON-CF | hand-verified | — | 153 lines: rustls client config for upstream MCP servers. `fetch()` handles TLS on Workers. |
| `cloudflare.rs` | 110 | UNVERIFIED | hand-verified | apps/mcp/src/transport.ts | 110 lines, ratio 0.125. |
| `lib.rs` | 104 | PORTED | signature-derived | packages/config/src/validate/entities.ts, apps/mcp/src/catalog.ts | signature coverage 10/18. |
| `jsonrpc.rs` | 71 | PORTED | cited-by-TS | apps/mcp/src/jsonrpc.ts | TS owner cites `crates/ferrogate-mcp/src/jsonrpc.rs` by path; signature coverage 4/4. |

<details><summary>TEST-ONLY modules (10, 2,204 lines)</summary>

| Module | Lines |
|---|---:|
| `http_client_test.rs` | 548 |
| `mcp_worker_deploy_test.rs` | 316 |
| `manager_test.rs` | 277 |
| `stdio_client_test.rs` | 260 |
| `cloudflare_test.rs` | 210 |
| `config_test.rs` | 176 |
| `protocol_test.rs` | 169 |
| `test_support.rs` | 148 |
| `tls_test.rs` | 69 |
| `jsonrpc_test.rs` | 31 |

</details>

### `crates/ferrogate-observability` — 8 product modules (2,120 lines), 3 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `prometheus.rs` | 586 | PORTED | signature-derived | packages/observability/src/prometheus.ts, apps/gateway/src/routes/metrics.ts | signature coverage 49/49. |
| `otlp.rs` | 451 | PORTED | cited-by-TS | apps/telemetry/src/schemas.ts | TS owner cites `crates/ferrogate-observability/src/otlp.rs` by path; signature coverage 27/62. |
| `config.rs` | 380 | PORTED | signature-derived | packages/observability/src/config.ts, packages/observability/src/index.ts | signature coverage 12/15. |
| `cloudflare.rs` | 224 | PORTED | cited-by-TS | packages/config/src/validate/helpers.ts | TS owner cites `crates/ferrogate-observability/src/cloudflare.rs` by path; signature coverage 9/13. |
| `metrics.rs` | 168 | PORTED | signature-derived | packages/observability/src/metrics.ts, packages/observability/src/prometheus.ts | signature coverage 6/6. |
| `backend.rs` | 151 | PORTED | signature-derived | packages/observability/src/backend.ts, packages/observability/src/cloudflare.ts | signature coverage 4/5. |
| `spans.rs` | 128 | PORTED | signature-derived | packages/observability/src/spans.ts, apps/gateway/src/inference/reliability.ts | signature coverage 12/19. |
| `lib.rs` | 32 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |

<details><summary>TEST-ONLY modules (3, 736 lines)</summary>

| Module | Lines |
|---|---:|
| `lib_test.rs` | 370 |
| `cloudflare_test.rs` | 234 |
| `backend_test.rs` | 132 |

</details>

### `crates/ferrogate-payments` — 7 product modules (2,033 lines), 2 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `wire.rs` | 759 | PORTED | signature-derived | packages/payments/src/wire.ts, packages/payments/src/index.ts | signature coverage 35/43. |
| `intent.rs` | 699 | PORTED | signature-derived | packages/payments/src/intent.ts, packages/policy/src/x402/wire.ts | signature coverage 21/24. |
| `proof.rs` | 183 | PORTED | signature-derived | packages/payments/src/proof.ts, packages/payments/src/index.ts | signature coverage 8/10. |
| `attempt_state.rs` | 152 | PORTED | signature-derived | packages/storage/src/payment-attempt.ts, packages/payments/src/attempt_state.ts | signature coverage 4/6. |
| `error.rs` | 120 | PORTED | signature-derived | packages/payments/src/index.ts, packages/payments/src/proof.ts | signature coverage 1/1. |
| `lib.rs` | 67 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; signature coverage 0/1. |
| `sdk.rs` | 53 | PORTED | signature-derived | packages/payments/src/index.ts, packages/payments/src/sdk.ts | signature coverage 6/7. |

<details><summary>TEST-ONLY modules (2, 485 lines)</summary>

| Module | Lines |
|---|---:|
| `intent_test.rs` | 390 |
| `attempt_state_test.rs` | 95 |

</details>

### `crates/ferrogate-policy` — 4 product modules (3,154 lines), 1 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `x402_spend.rs` | 1449 | PORTED | cited-by-TS | packages/policy/src/x402/wire.ts | TS owner cites `crates/ferrogate-policy/src/x402_spend.rs` by path; signature coverage 71/82. |
| `quota.rs` | 1119 | PORTED | signature-derived | packages/policy/src/quota.ts, apps/control-plane/src/routes/tenant_hierarchy.ts | signature coverage 6/6. |
| `workflow_budget.rs` | 354 | PORTED | signature-derived | packages/policy/src/workflow-budget.ts, apps/gateway/src/ratelimit/workflow.ts | signature coverage 13/13. |
| `lib.rs` | 232 | PORTED | signature-derived | packages/policy/src/policy-engine.ts, packages/policy/src/index.ts | signature coverage 5/6. |

<details><summary>TEST-ONLY modules (1, 1,061 lines)</summary>

| Module | Lines |
|---|---:|
| `x402_spend_test.rs` | 1061 |

</details>

### `crates/ferrogate-providers` — 16 product modules (8,777 lines), 1 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `sigv4.rs` | 1367 | PORTED | cited-by-TS | apps/gateway/src/assets/sigv4.ts | TS owner cites `crates/ferrogate-providers/src/sigv4.rs` by path; signature coverage 15/25. |
| `canonical.rs` | 944 | PORTED | signature-derived | packages/providers/src/canonical.ts, packages/providers/src/gemini.ts | signature coverage 9/9. |
| `openai.rs` | 878 | PORTED | signature-derived | packages/providers/src/openai.ts, packages/providers/src/anthropic.ts | signature coverage 15/18. |
| `gemini.rs` | 796 | PORTED | signature-derived | packages/providers/src/gemini.ts, packages/providers/src/vertex.ts | signature coverage 26/30. |
| `bedrock.rs` | 739 | PORTED | signature-derived | packages/providers/src/bedrock.ts, packages/providers/src/gemini.ts | signature coverage 17/23. |
| `registry.rs` | 618 | PORTED | signature-derived | packages/providers/src/registry.ts, packages/providers/src/types.ts | signature coverage 15/15. |
| `vertex.rs` | 540 | PORTED | signature-derived | packages/providers/src/vertex.ts, packages/providers/src/gemini.ts | signature coverage 10/16. |
| `anthropic.rs` | 536 | PORTED | cited-by-TS | apps/gateway/src/streaming/usage.ts | TS owner cites `crates/ferrogate-providers/src/anthropic.rs` by path; signature coverage 13/17. |
| `anthropic_messages.rs` | 533 | PORTED | signature-derived | apps/gateway/src/inference/anthropic.ts, packages/providers/src/anthropic_messages.ts | signature coverage 21/22. |
| `types.rs` | 468 | PORTED | signature-derived | packages/providers/src/types.ts, packages/providers/src/index.ts | signature coverage 39/48. |
| `models.rs` | 350 | PORTED | signature-derived | packages/providers/src/models.ts, apps/gateway/src/inference/ports.ts | signature coverage 11/17. |
| `cloudflare.rs` | 281 | PORTED | signature-derived | packages/providers/src/cloudflare.ts, packages/providers/src/index.ts | signature coverage 9/12. |
| `azure.rs` | 279 | PORTED | signature-derived | packages/providers/src/azure.ts, packages/providers/src/openai.ts | signature coverage 5/10. |
| `openrouter.rs` | 222 | PORTED | signature-derived | apps/gateway/src/inference/adapters.ts, packages/providers/src/openrouter.ts | signature coverage 3/6. |
| `grok.rs` | 168 | PORTED | signature-derived | packages/providers/src/grok.ts, apps/gateway/src/inference/adapters.ts | signature coverage 1/2. |
| `lib.rs` | 58 | PORTED | signature-derived | — | Trivial module (re-exports / small type alias set). |

<details><summary>TEST-ONLY modules (1, 416 lines)</summary>

| Module | Lines |
|---|---:|
| `cloudflare_test.rs` | 416 |

</details>

### `crates/ferrogate-routing` — 2 product modules (226 lines), 0 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `rollout.rs` | 205 | PORTED | signature-derived | packages/routing/src/rollout.ts, packages/routing/src/index.ts | signature coverage 6/6. |
| `lib.rs` | 21 | PORTED | cited-by-TS | packages/routing/src/index.ts | TS owner cites `crates/ferrogate-routing/src/lib.rs` by path; signature coverage 2/2. |

### `crates/ferrogate-runtime` — 37 product modules (29,044 lines), 30 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `self_hosted_worker.rs` | 3629 | PORTED | cited-by-TS | apps/agent-runtime/src/crypto.ts, apps/agent-runtime/src/durable/adapters.ts | TS owner cites `crates/ferrogate-runtime/src/self_hosted_worker.rs` by path; signature coverage 46/81. |
| `managed_worker.rs` | 3612 | UNVERIFIED | hand-verified | apps/control-plane/src/routes/admin_managed_worker.ts, apps/agent-runtime/src/workers/frame.ts | 3612 lines, ratio 0.11. Admin CRUD + the transport frame are ported; the managed-worker orchestration body was not re-derived. |
| `managed_external_action.rs` | 1997 | MISSING | hand-verified | apps/agent-runtime/src/ports.ts (CapabilityRequest — coarse capability strings) | 1997 lines: the 9-variant typed action contract (Tool, McpTool, Cli, Filesystem, Browser, Rest, Secret, Memory, NetworkEgress) with per-variant policy fields. TS models it as `requiredCapabilities: readonly string[]`, which cannot express a per-variant decision. |
| `framework_adapter.rs` | 1968 | PORTED | hand-verified | apps/agent-runtime/src/durable/adapters.ts, apps/agent-runtime/src/runs/do.ts, apps/agent-runtime/src/runs/lifecycle.ts |  |
| `cloudflare_agent_cost.rs` | 1487 | PORTED | hand-verified | apps/control-plane/src/routes/admin_agent_cost_burn.ts, packages/storage/src/agent-cost-burn.ts, apps/gateway/src/ratelimit/token-budget.ts | #428 agent cost governance. |
| `self_hosted_mtls.rs` | 1342 | UNVERIFIED | hand-verified | apps/agent-runtime/src/middleware/auth.ts (test/mtls.test.ts) | 1342 lines, ratio 0.15. TS has an mTLS-shaped worker-plane credential check; the certificate pinning/rotation body was not re-derived. |
| `action_identity.rs` | 1172 | PORTED | hand-verified | apps/agent-runtime/src/runs/governance.ts, apps/cli/src/action-identity.ts | Canonical `sha256:<hex>` action fingerprints (#305/#307). |
| `target_capability.rs` | 1149 | PORTED | cited-by-TS | packages/config/src/schema/capability-target.ts, packages/config/src/validate/capability-target.ts | TS owner cites `crates/ferrogate-runtime/src/target_capability.rs` by path; signature coverage 9/30. |
| `coding_agent/credential_broker.rs` | 1114 | MISSING | hand-verified | — | 1114 lines: the phase-1 credential grant/revoke broker (clone credential minted, scoped, then revoked at `finalize`). The single highest-risk unported module in this family. |
| `agent.rs` | 1085 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/runs/do.ts | 1085 lines: bounded agent harness over `std::process::Command`/Stdio. No process spawn on workerd. |
| `cloudflare_worker.rs` | 826 | PORTED | hand-verified | packages/cloudflare/src/client.ts, packages/cloudflare/src/scopes.ts | Workers Script API wrapper; largely superseded by native bindings (see cf-crate-assessment.md). |
| `coding_agent/materialize.rs` | 793 | MISSING | hand-verified | — | 793 lines: which commit, cloned with which credential, revoked where. |
| `cloudflare_container.rs` | 692 | PORTED | hand-verified | apps/agent-runtime/src/runs/governance.ts, apps/agent-runtime/src/ports.ts |  |
| `coding_agent/write_back.rs` | 664 | MISSING | hand-verified | — | 664 lines: who authorized the outward side effect, and where is the audit event. |
| `coding_agent/container_adapter.rs` | 640 | MISSING | hand-verified | — | 640 lines: `ContainerCodingAgentAdapter`, which drives git through #415 `/container/exec`. |
| `cloudflare_container_egress.rs` | 489 | PORTED | hand-verified | apps/agent-runtime/src/runs/governance.ts (egress allowlist; EMPTY ⇒ SEALED) | #471 prevention half. |
| `capability_boundary.rs` | 467 | UNVERIFIED | hand-verified | apps/agent-runtime/src/ports.ts (CapabilityRequest/GovernancePort), packages/config/src/validate/capability-target.ts | 467 lines; `capabilityBoundary` = 0 direct TS hits. Structurally represented by GovernancePort, but the boundary body was not re-derived. |
| `cloudflare_agent_memory.rs` | 465 | MISSING | hand-verified | — | 465 lines (#427): per-agent-instance memory — `state` get/set, SQL query, chat-history get/prune, the default-off Vectorize semantic-memory pilot, and the tenant-isolating instance naming scheme, all as governed calls to the agent-gateway Worker authenticated `/memory/*` routes. `agentMemory` = 0 TS hits and no `/memory/*` route exists in apps/agent-runtime. Blast radius: agents have no durable memory surface; chat history cannot be pruned per tenant. |
| `cloudflare_agent_schedule.rs` | 456 | PORTED | hand-verified | apps/control-plane/src/schedule/{engine,cron,model,scheduled}.ts, packages/storage/src/d1/agent-schedule-d1.ts |  |
| `cloudflare_container_tether_audit.rs` | 442 | MISSING | hand-verified | — | 442 lines (#471): tether-bypass **detection** — reconciles provider-reported usage against gateway-metered usage per run and emits a typed fail-loud verdict "so a bypass that prevention did not catch is never silent". `tether` = 0 TS hits. The PREVENTION half (enableInternet:false + one-host allowlist) IS ported in governance.ts; the detection half that exists precisely because prevention is only as good as its configuration is not. Security-relevant. |
| `isolation.rs` | 403 | OBSOLETE-ON-CF | hand-verified | apps/agent-runtime/src/ports.ts (IsolationGrant) | See governance.ts §8.2/8.4 platform-limit note. |
| `cloudflare_gateway_control.rs` | 387 | PORTED | hand-verified | apps/agent-runtime (IS the agent-gateway Worker these verbs targeted) | #413: the Rust mapped lifecycle verbs onto a remote Workers control API. In the TS tree that Worker is in-repo, so the hop collapses. |
| `coding_agent/run.rs` | 356 | MISSING | hand-verified | — | 356 lines: long-running filesystem-mutating execution to a terminal status. |
| `coding_agent/bootstrap.rs` | 345 | MISSING | hand-verified | — | 345 lines: which agent, which task, model traffic pointed where. |
| `cloudflare_worker_target.rs` | 307 | UNVERIFIED | hand-verified | packages/config/src/schema/capability-target.ts | 307 lines, ratio 0. |
| `coding_agent/extract.rs` | 301 | MISSING | hand-verified | — | 301 lines: what did it produce, and to which run_id does that belong (`id_is_consistent`). |
| `cloudflare_gateway_deploy.rs` | 300 | OBSOLETE-ON-CF | hand-verified | wrangler (PORT-PLAN: "Wrangler = bundle/deploy") | Deploying a Worker from application code; deploy is a Wrangler/control-plane concern on this stack. |
| `egress_dispatch_stage.rs` | 263 | MISSING | hand-verified | — | 263 lines (#353): the TYPED discriminant recording how far an outbound dispatch got on the wire, so a payment attempt can tell "no request byte reached the upstream" from "the request may have reached the upstream". 0 TS hits for `dispatchStage` or the message text. Consumers are the x402 settlement loop (dropped) — but the same distinction gates retry safety for any at-most-once egress. |
| `supabase_edge_function.rs` | 262 | MISSING | hand-verified | — | 262 lines: the Supabase Edge Function target of the brokered-egress pipeline. (Supabase appears in TS only as a storage-provider enum.) |
| `coding_agent/work_product_artifact.rs` | 251 | MISSING | hand-verified | apps/agent-runtime/src/runs/lifecycle.ts (PARTIAL — filter + run_id re-derivation only) | 251 lines. The TS carries the work-product envelope verbatim but explicitly declines to re-derive `product_id`, `repo_verified` and `published.matches_work_product` because the model has no port. Self-documented at lifecycle.ts:454-467: "`crates/ferrogate-runtime/src/coding_agent/` has NO TypeScript port anywhere in this tree — it is not in PORT-PLAN.md either." |
| `lib.rs` | 233 | UNVERIFIED | signature-derived | — | Not individually re-derived in this pass; signature coverage 0/1. |
| `coding_agent/mod.rs` | 219 | MISSING | hand-verified | — | The five-phase coding-agent adapter contract (#472): materialize -> bootstrap -> run -> extract -> write-back, plus the mandatory `finalize` that discharges phase-1 credential obligations. |
| `coding_agent/adapter.rs` | 209 | MISSING | hand-verified | — | 209 lines: the `CodingAgentAdapter` trait. |
| `coding_agent/error.rs` | 206 | MISSING | hand-verified | — | 206 lines. |
| `function_token.rs` | 200 | MISSING | hand-verified | — | 200 lines: the short-lived token minted for a brokered function invocation. |
| `function_egress.rs` | 197 | MISSING | hand-verified | — | 197 lines: runtime half of the brokered edge-function egress (#120). |
| `reload.rs` | 116 | OBSOLETE-ON-CF | hand-verified | apps/control-plane/src/adapters.ts | 116 lines: in-process config snapshot generation counter. A Worker isolate is replaced, not reloaded. |

<details><summary>TEST-ONLY modules (30, 11,014 lines)</summary>

| Module | Lines |
|---|---:|
| `cloudflare_agent_cost_test.rs` | 1354 |
| `coding_agent/adapter_test.rs` | 819 |
| `coding_agent/credential_broker_test.rs` | 718 |
| `coding_agent/container_adapter_test.rs` | 637 |
| `cloudflare_worker_test.rs` | 507 |
| `cloudflare_container_test.rs` | 485 |
| `self_hosted_mtls_conformance_test.rs` | 448 |
| `coding_agent/materialize_test.rs` | 439 |
| `cloudflare_agent_memory_test.rs` | 407 |
| `cloudflare_worker_target_test.rs` | 406 |
| `target_capability_test.rs` | 398 |
| `cloudflare_agent_schedule_test.rs` | 391 |
| `cloudflare_gateway_control_test.rs` | 387 |
| `coding_agent/write_back_test.rs` | 380 |
| `isolation_test.rs` | 362 |
| `self_hosted_mtls_issuance_test.rs` | 293 |
| `cloudflare_container_egress_test.rs` | 286 |
| `egress_dispatch_stage_test.rs` | 265 |
| `coding_agent/work_product_artifact_test.rs` | 249 |
| `capability_boundary_test.rs` | 243 |
| `cloudflare_gateway_deploy_test.rs` | 243 |
| `coding_agent/extract_test.rs` | 202 |
| `supabase_edge_function_test.rs` | 195 |
| `managed_external_action_red_team_test.rs` | 186 |
| `cloudflare_container_tether_audit_test.rs` | 143 |
| `function_egress_test.rs` | 138 |
| `function_egress_red_team_test.rs` | 136 |
| `function_token_test.rs` | 131 |
| `managed_external_action_target_test.rs` | 87 |
| `self_hosted_worker_security_test.rs` | 79 |

</details>

### `crates/ferrogate-secrets` — 4 product modules (1,745 lines), 4 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `lib.rs` | 796 | PORTED | signature-derived | packages/secrets/src/vault.ts, packages/secrets/src/registry.ts | signature coverage 16/21. |
| `cloudflare.rs` | 515 | PORTED | signature-derived | packages/secrets/src/cloudflare-consts.ts, packages/secrets/src/cloudflare.ts | signature coverage 12/16. |
| `cloudflare_bindings.rs` | 223 | PORTED | signature-derived | packages/secrets/src/cloudflare-bindings.ts, packages/secrets/src/index.ts | signature coverage 9/10. |
| `cloudflare_caps.rs` | 211 | PORTED | signature-derived | packages/secrets/src/cloudflare-caps.ts, packages/secrets/src/index.ts | signature coverage 11/11. |

<details><summary>TEST-ONLY modules (4, 1,139 lines)</summary>

| Module | Lines |
|---|---:|
| `cloudflare_test.rs` | 802 |
| `cloudflare_caps_test.rs` | 193 |
| `vault_debug_test.rs` | 97 |
| `cloudflare_debug_test.rs` | 47 |

</details>

### `crates/ferrogate-storage` — 43 product modules (49,824 lines), 37 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `lib.rs` | 18430 | PORTED | hand-verified | packages/storage/src/** (36 modules), apps/control-plane/src/store/** | 18430-line crate root (Postgres SQL + Stored* domain types). The domain types and the store contract are ported; the Postgres SQL is replaced by D1. |
| `mcp_identity.rs` | 2830 | PORTED | hand-verified | apps/mcp/src/durable.ts, apps/mcp/src/identity/oauth.ts, apps/mcp/src/identity/routes.ts |  |
| `control_plane_store_d1/mod.rs` | 2486 | PORTED | hand-verified | apps/control-plane/src/store/d1.ts, packages/storage/src/d1/index.ts |  |
| `control_plane_store_memory.rs` | 2458 | PORTED | hand-verified | apps/control-plane/src/store/memory.ts |  |
| `control_plane_store_postgres.rs` | 2090 | OBSOLETE-ON-CF | hand-verified | apps/control-plane/src/store/d1.ts | Postgres implementation of the store contract; D1 is the CF implementation. |
| `payment_attempt.rs` | 1522 | DELIBERATELY-DROPPED | hand-verified | packages/storage/src/payment-attempt.ts (schema only) | x402/Solana deprioritized. |
| `wallet.rs` | 1501 | PORTED | signature-derived | packages/storage/src/wallet.ts, packages/storage/src/d1/wallet-d1.ts | signature coverage 27/27. |
| `control_plane_store.rs` | 1318 | PORTED | hand-verified | apps/control-plane/src/ports.ts, apps/control-plane/src/store/query.ts | The store trait itself. |
| `control_plane_store_d1/assets.rs` | 1218 | PORTED | signature-derived | packages/storage/src/d1/assets-d1.ts, apps/gateway/src/assets/service.ts | signature coverage 15/19. |
| `agent_schedule.rs` | 1017 | PORTED | cited-by-TS | apps/control-plane/src/schedule/cron.ts, apps/control-plane/src/schedule/model.ts | TS owner cites `crates/ferrogate-storage/src/agent_schedule.rs` by path; signature coverage 27/28. |
| `control_plane_store_d1/wallet.rs` | 935 | PORTED | cited-by-TS | packages/storage/src/d1/wallet-d1.ts | TS owner cites `crates/ferrogate-storage/src/control_plane_store_d1/wallet.rs` by path; signature coverage 10/10. |
| `schema_migrations.rs` | 925 | OBSOLETE-ON-CF | hand-verified | apps/control-plane/src/store/d1.ts (CREATE TABLE ... IF NOT EXISTS), packages/storage/src/d1/* | 925 lines whose whole subject is parsing the Postgres migration ledger out of `sql/*.sql` at const-eval time. D1 schema is declared inline in the TS stores; there is no ledger to parse. NOTE: no TS equivalent of a migration VERSION pin exists — drift between the two D1 schema declarations would not be caught. |
| `control_plane_store_d1/rows.rs` | 789 | PORTED | hand-verified | packages/storage/src/d1/rows.ts | Row DTOs + SELECT column lists. |
| `workflow_budget.rs` | 754 | PORTED | signature-derived | packages/storage/src/workflow-budget.ts, packages/storage/src/d1/workflow-budget-d1.ts | signature coverage 18/19. |
| `site_domain_verification.rs` | 731 | PORTED | signature-derived | packages/storage/src/site-domain.ts, packages/storage/src/d1/site-domain-d1.ts | signature coverage 21/22. |
| `guardrail_evidence.rs` | 705 | PORTED | hand-verified | apps/gateway/src/guardrails/evidence.ts, packages/storage/src/index.ts |  |
| `control_plane_store_d1/workflow_budget.rs` | 671 | PORTED | signature-derived | packages/storage/src/workflow-budget.ts, packages/storage/src/d1/workflow-budget-d1.ts | signature coverage 5/5. |
| `control_plane_store_d1/core_entities.rs` | 620 | PORTED | hand-verified | apps/control-plane/src/store/d1.ts, apps/control-plane/src/store/api_keys.ts, apps/control-plane/src/store/tenancy.ts | API keys, tenant accounts, projects, workspaces (#420). |
| `postgres_row_mappers.rs` | 620 | OBSOLETE-ON-CF | hand-verified | packages/storage/src/d1/rows.ts | 620 lines of `tokio_postgres::Row -> Stored*`. D1 returns plain objects; `d1/rows.ts` is the replacement. |
| `rbac.rs` | 598 | PORTED | signature-derived | apps/cli/src/registry.ts, apps/control-plane/src/routes/rbac.ts | signature coverage 8/15. |
| `control_plane_store_d1/worker_stores.rs` | 567 | PORTED | hand-verified | apps/control-plane/src/store/worker_registry.ts | Managed + self-hosted worker stores (#449); WRITE half landed wave 17 (task #102). |
| `control_plane_store_d1/agent_schedule.rs` | 563 | PORTED | signature-derived | packages/storage/src/d1/agent-schedule-d1.ts | signature coverage 7/8. |
| `control_plane_store_d1/rbac_site_domain.rs` | 556 | PORTED | hand-verified | apps/control-plane/src/store/rbac_registry.ts, packages/storage/src/d1/site-domain-d1.ts, packages/storage/src/d1/budget-alerts-d1.ts | RBAC + site domains + budget-alert idempotency ledger (#445). |
| `control_plane_store_d1/auth_quota.rs` | 519 | PORTED | hand-verified (CORRECTED wave 19) | apps/control-plane/src/store/quota_registry.ts (quota policies + plans ONLY) | 519 lines covering "admin users, **SSO**, refresh tokens, quota policies, plans" (#440). Quotas and plans are ported; the **admin-user / SSO-config / refresh-token tables are not** — `sso_config` = 0 TS hits. This is the STORAGE half of the same auth-service gap, and it is why that gap is not just a missing router. **CORRECTED 2026-08-01 (see MISSING-TRIAGE.md §1): this row was STALE — apps/control-plane/src/session/store.ts:182-300 (admin_users/memberships/refresh tokens) + identity/adapters.ts:321-492 (sso_provider_configs, sso_pending_flows).** |
| `control_plane_store_d1/billing.rs` | 466 | PORTED | signature-derived | packages/storage/src/d1/billing-d1.ts, apps/gateway/src/metering/outbox.ts | signature coverage 1/1. |
| `site_domain.rs` | 416 | PORTED | signature-derived | packages/storage/src/site-domain.ts, apps/cli/src/registry.ts | signature coverage 4/8. |
| `control_plane_store_d1/usage.rs` | 411 | PORTED | signature-derived | packages/storage/src/d1/usage-d1.ts, packages/storage/src/metadata-rollups.ts | signature coverage 3/4. |
| `lifecycle_gate.rs` | 399 | PORTED | cited-by-TS | apps/control-plane/src/ports.ts, apps/gateway/src/ports.ts | TS owner cites `crates/ferrogate-storage/src/lifecycle_gate.rs` by path; signature coverage 17/18. |
| `control_plane_store_d1/observability.rs` | 390 | PORTED | hand-verified | apps/control-plane/src/routes/admin_request_log.ts, apps/control-plane/src/routes/agent_run.ts, packages/storage/src/d1/monotonic.ts (`replayFloor`) | Agent runs/events, request/audit logs, replay floors (#447). |
| `asset_lifecycle.rs` | 352 | PORTED | signature-derived | packages/storage/src/retention.ts, packages/storage/src/d1/retention-d1.ts | signature coverage 19/21. |
| `control_plane_store_d1/guardrail.rs` | 346 | PORTED | signature-derived | packages/storage/src/guardrail-binding.ts, apps/control-plane/src/routes/guardrail_policy.ts | signature coverage 3/3. |
| `agent_cost_burn.rs` | 320 | PORTED | signature-derived | packages/storage/src/agent-cost-burn.ts, packages/storage/src/ids.ts | signature coverage 5/5. |
| `metadata_rollups.rs` | 303 | PORTED | signature-derived | packages/storage/src/metadata-rollups.ts, packages/storage/src/d1/usage-d1.ts | signature coverage 4/4. |
| `control_plane_store_d1/client.rs` | 273 | PORTED | hand-verified | packages/storage/src/tenant-router.ts, packages/storage/src/tenant-rest.ts | Query plumbing + tenant/control-database routing. |
| `observed_agent_presence.rs` | 250 | PORTED | signature-derived | packages/storage/src/presence.ts, packages/storage/src/d1/monotonic.ts | signature coverage 5/5. |
| `budget_alerts.rs` | 249 | PORTED | signature-derived | packages/storage/src/budget-alerts.ts, packages/storage/src/d1/budget-alerts-d1.ts | signature coverage 5/5. |
| `control_plane_create.rs` | 248 | PORTED | hand-verified | apps/control-plane/src/store/d1.ts (atomic()), apps/control-plane/src/store/memory.ts | Atomic create-if-absent (#512); the D1 half-apply bug was fixed and pinned in wave 17 (task #65). |
| `control_plane_store_d1/observed_presence.rs` | 220 | PORTED | signature-derived | packages/storage/src/presence.ts | signature coverage 2/2. |
| `async_postgres.rs` | 217 | OBSOLETE-ON-CF | hand-verified | packages/storage/src/tenant-rest.ts, packages/storage/src/tenant-router.ts | deadpool-postgres connection pool. D1 bindings and the D1 REST transport replace it. |
| `control_plane_store_d1/provisioning.rs` | 176 | PORTED | hand-verified | packages/cloudflare/src/d1.ts (`createDatabase`), packages/storage/src/tenant-router.ts (`database_registry`) | Control/tenant D1 database provisioning lifecycle + registry persistence. |
| `lifecycle_status.rs` | 144 | PORTED | hand-verified | apps/control-plane/src/store/lifecycle.ts, apps/gateway/src/adapters.ts |  |
| `control_plane_store_d1/config_documents.rs` | 128 | PORTED | signature-derived | packages/config/src/validate/policies.ts, packages/config/src/schema/enums.ts | signature coverage 7/7. |
| `control_plane_store_d1/client_config.rs` | 93 | PORTED | hand-verified | packages/storage/src/provider.ts |  |

<details><summary>TEST-ONLY modules (37, 20,897 lines)</summary>

| Module | Lines |
|---|---:|
| `control_plane_store_d1_test.rs` | 6224 |
| `schema_migrations_test.rs` | 1574 |
| `mcp_identity_test.rs` | 1240 |
| `control_plane_schema_test.rs` | 1115 |
| `asset_quota_admission_test.rs` | 990 |
| `payment_attempt_test.rs` | 965 |
| `overview_aggregate_test.rs` | 716 |
| `site_domain_test.rs` | 514 |
| `lifecycle_gate_test.rs` | 500 |
| `transaction_pin_scan_test.rs` | 420 |
| `site_domain_verification_test.rs` | 404 |
| `action_identity_persistence_test.rs` | 397 |
| `asset_channel_lifecycle_test.rs` | 384 |
| `asset_visibility_promotion_test.rs` | 340 |
| `asset_lifecycle_test.rs` | 339 |
| `payment_attempt_pagination_test.rs` | 326 |
| `guardrail_policy_test.rs` | 321 |
| `agent_schedule_test.rs` | 315 |
| `guardrail_evidence_test.rs` | 310 |
| `schema_validation_test.rs` | 308 |
| `asset_storage_usage_test.rs` | 307 |
| `transaction_pin_scan_test_support.rs` | 281 |
| `wallet_reservation_sweep_x402_test.rs` | 268 |
| `payment_attempt_amount_domain_test.rs` | 265 |
| `async_postgres_test.rs` | 254 |
| `asset_withheld_listing_test.rs` | 236 |
| `agent_cost_burn_test.rs` | 229 |
| `replay_floor_test.rs` | 223 |
| `billing_outbox_replay_test.rs` | 192 |
| `schema_routing_test_support.rs` | 186 |
| `observed_agent_presence_test.rs` | 175 |
| `usage_metadata_schema_test.rs` | 171 |
| `asset_visibility_test.rs` | 169 |
| `usage_aggregate_sum_test.rs` | 82 |
| `lifecycle_status_test.rs` | 81 |
| `storage_ledger_sink_test.rs` | 53 |
| `postgres_error_test.rs` | 23 |

</details>

### `crates/ferrogate-sync-bridge` — 1 product modules (80 lines), 0 test modules

| Module | Lines | Class | Evidence | TS owner | Note |
|---|---:|---|---|---|---|
| `lib.rs` | 80 | DELIBERATELY-DROPPED | hand-verified | — (deleted at parity) | Wave-17 finding: `sync-bridge` is legitimately dead code. The TS `packages/sync-bridge` was deleted rather than ported; see task #118 and CUTOVER-READINESS.md. |

## Repo-hygiene finding (out of scope to fix here)

Two files exist whose **names contain embedded newlines** — the residue of a
botched shell heredoc. Both are byte-identical copies of
`apps/agent-runtime/src/middleware/auth.ts` (27,753 bytes each):

```
apps/agent-runtime/src/admission/admit.ts\n    message: (requestId: string): string =>\n …
apps/mcp/src/admission/gate.ts\n    code: "quota_scope_disabled",\n …
```

They are not importable (they do not end in `.ts`), so they are inert — but they
corrupt the output of `ls`, `grep -rl` and any `find | while read` loop that walks
those directories, which is exactly the class of tool an ownership audit runs.
They should be deleted by whoever owns `apps/*/src`.
