# DROPPED CAPABILITIES — capabilities this product has decided not to offer

**Owner decision · 2026-08-02 · branch `main-ts` · worktree `/home/dev/ferrogate-ts`**

This document exists because of a specific failure mode. `POST /v1/functions/execute`,
`GET /v1/tools` and `POST /v1/tools/execute` answered `501` on 2026-08-01 and they
answer `501` today. **Nothing about the route table changed.** What changed is
that on 2026-08-01 they were unfinished ports carrying `PORT-TODO(...)` notes,
and on 2026-08-02 the **owner decided not to offer them at all**.

Those two situations look identical in a route table and completely different to
an operator paging at 3am, to an auditor asking what this deployment does, and to
whoever picks this repository up in a year. So the difference is written down in
three places that cannot drift apart:

| Where | What it records | What happens if it is edited alone |
|---|---|---|
| `apps/gateway/src/routes/index.ts` — `DROPPED_CAPABILITIES` | the decision, in code, next to the mount | `test/routes/dropped-capabilities.test.ts` goes RED |
| the wire — `501 capability_not_offered` | the decision, to every caller | same gate goes RED |
| **this document** | the decision, its reasoning, and the Rust it replaces | same gate goes RED |

The gate is `apps/gateway/test/routes/dropped-capabilities.test.ts`. It
deliberately **hard-codes** the dropped set, the status, the code and the date
rather than importing them, so it does not follow an edit to the code it gates.
Un-dropping one of these operations, adding a fourth drop, or softening the
refusal back into a promise is RED until this document and that gate are updated
too — i.e. until somebody records a decision.

---

## 0. The decision

> **S1 (`executeFunction`) and S2 (`listTools` / `executeTool`) are DROPPED.**
> — owner, 2026-08-02

`docs/rewrite/CUTOVER-READINESS.md` §0.3 set the exit criterion for deleting
`crates/**`: for each of the five spec-bound clusters S1–S5, exactly one of
*built*, *dropped by the owner*, or *transcribed at the fidelity §3 names*. Wave
24 cleared S3 and S4 by transcription (`SPEC-TRANSCRIPTS.md`) and S5 by
construction (`apps/mcp/src/entitlements.ts`, seam `MCP-P15`). §0.5.6 recorded
that "precisely two things" remained, "and they are the same two the owner is
deciding".

The owner has now decided, and **drop was one of the three exits the
certification itself offered** — not a shortcut around it. With S1 and S2
dropped, the overlap between CLASS A and the Rust's role as a specification is
empty, and the deletion gate is satisfied.

### 0.1 What "dropped" means here, precisely

* It is a **product position**, not an outage, not a regression to be repaid,
  and not work in flight. Nothing in the backlog tracks it.
* It is **not a platform limit.** Cloudflare Workers can host all three. §S1
  below shows `executeFunction` needs only `fetch()` and WebCrypto HMAC; §S2
  shows the catalogue is a filtered projection. Anyone who reopens this should
  know the constraint was never technical.
* It is **revisitable** — by the owner, deliberately, at which point §4 of this
  document is the brief. It is not revisitable by a pull request that quietly
  mounts a handler.

---

## 1. What the deployment answers today

All three are **mounted**, matched at the contract's own path and method, and
run the full `contractAuth` ladder. That ordering is deliberate: an unmounted
operation would answer `404 not_found`, which claims the endpoint does not
exist — it does, and this deployment declines to serve it. And answering the
refusal *before* the guard would turn these three into an unauthenticated oracle
for what the deployment offers.

```
anonymous                      → 401 missing_api_key
authenticated, wrong scope     → 403 scope_denied
suspended tenant               → 403 tenancy_suspended
entitled caller                → 501 capability_not_offered      ← the decision
```

The refusal body:

```json
{
  "error": {
    "message": "listTools is not offered by this deployment: this gateway does not publish a native tool catalogue. The capability was dropped by owner decision on 2026-08-02 (cutover cluster S2) — a deliberate product position, not an outage and not a build under way. The decision, the behaviour it dropped and what a future implementer would need are recorded in docs/rewrite/DROPPED-CAPABILITIES.md.",
    "type": "ferrogate_error",
    "code": "capability_not_offered",
    "request_id": "..."
  }
}
```

### 1.1 Why the status is still 501, and why the CODE changed

**The contract does not prescribe a status.** `docs/openapi/runtime-api-contract.json`
carries no response-status vocabulary at all — an operation is
`{path, method, operation_id, visibility, auth, rbac_action}` and nothing more.
So there was no contract rule to satisfy and no status to change to. 501 stays,
for three reasons:

1. **It is the house precedent.** The only 501 the Rust gateway ever originates
   is `crates/ferrogate-gateway/src/server/local.rs:11835`
   (`self_hosted_worker_production_mtls_not_implemented`) — "this build does not
   do this", the same shape of answer.
2. **It is the only status whose definition fits.** RFC 9110 §15.6.2: *"the
   server does not support the functionality required to fulfil the request"*,
   and it is the one non-2xx defined as cacheable by default — permanent unless
   stated otherwise. That is a dropped capability.
3. **Every alternative lies.** `404` denies a route that exists and is
   auth-guarded. `403` blames the caller's credential for a decision about the
   deployment. `503` promises the capability returns when something recovers.

What was wrong was never the status. It was the **body**. `501 not_implemented`
plus a `PORT-TODO(...)` note reads as a promise, and after 2026-08-02 there is
nothing being promised. The machine-readable code is the half that matters most:
a client switching on `not_implemented` is being told to retry after the next
release; a client switching on `capability_not_offered` is being told to stop
asking, or to pick a deployment that offers it.

---

## 2. S1 — `executeFunction`

<!-- DROPPED-OPERATION-ID: executeFunction -->

| | |
|---|---|
| **Operation** | `POST /v1/functions/execute`, scope `functions.execute`, visibility `public` |
| **Cluster** | S1 (`CUTOVER-READINESS.md` §3, §0.5.6 item 1) |
| **TS today** | `501 capability_not_offered` |
| **Decided** | owner, 2026-08-02 — DROP |

### 2.1 What the Rust did

**It is a BROKER, not a sandbox.** That correction matters, because the wrong
description ("out-of-process sandboxed user code, blocked on Containers") sat in
the TypeScript source for eighteen waves and is the reason the operation was
filed as platform-blocked when it never was. `cert2-dataplane` caught it and
this document repeats the correction so the delete does not re-bury it.

Entry point: **`crates/ferrogate-gateway/src/server/local.rs:3219`**
`handle_function_execute`. The ladder, in the Rust's own order:

1. **`405 method_not_allowed`** unless the method is `POST`
   (`local.rs:3230`, message *"function execute endpoint requires POST"*).
2. **Cloudflare Worker branch (#435)** — taken only when the operator set the
   `FG_FN_TARGET_KIND=cloudflare_worker` discriminant, dispatching to
   `local.rs:3417` `handle_function_execute_cloudflare`. At most one branch is
   enabled per process; the Supabase path below remains the default.
3. **Fail closed: `503 function_egress_disabled`** (`local.rs:3254`, *"function
   egress broker is not configured"*) when no signing secret is configured. The
   broker is off unless explicitly switched on.
4. **`413 payload_too_large`** against `limits().tool_body_max_bytes()`.
5. **`400 invalid_json`** on a body that is not a `FunctionInvocationRequest`.
6. **`authenticate(..., "functions.execute", ...)`**.
7. **Egress authorisation** against the per-tenant allowlist.
8. **Token minting**, then an HTTP `POST` to the target.

**The allowlist** — `crates/ferrogate-runtime/src/function_egress.rs`
(197 lines, `0` `todo!()`). `FunctionEgressAllowlist` (`:36`) holds per-tenant
`{project_base_url, function_slugs}` entries (`:31`) and is **deny-by-default**:
its own module docs (`:11`) say an empty allowlist authorises nothing.
`authorize_validated` (`:129`) trims the requested slug, matches it against the
tenant's `function_slugs` (`:144`) and refuses with *"tenant {tenant} may not
invoke {function_slug} at {base_url}"* (`:71`). The Cloudflare variant matches a
Worker `invoke_path` where the Supabase path matches a `function_slug`
(`:109`).

**The wildcard slug — added in wave 25.** `cert4-final.md` §2.4 flagged this as
the one omission in the S1 transcription. It was half right: the wildcard was
*already* transcribed, in `SPEC-TRANSCRIPTS.md` PART D §D3 (lines 1507, 1562),
which cert-4 did not check — it read this document only. It is added here anyway
so that the *drop record* is self-contained, because the two documents are read
by different people for different reasons and neither should require the other.

`ANY_FUNCTION_SLUG` (`function_egress.rs:21`) is the literal `"*"`,
and a rule whose `function_slugs` contains it permits **any** slug under that
rule's `base_url` for that tenant. The match at `:144` is

```rust
slug == ANY_FUNCTION_SLUG || slug.trim() == requested_slug
```

so note three things a re-implementer would otherwise get wrong:

* the wildcard is compared **un-trimmed** (`slug == "*"`), while a literal slug
  is compared **trimmed** — `" * "` in an allowlist is a literal slug named
  `"*"`, not a wildcard;
* the wildcard widens the **slug** axis only. `tenant` is still matched exactly
  and `base_url` still through `normalize_base_url` on both sides, so `"*"`
  never becomes an any-tenant or any-host rule;
* deny-by-default is unchanged: with no rule for the tenant the refusal is
  `NoRuleForTenant`, not `TargetNotAllowed`, and the two are distinguishable.

`cert4-final.md` §2.4 flagged this as the one omission in the S1 transcription,
and correctly noted that omitting it **errs fail-CLOSED** — an allowlist built
without a wildcard refuses calls the Rust would have allowed, which is an
operator inconvenience and never a security regression. It is recorded anyway,
because a fail-closed divergence is still a divergence and this was the last
wave in which the source could be consulted.

**The token** — `crates/ferrogate-runtime/src/function_token.rs` (200 lines).
Short-lived scoped **HS256 JWT** minted per call, so a static Supabase
service-role key never leaves the gateway and a leaked token authorises at most
one function for a few seconds. Claim set (`function_token.rs:30`
`FunctionTokenClaims`):

| claim | meaning |
|---|---|
| `iss` | issuer, e.g. `ferrogate` |
| `aud` | **the function slug this token may invoke** |
| `tenant` | the tenant the call is attributed to |
| `capability` | the capability exercised, for edge-function-side authorization |
| `iat` / `exp` | unix seconds |

TTLs are bounded in the module: `DEFAULT_FUNCTION_TOKEN_TTL_SECS = 60`,
`MAX_FUNCTION_TOKEN_TTL_SECS = 300`. Verification uses a constant-time compare
(`subtle::ConstantTimeEq`) and the error set is
`{EmptySigningSecret, EmptyField, ZeroTtl, Encoding, MalformedToken, BadSignature, Expired}`.

**The dispatch** — `crates/ferrogate-runtime/src/supabase_edge_function.rs`
(262 lines) for Supabase, or the Cloudflare Worker branch above. Adversarial
coverage that a future implementer should know exists:
`crates/ferrogate-runtime/src/function_egress_red_team_test.rs`.

### 2.2 Why it was dropped

The owner's call. The observations that were on the table when it was made:

* It is a **broker for someone else's compute** — a tenant's Supabase Edge
  Function or Worker. It runs no user code itself and produces no gateway
  behaviour beyond authorising, signing and forwarding. On Cloudflare, a tenant
  who wants that can call their own Worker directly.
* The security value it adds (deny-by-default egress + a 60-second,
  single-function token instead of a static service-role key) is real, but it is
  value **only to a deployment that is already brokering** — which this one has
  decided not to do.
* Cost: it is the largest of the two remaining clusters, ~400 lines of Rust with
  no TypeScript counterpart and a red-team suite behind it.

### 2.3 If it is ever revisited

* **Nothing here is platform-blocked.** `fetch()` + WebCrypto HMAC-SHA256 + a
  config table are sufficient. There is no paid-plan prerequisite and no
  Containers dependency. Do not re-file it as one.
* **Port the fail-closed direction first.** The allowlist's value is that an
  empty configuration authorises nothing; a port that treats "no allowlist" as
  "allow" is an SSRF surface with the gateway's own network position.
* **Keep the token narrow.** `aud` = one function slug, `capability` scoped, TTL
  ≤ 300s, constant-time signature compare. The reason this exists at all is that
  the alternative was handing out a static service-role key.
* **Keep the two target kinds mutually exclusive**, the way
  `FG_FN_TARGET_KIND` does — at most one branch enabled per process.
* Pin the refusal ladder in the order above; `413` before authentication is a
  deliberate resource decision, not an accident.

---

## 3. S2 — `listTools` and `executeTool`

<!-- DROPPED-OPERATION-ID: listTools -->
<!-- DROPPED-OPERATION-ID: executeTool -->

| | |
|---|---|
| **Operations** | `GET /v1/tools` (scope `tools.read`), `POST /v1/tools/execute` (scope `tools.execute`) |
| **Cluster** | S2 (`CUTOVER-READINESS.md` §3, §0.5.6 item 2) |
| **TS today** | `501 capability_not_offered` on both |
| **Decided** | owner, 2026-08-02 — DROP |

### 3.1 What the Rust did

**The catalogue half** — `crates/ferrogate-gateway/src/server/local.rs:2890`
`handle_tools`:

1. `authenticate(&state, headers, "tools.read", ...)`.
2. Optional `?route=` query parameter, parsed off the query string.
3. `state.tools_for(&auth.tenant_context(), auth.api_key_id.as_deref(), route.as_deref())`.
4. An **admin audit event** (`tool.list`, target `route:{route}` or `tools`,
   outcome `success`, detail *"listed N tools"*) — the listing is audited, not
   just the execution.
5. `AdminList::new(tools)` at `200 OK`.

`tools_for` is **`crates/ferrogate-gateway/src/extensions.rs:214`**, and it is
small — a filter over the registry's tools by
`tool_visible(tool, tenant, api_key_id, route)`. Siblings worth knowing:
`all_tools()` (`:227`, unfiltered) and `tools_for_plugin()` (`:231`). The
projection is per-tenant, per-API-key and per-route; the same registry is read
from `server/chat.rs:2999`, `server/messages.rs:1611` and `state_routing.rs:23`,
and the MCP-specific projection is `mcp_tools_for` (`server/mcp_rpc.rs:328`).

**The execution half** — `local.rs:2935` `handle_tool_execute` delegates
immediately to `local.rs:3573` `handle_tool_execute_with_backend` with
`ToolExecuteBackend::Extension`; `handle_mcp_tool_execute` is the same function
with the MCP backend. The path is: approval record → governed chokepoint →
backend dispatch.

### 3.2 Why it was dropped

* The gateway's native catalogue would have had **two sources** — the extension
  registry and the registered MCP servers — and the TypeScript tree has only the
  second (`apps/mcp`, which serves MCP tools over the MCP protocol on its own
  Worker). A `/v1/tools` that listed one of the two would *understate what a
  tenant may call*, which is a worse answer than refusing.
* The extension/plugin registry that backs the first source has no TypeScript
  package and no plan for one.
* MCP tool listing and execution are not lost to the product: they live on
  `apps/mcp`, including the plan/RBAC entitlement ladder built in wave 24
  (`apps/mcp/src/entitlements.ts`, seam `MCP-P15`). What is dropped is the
  **gateway's own native tool surface**, not tools as a concept.

### 3.3 If it is ever revisited — the hook model must be DESIGNED FRESH

This is the certification's own warning (`CUTOVER-READINESS.md` §3, row S2) and
it is the single most important thing to carry forward:

> Note `extensions.rs`'s `RequestHook` enum has one variant (`Noop`) and
> `EventSink` one (`audit_log`) — the **hook model should be designed fresh**,
> not copied. Keep the catalogue.

Verified first-hand against the Rust while writing this document:

```rust
// crates/ferrogate-gateway/src/extensions.rs:711
enum RequestHook {
    Noop(HookConfig),
}

// crates/ferrogate-gateway/src/extensions.rs:824
enum EventSink {
    AuditLog(AuditLogSink),
}
```

A one-variant enum is an abstraction that was **never exercised by a second
case**. Copying it would inherit a plugin architecture whose extension points
have never been shown to extend — the classic shape that fits exactly one
implementation and fights the second. So:

* **Keep** the catalogue semantics: the per-tenant / per-API-key / per-route
  visibility filter of `tools_for`, and the audit event on the LIST, not only on
  the execute.
* **Keep** the refusal ordering: scope check before anything else, so the
  surface never discloses tool names to an under-scoped key.
* **Design fresh**: the hook/sink model, and how a native catalogue would
  compose with `apps/mcp`'s catalogue. Listing one source and calling it "the
  tools" is the mistake this drop avoids; a fresh design must answer the union
  or say why it does not.
* Whatever lands must also decide the governed-dispatch half — the approval
  record and the chokepoint — which the TypeScript tree does not have either.

---

## 4. What a future implementer needs, in one place

1. **The Rust is gone.** Every `crates/...:line` citation in this document was
   read and verified on 2026-08-02, immediately before the tree was deleted.
   After the delete they are historical pointers into `git` history at tag
   `legacy-rs`, not paths you can open.
2. **Neither cluster was platform-blocked.** If a future note claims otherwise,
   it is repeating the error `cert2-dataplane` already corrected once.
3. **Re-enabling is a product decision, and the tree enforces that.** Adding a
   handler for one of these ids requires removing its entry from
   `DROPPED_CAPABILITIES` in `apps/gateway/src/routes/index.ts`, removing its
   `DROPPED-OPERATION-ID` marker comment from the cluster section of this
   document, and removing its row from
   `apps/gateway/test/routes/dropped-capabilities.test.ts`. Any one of those
   alone is RED.
4. **`501 capability_not_offered` is now a wire contract of its own.** If the
   set of dropped operations changes, clients that switch on it change with it —
   which is the point of making the drop explicit rather than accidental.

---

## 5. Provenance

| Claim | Source, read first-hand 2026-08-02 |
|---|---|
| S1 entry point and refusal ladder | `crates/ferrogate-gateway/src/server/local.rs:3219`, `:3230`, `:3254`, `:3417` |
| S1 allowlist, deny-by-default | `crates/ferrogate-runtime/src/function_egress.rs:11`, `:31`, `:36`, `:71`, `:129`, `:144` |
| S1 token claim set and TTL bounds | `crates/ferrogate-runtime/src/function_token.rs:23-43` |
| S1 dispatch | `crates/ferrogate-runtime/src/supabase_edge_function.rs` (262 lines) |
| S2 catalogue handler + audit event | `crates/ferrogate-gateway/src/server/local.rs:2890` |
| S2 projection | `crates/ferrogate-gateway/src/extensions.rs:214` |
| S2 execution | `crates/ferrogate-gateway/src/server/local.rs:2935`, `:3573` |
| S2 one-variant hook/sink enums | `crates/ferrogate-gateway/src/extensions.rs:711`, `:824` |
| The 501 house precedent | `crates/ferrogate-gateway/src/server/local.rs:11835` |
| The exit criterion the drop satisfies | `docs/rewrite/CUTOVER-READINESS.md` §0.3, §3, §0.5.6 |
