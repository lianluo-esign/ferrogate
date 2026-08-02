# Parity audit — dead packages and dead seams

**Scope.** Two questions, one document.

1. Six `packages/*` with zero or near-zero real importers under `apps/*/src`:
   `routing`, `observability`, `secrets`, `schemas`, `payments`, `sync-bridge`.
   For each: **wrongly dead** (must be wired) or **legitimately dead** (say why).
2. Every app's `ports.ts`: does the **deployed** composition root supply a real
   implementation, or is the in-memory default what production runs?

This document is a **verdict**. It wires nothing and implements nothing.

---

## 0. Method, and a trap that invalidates a naive census

The obvious census — `grep -rn 'from "@ferrogate/x"' apps/*/src` — is **wrong in
this environment**, for two independent reasons, and both were hit while
producing this audit:

- The shell's `grep` is a shim (`ugrep --ignore-files`) that honours ignore
  files. It reported **zero** matches for `secret` in
  `apps/mcp/src/ports.ts` — a file that contains 42. `/usr/bin/grep` and `rg`
  both report 42. **Any census run through the shell `grep` function is
  unreliable.** Use `rg`, `/usr/bin/grep`, or a script.
- Multi-line `import {\n … \n} from "@ferrogate/x"` is invisible to a
  line-oriented pattern.

The census below was produced with a Python module-specifier extractor over
every `.ts` file under `apps/*/src` and `packages/*/src`, matching
`@ferrogate/<pkg>` and `@ferrogate/<pkg>/<subpath>` on `import`/`export … from`
and bare `import "…"`. **Comments and docstrings are excluded by construction.**

### Census (authoritative, as of this audit)

| package | value imports | type-only imports | where |
|---|---:|---:|---|
| `routing` | 1 | 0 | `apps/gateway/src/inference/candidates.ts:26`, `apps/gateway/src/inference/shadow.ts` |
| `observability` | **0** | 1 | `apps/gateway/src/cache/metrics.ts:37` — `import type`, **erased at build** |
| `secrets` | 2 | 0 | `apps/mcp/src/ports.ts:47`, `packages/config/src/validate/helpers.ts:9` |
| `schemas` | **0** | **0** | nowhere — despite being a declared dependency of 6 workspaces |
| `payments` | 2 | — | `packages/policy/src/x402/wire.ts` only |
| `sync-bridge` | **0** | **0** | nowhere |

Two premises in the audit brief are now **stale** and should not be carried
forward: `secrets` is no longer 0 (it was mounted in `apps/mcp`), and `schemas`
is **not** "consumed via packages rather than apps" — it is consumed by nothing
at all, in either layer.

---

## 1. `@ferrogate/sync-bridge` — **(b) LEGITIMATELY DEAD → DELETE**

**Verdict: delete the package outright.** Not "keep as dead weight", not "wire
it". This is the one package where the correct action is removal.

Evidence:

- The Rust crate is **one function in 80 lines**
  (`crates/ferrogate-sync-bridge/src/lib.rs`): `block_on_sync_bridge(future) -> T`,
  which parks the calling **thread** so a synchronous Pingora filter hook, sweep
  thread, or Unix `SO_PEERCRED` authorizer can call an `.await`-ing method.
- `docs/legacy/inventory-edge-control.md` §7 is unambiguous: *"This crate has no
  reason to exist on CF … Drop it during the port; each
  `block_on_sync_bridge(x.await-ing())` call site becomes a plain `await x`."*
  The cluster summary table at line 665 lists its CF/TS target as literally
  **`Deleted`**.
- The three Rust caller classes are all eliminated by this rewrite: Pingora is
  gone (PORT-PLAN "the single largest new build"), there are no threads in
  workerd, and the Unix authorizer has no CF equivalent.
- `packages/sync-bridge/src/bridge.ts` is honest about what it became:
  `blockOnSyncBridge<T>(f): Promise<T>` whose body is
  `return await started`. It is `await` with a docstring. The
  `RuntimeFlavor`/strategy model in `runtime.ts` is a *parity view* of Rust
  branch structure that cannot execute.

**Why keeping it is a net negative, not neutral:** 420 lines and 2 test files
maintained on the build graph that encode a mechanism which is *impossible* on
the platform. The `PORT-TODO(inventory §7)` markers in `bridge.ts:53` and
`runtime.ts:43` are correctly written as PLATFORM LIMIT — but a platform limit
on a mechanism nothing needs is not a limit worth carrying. Delete
`packages/sync-bridge/` and remove `ferrogate-sync-bridge` from the crate→package
map in PORT-PLAN.md at the same time.

**Nothing breaks:** zero importers, and `Cargo.toml` shows the Rust crate was a
dependency of `ferrogate-gateway` only, whose TS successor (`apps/gateway`) is
uniformly async.

---

## 2. `@ferrogate/payments` — **(b) LEGITIMATELY DEAD by directive; KEEP**

**Verdict: correctly dead at the app layer. Do not wire. Do not delete.**

- x402/Solana is **deprioritized by standing user directive**. That is a product
  decision, not a platform gap, and it is recorded consistently across the tree
  (`packages/policy/src/index.ts:30`, `packages/config/src/index.ts:29`,
  `apps/control-plane/src/routes/x402_spend_policy.ts:19`).
- It is **not orphaned**: `packages/policy/src/x402/wire.ts` imports
  `RequestBodyHash`, `validateSolanaAddress` and the wire types from it, and
  `packages/policy/package.json` declares the dependency. This is the "consumed
  by another package, not by an app" shape — the healthy version of it, with a
  real import.
- Rust parity confirms the app-layer absence is a *deferral*, not a miss:
  `ferrogate-gateway` used it on the live path
  (`state_x402_negotiation.rs:59`, `state_x402_reconciler.rs:56`). Those two
  paths are exactly what the directive defers.
- The three `/admin/v1/x402-spend-policies/*` operations are served today over
  stored policy rows with a `PORT-TODO(x402)` naming settlement as the deferred
  half. That is the right shape: contract surface present and guarded, money
  movement absent and marked.
- Its two `PORT-TODO`s (`proof.ts:31`, `intent.ts:320`) are genuine
  platform/language limits and should stay.

---

## 3. `@ferrogate/schemas` — **(b) LEGITIMATELY DEAD as a barrel, but it is CARRYING A DEFECT**

**Verdict: the package should not be "wired". Its re-export barrel is
legitimately redundant. But two of its three owned symbols are WRONG, and one is
triplicated — those are real problems that wiring would make worse, not better.**

### 3.1 Why the barrel is legitimately dead

~90% of `packages/schemas/src/index.ts` is a **pure re-export of
`@ferrogate/core`** (`toolDef`, `toolCall`, `approvalPolicy`, `tenantContext`,
`redactSecretShapedKeys`, `gatewayError`, …). Apps import those symbols from
`@ferrogate/core` directly, which is the *same single source of truth*. There is
no drift risk in that, and adding a hop through `schemas` would buy nothing.
Verdict (b) for the re-export surface: correct as-is.

### 3.2 The owned surface is a fiction — three findings

**(i) `errorEnvelopeSchema` does not describe any FerroGate response.**

`packages/schemas/src/wire.ts:30` declares `{ code, message, requestId? }`.
The envelope every surface actually writes — byte-identical to Rust
`responses.rs::write_json_error` and pinned across the gateway suite — is

```json
{ "error": { "message": "…", "type": "ferrogate_error", "code": "…", "request_id": "…" } }
```

(`apps/gateway/src/inference/errors.ts:54`,
`apps/gateway/src/assets/schemas.ts:319`). The two do not overlap in shape *or*
in field naming (`requestId` vs `request_id`). Wiring the package's version at
any boundary would **break wire parity**. The correct envelope is already
declared locally in `apps/gateway/src/assets/schemas.ts` and should be treated as
the source of truth; `packages/schemas`' copy should be **corrected or removed**,
never adopted.

**(ii) `OPENAPI_OPERATION_COUNT = 251` is the third independent copy** of a
constant that already exists as `EXPECTED_OPERATION_COUNT`
(`apps/gateway/src/contract.ts:123`) and `EXPECTED_TOTAL_OPERATION_COUNT`
(`apps/control-plane/src/contract.ts:119`). Three copies of one number, nothing
forcing them to move together — precisely the drift this package's own docstring
claims to prevent.

**(iii) `scopeSchema` / `assertScopeParity`** guard `@ferrogate/core`'s `Scope`
(`{tenant, project?, workspace?}`), which no app's request path uses — the
gateway's tenancy vocabulary is `CallerScope` (`{kind:"tenant", tenantId}` /
`{kind:"platform_operator"}`, `apps/gateway/src/ports.ts:48`). The parity guard
compiles, and guards nothing anyone runs.

The existing `PORT-TODO(inventory §1.3/§1.4)` marker at `index.ts:89` is
excellent and honest about `registerWireSchema` having zero callers. It does not
cover (i)–(iii); a marker has been added for those (§8).

---

## 4. `@ferrogate/routing` — **(a) WAS WRONGLY DEAD; now LARGELY WIRED. Two residual gaps.**

**Verdict: the canary leg is genuinely mounted with a real mount gate. Shadow is
landing concurrently. Two things are still dead: the cross-isolate shadow budget
DO, and `RouteMatcher`.**

### What is now live

`apps/gateway/src/inference/candidates.ts:26` imports `canarySelected`,
`shadowSampled`, `ShadowBudgetLedger` from the package (not re-derived), and
`applyCanary` runs on the deployed path at
`apps/gateway/src/inference/handlers.ts:381`:

```ts
const rolled = servableCandidates(applyCanary(resolved, caller));
```

The mount gate is real, and it is the right shape:
`apps/gateway/test/inference/reliability.test.ts:515` drives the **real**
`createInferenceRouter` (the same assembly the deployed `inferenceRouteModule`
uses) with only the outbound provider `fetch` intercepted, declares the canary at
a *lower* priority than the primary so nothing but `applyCanary` can promote it,
and computes the expected split from the **package's own** `rolloutBucket` rather
than a hard-coded table — so a second bucketing implementation in the gateway
would diverge and fail. It also asserts both buckets are non-empty, which kills
the "always answers the same way" vacuity.

`apps/gateway/src/inference/shadow.ts` (`shadowMirrorFor` / `spawnShadowMirror`,
fired from `handlers.ts:395,501`) landed during this audit and closes the
shadow-mirroring gap. **Note:** `shadowCandidate` in `candidates.ts:446` now has
**zero callers** — it was superseded by `shadow.ts` and should be deleted by
whoever owns that slice, or it becomes the next dead seam.

### Residual gap 1 — `ShadowBudgetDurableObject` is not mounted

`shadow.ts:154` falls back to a module-scope `ShadowBudgetLedger`, so a shadow
cap of `N` becomes **`N` per live isolate**. `SHADOW_BUDGET` appears in **no**
`wrangler.toml` and `ShadowBudgetDurableObject` is re-exported from **no**
`worker.ts`. Over-mirroring bills real provider money, so the loose cap is a cost
defect, not cosmetic. The exact three edits are already written out in
`apps/gateway/src/inference/shadow.ts:181-195` — they belong to the integrate
step, which owns `worker.ts` and `wrangler.toml`.

### Residual gap 2 — `RouteMatcher` has no implementation and no caller

`packages/routing/src/route.ts:29` is an interface only. Its intended
implementer is the operator reverse-proxy fall-through flagged at
`apps/gateway/src/routes/index.ts:391`, which does not exist in this tree. This
is a **deferred feature**, correctly marked — not a wiring miss.

### Stale marker

`packages/routing/src/index.ts:21` still reads **"THIS PACKAGE IS NOT MOUNTED"**
and asserts a grep returns "exactly one hit … inside a docstring". That is now
false. The marker belongs to the slice that closed it (task #79); it should be
rewritten to cover only the two residual gaps above. **Not edited here** — never
delete a marker you did not close.

---

## 5. `@ferrogate/observability` — **(a) WRONGLY DEAD. This is the single largest gap in the audit.**

**Verdict: the entire telemetry pipeline has a receiver, a wire format, an
authentication scheme, and a deployed collector Worker — and NO PRODUCER. Not one
line of any app constructs a backend or emits a signal.**

### The evidence

The only reference to the package from any `apps/*/src` is
`import type { GatewayMetricsSnapshot }` at
`apps/gateway/src/cache/metrics.ts:37` — a **type-only** import, erased by the
compiler. At runtime the package contributes **zero bytes** to every deployed
Worker.

`CloudflareBackend`, `OtlpBackend`, `renderPrometheusText`,
`buildOtlpMetricsRequest`, `buildOtlpTracesRequest`, `buildOtlpLogsRequest`
are constructed/called **nowhere** outside `packages/observability/` and its own
tests. (`rg` across `apps/` returns only docstring mentions.)

### What Rust did, and what that means is missing

`crates/ferrogate-gateway/src/telemetry.rs:32` starts a background sender that,
every 5 s, calls `state.telemetry_backend()` and pushes a metrics snapshot plus
OTLP **logs** (request logs, audit events, billing events) and **trace spans** to
either `OtlpBackend` or, when configured, `CloudflareBackend` — whose bearer
token it resolves through `SecretResolverRegistry`
(`state_observability.rs:48-71`).

The TS rewrite ported **both ends and neither middle**:

- **Receiver, complete:** `apps/telemetry` is a fully-built OTLP collector — it
  parses `/v1/{metrics,traces,logs}`, authenticates a bearer `COLLECTOR_TOKEN`,
  and writes to a declared `[[analytics_engine_datasets]] TELEMETRY` binding.
  Its own docstrings (`src/auth.ts:6`, `src/ports.ts:21`, `src/app.ts:33`) say,
  correctly, that it accepts exactly what `CloudflareBackend` sends.
- **Producer, absent:** nothing sends. **`apps/telemetry` cannot receive a single
  byte in production.** It is a deployed, authenticated, dead endpoint.

### Concrete consequences today

1. **No gateway telemetry exists at all.** No spans, no OTLP logs, no metrics
   leave the data plane. `packages/observability/src/spans.ts` defines the 6
   canonical span templates (`GATEWAY_REQUEST`, `AUTH`, `POLICY`, `MODEL_ROUTE`,
   `PROVIDER_DISPATCH`, `BILLING_WRITE`) — none is ever emitted.
2. **Distributed tracing is adopted and then dropped on the floor.**
   `apps/gateway/src/middleware/trace.ts` correctly adopts a valid inbound
   `traceparent` (byte-for-byte the Rust `valid_traceparent` rules) and parks the
   trace id on the request context — and no consumer ever turns it into a span.
   The correlation id is computed and discarded.
3. **`apps/mcp` audit evidence is knowingly stranded.** `apps/mcp/wrangler.toml`
   (the "NOT DECLARED — and why" block) states it: `InMemoryAuditSink` holds the
   `tool.execute` / `mcp.identity.*` rows including the `#522` `agent_run_id`
   correlation column only for the life of the isolate, and names
   `apps/telemetry` as the durable sink it is waiting on. Nothing wires the two.

### Where it must mount

`apps/gateway` — a backend built from env (collector endpoint + bearer token) and
flushed per request via `ctx.waitUntil(...)`, and/or drained from a buffer by the
`scheduled` handler the gateway already has (`gatewayScheduled` in
`src/worker.ts`, `[triggers]` already in `wrangler.toml`). Rust's 5-second
background thread has no workerd twin, so `waitUntil` at request end is the
faithful mapping, not a compromise. `apps/mcp` needs the same seam for its audit
sink.

The mount gate must be an assertion that a **request through `SELF`** causes an
outbound fetch to the collector endpoint carrying the adopted trace id — not a
direct call to `buildOtlpTracesRequest`, which would survive un-wiring exactly as
the circuit-breaker tests did.

### A defect that proves the package is dead: a 3× wrong platform constant

`packages/observability/src/analytics-engine.ts:45` declares

```ts
export const AE_MAX_BLOB_BYTES = 5120;
```

`apps/telemetry/src/limits.ts:35` independently declares

```ts
export const AE_MAX_BLOB_BYTES = 16 * 1024;
```

Cloudflare's documented limit is **16 KB total blob size per data point**
(20 blobs, 20 doubles, 1 index ≤ 96 bytes, 250 `writeDataPoint` calls per
invocation). **The package's 5120 is wrong** — `analyticsEngineDataPointViolation`
would reject legitimate data points at ~⅓ of the real ceiling. A 3× error in a
platform limit has sat there un-noticed *because nothing calls it*.

The duplication is broader than one constant: `apps/telemetry/src/limits.ts`
(165 lines) and `apps/telemetry/src/sink.ts`'s own `AnalyticsEngineSink`
re-implement `packages/observability/src/analytics-engine.ts` (264 lines) — the
"reimplemented locally while the package went dead" pattern, caught with a
diverging value.

**Recommended resolution:** the app's 16 KiB is correct; fix the package
constant, then collapse one implementation into the other. Do **not** blindly
adopt the package's clamps — they are the wrong ones.

---

## 6. `@ferrogate/secrets` — **(a) WAS WRONGLY DEAD; now PARTLY WIRED. One real gap left.**

**Verdict: the MCP mount is real and well-gated. The gateway's provider
credentials still bypass the package entirely.**

### What is live

`apps/mcp/src/ports.ts:47` imports `SecretResolverRegistry`, and `resolvePorts`
binds `secrets: secretResolverOverride ?? workerSecretResolver(env)` in **every**
posture. `apps/mcp/test/secrets-mount.test.ts` is a model mount gate: it
deliberately never calls `setSecretResolver`, drives the real Worker over `SELF`,
and each case goes red with `503 mcp_identity_secret_unavailable` if the binding
is dropped — with a negative control (an unbound reference must still fail) so
"not 503" means something. `packages/config/src/validate/helpers.ts:9` uses
`parseSecretRef` for config validation.

### The gap — provider API keys never touch the resolver

`apps/gateway/src/inference/catalog.ts` reads a provider's credential as a **raw
`env[api_key_var]` lookup**. It never constructs `SecretResolverRegistry`, so on
the data plane a provider credential can only ever be a plain Worker secret
binding: **`env://`, `vault://` and `cf://` refs are unreachable**, and the
gateway's own docstrings acknowledge the pending move
(`apps/gateway/src/assets/sigv4.ts:177`, `wrangler.toml:212`).

Rust resolved through the registry at three gateway sites —
`state_observability.rs:61` (collector token), `state_mcp_identity.rs:2494`
(MCP client secret, now ported), `acme.rs:823` (ACME account key; ACME/TLS has no
CF twin — correctly dropped). The first is blocked behind §5 and the provider-key
leg is open. Tracked as task #83.

### Legitimately unclosable half

The `PORT-TODO(4.6/4.7)` markers in `cloudflare-bindings.ts` /
`cloudflare-client.ts` are correct and must stay: a `[[secrets_store_secrets]]`
binding resolves at **deploy** time, there is no runtime "open secret by name"
API, and the local runtime has no Secrets Store emulation. The consuming half
(`cf://` name → bound slot) is implemented and tested; the provisioning half
cannot be.

---

## 7. Dead-seam sweep — is the deployed root running the in-memory default?

"Real in production" = what the **committed `wrangler.toml`** + composition root
actually produce. "Test holds it" = a test that goes **red** if the production
binding regresses to the in-memory default (a test that injects its own fake into
a harness does **not** count).

### 7.1 `apps/agent-runtime` — **EVERY PORT IS IN-MEMORY IN PRODUCTION** ⚠️ never audited before

`apps/agent-runtime/src/ports.ts:915`:

```ts
export function resolveDeps(env: AgentRuntimeBindings): AgentRuntimeDeps | undefined {
  if (env.FG_DEV_IN_MEMORY_PORTS !== "1") return undefined;
  return { apiKeys: inMemoryApiKeyPort(…), workerIdentities: inMemoryWorkerIdentityPort(…), … };
}
```

There is **exactly one branch**. No real-adapter path exists **anywhere** in this
app — not unbound, *unwritten*. And `apps/agent-runtime/wrangler.toml:64` commits

```toml
FG_DEV_IN_MEMORY_PORTS = "1"
```

three lines under a comment reading *"DEV / TEST ONLY … Production MUST NOT set
this."* **The committed deployment configuration contradicts its own docstring.**
Deploy this file and every port is the dev bundle.

| port | real in production? | evidence | test holds it? |
|---|---|---|---|
| `apiKeys` | ❌ in-memory | `inMemoryApiKeyPort(FG_DEV_API_KEYS)`; no D1 `api_keys` | ❌ |
| `workerIdentities` | ❌ in-memory | `inMemoryWorkerIdentityPort(FG_DEV_SELF_HOSTED_WORKERS)`; the Secrets-Store registry is a `TODO(bindings)` comment | ❌ |
| `governance` | ❌ in-memory | `inMemoryGovernancePort`; no `CONTAINER_SANDBOX`/`[[containers]]` | ❌ |
| `upstreams` | ❌ in-memory | `inMemoryAgentUpstreamPort(FG_DEV_AGENT_UPSTREAMS)` | ❌ |
| `guardrails` | ✅ real | `deterministicGuardrailPort` = real `@ferrogate/guardrails` detector; policy from a var | partly |
| `config` | ✅ real | `configFromEnv` reads real operator vars | ✅ |
| `clock` | ✅ real | `systemClock` | n/a |
| `AGENT_RUN_STATE` / `WORKER_PLANE` DOs | ✅ real | declared + `new_sqlite_classes` + re-exported from `worker.ts` | ✅ |

The **only** test touching the flag (`test/contract.test.ts:514`) asserts the
*fail-closed* direction — unset ⇒ 503. Nothing asserts a real adapter is ever
reachable, because none exists. No D1, R2 or Queue binding is declared; the
`TODO(bindings)` block at `wrangler.toml:102` enumerates all of them.

**Verdict:** the run/job lifecycle is durable (the two DOs are real); **identity,
governance and the upstream catalog are not.** Everything a self-hosted worker
authenticates against is a JSON var.

### 7.2 `apps/mcp` — durable identity is IMPLEMENTED, BOUND, and BYPASSED ⚠️

Worse than 7.1, because here the real implementation exists and is skipped by one
variable. `resolvePorts` (`src/ports.ts:1638`) takes postures in order, and
posture 1 short-circuits:

```ts
if (env.FG_DEV_IN_MEMORY_PORTS === "1") return { ...inMemoryPorts(), guardrails, secrets };
```

`apps/mcp/wrangler.toml:37` commits `FG_DEV_IN_MEMORY_PORTS = "1"` — under the
same *"Production MUST NOT set this"* comment. So the declared `[[d1_databases]]
DB`, `[[kv_namespaces]] MCP_OAUTH_KV`, `McpOauthFlowClaim` DO and
`FerroGateMcpSession` DO are **never reached** by the committed config, and
`DurableCredentialStore` is never constructed.

This is not inference — a test **pins** it:
`apps/mcp/test/durable-identity.test.ts:550`

```ts
it("keeps the dev bundle in charge when the dev flag is set", () => {
  const ports = resolvePorts({ ...base, FG_DEV_IN_MEMORY_PORTS: "1" });
  expect(ports.credentials).not.toBeInstanceOf(DurableCredentialStore);
});
```

| port | real in production (as committed)? | notes |
|---|---|---|
| `guardrails` | ✅ real | bound in *every* posture; gated by `test/guardrails.test.ts` over `SELF` |
| `secrets` | ✅ real | bound in every posture; gated by `test/secrets-mount.test.ts` |
| `credentials` | ❌ in-memory | `DurableCredentialStore` exists + D1/KV/DO bound, bypassed by the flag |
| `cipher` | ❌ per-isolate | `webCryptoIdentityCipher` ephemeral key; grants unreadable after eviction |
| `auth` | ❌ in-memory | dev key table; posture 2/3 would give `UnboundAuth` → fail-closed 503 |
| `audit` | ❌ in-memory | `InMemoryAuditSink`; `#522` `agent_run_id` rows die with the isolate (see §5) |
| `metrics`, `entitlements`, `upstreams`, `approvals`, `assets` | ❌ in-memory | no durable leg in any posture |

**Highest-leverage single change in this whole audit:** remove
`FG_DEV_IN_MEMORY_PORTS` from the two committed `wrangler.toml` files (or move it
into a `[env.dev]` block). That is a **composition-root edit** — it belongs to the
integrate step, not to a package agent.

### 7.3 `apps/cli` — clean ✅ (never audited before)

`createDefaultRuntime()` (`apps/cli/src/index.ts:37`) binds a real implementation
for all six ports.

| port | real in production? | production impl | test holds it? |
|---|---|---|---|
| `client` | ✅ | `createFetchControlPlaneClient(fetch, transport)` | ✅ `test/transport.test.ts:456` — drives `main()` on the default runtime and asserts a real `fetch` occurred; red if it regressed to `createInMemoryControlPlaneClient` |
| `gatewayClient` | ✅ | `createFetchGatewayClient` | ❌ no composition-root gate |
| `io` | ✅ | `createNodeIo` | ❌ |
| `contextStorage` | ✅ | `createFileContextStorage(io)` | ❌ |
| `configValidator` | ✅ | `createFerrogateConfigValidator` (real `@ferrogate/config` loader + `#542` auth-posture gate) — **not** `createStructuralConfigValidator`, whose docstring at `ports.ts:610` says so explicitly | ❌ swapping the two would leave the suite green |
| `keyHasher` | ✅ | `createNodeKeyHasher` | ❌ |

**Verdict: no dead seam in the CLI.** The residual risk is regression, not
current state: 5 of 6 have no gate. The cheapest fix is to extend the existing
`describe("the shipped runtime wires the real transports")` block with identity
assertions on `createDefaultRuntime()`'s other five fields.

### 7.4 `apps/gateway` — mostly real; two audit sinks are dead seams

| port | real in production? | evidence |
|---|---|---|
| `apiKeys` | ✅ | `d1ApiKeyResolverFromEnv` over `DB`, config vars as fallback (Rust order) |
| `rbac` | ✅ | `D1RbacAuthorizer` over `CONTROL_DB`, vars as fallback |
| `lifecycle` | ⚠️ vars only | `ConfiguredTenancyLifecycleGate`; `TENANCY_LIFECYCLE = "{}"` committed. No durable leg — marker already present |
| `internalTransport` | ⚠️ vars only | `SELF_HOSTED_WORKER_REGISTRY = "[]"` committed ⇒ **no self-hosted worker can authenticate as deployed**; transport secret in a var (marker present) |
| ratelimit limiter | ✅ | `RATE_LIMIT` DO declared + re-exported from `worker.ts` |
| provider circuit | ✅ | `PROVIDER_CIRCUIT` DO declared + re-exported |
| metering sink | ✅ | `BILLING_DB` D1 + `BILLING` Queue producer |
| assets `objects` | ✅ | R2 `ASSETS` |
| assets `metadata` | ✅ | `D1AssetMetadataStore` (`assets/d1.ts:543`) |
| assets `presigner` | ⚠️ `UnavailablePresigner` | documented platform limit (R2 bindings have no presign) |
| assets `screener` | ✅ | `BuiltinEicarScreener` — a deliberate builtin, not a stub |
| **assets `audit`** | ❌ **in-memory** | `assetDepsFromEnv` (`assets/handlers.ts:550`) never supplies `audit`, so `buildAssetService` falls to `new InMemoryAssetAuditSink()`. **Every asset audit event is lost on isolate eviction.** No marker |
| **guardrails `evidence`** | ❌ **in-memory** | `guardrailOptions` (`guardrails/config.ts`) binds `evidence: new InMemoryGuardrailEvidenceSink()` **unconditionally**, even with `CONTROL_DB` bound. **Guardrail evidence — the record of what was screened and blocked — is not durable.** No marker |
| shadow budget | ⚠️ per-isolate | `SHADOW_BUDGET` DO unbound (§4) |
| tenancy routing | ⚠️ inert | `GATEWAY_TENANT_DB_ROUTING = "off"` committed — deliberate, documented |
| telemetry export | ❌ **absent** | §5 |

Both ❌ rows exhibit the canonical failure: `apps/gateway/test/guardrails/*.test.ts`
and `test/assets/*.test.ts` construct **their own** sinks and pass them into the
harness (`audit: h.audit`, `evidence: new InMemoryGuardrailEvidenceSink()`), so
the production binding is never exercised and **no test would go red if it stayed
in-memory forever.**

### 7.5 `apps/control-plane` — one no-op port in production

| port | real in production? | evidence |
|---|---|---|
| `store` | ✅ | D1 `DB` bound; `CONTROL_PLANE_STORE` unset ⇒ not `"memory"` |
| `apiKeys` / `rbac` / `lifecycle` | ✅ | D1-backed, vars as fallback |
| `runtime` | ✅ (partial) | `StoreRuntimeStatus`; the `observability()` feed returns empty by a correctly-marked platform limit (Analytics Engine has no offline read API) |
| `tenantDatabases` | ⚠️ | `EnvBindingTenantDatabaseRouter` is real, but **no per-tenant `[[d1_databases]]` stanza is declared**, so `forTenant` throws `StorageError` until a tenant is provisioned *and* its binding added at deploy time. This is the known open constraint of the database-per-tenant directive, documented at `adapters.ts:700-710` |
| **`txtResolver`** | ❌ **no-op** | `SITE_DOMAIN_RESOLVER` is **not in the committed `[vars]`**, so `resolveTxtResolver` (`adapters.ts:592`) returns `UnboundTxtResolver` — `POST /admin/v1/site-domains/{hostname}/verify` can **never** verify a domain as deployed. Fail-closed and honestly reported, but a production no-op. No test covers the default |
| `corsAllowedOrigin` | ✅ | `null` ⇒ preflight surface absent — deliberate |

### 7.6 `apps/telemetry` — real, and unreachable

`resolveSink` returns a real `AnalyticsEngineSink` over the declared
`[[analytics_engine_datasets]] TELEMETRY` binding, degrading to
`503 telemetry_sink_unavailable` when unbound. The port itself is clean. **The
Worker as a whole is dead**, for the reason in §5: nothing produces telemetry.

---

## 8. Markers added by this audit

Only where a real gap had **no** existing marker. Nothing was deleted, nothing
was wired.

| file | gap |
|---|---|
| `packages/observability/src/index.ts` | NO PRODUCER: zero runtime importers in any app; `apps/telemetry` cannot receive anything; `AE_MAX_BLOB_BYTES` is 3× under the documented CF limit |
| `packages/schemas/src/wire.ts` | `errorEnvelopeSchema` does not match the shipped envelope; `OPENAPI_OPERATION_COUNT` is the third copy of 251 |
| `packages/sync-bridge/src/index.ts` | verdict: DELETE at parity, per inventory §7 |
| `apps/agent-runtime/src/ports.ts` | `resolveDeps` has no real-adapter branch, and the committed `wrangler.toml` sets the dev flag |

---

## 9. Ranked actions

1. **Wire a telemetry producer in `apps/gateway`** (§5). The largest gap: an
   entire deployed Worker is unreachable and the data plane is unobservable.
2. **Remove `FG_DEV_IN_MEMORY_PORTS = "1"` from the two committed
   `wrangler.toml` files** (§7.1, §7.2). One-line composition-root edits that
   move `apps/mcp` from all-in-memory to its already-built durable identity
   posture. **Integrate-step owned.**
3. **Fix `AE_MAX_BLOB_BYTES = 5120` → 16 KiB in `packages/observability`** and
   collapse the duplicate AE clamp implementation (§5).
4. **Give `apps/gateway` durable guardrail-evidence and asset-audit sinks**
   (§7.4) — `CONTROL_DB` is already bound; both are security/compliance records.
5. **Bind `SHADOW_BUDGET`** or accept the per-isolate cap in writing (§4).
6. **Route gateway provider credentials through `@ferrogate/secrets`** (§6,
   task #83).
7. **Delete `packages/sync-bridge`** (§1).
8. **Correct or delete `packages/schemas`' owned envelope + count** (§3.2), and
   collapse the three copies of 251 to one.
9. **Build real adapters for `apps/agent-runtime`** (§7.1) — the largest
   remaining build, and correctly last: it needs bindings that do not exist yet.
10. **Extend the CLI composition-root gate to the other five ports** (§7.3) —
    cheap regression insurance, no current defect.
