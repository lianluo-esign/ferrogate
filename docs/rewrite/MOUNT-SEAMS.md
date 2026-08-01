# MOUNT-SEAMS — the durable mount-seam inventory

> **Read §15 before trusting any *Expected RED* cell below.** The wave-14 sweep
> found that **eight** rows' expectations were wrong — four `compatibility_flags`
> rows, three agent-runtime `[vars]` rows and GW-T18 — and that **three** T1 rows
> (GW-A1, AR-P4, plus the MCP/AR `new_sqlite_classes` set) had no working gate at
> all. §15 records every correction; the rows themselves are annotated only where
> the recipe itself was wrong.

**Status:** re-derived MECHANICALLY from every composition root on 2026-08-01
(wave 14). This file replaces the practice of recording the mount table in
commit messages, which recorded COUNTS but never NAMES — so each wave had to
re-derive the inventory from scratch, and the wave-13 re-derivation found **29
seams that had never been proven at all** (the CLI runtime's six ports, the
telemetry app factory, and four non-gateway Workers' entire `wrangler.toml`
binding sets).

---

## 1. What a "mount seam" is, and why this file exists

The dominant defect in this project is not broken code. It is code that is fully
implemented, fully tested, and **never mounted on the app the Worker exports** —
dead in production while every suite stays green. Ten have been caught. A *mount
seam* is any single line of code or config whose removal silently un-deploys
working behaviour.

A seam is only "proven" when **removing it makes a named test go RED**. Asserting
that a handler EXISTS is not asserting that it DOES anything.

### The three traps this table is organised around

1. **`real ?? fallback`.** A seam of that shape needs a gate asserting something
   ONLY the real implementation can produce. Every such row is marked `??` in the
   *Seam* column.
2. **The local runner is more permissive than Cloudflare.** `@cloudflare/vitest-pool-workers`
   builds a Durable Object namespace from the BINDING alone and never reads
   `[[migrations]]`; it also skips workerd's entrypoint-shape check on `main`.
   Rows whose only proof channel is `wrangler dev` / `wrangler deploy` are marked
   **`DEPLOY-ONLY`** in the *Expected RED* column.
3. **A handler that exists ≠ a handler that runs.** `gatewayScheduled`'s body was
   gutted to a no-op and 1711 tests stayed green (GW-C10 below).

---

## 2. Mutation protocol (run this verbatim for every row)

```bash
F=<file>                       # the absolute path in the row
cp "$F" /tmp/seam.bak
sha256sum "$F" > /tmp/seam.sha
<apply the row's MUT recipe>
<run the row's CONFIRM grep>   # MUST print nothing (or the stated count)
bun run test                   # in the app dir — NOT bare `bunx vitest run`
                               # -> MUST be RED, and RED in the stated file
cp /tmp/seam.bak "$F"
sha256sum -c /tmp/seam.sha     # MUST say OK
bun run test                   # -> MUST be GREEN
```

**The CONFIRM grep is not optional.** A concurrent write can silently revert the
edit before the build, and a mutation that never landed looks exactly like a
vacuous test. Grep the file back OFF DISK before believing a GREEN result.

**Use `bun run test`, not `bunx vitest run`.** `apps/gateway` chains two extra
vitest projects and `apps/agent-runtime` chains one; three seams below are RED
ONLY under the full command (§5).

### Recipe shorthand used in the *Mutation* column

| Tag | Expansion |
|---|---|
| `MUT-1 /RE/` | `perl -i -ne 'print unless m{RE}' "$F"` — delete every line matching |
| `MUT-2 "OLD"→"NEW"` | `perl -0777 -i -pe 's{\QOLD\E}{NEW}' "$F"` — literal replace |
| `MUT-3 «block»` | `perl -0777 -i -pe 's{\Q«block»\E\n}{}' "$F"` — delete a contiguous TOML stanza verbatim |
| `MUT-4 [hdr]` | comment a whole TOML stanza out: `perl -i -pe 'if (/^\[\[hdr\]\]/){$m=1} elsif (/^\[/){$m=0} s/^/#MUT /  if $m' "$F"` (the config gates drop `#` lines, so commenting ≡ deleting) |

Default CONFIRM for `MUT-1`/`MUT-3`: `grep -n '<anchor>' "$F"` prints nothing.
Default CONFIRM for `MUT-2`: `grep -n 'NEW' "$F"` prints exactly the mutated line.

---

## 3. Risk tiers

| Tier | Meaning |
|---|---|
| **T1** | money · auth · tenant isolation · Durable Object bindings · deploy-blocking config |
| **T2** | request-path behaviour |
| **T3** | cosmetic or redundant |

---

## 4. The incremental re-proof policy this file enables

The full 75-seam pass in wave 13 took **hours**. From wave 14 onward a wave
re-proves:

- **(a)** every seam whose FILE was touched in that wave, and
- **(b)** every **T1** seam, unconditionally.

**This is an honest trade of coverage for wall-clock.** A T2/T3 seam in an
untouched file is assumed still mounted on the strength of its last proof. That
assumption is wrong the moment a shared refactor moves a mount without touching
the row's file — which is precisely how seams have been lost here before.

Two hard exceptions where a **FULL pass over every row** is mandatory:

1. **before the single authorised live `wrangler deploy`** (the deploy-only rows
   in §6/§8/§10/§12/§14 have never been exercised by any local runner);
2. **before deleting the Rust tree** (`crates/**`, `workers/**`) — after that
   there is no reference implementation left to re-derive a lost mount from.

Also re-run the full pass whenever a row's *Expected RED* file is renamed,
deleted or rewritten: the gate is the seam's only proof, and a gate that no
longer exists is a seam that is no longer proven.

---

## 5. PROVEN-ON-ESCALATION — do not mistake a main-project green for a pass

Three seams are GREEN under the app's default vitest project and go RED **only**
under the full `bun run test`, because their gates are `*.spec.ts` files that the
main `include: ["test/**/*.test.ts"]` glob does not match.

| ID | Seam | Chained config that carries the gate |
|---|---|---|
| **GW-C8** | `tenantDatabase()` in `GATEWAY_MIDDLEWARE` | `apps/gateway/test/tenancy/harness/vitest.config.ts` |
| **AR-P1** | `env.DB !== undefined ? d1ApiKeyPort(env.DB) :` in `resolveDeps` | `apps/agent-runtime/test/durable/harness/vitest.config.ts` |
| **AR-P2** | `env.CONTROL_DB !== undefined ? d1WorkerIdentityPort(env.CONTROL_DB) :` | `apps/agent-runtime/test/durable/harness/vitest.config.ts` |

A fourth chained project — `apps/gateway/test/ratelimit/harness/vitest.config.ts`
— carries `durable-object.spec.ts` / `enforcement.spec.ts`, which are the
behavioural half of GW-E3/GW-T8. Treat any `.spec.ts` gate as escalation-only.

---

## 6. `apps/gateway` — 53 seams

### 6.1 Entry module `apps/gateway/src/worker.ts`

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-E1 | `fetch: (request, env, ctx) => app.fetch(request, env, ctx),` | `MUT-1 /fetch: \(request, env, ctx\)/` | `grep -n 'app.fetch' src/worker.ts` → nothing | every `SELF.fetch` suite; `test/health.test.ts` | T1 |
| GW-E2 | `scheduled: (controller, env, ctx) => gatewayScheduled(controller, env, ctx),` | `MUT-1 /scheduled: \(controller, env, ctx\)/` | `grep -n 'gatewayScheduled(controller' src/worker.ts` → nothing | `test/metering/cron-mount.test.ts`; `test/cron-trigger.test.ts` | T1 |
| GW-E3 | `export { RateLimiterDurableObject } from "./ratelimit/index.js";` | `MUT-1 /export \{ RateLimiterDurableObject \}/` | `grep -n 'RateLimiterDurableObject' src/worker.ts` → nothing | `test/wrangler-bindings.test.ts` ("resolves each bound class against the ENTRY module"); `test/ratelimit/durable-object.spec.ts` (escalation) | T1 |
| GW-E4 | `export { ProviderCircuitDurableObject } from "./inference/index.js";` | `MUT-1 /export \{ ProviderCircuitDurableObject \}/` | as above | `test/wrangler-bindings.test.ts` | T1 |
| GW-E5 | `export { ShadowBudgetDurableObject } from "@ferrogate/routing/durable-objects";` | `MUT-1 /export \{ ShadowBudgetDurableObject \}/` | as above | `test/wrangler-bindings.test.ts`; `test/inference/shadow-budget-binding.test.ts` | T1 |

### 6.2 Composition root `apps/gateway/src/index.ts`

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-C1 | `const usage = createMeteringUsageSink({ bindings: meteringBindingsFromEnv });` | `MUT-2 "{ bindings: meteringBindingsFromEnv }"→"{}"` | `grep -n 'createMeteringUsageSink({})' src/index.ts` | `test/metering/wiring.test.ts` (D1 row read back from `BILLING_DB`) | T1 |
| GW-C2 | `inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),` (line 97) | `MUT-1 /^  inferenceRouteModule\(/` | `grep -n 'inferenceRouteModule({' src/index.ts` → nothing | `test/contract.test.ts` (31 owned ops); `test/inference/wiring.test.ts` | T1 |
| GW-C3 | `assetRouteModule({ depsFromEnv: assetDepsFromEnv }),` (line 98) | `MUT-1 /^  assetRouteModule\(/` | `grep -n 'assetRouteModule({' src/index.ts` → nothing | `test/contract.test.ts`; `test/assets/routes.test.ts` | T2 |
| GW-C4 | `meteringDrain(usage),` — **index 0** of `GATEWAY_MIDDLEWARE` (line 178) | `MUT-1 /^  meteringDrain\(usage\),$/` | `grep -n 'meteringDrain(usage)' src/index.ts` → nothing | `test/metering/wiring.test.ts` (structural order gate + behavioural D1 gate) | T1 |
| GW-C5 | `requestTelemetry(),` (line 200) | `MUT-1 /^  requestTelemetry\(\),$/` | `grep -n 'requestTelemetry(),' src/index.ts` → nothing | `test/telemetry/middleware-mount.test.ts` (non-inference op `putAsset`) | T2 |
| GW-C6 | `rateLimit(),` (line 203) | `MUT-1 /^  rateLimit\(\),$/` | `grep -cn 'rateLimit()' src/index.ts` → 1 (the docblock mention survives) | `test/ratelimit/guards.test.ts`; `test/inference/wiring.test.ts` (TPM window) | T1 |
| GW-C7 | `guardrails(async (env) => ({ … })),` (lines 211-230) | `MUT-2 "guardrails(async (env) => ({"→"((async()=>{}) as never) \|\| guardrails(async (env) => ({"` — or comment lines 211-230 | `grep -n 'as never' src/index.ts` | `test/guardrails/wiring.test.ts`; `test/guardrails/middleware.test.ts` | T1 |
| GW-C8 | `tenantDatabase(),` (line 232) — **ESCALATION (§5)** | `MUT-1 /^  tenantDatabase\(\),$/` | `grep -n 'tenantDatabase(),' src/index.ts` → nothing | `test/tenancy/mount.spec.ts` — **only under `bun run test`** | T1 |
| GW-C9 | `const { app, router } = createGatewayApp({ modules: GATEWAY_ROUTE_MODULES, middleware: GATEWAY_MIDDLEWARE });` | `MUT-2 "modules: GATEWAY_ROUTE_MODULES,"→""` | `grep -n 'GATEWAY_ROUTE_MODULES,' src/index.ts` → nothing | `test/contract.test.ts` (all 31 ids registered on the real router) | T1 |
| GW-C10 | `await usage.sweep({ env, ctx });` — the BODY of `gatewayScheduled` | `MUT-1 /await usage\.sweep\(\{ env, ctx \}\)/` | `grep -n 'usage.sweep' src/index.ts` → nothing | `test/metering/cron-mount.test.ts` — **the wave-13 finding: this was GREEN across 1711 tests before that gate existed** | T1 |
| GW-C11 | `app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));` | `MUT-1 /app\.get\("\/version"/` | `grep -n '"/version"' src/index.ts` → nothing | **NO GATE — corrected wave 15.** The cell said `test/health.test.ts`; the full pass found the mutation **GREEN** across all 1786 gateway tests, and `grep -rn "/version" apps/gateway/test` returns nothing. Deleting the route is invisible | T3 |

### 6.3 Route registration `apps/gateway/src/routes/index.ts` (`createGatewayApp`)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-R1 | `app.onError(gatewayErrorHandler);` (346) | `MUT-1 /app\.onError\(gatewayErrorHandler\)/` | anchor gone | `test/routes/trace.test.ts` (error envelope) | T2 |
| GW-R2 | `app.notFound(gatewayNotFoundHandler);` (347) | `MUT-1 /app\.notFound\(gatewayNotFoundHandler\)/` | anchor gone | `test/contract.test.ts` (404 control probe) | T2 |
| GW-R3 | `app.use("*", requestId);` (348) — requestId **+ W3C traceparent ingress** | `MUT-1 /app\.use\("\*", requestId\)/` | anchor gone | `test/routes/trace.test.ts`; `test/routes/ingress-deployed.test.ts` | T2 |
| GW-R4 | `app.use("*", options.networkAccess ?? networkAccess());` (355) — **pre-auth** `??` | `MUT-1 /options\.networkAccess \?\? networkAccess\(\)/` | anchor gone | `test/routes/network.test.ts`; `test/routes/ingress-deployed.test.ts` | T1 |
| GW-R5 | `app.use("*", contractAuth(options.deps ?? depsFromEnv));` (359) `??` | `MUT-2 "contractAuth(options.deps ?? depsFromEnv)"→"async (_c, n) => await n()"` | `grep -n 'async (_c, n)' src/routes/index.ts` | `test/auth.test.ts`; `test/rbac.test.ts` | T1 |
| GW-R6 | `for (const middleware of …) { app.use("*", middleware); }` (364) — mounts all of `GATEWAY_MIDDLEWARE` | `MUT-1 /^    app\.use\("\*", middleware\);$/` | anchor gone | `test/metering/wiring.test.ts` + every §6.2 middleware gate | T1 |
| GW-R7 | `app.use("*", options.responseCache ?? responseCache());` (375) `??` | `MUT-1 /options\.responseCache \?\? responseCache\(\)/` | anchor gone | `test/cache/deployed.test.ts`; `test/cache/middleware.test.ts` | T2 |
| GW-R8 | `router.register("getHealthz", healthzHandler);` + `router.register("getReadyz", readyzHandler);` (380-381) | `MUT-1 /router\.register\("get(Healthz\|Readyz)"/` | anchors gone | `test/health.test.ts`; `test/routes/readiness.test.ts` | T2 |
| GW-R9 | `registerToolingRoutes(router);` (383) — skills, prompts, agent-discovery, 3× `registerNotImplemented` | `MUT-1 /^  registerToolingRoutes\(router\);$/` | anchor gone | `test/routes/skills.test.ts`, `prompts.test.ts`, `agent-discovery.test.ts`; `test/contract.test.ts` | T2 |
| GW-R10 | `module.register(router);` (386) — mounts `GATEWAY_ROUTE_MODULES` | `MUT-1 /^    module\.register\(router\);$/` | anchor gone | `test/contract.test.ts` (24 of 31 ops vanish — the original defect) | T1 |
| GW-R11 | `app.all("*", options.reverseProxy ?? reverseProxyFallThrough());` (407) `??` — must stay LAST | `MUT-1 /options\.reverseProxy \?\? reverseProxyFallThrough\(\)/` | anchor gone | `test/routes/reverse-proxy.test.ts` | T2 |

### 6.4 Adapters `apps/gateway/src/adapters.ts` (`depsFromEnv`, 1096-1115)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-A1 | `apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,` `??` | `MUT-2 "d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured"→"configured"` | `grep -n 'apiKeys: configured' src/adapters.ts` | `test/keys/resolver.test.ts` | T1 |
| GW-A2 | `lifecycle: durableLifecycle === null ? configuredLifecycle : denyIfEitherDenies(durableLifecycle, configuredLifecycle),` | `MUT-2 "denyIfEitherDenies(durableLifecycle, configuredLifecycle)"→"configuredLifecycle"` | `grep -n 'denyIfEitherDenies' src/adapters.ts` → declaration only | `test/lifecycle-chain.test.ts` | T1 |
| GW-A3 | `rbac: D1RbacAuthorizer.fromEnv(…, { fallback: configuredRbac }) ?? configuredRbac,` `??` | `MUT-2 "D1RbacAuthorizer.fromEnv("→"undefined ?? ((x:never)=>x)!(" ` (simplest: replace the whole ternary with `configuredRbac`) | `grep -n 'rbac: configuredRbac' src/adapters.ts` | `test/rbac.test.ts` | T1 |
| GW-A4 | `internalTransport: ConfiguredInternalTransport.fromEnv(env),` | `MUT-2 "ConfiguredInternalTransport.fromEnv(env)"→"{ verify: () => ({ ok: true }) } as never"` | `grep -n 'ok: true } as never' src/adapters.ts` | `test/auth.test.ts` (worker-token 401/403 taxonomy) | T1 |

### 6.5 Asset binding adapter `apps/gateway/src/assets/handlers.ts`

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-A5 | `...(metadata !== null ? { metadata } : {}),` (603) | `MUT-1 /\.\.\.\(metadata !== null/` | anchor gone | `test/assets/wiring.test.ts` (row read from `stored_assets` in `DB`) | T1 |
| GW-A6 | `...(audit !== null ? { audit } : {}),` (604) | `MUT-1 /\.\.\.\(audit !== null/` | anchor gone | `test/assets/wiring.test.ts` | T1 |
| GW-A7 | `...(objects !== undefined ? { objects } : {}),` (602) | `MUT-1 /\.\.\.\(objects !== undefined \? \{ objects \}/` | anchor gone | `test/assets/r2.test.ts`; `test/assets/routes.test.ts` | T2 |
| GW-A8 | `await serviceFor(context).flushAudit();` (748) — the COMMIT of the buffered audit sink | `MUT-1 /flushAudit\(\);/` | `grep -n 'flushAudit()' src/assets/handlers.ts` → nothing | `test/assets/wiring.test.ts` (third named mutation) | T1 |

### 6.6 Deploy config `apps/gateway/wrangler.toml`

| ID | Seam (exact config) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| GW-T1 | `main = "src/worker.ts"` | `MUT-2 "src/worker.ts"→"src/index.ts"` | `grep -n 'main = ' wrangler.toml` | **DEPLOY-ONLY** — `bunx wrangler dev --local` fails `Incorrect type for map entry 'EXPECTED_OPERATION_COUNT'`; `e2e/` catches it. vitest does NOT | T1 |
| GW-T2 | `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_flags/` | anchor gone | whole suite (hono + WebCrypto/SigV4 fail to resolve) | T1 |
| GW-T3 | `[[r2_buckets]]` / `binding = "ASSETS"` | `MUT-4 [r2_buckets]` | `grep -n '^binding = "ASSETS"' wrangler.toml` → nothing | `test/assets/r2.test.ts` (503 `asset_bucket_unavailable` instead of 200) | T2 |
| GW-T4 | `[[d1_databases]] binding = "DB"` + `migrations_dir = "../../sql/d1-ts/tenant"` | `MUT-3 «[[d1_databases]]\nbinding = "DB"\ndatabase_name = "ferrogate-tenant"\ndatabase_id = "replace-at-deploy"\nmigrations_dir = "../../sql/d1-ts/tenant"»` | `grep -n 'binding = "DB"' wrangler.toml` → nothing | `test/keys/resolver.test.ts`, `test/assets/d1.test.ts`, `test/setup-d1.ts` (pool fails to apply migrations) | T1 |
| GW-T5 | `[[d1_databases]] binding = "BILLING_DB"` | `MUT-3` the 5-line stanza | anchor gone | `test/metering/d1.test.ts`, `test/metering/wiring.test.ts` | T1 |
| GW-T6 | `[[d1_databases]] binding = "CONTROL_DB"` | `MUT-3` the 5-line stanza | anchor gone | `test/guardrails/d1.test.ts`, `test/rbac.test.ts`, `test/cache/deployed.test.ts` | T1 |
| GW-T7 | `[[queues.producers]] binding = "BILLING"` | `MUT-4 [queues.producers]` | `grep -n 'binding = "BILLING"$' wrangler.toml` → nothing | `test/metering/durable.test.ts` (publish leg) | T1 |
| GW-T8 | `[[durable_objects.bindings]] name = "RATE_LIMIT"` (768-770) | `MUT-3 «[[durable_objects.bindings]]\nname = "RATE_LIMIT"\nclass_name = "RateLimiterDurableObject"»` | `grep -n 'RATE_LIMIT' wrangler.toml` → nothing | `test/wrangler-bindings.test.ts`; `test/ratelimit/durable-object.spec.ts` (escalation) | T1 |
| GW-T9 | `new_sqlite_classes = ["RateLimiterDurableObject"]` (774) | `MUT-1 /new_sqlite_classes = \["RateLimiterDurableObject"\]/` | anchor gone | `test/wrangler-bindings.test.ts` — **before that gate this was GREEN across 1610 tests and would have failed the first real `wrangler deploy`** | T1 |
| GW-T10 | `[[durable_objects.bindings]] name = "PROVIDER_CIRCUIT"` (800-802) | `MUT-3` the 3-line stanza | anchor gone | `test/wrangler-bindings.test.ts`; `test/inference/reliability-mount.test.ts` | T1 |
| GW-T11 | `new_sqlite_classes = ["ProviderCircuitDurableObject"]` (806) | `MUT-1 /new_sqlite_classes = \["ProviderCircuitDurableObject"\]/` | anchor gone | `test/wrangler-bindings.test.ts` | T1 |
| GW-T12 | `[[durable_objects.bindings]] name = "SHADOW_BUDGET"` (826-828) | `MUT-3` the 3-line stanza | anchor gone | `test/inference/shadow-budget-binding.test.ts`; `test/wrangler-bindings.test.ts` — **was GREEN across 1390 tests before that gate** | T1 |
| GW-T13 | `new_sqlite_classes = ["ShadowBudgetDurableObject"]` (832) | `MUT-1 /new_sqlite_classes = \["ShadowBudgetDurableObject"\]/` | anchor gone | `test/wrangler-bindings.test.ts` | T1 |
| GW-T14 | `[[services]] binding = "TELEMETRY_COLLECTOR"` / `service = "ferrogate-telemetry"` (860-862) | `MUT-3` the 3-line stanza | anchor gone | `test/wrangler-bindings.test.ts` (declared AND runtime-resolvable) — **was GREEN before that gate** | T2 |
| GW-T15 | `[triggers]` / `crons = ["* * * * *"]` (887-888) | `MUT-2 "[triggers]"→"[disabled_triggers]"` | `grep -n 'disabled_triggers' wrangler.toml` | `test/cron-trigger.test.ts` — **was GREEN across 1464 tests before that gate** | T1 |
| GW-T16 | `[vars]` × 3: `FERROGATE_ASSET_REQUIRE_SIGNATURE`, `…_PUBLISHER_ED25519_KEYS`, `…_PUBLISHER_MINISIGN_KEYS` | `MUT-1 /^FERROGATE_ASSET_/` | anchors gone | `test/wrangler-bindings.test.ts` §"asset publisher-signature policy vars" (drift + posture + name-is-read) | T1 |
| GW-T17 | `[vars]`: `GATEWAY_SKILL_PACKAGES = "[]"`, `GATEWAY_PROMPT_TEMPLATES = "[]"` | `MUT-1 /^GATEWAY_(SKILL_PACKAGES\|PROMPT_TEMPLATES)/` | anchors gone | `test/wrangler-bindings.test.ts` §"operator config tables" — **drift-only gate; deliberately weaker, the committed value is inert by design** | T3 |
| GW-T18 | the remaining **47** `[vars]` entries (`GATEWAY_NATIVE_API_KEYS` … `TELEMETRY_SIGNALS`) as one block | `MUT-4 [vars]` (comment the whole table) | `grep -c '^GATEWAY_' wrangler.toml` → 0 | partial: `test/auth.test.ts`, `test/contract.test.ts`, `test/cache/config.test.ts`. **Only 5 of the 49 vars have a name-drift gate (GW-T16/T17); the other 47 are committed as fail-closed empties and a DELETED one is behaviourally indistinguishable from a declared-empty one.** Known accepted gap | T2 |

---

## 7. `apps/control-plane` — 28 seams

### 7.1 Entry module `apps/control-plane/src/worker.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CP-E1 | `fetch: (request, env, ctx) => app.fetch(request, env, ctx),` | `MUT-1 /fetch: \(request, env, ctx\)/` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | T1 |
| CP-E2 | `scheduled: (controller, env, ctx) => scheduled(controller, env, ctx),` | `MUT-2 "const handler: ExportedHandler<Parameters<typeof scheduled>[1]> = {"→"…" then drop the `scheduled` key`; or revert the file to `export { default } from "./index.js";` | `grep -n 'scheduled:' src/worker.ts` → nothing | `test/worker-entry.test.ts` | T1 |

### 7.2 Composition root `apps/control-plane/src/index.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CP-C1 | `app.onError(controlPlaneErrorHandler);` | `MUT-1 /app\.onError\(controlPlaneErrorHandler\)/` | anchor gone | `test/crud.test.ts` (error envelope shape) | T2 |
| CP-C2 | `app.notFound(controlPlaneNotFoundHandler);` | `MUT-1 /app\.notFound\(controlPlaneNotFoundHandler\)/` | anchor gone | `test/wiring.test.ts` (404 control probe) | T2 |
| CP-C3 | `app.use("*", requestId);` | `MUT-1 /app\.use\("\*", requestId\)/` | anchor gone | `test/crud.test.ts` (`request_id` in envelope) | T2 |
| CP-C4 | `c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));` | `MUT-2 "{ requestId: c.get(\"requestId\") }"→"{}"` | `grep -n 'resolveDeps(c.env, {})' src/index.ts` | `test/d1-store.test.ts` (`audit_events.request_id`); full removal → `test/wiring.test.ts` | T1 |
| CP-C5 | `app.use("*", corsResponseHeaders);` | `MUT-1 /app\.use\("\*", corsResponseHeaders\)/` | anchor gone | `test/cors.test.ts` | T2 |
| CP-C6 | `app.use("*", adminCorsPreflight);` — must precede `contractAuth` | `MUT-1 /app\.use\("\*", adminCorsPreflight\)/` | anchor gone | `test/cors.test.ts` (OPTIONS not challenged) | T2 |
| CP-C7 | `app.use("*", contractAuth());` | `MUT-1 /app\.use\("\*", contractAuth\(\)\)/` | anchor gone | `test/auth.test.ts`; `test/rbac-d1.test.ts` | T1 |
| CP-C8 | `export const MOUNTED_ROUTES: readonly RegisteredRoute[] = registerRoutes(app);` | `MUT-2 "registerRoutes(app)"→"[]"` | `grep -n 'RegisteredRoute\[\] = \[\]' src/index.ts` | `test/wiring.test.ts` (asserts Hono's OWN `app.routes`) — **`test/contract.test.ts` alone stays GREEN, which is why `wiring.test.ts` exists** | T1 |
| CP-C9 | `app.get("/healthz", …)` and `app.get("/readyz", …)` | `MUT-1 /app\.get\("\/(healthz\|readyz)"/` | anchors gone | `test/health.test.ts` — **the hole that surfaced only on the first real `wrangler dev --local` boot** | T2 |
| CP-C10 | `export default withAliasCanonicalization(app);` | `MUT-2 "withAliasCanonicalization(app)"→"app"` | `grep -n 'export default app;' src/index.ts` | `test/alias.test.ts` (`/control/v1/*` → 404) | T2 |

### 7.3 Route registration `apps/control-plane/src/routes/index.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CP-R1 | `export const GROUP_MODULES: readonly GroupModule[] = [ …31 modules… ];` | `MUT-1 /^  adminApiKeyRoutes,$/` (drop any one entry) | `grep -n 'adminApiKeyRoutes,' src/routes/index.ts` → nothing | `test/contract.test.ts` + `test/wiring.test.ts`; `buildHandlerTable()` also throws `orphan group` at module load | T1 |
| CP-R2 | the `app.on(method, path, handler)` call inside `registerRoutes` | `MUT-2 "app.on("→"void ((…: never) => 0) && app.on("` — simplest: delete the `app.on(` statement line | `grep -n 'app.on(' src/routes/index.ts` → nothing | `test/wiring.test.ts` (`app.routes` empty) | T1 |

### 7.4 Adapters `apps/control-plane/src/adapters.ts` (`resolveDeps`, 737-760)

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CP-A1 | `const store = resolveStore(env, context);` → `D1ControlPlaneStore` | `MUT-2 "resolveStore(env, context)"→"resolveStore({} as never, context)"` | `grep -n '{} as never, context' src/adapters.ts` | `test/d1-store.test.ts`, `test/store-conformance.test.ts` | T1 |
| CP-A2 | `apiKeys: resolveApiKeys(env),` | `MUT-2 "resolveApiKeys(env)"→"resolveApiKeys({} as never)"` | mutated line present | `test/api-keys-d1.test.ts`, `test/auth.test.ts` | T1 |
| CP-A3 | `lifecycle: resolveLifecycle(env, store),` | `MUT-2 "resolveLifecycle(env, store)"→"resolveLifecycle({} as never, store)"` | mutated line present | `test/lifecycle-d1.test.ts` | T1 |
| CP-A4 | `rbac: resolveRbac(env),` | `MUT-2 "resolveRbac(env)"→"resolveRbac({} as never)"` | mutated line present | `test/rbac-d1.test.ts` | T1 |
| CP-A5 | `tenantDatabases: resolveTenantDatabases(env),` | `MUT-2 "resolveTenantDatabases(env),"→"undefined as never,"` | mutated line present | `test/tenant-db.test.ts`, `test/native-key-tenant-db.test.ts` | T1 |
| CP-A6 | `controlDatabase: resolveControlDatabase(env),` | `MUT-2 "resolveControlDatabase(env)"→"null"` | `grep -n 'controlDatabase: null' src/adapters.ts` | `test/billing-replay.test.ts`, `test/worker-registry.test.ts` | T1 |
| CP-A7 | `runtime: new StoreRuntimeStatus(store),` | `MUT-2 "new StoreRuntimeStatus(store)"→"{ report: async () => ({}) } as never"` | mutated line present | `test/runtime-status.test.ts` | T3 |
| CP-A8 | `txtResolver: resolveTxtResolver(env),` | `MUT-2 "resolveTxtResolver(env)"→"{ lookupTxt: async () => [] } as never"` | mutated line present | `test/site-domain-cas.test.ts`, `test/wiring.test.ts` | T2 |
| CP-A9 | `corsAllowedOrigin: corsAllowedOrigin === undefined \|\| corsAllowedOrigin === "" ? null : corsAllowedOrigin,` | `MUT-2 "? null : corsAllowedOrigin"→"? null : null"` | mutated line present | `test/cors.test.ts` | T2 |

### 7.5 Deploy config `apps/control-plane/wrangler.toml`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CP-T1 | `main = "src/worker.ts"` | `MUT-2 "src/worker.ts"→"src/index.ts"` | mutated line present | **DEPLOY-ONLY** — `wrangler dev --local` refuses (`MOUNTED_ROUTES` is an array); vitest does NOT | T1 |
| CP-T2 | `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_flags/` | anchor gone | whole suite | T1 |
| CP-T3 | `[[d1_databases]] binding = "DB"` + `migrations_dir = "../../sql/d1-ts/control"` | `MUT-4 [d1_databases]` | `grep -n 'binding = "DB"' wrangler.toml` → nothing | `test/d1.ts` setup; every D1 suite | T1 |
| CP-T4 | `[triggers]` / `crons = ["* * * * *"]` | `MUT-2 "[triggers]"→"[disabled_triggers]"` | mutated line present | `test/cron-trigger.test.ts` — **was GREEN across 428 tests before that gate** | T1 |
| CP-T5 | `[vars]` fail-closed empties (`CONTROL_PLANE_NATIVE_API_KEYS`, `CONTROL_PLANE_STATIC_API_KEYS`, `TENANCY_LIFECYCLE`, `TENANT_RBAC_ACTIONS`, `CONTROL_PLANE_SEED`) | `MUT-4 [vars]` | `grep -c '^CONTROL_PLANE_' wrangler.toml` → 0 | `test/auth.test.ts` partially. **No name-drift gate exists here** (the gateway has one; this app does not). Known gap | T2 |

---

## 8. `apps/mcp` — 25 seams

### 8.1 Entry module `apps/mcp/src/worker.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| MCP-E1 | `export { default } from "./index.js";` | `MUT-1 /export \{ default \} from "\.\/index\.js"/` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | T1 |
| MCP-E2 | `export { McpOauthFlowClaim } from "./oauth-flow.js";` | `MUT-1 /export \{ McpOauthFlowClaim \}/` | anchor gone | `test/oauth-flow-claim.test.ts` (namespace unreachable → workerd start error) | T1 |
| MCP-E3 | `export { FerroGateMcpSession } from "./session.js";` | `MUT-1 /export \{ FerroGateMcpSession \}/` | anchor gone | `test/durable-upstreams.test.ts` (the only file that touches `MCP_SESSION`). **`src/worker.ts`'s docblock cites `test/session.test.ts`, which DOES NOT EXIST in the repo — a stale citation; re-point it or add the file** | T1 |

### 8.2 Composition root `apps/mcp/src/index.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| MCP-C1 | `ingressRouteModule(),` in `MCP_ROUTE_MODULES` | `MUT-1 /^  ingressRouteModule\(\),$/` | anchor gone | `test/contract.test.ts` (`mcpJsonRpc`, `executeMcpTool` unreachable) | T1 |
| MCP-C2 | `identityRouteModule(),` | `MUT-1 /^  identityRouteModule\(\),$/` | anchor gone | `test/contract.test.ts`, `test/identity.test.ts` (4 identity ops) | T1 |
| MCP-C3 | `const { app, router } = createMcpApp({ modules: MCP_ROUTE_MODULES });` | `MUT-2 "{ modules: MCP_ROUTE_MODULES }"→"{}"` | `grep -n 'createMcpApp({})' src/index.ts` | `test/contract.test.ts` | T1 |

### 8.3 Route registration `apps/mcp/src/routes/index.ts` (`createMcpApp`)

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| MCP-R1 | `router.register("getHealthz", …)` / `router.register("getReadyz", …)` (207-208) | `MUT-1 /router\.register\("get(Healthz\|Readyz)"/` | anchors gone | `test/health.test.ts` | T2 |
| MCP-R2 | `module.register(router);` (222) | `MUT-1 /^    module\.register\(router\);$/` | anchor gone | `test/contract.test.ts` (all 6 owned ops vanish) | T1 |
| MCP-R3 | `app.notFound((c) => { … })` (225) | `MUT-1 /app\.notFound\(\(c\) => \{/` (then repair the block) — simplest: `MUT-2` the envelope code string | `grep -n 'not_found' src/routes/index.ts` | `test/contract.test.ts` (404 control probe) | T2 |
| MCP-R4 | `app.onError((error, c) => { … })` (230) | `MUT-2 "internal_error"→"MUTATED"` | `grep -n 'MUTATED' src/routes/index.ts` | **NO GATE — corrected wave 15.** The cell said `test/jsonrpc.test.ts`; the mutation is **GREEN** across all 359 mcp tests and `grep -rn internal_error apps/mcp/test` returns nothing. The 500 envelope code is asserted by nothing | T2 |

### 8.4 Ports `apps/mcp/src/ports.ts` (`resolvePorts`, 1716-1740)

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| MCP-P1 | `const auth = durableAuth(env);` → `new D1McpAuth(env.DB, …)` | `MUT-2 "if (env.DB === undefined) return new UnboundAuth();"→"return new UnboundAuth();"` | `grep -n 'return new UnboundAuth();' src/ports.ts` → 1 unconditional | `test/d1-auth.test.ts` | T1 |
| MCP-P2 | `const approvals = durableApprovals(env);` → `new D1ToolApprovals(env.DB)` | `MUT-2 "return new D1ToolApprovals(env.DB);"→"return new AutoApproval();"` | mutated line present | `test/approvals.test.ts` | T1 |
| MCP-P3 | `const secrets = secretResolverOverride ?? workerSecretResolver(env);` `??` | `MUT-2 "workerSecretResolver(env)"→"{ resolve: async () => undefined }"` | mutated line present | `test/secrets-mount.test.ts` (the file that exists BECAUSE this was the stub) | T1 |
| MCP-P4 | `const guardrails = deterministicManagedActionGuardrails(parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS));` | `MUT-2 "parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS)"→"{}"` | `grep -n 'ManagedActionGuardrails({})' src/ports.ts` | `test/guardrails.test.ts` | T2 |
| MCP-P5 | `credentials: new DurableCredentialStore(env.MCP_OAUTH_KV, env.DB, … DurableOauthFlowStore(env.MCP_OAUTH_FLOWS))` | `MUT-1 /credentials: new DurableCredentialStore\(/` (then repair) — or `MUT-2 "if (durableIdentityBound(env)) {"→"if (false) {"` | `grep -n 'if (false)' src/ports.ts` | `test/durable-identity.test.ts` | T1 |
| MCP-P6 | `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY) as IdentityCipherPort,` | `MUT-1 /cipher: identityCipherFrom\(/` (inside the same `if` block) | anchor gone | `test/durable-identity.test.ts` ("malformed key material fails CLOSED") | T1 |

### 8.5 Deploy config `apps/mcp/wrangler.toml` — **NO CONFIG GATE EXISTS IN THIS APP**

`apps/mcp/vitest.config.ts` sets `main: "./src/worker.ts"` EXPLICITLY, overriding
the toml, and binds no `TEST_WRANGLER_TOML`. Nothing in `apps/mcp/test/` reads the
committed file. Rows marked **DEPLOY-ONLY** below are therefore unproven locally.

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| MCP-T1 | `main = "src/worker.ts"` | `MUT-2 "src/worker.ts"→"src/index.ts"` | mutated line present | **DEPLOY-ONLY** (`e2e/` runs `wrangler dev` for mcp — that catches it) | T1 |
| MCP-T2 | `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_flags/` | anchor gone | whole suite | T1 |
| MCP-T3 | `[[kv_namespaces]] binding = "MCP_OAUTH_KV"` | `MUT-4 [kv_namespaces]` | `grep -n 'MCP_OAUTH_KV' wrangler.toml` → nothing | `test/durable-identity.test.ts` | T1 |
| MCP-T4 | `[[durable_objects.bindings]] name = "MCP_OAUTH_FLOWS"` | `MUT-3 «[[durable_objects.bindings]]\nname = "MCP_OAUTH_FLOWS"\nclass_name = "McpOauthFlowClaim"»` | anchor gone | `test/oauth-flow-claim.test.ts` | T1 |
| MCP-T5 | `[[durable_objects.bindings]] name = "MCP_SESSION"` | `MUT-3` the 3-line stanza | anchor gone | `test/durable-upstreams.test.ts` | T1 |
| MCP-T6 | `[[migrations]] tag = "v1"` / `new_sqlite_classes = ["McpOauthFlowClaim"]` | `MUT-1 /new_sqlite_classes = \["McpOauthFlowClaim"\]/` | anchor gone | **DEPLOY-ONLY — NO GATE.** vitest builds the namespace from the binding alone; Cloudflare rejects at deploy (`Cannot create binding for class … not currently defined`). Port `apps/gateway/test/wrangler-bindings.test.ts` here | T1 |
| MCP-T7 | `[[migrations]] tag = "v2"` / `new_sqlite_classes = ["FerroGateMcpSession"]` | `MUT-1 /new_sqlite_classes = \["FerroGateMcpSession"\]/` | anchor gone | **DEPLOY-ONLY — NO GATE** (as MCP-T6) | T1 |
| MCP-T8 | `[[d1_databases]] binding = "DB"` (no `migrations_dir` — deliberate? unverified) | `MUT-4 [d1_databases]` | anchor gone | `test/d1-auth.test.ts`, `test/approvals.test.ts` | T1 |
| MCP-T9 | `[vars] FG_DEV_IN_MEMORY_PORTS = "1"` — **a dev flag COMMITTED to the deploy config** | `MUT-2 "FG_DEV_IN_MEMORY_PORTS = \"1\""→"FG_DEV_IN_MEMORY_PORTS = \"0\""` | mutated line present | `test/fixtures.ts`-seeded suites go red. **`docs/rewrite/CLOUD-VERIFICATION.md` §B1 requires overriding this to `"0"` for the live deploy — a deploy that inherits `"1"` runs the in-memory port bundle in production** | T1 |
| MCP-T10 | the COMMENTED cross-script counter stanza: `#   name = "RATE_LIMIT"` / `#   class_name = "RateLimiterDurableObject"` / `#   script_name = "ferrogate-gateway"` (wave 16) | `MUT-1 /#   script_name = "ferrogate-gateway"/` | `grep -n 'script_name' wrangler.toml` → nothing | `test/env-var-drift.test.ts` §"keeps RATE_LIMIT commented, CROSS-SCRIPT, and claimed by no migration". **The BINDING itself is DEPLOY-ONLY and cannot be otherwise** — workerd refuses to start with an unresolvable `script_name` (`binding "RATE_LIMIT" refers to a service "core:user:ferrogate-gateway", but no such service is defined`), so uncommenting it takes the suite to 0 collected tests and `wrangler dev --local` to no boot. What IS gated locally is the three ways the stanza can rot: uncommented, `script_name` dropped (⇒ a SECOND private counter namespace and double the RPM allowance), or a `new_sqlite_classes` added here for a class this script does not export | T1 |

---

## 9. `apps/agent-runtime` — 29 seams

### 9.1 Entry module `apps/agent-runtime/src/worker.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| AR-E1 | `export { default } from "./index.js";` | `MUT-1 /export \{ default \} from "\.\/index\.js"/` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | T1 |
| AR-E2 | `export { AgentRunState } from "./runs/do.js";` | `MUT-1 /export \{ AgentRunState \} from "\.\/runs\/do\.js"/` | `grep -c 'AgentRunState' src/worker.ts` → 0 | `test/lifecycle.test.ts`, `test/sse.test.ts` | T1 |
| AR-E3 | `export { WorkerPlane } from "./workers/plane.js";` | `MUT-1 /export \{ WorkerPlane \} from "\.\/workers\/plane\.js"/` | `grep -c 'WorkerPlane' src/worker.ts` → 0 | `test/internal-auth.test.ts`, `test/cancel.test.ts` | T1 |

### 9.2 Composition root `apps/agent-runtime/src/index.ts`

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| AR-C1 | `app.onError(errorHandler);` (32) | `MUT-1 /app\.onError\(errorHandler\)/` | anchor gone | `test/contract.test.ts` (error envelope) | T2 |
| AR-C2 | `app.notFound(notFoundHandler);` (33) | `MUT-1 /app\.notFound\(notFoundHandler\)/` | anchor gone | **NO GATE — corrected wave 15.** **GREEN** across 325+43 tests. `contract.test.ts`'s 404 control probes never reach Hono's notFound: `src/middleware/auth.ts:574,585` throws the identical `404 not_found` for an undocumented path inside an owned prefix, so this line only fires OUTSIDE `/v1/*` — which nothing tests | T2 |
| AR-C3 | `app.use("*", correlation);` (34) | `MUT-1 /app\.use\("\*", correlation\)/` | anchor gone | `test/contract.test.ts` (`x-request-id`) | T2 |
| AR-C4 | `app.use("/v1/*", contractAuth);` (50) | `MUT-1 /app\.use\("\/v1\/\*", contractAuth\)/` | anchor gone | `test/isolation.test.ts`, `test/internal-auth.test.ts` (tenant-vs-worker credential split) | T1 |
| AR-C5 | `app.route("/", runRoutes);` (52) | `MUT-1 /app\.route\("\/", runRoutes\)/` | anchor gone | `test/lifecycle.test.ts`, `test/contract.test.ts` | T2 |
| AR-C6 | `app.route("/", agentRoutes);` (53) | `MUT-1 /app\.route\("\/", agentRoutes\)/` | anchor gone | `test/agents.test.ts`, `test/contract.test.ts` | T2 |
| AR-C7 | `app.route("/", workerRoutes);` (54) — the six `auth.kind: "internal"` callbacks | `MUT-1 /app\.route\("\/", workerRoutes\)/` | anchor gone | `test/internal-auth.test.ts`, `test/isolation-grant.test.ts` | T1 |
| AR-C8 | `app.get("/healthz", …)` / `app.get("/readyz", …)` (37-38) | `MUT-1 /app\.get\("\/(healthz\|readyz)"/` | anchors gone | `test/health.test.ts` | T2 |
| AR-C9 | `export { AgentRunState } … / export { WorkerPlane } …` in **index.ts** (duplicates AR-E2/E3) | `MUT-1` both lines | anchors gone | none — redundant with `src/worker.ts`; kept because `vitest.config.ts` can point `main` at either | T3 |

### 9.3 Ports `apps/agent-runtime/src/ports.ts` (`resolveDeps`, 1018-1062)

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| AR-P1 | `env.DB !== undefined ? d1ApiKeyPort(env.DB) :` — **ESCALATION (§5)** | `MUT-2 "env.DB !== undefined\n      ? d1ApiKeyPort(env.DB)\n      : dev"→"dev"` (any edit that removes the D1 leg) | `grep -n 'd1ApiKeyPort' src/ports.ts` → import only | `test/durable/mount.spec.ts` — **only under `bun run test`; the app's own 259-test main project stays GREEN** | T1 |
| AR-P2 | `env.CONTROL_DB !== undefined ? d1WorkerIdentityPort(env.CONTROL_DB) :` — **ESCALATION (§5)** | as AR-P1 | `grep -n 'd1WorkerIdentityPort' src/ports.ts` → import only | `test/durable/mount.spec.ts` — escalation-only | T1 |
| AR-P3 | `if (apiKeys === undefined \|\| workerIdentities === undefined) return undefined;` — the FAIL-CLOSED gate | `MUT-1 /if \(apiKeys === undefined/` | anchor gone | `test/contract.test.ts` (dev flag unset + no D1 ⇒ 503 `agent_runtime_unavailable`) | T1 |
| AR-P4 | `governance: inMemoryGovernancePort({ governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS) }),` | `MUT-2 "parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS)"→"[]"` — **corrected in wave 14. The recipe here was `→ ["*"]`, which is a NO-OP:** egress is matched with `allowedHosts.has(host)`, exact membership, so `"*"` is a wildcard for `grantableCapabilities` but a literal hostname for egress | mutated line present | `test/governance-mount.test.ts` (wave 14). **NOT `test/isolation-grant.test.ts`** — that file builds the port by hand and never calls `resolveDeps`; see §15.1 | T1 |
| AR-P5 | `upstreams: inMemoryAgentUpstreamPort(parseJsonVar(env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined), []))` `??` | `MUT-2 "env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined)"→"env.AGENT_UPSTREAMS"` | mutated line present | `test/agents.test.ts` (14 A2A dispatch cases) | T2 |
| AR-P6 | `guardrails: deterministicGuardrailPort(parseJsonVar(env.FG_DEV_A2A_GUARDRAILS, {})),` | `MUT-2 "env.FG_DEV_A2A_GUARDRAILS"→"undefined"` | mutated line present | `test/guardrails.test.ts` | T2 |
| AR-P7 | `config: inMemoryConfigPort(configFromEnv(env)),` | `MUT-2 "configFromEnv(env)"→"configFromEnv({} as never)"` | mutated line present | `test/budget.test.ts` (`AGENT_JOB_MAX_OPEN_PER_TENANT`, `…_DISPATCH_TTL_SECS`) | T2 |

### 9.4 Deploy config `apps/agent-runtime/wrangler.toml` — **NO CONFIG GATE EXISTS IN THIS APP**

`vitest.config.ts` sets `main: "./src/worker.ts"` explicitly and binds no
`TEST_WRANGLER_TOML`; nothing in `apps/agent-runtime/test/` reads the committed
file. This app is also **not covered by `e2e/`** (only gateway + mcp are), so
DEPLOY-ONLY here means *no local proof channel at all*.

| ID | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| AR-T1 | `main = "src/worker.ts"` | `MUT-2 "src/worker.ts"→"src/index.ts"` | mutated line present | **DEPLOY-ONLY, NO E2E** — `bunx wrangler dev --local` boot is the only proof | T1 |
| AR-T2 | `compatibility_date = "2025-11-17"` + `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_(date\|flags)/` | anchors gone | whole suite | T1 |
| AR-T3 | `[[durable_objects.bindings]] name = "AGENT_RUN_STATE"` | `MUT-3 «[[durable_objects.bindings]]\nname = "AGENT_RUN_STATE"\nclass_name = "AgentRunState"»` | anchor gone | `test/lifecycle.test.ts`, `test/sse.test.ts` | T1 |
| AR-T4 | `[[durable_objects.bindings]] name = "WORKER_PLANE"` | `MUT-3` the 3-line stanza | anchor gone | `test/internal-auth.test.ts`, `test/cancel.test.ts` | T1 |
| AR-T5 | `new_sqlite_classes = ["AgentRunState", "WorkerPlane"]` | `MUT-1 /new_sqlite_classes = \["AgentRunState", "WorkerPlane"\]/` | anchor gone | **DEPLOY-ONLY — NO GATE.** Both classes lose their SQLite backend / are rejected at deploy. Port `wrangler-bindings.test.ts` here | T1 |
| AR-T6 | `[vars] FG_DEV_IN_MEMORY_PORTS = "1"` — dev flag committed to the deploy config | `MUT-2 "FG_DEV_IN_MEMORY_PORTS = \"1\""→"…= \"0\""` | mutated line present | main project goes red (fixtures unseeded). **CLOUD-VERIFICATION §B1 requires `"0"` at deploy** | T1 |
| AR-T7 | `[vars] FG_REQUIRE_PRODUCTION_MTLS = "0"` | `MUT-2 "\"0\""→"\"1\""` on that line | mutated line present | `test/mtls.test.ts`. **Committed OFF — must be `"1"` in production** | T1 |
| AR-T8 | `[vars] CONTAINER_GOVERNED_EGRESS_HOSTS = ""` (sealed by default, #471) | `MUT-2 "CONTAINER_GOVERNED_EGRESS_HOSTS = \"\""→"…= \"*\""` | mutated line present | `test/isolation-grant.test.ts` | T1 |
| AR-T9 | `[vars] AGENT_RUNTIME_ENABLED`, `AGENT_JOB_MAX_OPEN_PER_TENANT`, `AGENT_JOB_DISPATCH_TTL_SECS`, `FG_DEV_A2A_GUARDRAILS` | `MUT-1 /^AGENT_(RUNTIME_ENABLED\|JOB_)/` | anchors gone | `test/budget.test.ts` (limits fall back to defaults — **weak: absent ≈ default, so drift is invisible; no name-drift gate**) | T2 |
| AR-T10 | the COMMENTED cross-script counter stanza: `#   name = "RATE_LIMIT"` / `#   class_name = "RateLimiterDurableObject"` / `#   script_name = "ferrogate-gateway"` (wave 16) | `MUT-1 /#   script_name = "ferrogate-gateway"/` | `grep -n 'script_name' wrangler.toml` → nothing | `test/env-var-drift.test.ts` §"keeps RATE_LIMIT commented, CROSS-SCRIPT, and claimed by no migration" — same three rot-directions and the same DEPLOY-ONLY reason as MCP-T10. A `RateLimiterDurableObject` defined in THIS Worker instead would compile, deploy and pass every test while handing `/v1/agent-jobs` its own full RPM quota, which is a quieter version of the admission bypass wave 16 closed | T1 |

---

## 10. `apps/telemetry` — 14 seams

| ID | File | Seam | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|---|
| TEL-E1 | `src/worker.ts` | `export { default } from "./index.js";` | `MUT-1 /export \{ default \}/` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | T1 |
| TEL-C1 | `src/index.ts` | `const app = createTelemetryApp(); export default app;` | `MUT-2 "createTelemetryApp()"→"new (await import(\"hono\")).Hono()"` — simplest: `MUT-2 "export default app;"→""` | `grep -n 'export default app;' src/index.ts` → nothing | `test/routes.test.ts` (drives the DEFAULT EXPORT) | T1 |
| TEL-A1 | `src/app.ts` | `app.get("/healthz", …)` | `MUT-1 /app\.get\("\/healthz"/` | anchor gone | `test/routes.test.ts`, `test/health.test.ts` | T2 |
| TEL-A2 | `src/app.ts` | `app.get("/readyz", …)` returning **503 when the sink is unconfigured** | `MUT-2 "configured ? 200 : 503"→"200"` | mutated line present | `test/health.test.ts` | T2 |
| TEL-A3 | `src/app.ts` | `for (const [path, signal] of Object.entries(OTLP_ROUTES)) { app.post(path, …) }` | `MUT-1 /^    app\.post\(path, async \(c\) => \{$/` (or empty `OTLP_ROUTES`) | `grep -n 'app.post(path' src/app.ts` → nothing | `test/routes.test.ts`, `test/ingest.test.ts` | T1 |
| TEL-A4 | `src/app.ts` | `const denial = requireBearer(c.req.raw, c.env?.COLLECTOR_TOKEN); if (denial) return denial;` | `MUT-1 /if \(denial\) return denial;/` | anchor gone | `test/ingest.test.ts` (anonymous ingest must be refused) | T1 |
| TEL-A5 | `src/app.ts` | `app.all(path, () => … 405 …)` | `MUT-1 /^    app\.all\(path,/` | anchor gone | `test/routes.test.ts` (GET on an OTLP path ⇒ 405 not 404) | T3 |
| TEL-A6 | `src/app.ts` | `app.notFound((c) => json(errorBody(TelemetryErrorCode.NotFound, …), 404))` | `MUT-1 /app\.notFound\(\(c\) =>/` (repair block) | `grep -n 'notFound' src/app.ts` → nothing | `test/routes.test.ts` | T3 |
| TEL-P1 | `src/ports.ts` | `resolveSink(env)` → `new AnalyticsEngineSink(dataset)` | `MUT-2 "return new AnalyticsEngineSink(dataset);"→"return null;"` | mutated line present | `test/ingest.test.ts`, `test/health.test.ts` (readyz flips to 503) | T1 |
| TEL-T1 | `wrangler.toml` | `main = "src/worker.ts"` | `MUT-2 "src/worker.ts"→"src/index.ts"` | mutated line present | **DEPLOY-ONLY, NO E2E** — `vitest.config.ts` overrides `main`, and telemetry is not in `e2e/`. `wrangler dev --local` is the only proof | T1 |
| TEL-T2 | `wrangler.toml` | `[[analytics_engine_datasets]] binding = "TELEMETRY"` | `MUT-4 [analytics_engine_datasets]` | `grep -n 'TELEMETRY' wrangler.toml` → nothing | `test/ingest.test.ts` (503 `telemetry_sink_unavailable`) | T1 |
| TEL-T3 | `wrangler.toml` | `[vars] MAX_BODY_BYTES = "4194304"` | `MUT-1 /^MAX_BODY_BYTES/` | anchor gone | weak — `vitest.config.ts` overrides it with `"2048"`, so the committed value is **not** exercised. **No gate; drift is invisible** | T2 |
| TEL-T4 | `wrangler.toml` | `[observability]` / `[observability.logs]` / `[observability.traces]` | `MUT-4 [observability]` | anchors gone | none — Workers Logs config, no local effect | T3 |
| TEL-T5 | `wrangler.toml` | `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_flags/` | anchor gone | whole suite | T1 |

---

## 11. `apps/cli` — 8 seams (a Bun binary, not a Worker)

All eight live in `createDefaultRuntime()` in `apps/cli/src/index.ts`. Every one
of them can be swapped for a legitimate TEST double (`createTestRuntime`,
`createInMemory*`, `createStructuralConfigValidator`, `createMemoryContextStorage`)
without breaking a compile — which is exactly why each needs a gate that only the
PRODUCTION implementation can pass. Before wave 13 only `client` had one.

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Tier |
|---|---|---|---|---|---|
| CLI-1 | `const io = createNodeIo();` | `MUT-2 "createNodeIo()"→"createInMemoryIo({})"` | `grep -n 'createInMemoryIo' src/index.ts` | `test/composition-root.test.ts` — "io.env IS process.env" (identity), real `readFile`, real CSPRNG, wall clock | T1 |
| CLI-2 | `client: createFetchControlPlaneClient(fetch, transport),` | `MUT-2 "createFetchControlPlaneClient(fetch, transport)"→"createInMemoryControlPlaneClient()"` | mutated line present | `test/transport.test.ts` — "the shipped runtime wires the real transports" | T1 |
| CLI-3 | `gatewayClient: createFetchGatewayClient(fetch, transport),` | `MUT-2 "createFetchGatewayClient(fetch, transport)"→"createInMemoryGatewayClient()"` | mutated line present | `test/composition-root.test.ts` — "a legacy `assets` verb reaches fetch, not the in-memory fake" | T2 |
| CLI-4 | `contextStorage: createFileContextStorage(io),` | `MUT-2 "createFileContextStorage(io)"→"createMemoryContextStorage()"` | mutated line present | `test/composition-root.test.ts` — `contextStorage.path()` must be `$FERROGATE_CLI_HOME/contexts.toml`, resolved through the runtime's OWN `io.env` | T2 |
| CLI-5 | `configValidator: createFerrogateConfigValidator(),` | `MUT-2 "createFerrogateConfigValidator()"→"createStructuralConfigValidator()"` | mutated line present | `test/composition-root.test.ts` — "rejects a document the structural validator would ACCEPT" (+ accepts a real Caddyfile, so the refusal is not blanket) | T2 |
| CLI-6 | `keyHasher: createNodeKeyHasher(),` | `MUT-2 "createNodeKeyHasher()"→"{ hash: async () => \"0\".repeat(128) }"` | mutated line present | `test/composition-root.test.ts` — "hash() reproduces the gateway's stored BLAKE2b-512 construction" | T1 |
| CLI-7 | `const transport = { readFile: (path: string) => io.readFile(path) };` — the `--ca-bundle` TLS seam shared by both clients | `MUT-2 "{ readFile: (path: string) => io.readFile(path) }"→"{ readFile: async () => \"\" }"` | mutated line present | **NO GATE — corrected wave 15.** **GREEN** across all 339 cli tests. `test/transport.test.ts:360,367` hands `createFetchControlPlaneClient` a transport it builds ITSELF and never calls `createDefaultRuntime()`, so the composition root's CA-bundle wiring is untested — the same factory-vs-mount confusion that made GW-A1 a fake mount | T2 |
| CLI-8 | `if (entry !== undefined && (entry.endsWith("/index.ts") \|\| entry.endsWith("/ferrogate"))) { process.exit(await main(…)); }` | `MUT-2 "entry.endsWith(\"/ferrogate\")"→"false"` | mutated line present | **NO GATE** — the compiled-binary entry guard is not exercised by vitest (which imports `main` directly). Proof channel: `bun run build && ./dist/ferrogate --version`. Known gap | T2 |

---

## 12. Counts

### By app

| App | Seams | T1 | T2 | T3 |
|---|---:|---:|---:|---:|
| `apps/gateway` | 53 | 38 | 13 | 2 |
| `apps/control-plane` | 28 | 17 | 10 | 1 |
| `apps/mcp` | 25 | 21 | 4 | 0 |
| `apps/agent-runtime` | 28 | 17 | 10 | 1 |
| `apps/telemetry` | 14 | 8 | 3 | 3 |
| `apps/cli` | 8 | 3 | 5 | 0 |
| **Total** | **156** | **104** | **45** | **7** |

Under the §4 policy an incremental wave re-proves **104 T1 seams** plus whatever
its own diff touched, instead of all 156.

### By proof channel

| Channel | Seams |
|---|---|
| RED under the app's default vitest project | 144 |
| RED **only** under the full `bun run test` (escalation, §5) | 3 — GW-C8, AR-P1, AR-P2 |
| **DEPLOY-ONLY** — `wrangler dev` / `e2e/` only, invisible to vitest | 5 — GW-T1, CP-T1, MCP-T1, AR-T1, TEL-T1 |
| **NO GATE AT ALL** — no local proof channel exists today | 4 — MCP-T6, MCP-T7, AR-T5, CLI-8 |
| Deliberately weak / drift-only gates | 5 — GW-T17, GW-T18, CP-T5, AR-T9, TEL-T3 |

---

## 13. Reconciliation against last wave's 75, and what is new

**The prior table's seam NAMES are not recoverable.** Wave 13's commit message
records "75 seams … the wave-12 table of 46 … plus 29 not previously in it" and
names exactly ONE id (`G14` = `gatewayScheduled`'s body, here **GW-C10**). No
file, branch or commit in this repository contains the wave-12 or wave-13 seam
list. That is the whole reason this file exists, and it means an exact row-by-row
diff against the 75 is impossible — only a category-level reconciliation is
honest.

**Category reconciliation.** Wave 13's 29 additions were described as: the CLI
runtime's six ports (**CLI-1…CLI-6**), the telemetry app factory (**TEL-A1…TEL-A6**,
**TEL-C1**, **TEL-P1**), the four non-gateway Workers' `wrangler.toml` binding sets
(**CP-T1…T5**, **MCP-T1…T9**, **AR-T1…T9**, **TEL-T1…T5**), and wave 13's own new
seam (**GW-T16**). All of those are present and accounted for below.

This table has **156 rows against last wave's 75**, because it decomposes each
`wrangler.toml` stanza, each `resolveDeps`/`resolvePorts` port slot and each
`app.use`/`app.on` line into an INDIVIDUALLY mutatable row rather than grouping
them. Most of the extra 81 rows are that finer granularity, not newly-discovered
behaviour. The following, however, are seams I could find **no evidence had ever
been enumerated or proven** — each is either a distinct mount line no prior
category covers, or a line with no gate at all:

1. **GW-R1 … GW-R11** — the eleven mount lines *inside* `createGatewayApp`
   (`onError`, `notFound`, `requestId`, the pre-auth `networkAccess`, `contractAuth`,
   the caller-middleware loop, `responseCache`, the two health registrations,
   `registerToolingRoutes`, the module loop, and the `reverseProxy` fall-through).
   Prior waves proved the ARRAYS in `src/index.ts`; the lines that consume them
   were never rows.
2. **CP-A1 … CP-A9** — the nine port slots of `resolveDeps`. Only the store had
   ever been discussed by name.
3. **CP-C4** — the `c.set("deps", resolveDeps(…, { requestId }))` middleware, and
   specifically the `requestId` argument that stamps `audit_events`.
4. **CP-R2** — the `app.on(...)` call inside `registerRoutes` (distinct from
   CP-C8, the `registerRoutes(app)` call site).
5. **MCP-R1 … MCP-R4** — the four mount lines inside `createMcpApp`.
6. **MCP-P4** — the guardrail port slot in `resolvePorts` (P1/P2/P3/P5/P6 have
   named gates; P4 did not appear in any prior narrative).
7. **AR-C1 … AR-C9** — the nine mount lines of the agent-runtime composition
   root, including **AR-C9**, a genuinely REDUNDANT duplicate of AR-E2/AR-E3.
8. **AR-P3 … AR-P7** — the fail-closed gate and the four non-credential port
   slots.
9. **CLI-7** and **CLI-8** — the shared `transport` TLS seam and the compiled
   binary's process-entry guard. Wave 13 enumerated six CLI ports; these are the
   seventh and eighth lines in the same function, and **CLI-8 has no gate**.
10. **GW-A8** — `await serviceFor(context).flushAudit()`. Named as a mutation in
    `test/assets/wiring.test.ts`'s docblock but never as a standalone seam row.
11. **GW-T18** — the 47 `[vars]` entries with no name-drift gate.
12. **TEL-A4** — `requireBearer(...)` on the OTLP ingest path. An auth seam in an
    app whose seams were previously summarised as "the telemetry app factory".

### Three findings this derivation surfaced (not seams — defects in the seam net)

- **`apps/mcp` and `apps/agent-runtime` have NO committed-`wrangler.toml` gate.**
  Both `vitest.config.ts` files set `main` explicitly (overriding the toml) and
  bind no `TEST_WRANGLER_TOML`. Their `[[migrations]] new_sqlite_classes` lines
  (**MCP-T6, MCP-T7, AR-T5**) are therefore in exactly the state
  `apps/gateway/test/wrangler-bindings.test.ts` was written to end: mutating them
  leaves every test green and breaks `wrangler deploy`. Porting that gate to both
  apps is the single highest-value follow-up in this file.
- **`apps/mcp/src/worker.ts` cites `test/session.test.ts`, which does not exist.**
  The `FerroGateMcpSession` re-export (**MCP-E3**) is gated only incidentally, by
  `test/durable-upstreams.test.ts`.
- **Two committed dev flags ship in deploy configs** (**MCP-T9**, **AR-T6**:
  `FG_DEV_IN_MEMORY_PORTS = "1"`) plus **AR-T7** (`FG_REQUIRE_PRODUCTION_MTLS = "0"`).
  `CLOUD-VERIFICATION.md` §B1 covers the first two by procedure; nothing
  mechanical stops a deploy inheriting any of the three.

---

## 14. Maintenance rules for this file

1. **Adding a mount = adding a row here, in the same slice.** A mount with no row
   is a mount nobody will re-prove.
2. Record the mutation VERBATIM, including the observed RED message, in the
   slice's report — not just "went red".
3. Never delete a row because its seam looks obvious. Ten obvious mounts were
   already dead.
4. If a seam genuinely cannot be gated locally, keep the row and mark it
   **DEPLOY-ONLY** or **NO GATE** with the reason. Closing five honestly beats
   "closing" thirty by deletion.

---

## 15. Wave-14 incremental re-proof — results, corrections and new rows

The first wave to run the §4 policy instead of the full pass. **83 seams were
re-proved by mutation** (every T1 row with a local proof channel, plus every row
whose file the wave touched); the untouched T2/T3 rows were skipped by design.
Wall clock for the sweep was minutes rather than the wave-13 hours, and it still
found four defects in the seam net. Every result below was produced by the §2
protocol with the CONFIRM grep read back off disk, and every file was restored
and `sha256sum -c`-verified byte-identical.

### 15.1 Four seams came back GREEN — and what each one turned out to be

Not every GREEN is a fake mount, and saying which is which is the whole value of
the exercise.

| ID | Verdict | What it actually was |
|---|---|---|
| **GW-A1** | **FAKE MOUNT — real defect, now closed** | Replacing `apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured` with a bare `configured` — unwiring D1 from the gateway's entire credential path — left all 43 tests in `test/keys/resolver.test.ts` GREEN, and the rest of the suite with it. That file tests the FACTORY (`d1ApiKeyResolverFromEnv({ DB: db })` returns a working resolver) and never asserted that `depsFromEnv` calls it. A T1 auth seam with no gate. **Closed**: `describe("depsFromEnv — the gateway's credential path is wired to D1")` authenticates a secret that exists ONLY as a D1 row and asserts `source === "durable_native"`, which nothing but the real wiring can produce, plus a second case proving the `??` fallback still reaches the operator tables. Mutation now RED. |
| **AR-P4** | **NO GATE (real) + a WRONG RECIPE in this file** | Two separate faults. (1) The recipe recorded here — replace `parseGovernedEgressHosts(...)` with `["*"]` — is a **no-op**: `inMemoryGovernancePort` matches egress with `allowedHosts.has(host)`, an exact set membership test, so `"*"` is a wildcard for `grantableCapabilities` but a literal hostname for egress. The corrected recipe is `→ []`. (2) Under the corrected recipe the seam was still ungated: `test/isolation-grant.test.ts` builds `inMemoryGovernancePort({...})` by hand eleven times and never calls `resolveDeps`, so the sealed-by-default guarantee (#471) was proven for the POLICY and not for the MOUNT. **Closed**: `test/governance-mount.test.ts`. Mutation now RED. |
| **MCP-P6** | **NOT a fake mount — this file's expectation was wrong** | Deleting `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY)` from the durable-identity branch leaves `test/durable-identity.test.ts` green because the BASE port bundle already sets `cipher: webCryptoIdentityCipher()` (`src/ports.ts:1404`). The mutation therefore does not remove a capability, it swaps one working cipher for another. The seam is **weakly gated, not dead**; proving it needs an assertion that the cipher is KEYED from `FERROGATE_MCP_IDENTITY_KEY`. Left open and re-tiered here rather than papered over. |
| **AR-T5 / MCP-T6 / MCP-T7** | **NO GATE, exactly as §13 predicted — now closed** | Confirmed green under mutation. See §15.2. |

### 15.2 The §13 "highest-value follow-up" is done

`apps/mcp` and `apps/agent-runtime` now have committed-`wrangler.toml` gates:
`vitest.config.ts` in each binds `TEST_WRANGLER_TOML`, and each app has a
`test/wrangler-bindings.test.ts` ported from the gateway's. Consequences:

- **MCP-T6, MCP-T7, AR-T5** are no longer NO-GATE. All three go RED on deletion,
  **and also on substituting `new_classes` for `new_sqlite_classes`** — the
  variant that deploys successfully and silently gives the class the key-value
  backend. That substitution was proved RED explicitly (rows `AR-T5b`, `MCP-T7b`).
- **MCP-T1 and AR-T1** are no longer DEPLOY-ONLY: `main = "src/worker.ts"` is now
  asserted textually, so pointing `main` at the composition root fails locally
  instead of at `wrangler dev`. That leaves **3** DEPLOY-ONLY rows, not 5.
- **AR-T6, AR-T7, AR-T8** gained drift-only gates (see §15.3 for why nothing
  stronger is possible).

### 15.3 `compatibility_flags` and the pinned-binding vars: corrected expectations

| Rows | This file said | The sweep found |
|---|---|---|
| **GW-T2, CP-T2, MCP-T2, TEL-T5** (`compatibility_flags = ["nodejs_compat"]`) | "whole suite" goes RED | **GREEN in all four apps**, including under the app's FULL `bun run test`. Nothing in the TypeScript tree imports a `node:` builtin on a path the suites reach, so the flag is not load-bearing locally. These are **DEPLOY-ONLY**, not behavioural. (`AR-T2` is the exception and genuinely goes RED, because its recipe also deletes `compatibility_date`.) |
| **AR-T6, AR-T7, AR-T8** | named behavioural gates | **GREEN.** `apps/agent-runtime/vitest.config.ts` pins `FG_DEV_IN_MEMORY_PORTS`, `FG_REQUIRE_PRODUCTION_MTLS` and `CONTAINER_GOVERNED_EGRESS_HOSTS` as explicit miniflare bindings, which win over the toml — so the COMMITTED value is never exercised. §9.4's header ("NO CONFIG GATE EXISTS IN THIS APP") was right and the rows' *Expected RED* column was wrong. Pinning is the correct call for hermetic tests, so these can only ever be **drift gates**; they now have them. |
| **GW-T18** | "partial: `test/auth.test.ts`, `test/contract.test.ts`, `test/cache/config.test.ts`" | **GREEN** across all three. Commenting out the whole `[vars]` table changes nothing those files can see, because `vitest.config.ts` re-supplies the vars that matter as explicit bindings. The gap is **wider than recorded**: not "5 of 49 vars have a drift gate", but "the other 44 have no gate of any kind, behavioural or drift". Still accepted, now accurately. |

### 15.4 New rows (wave 14)

| ID | File | Seam | Mutation | Expected RED | Tier |
|---|---|---|---|---|---|
| **GW-TS** | `apps/gateway/wrangler.toml` | `GATEWAY_CACHE_SEMANTIC_THRESHOLD = "0.92"` — declared by the integrate step; `src/cache/config.ts` read it while the deploy config named only its seven siblings | `MUT-1 /^GATEWAY_CACHE_SEMANTIC_THRESHOLD/` | `test/wrangler-bindings.test.ts` §"the response-cache [vars] src/cache/config.ts reads" — a NAME-DRIFT gate. The committed value is the code's own fallback, deliberately, so no behavioural gate is possible | T3 |
| **AR-G1** | `apps/agent-runtime/src/ports.ts` | `governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS)` — the mount half of AR-P4 | `MUT-2 "parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS)"→"[]"` | `test/governance-mount.test.ts` | T1 |
| **GW-A1b** | `apps/gateway/src/adapters.ts` | the behavioural half of GW-A1 | as GW-A1 | `test/keys/resolver.test.ts` §"depsFromEnv — the gateway's credential path is wired to D1" | T1 |
| **MCP-W1** | `apps/mcp/vitest.config.ts` | `TEST_WRANGLER_TOML: WRANGLER_TOML` — without it the whole config gate throws | remove the binding | `test/wrangler-bindings.test.ts` (explicit "not bound" error) | T1 |
| **AR-W1** | `apps/agent-runtime/vitest.config.ts` | as MCP-W1 | remove the binding | `test/wrangler-bindings.test.ts` | T1 |

### 15.5 What wave 14 SKIPPED, and the risk that carries

Every T2/T3 row in a file the wave did not touch was skipped: the §6.3 route rows
other than GW-R4/R5/R6/R7/R10, GW-C11, GW-R1/R2/R3/R8/R9/R11, CP-C1/C2/C3/C5/C6,
CP-A7/A8/A9, MCP-R1/R3/R4, MCP-P4, AR-C1/C2/C3/C5/C6/C8/C9, AR-P5/P6/P7,
TEL-A1/A2/A5/A6, TEL-T3/T4, CLI-3/4/5/7, GW-T17. Their last proof is wave 13's.

That is the trade §4 describes and it is not free: **a shared refactor that moves
a mount without touching the row's file is invisible to an incremental wave.**
The two mandatory full-pass triggers in §4 are unchanged, and after wave 14's
findings a third is worth stating — **run the full pass whenever a `vitest.config.ts`
changes**, because a pinned binding is exactly what turned three T1 config rows
into no-ops without anyone editing the rows' file.

---

## 16. Wave-15 FULL PASS — the §4 mandatory pass, executed

§4 names two triggers for a FULL pass over every row: before the single
authorised live `wrangler deploy`, and **before deleting the Rust tree**. Wave 15
is that gate, so the incremental policy of §4/§15 was suspended and **every row
was re-proved by mutation**.

### 16.1 Protocol and totals

Run with the §2 protocol, mechanised: `cp` → `sha256sum` → mutate → **CONFIRM
grep read back OFF DISK** → `bun run test` in the app dir → restore →
`sha256sum -c`. A run whose CONFIRM grep did not fire was recorded as
`CONFIRM-FAIL` and never counted as a proof; zero occurred in the final pass
(five recipe defects were caught and repaired during a dry pass first — see
16.4). Two extra guards were added on top of §2 because of the wave-14 lesson
that a *semantically inert* mutation looks exactly like a proven seam:

1. **Marker uniqueness.** Every `MUT-2` replacement carries a `/*MUT*/` token,
   and the driver refuses to run a row whose replacement text ALREADY exists in
   the pristine file — otherwise "the new text is present" confirms nothing.
2. **Behaviour, not bytes.** Recipes that would only have produced a *syntax
   error* (an orphaned block) were rewritten as `if (false as boolean) …`
   guards, so the mutated tree still compiles and the RED is an assertion
   failure rather than a parse failure. Every GREEN was then hand-checked to
   confirm the mutation really did change behaviour (16.3).

| Measure | Result |
|---|---|
| Inventory rows re-proved | **161 / 161** (156 of §12 + the 5 wave-14 rows of §15.4) |
| Mutation runs executed | **163** (GW-A1/GW-A1b share one mutation; +3 `new_classes` substitution variants `MCP-T6b`, `MCP-T7b`, `AR-T5b`) |
| **RED** | **150** |
| **GREEN** | **13** |
| CONFIRM-FAIL | **0** |
| Restored byte-identical (`sha256sum -c`) | **163 / 163** |
| Whole-tree check after the pass | **827 / 827** `.ts` + `.toml` files byte-identical to the pre-pass snapshot |

### 16.2 The 13 GREEN rows — 9 expected, **4 newly-found unproven seams**

| ID | Verdict | Reading |
|---|---|---|
| GW-T2, CP-T2, MCP-T2, TEL-T5 | **expected** | `compatibility_flags` — DEPLOY-ONLY, exactly as §15.3 corrected |
| CP-T1, TEL-T1 | **expected** | `main = …` — DEPLOY-ONLY (`MCP-T1`/`AR-T1` are now gated and went RED, per §15.2) |
| TEL-T4 | **expected** | `[observability]` — no local effect, row already says "none" |
| MCP-P6 | **expected** | weakly gated, not dead — §15.1's ruling reconfirmed |
| CLI-8 | **expected** | the compiled-binary entry guard, already **NO GATE** in the row |
| **GW-C11** | **NEWLY UNPROVEN** | `/version` is asserted by nothing. Row corrected. T3 |
| **MCP-R4** | **NEWLY UNPROVEN** | the `app.onError` 500 envelope code is asserted by nothing. Row corrected. T2 |
| **AR-C2** | **NEWLY UNPROVEN** | `app.notFound(notFoundHandler)` is dead for every path the suite probes, because `middleware/auth.ts:574,585` throws the identical `404 not_found` first. Row corrected. T2 |
| **CLI-7** | **NEWLY UNPROVEN** | the composition root's `--ca-bundle` transport. `test/transport.test.ts` builds its OWN transport and never calls `createDefaultRuntime()` — the same factory-vs-mount confusion that made GW-A1 a fake mount in wave 14. Row corrected. T2 |

None of the four is money, auth or tenant isolation. All four are T2/T3.
Three of them (GW-C11, AR-C2, CLI-7) sit in the set §15.5 recorded as SKIPPED by
the wave-14 incremental policy — which is precisely the cost §4 warned that
policy carries, now measured rather than asserted.

### 16.3 Every GREEN was checked for semantic effect

A GREEN only means "unproven" if the mutation genuinely changed behaviour.
Checked individually:

- **GW-C11** — the route is removed; `/version` then falls through to the
  reverse-proxy fall-through. Real. `grep -rn "/version" apps/gateway/test` → 0.
- **MCP-R4** — `"internal_error"` occurs exactly ONCE in the file (line 237), so
  the single-occurrence `perl` replace hit the intended site; the wire code
  changes. `grep -rn internal_error apps/mcp/test` → 0.
- **AR-C2** — with the handler unmounted Hono answers a plain-text 404 instead
  of the JSON envelope. Real, and confirmed unreachable-by-test by reading
  `contract.test.ts:404-441` against `middleware/auth.ts:574`.
- **CLI-7** — `readFile` returns `""`; `test/transport.test.ts:399` proves an
  empty bundle is REJECTED, so the mutated runtime would fail at runtime. Real.

### 16.4 Five recipes in this file were themselves defective — repaired

Found by a dry pass (mutate → CONFIRM → restore, no test run) before the real
sweep. Each would have produced a false result:

| Row | Defect in the recorded recipe | Repair used |
|---|---|---|
| GW-A3 | the default `MUT-2` CONFIRM ("OLD absent") cannot fire: the replacement `rbac: configuredRbac,` still contains the OLD text's first line `rbac:` | CONFIRM on a unique `/*MUT*/`-marked replacement |
| MCP-R3, TEL-A3, TEL-A5, TEL-A6 | recorded as `MUT-1` line deletions that orphan a multi-line block ⇒ a **parse error**, not a behaviour change | `if (false as boolean) …` guard, keeping the tree compilable |
| GW-C7 | the recorded `((async()=>{}) as never) \|\| guardrails(…)` inserts a middleware that never calls `next()`, breaking every request rather than only guardrails | delete the whole `guardrails(...)` entry from `GATEWAY_MIDDLEWARE` |

### 16.5 The wave-15 var-drift gates closed six §15.3 holes

§15.3 recorded `GW-T18` and the `[vars]` families as GREEN — "no gate of any
kind, behavioural or drift". The new `test/env-var-drift.test.ts` in all five
Workers changes that: **GW-T17, GW-T18, GW-TS, CP-T5, AR-T9 and TEL-T3 now all
go RED**, and `AR-T6`/`AR-T7`/`AR-T8` fail with an explicit
*"explains every overridden var with an explicit pin in vitest.config.ts"*
message. The gates remain **drift** gates, not behavioural ones — the pinned
miniflare bindings still win over the committed values — but a deleted or
renamed var is no longer invisible. Update §12's "deliberately weak" row from 5
seams to **0 ungated var families**.
