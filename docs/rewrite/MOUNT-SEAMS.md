# MOUNT-SEAMS — the durable mount-seam inventory

**Status: RE-DERIVED FROM SCRATCH in wave 18; MADE MACHINE-COMPLETE in wave 21.**
Not patched. Every row below was produced by walking the composition roots
mechanically — the file list is in §2 — and matching the wave-17 table against
that walk afterwards, in that order. Doing it the other way round is what let a
MISSING row stay invisible for seventeen waves.

> **Wave 21 made this file a machine artefact, and that immediately exposed two
> defects a human reader glosses over.** `bun scripts/seam-proof.mjs --list`
> parsed only **170 of the 189** rows — bold ID cells, one lowercase sub-ID and
> one struck-through tombstone were all invisible to it — so a "full" scripted
> pass silently skipped 20 rows while reporting success. And **13 rows named no
> test file a runner could resolve**, so they could not be proven narrowly at
> all. Both are closed: every row now carries a machine-readable **Channel**
> column (§6, §13.2), every row's *Expected RED* cell names a resolvable file or
> declares `NONE` with a category reason, and the tool **exits non-zero** when
> its own count disagrees with §13.1's total. §13.3 is the reconciliation.
> Three seams got their first gate ever in the process: **TEL-T4** (the
> observability Worker's own logs/traces block), **AR-C9**, and the narrowed
> **AR-T11** finding.

> **Read §3 first.** The wave-18 walk found **eight mount lines that had never
> been a row in any wave's table**, one row whose seam is **DEAD IN PRODUCTION**
> (`GW-C11`), one row that was **stale** (`AR-C8` describes lines that no longer
> exist), and **three T1 rows whose only cited gate was a harness that builds
> its own Worker** and therefore proves nothing about the deployed config.

---

## 1. What a mount seam is, and the failure this file exists to stop

The dominant defect in this project is not broken code. It is code that is
fully implemented, fully tested, and **never mounted on the app the Worker
exports** — dead in production while every suite stays green. Eleven have now
been caught. A *mount seam* is any single line of code or config whose removal
silently un-deploys working behaviour.

A seam is "proven" only when **removing it makes a named test go RED**.
Asserting that a handler EXISTS is not asserting that it RUNS.

### The five traps this table is organised around

1. **`real ?? fallback`.** Needs a gate asserting something ONLY the real
   implementation can produce. Marked `??` in the *Seam* column.
2. **The local runner is more permissive than Cloudflare.**
   `@cloudflare/vitest-pool-workers` builds a Durable Object namespace from the
   BINDING alone and never reads `[[migrations]]`; it skips workerd's
   entrypoint-shape check on `main`; and it supplies its own runtime flags, so
   `compatibility_flags` is not load-bearing locally. Marked **DEPLOY-ONLY**.
3. **A handler that exists ≠ a handler that runs.** `gatewayScheduled`'s body
   was gutted to a no-op and 1711 tests stayed green (GW-C10).
4. **A pinned miniflare binding BEATS the committed toml.** Three T1 config rows
   were no-ops for two waves because `vitest.config.ts` re-supplied the value.
   Those can only ever be **drift** gates; they are marked *drift-only*.
5. **A gate that builds its own app, or its own `wrangler.toml`, proves the
   FACTORY and never the MOUNT.** §4 is the audit of every such gate in the
   repo. This is the trap that fired most often in wave 18.

### A sixth, new in wave 18: a mount can be **shadowed**

`createGatewayApp` ends with `app.all("*", … reverseProxyFallThrough())`, which
TERMINATES the chain. A route registered after it is dead. `GW-C11` is exactly
that, in production, today. No mutation can prove a dead seam — which is why
wave 15 read its GREEN as "unproven" when the truth was "unreachable". A GREEN
mutation has two possible readings and this file now records which one applies
to every GREEN row.

---

## 2. The composition roots this inventory was derived from

Walked exhaustively. Anything not on this list is not a composition root, and
anything on it that has no rows below is an error in this file.

| App | Files walked |
|---|---|
| `apps/gateway` | `src/worker.ts` · `src/index.ts` · `src/routes/index.ts` · `src/adapters.ts` · `src/assets/handlers.ts` · `src/inference/defaults.ts` · `src/ratelimit/workflow.ts` · `wrangler.toml` · `vitest.config.ts` · `test/ratelimit/harness/{vitest.config.ts,wrangler.toml,worker.ts}` · `test/tenancy/harness/{vitest.config.ts,wrangler.toml,worker.ts}` |
| `apps/control-plane` | `src/worker.ts` · `src/index.ts` · `src/routes/index.ts` · `src/adapters.ts` · `wrangler.toml` · `vitest.config.ts` |
| `apps/mcp` | `src/worker.ts` · `src/index.ts` · `src/routes/index.ts` · `src/ports.ts` · `wrangler.toml` · `vitest.config.ts` |
| `apps/agent-runtime` | `src/worker.ts` · `src/index.ts` · `src/ports.ts` · `wrangler.toml` · `vitest.config.ts` · `test/durable/harness/{vitest.config.ts,wrangler.toml}` |
| `apps/telemetry` | `src/worker.ts` · `src/index.ts` · `src/app.ts` · `src/ports.ts` · `wrangler.toml` · `vitest.config.ts` |
| `apps/cli` | `src/index.ts` (`createDefaultRuntime` + the process-entry guard) · `vitest.config.ts` |

The extraction that produced the raw line list:

```bash
for a in gateway control-plane mcp agent-runtime telemetry cli; do
  for f in src/worker.ts src/index.ts src/routes/index.ts src/app.ts; do
    p="apps/$a/$f"; [ -f "$p" ] || continue
    grep -nE '^\s*(app|router)\.(use|on|all|get|post|put|patch|delete|route|onError|notFound)\(|^\s*export (default|\{)|register[A-Za-z]*\(|module\.register|fetch:|scheduled:|^\s*[a-zA-Z][A-Za-z0-9_]*\(.*\),\s*$' "$p" | sed "s|^|$p:|"
  done
done
```

Ports/adapters were walked by printing each `resolveDeps` / `resolvePorts` /
`depsFromEnv` / `createDefaultRuntime` body in full and giving **every property
of the returned object** its own row. `wrangler.toml` was walked by stripping
comments and listing every `[`-header, `binding`, `name`, `class_name`,
`new_sqlite_classes`, `service`, `crons`, `dataset` and `[vars]` key.

---

## 3. WAVE-18 AND WAVE-21 FINDINGS — read before trusting any row

### 3.1 Eight mount lines that were in NO wave's table

A wrong row is visible; a **missing** row is not. These eight were found by the
§2 walk, not by reading the old table. Seven turned out to have gates already;
the eighth did not, and is a live defect.

| New ID | File:line | Line | Gated? |
|---|---|---|---|
| **GW-R4** | `src/routes/index.ts:396` | `app.use("*", requestMetrics());` | YES — `test/routes/metrics.test.ts`, **3 RED** |
| **GW-R8** | `src/routes/index.ts:421` | `app.use("*", options.nodeDrain ?? nodeDrainGate());` `??` | YES — `test/routes/drain.test.ts`, **3 RED** |
| **GW-R11** | `src/routes/index.ts:445` | `router.register("getMetrics", metricsHandler);` | YES — `contract.test.ts` + `routes/metrics.test.ts`, **5 RED** |
| **GW-R14** | `src/routes/index.ts:455` | `app.get("/health", (c) => c.json({ ok: true }));` | YES — `test/health.test.ts`, **1 RED** |
| **MCP-R3** | `src/routes/index.ts:229` | `app.get("/health", …);` | YES — `contract.test.ts` + `health.test.ts`, **2 RED** |
| **MCP-P7** | `src/ports.ts:1776` | `const admission = durableAdmission(env);` | YES — `admission.test.ts`, `d1-auth.test.ts`, `server-catalog.test.ts`, **12 RED** |
| **AR-P8** | `src/ports.ts` (`resolveDeps`) | `admission: admissionFromEnv(env as AdmissionBindings),` | YES — `test/admission.test.ts`, **4 RED** |
| **AR-V1** | `src/index.ts:45` | `app.get("/version", …);` | **NO — closed in wave 18**, see §3.4 |

Two more were derived and are gated but had never been named: `CP-A10`
(`listDefaultLimit`) and `CP-A11` (`listMaxLimit`), the two `resolveDeps` slots
after `corsAllowedOrigin`. Both are **drift-only** — mutating them to their own
constants is RED in `test/env-var-drift.test.ts` (3 RED) because the `env.` read
disappears, but no behavioural test reads a non-default limit.

### 3.2 GW-C11 was not "unproven". It was DEAD IN PRODUCTION — and wave 18 FIXED it.

`apps/gateway/src/index.ts:243` registers

```ts
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));
```

**after** `createGatewayApp` has already installed
`app.all("*", options.reverseProxy ?? reverseProxyFallThrough())`. Hono runs
matched handlers in registration order and, with `GATEWAY_ROUTES` unset, the
fall-through calls `c.notFound()` — it terminates. Measured against the deployed
Worker through `SELF`:

```
GET https://gw.test/version
  -> 404  {"error":{"message":"no route for GET /version","type":"ferrogate_error",
           "code":"not_found","request_id":"7244f0ca-…"}}
```

The gateway is **the only one of the five Workers that does not serve
`/version`** (`mcp`, `control-plane`, `agent-runtime` and `telemetry` all do,
and all four are gated). Wave 15 §16.3 checked this GREEN "for semantic effect"
and recorded *"the route is removed; `/version` then falls through to the
reverse-proxy fall-through. Real."* — the mechanism was right and the conclusion
was wrong: the fall-through already wins, so the mutation is a **semantic
no-op**, and the row is a DEFECT rather than a gap in the seam net.

**Fix (one line, owned by whoever may edit the composition root):** delete
`src/index.ts:243` and register the same route inside `createGatewayApp`
(`src/routes/index.ts`) immediately beside
`app.get("/health", (c) => c.json({ ok: true }));` at line 455, which is the
last line above the fall-through.

**The wave-18 INTEGRATE step made exactly that change** (it owns the composition
roots): `src/index.ts:243` is gone, and `src/routes/index.ts` now carries
`app.get("/version", …)` immediately below `app.get("/health", …)` and
immediately above the fall-through. The `test.todo` was replaced with the real
assertion, and the seam was re-proven by deleting the registration: **2 RED**
(`answers 200 with the public API major, through SELF`; `is registered ABOVE the
fall-through, unlike the late probe`), restored GREEN. The row is now **GW-R16**.

The paragraph below records what the DELIVERING agent could do, and is kept
because the rule it pinned is what stops the next occurrence:

**Wave 18's seam agent could not write that gate** — `apps/*/src/**` was out of its scope and a
test asserting the correct 200 would be RED on delivery, while a test asserting
the current 404 would lock the defect in. What it wrote instead is
`apps/gateway/test/routes/registration-order.test.ts`, which pins the *rule*
that makes this a defect and is green today:

- a route registered BEFORE the fall-through (`/health`) is served — mutation:
  move `app.get("/health", …)` below `app.all("*", …)` ⇒ **2 RED**
  (`health.test.ts` + this file);
- a probe route attached to the DEPLOYED `app` object AFTER `createGatewayApp`
  returned — the exact position `/version` occupies — is **404**, with the
  gateway's own envelope naming the path.

plus a `test.todo` carrying the exact fix and the exact assertion to replace it
with. So the next route put on the wrong side of the fall-through fails in the
suite, and `/version` stays visible in every run until it is fixed.

### 3.3 AR-C8 was stale — a row describing lines that no longer exist

The wave-17 table's `AR-C8` reads *"`app.get("/healthz", …)` / `app.get("/readyz", …)` (37-38)"*
in `apps/agent-runtime/src/index.ts`. Those lines are gone: both probes moved
into `src/routes/health.ts` and are mounted by `app.route("/", healthRoutes);`
at line 44 — which is `AR-C10`, added in wave 17 without deleting the row it
superseded. A stale row is worse than no row: it reads as coverage. Deleted
here; `AR-C10` is the live one.

### 3.4 Six seams had NO valid gate. All six are now closed by mutation.

Every one was confirmed GREEN off disk first, with the CONFIRM grep read back,
then closed with a new test file under `apps/*/test/`, then re-mutated to RED.

| Row | Measured GREEN (before) | Gate added (wave 18) | RED (after) |
|---|---|---|---|
| **AR-C2** `app.notFound(notFoundHandler)` | 385 + 51 green with the handler unmounted | `apps/agent-runtime/test/routes/root-mounts.test.ts` | **3 RED** |
| **AR-V1** `app.get("/version", …)` | 385 + 51 green with the route deleted | same file | **2 RED** |
| **MCP-R6** `app.onError((error, c) => …)` | 397 green with `"internal_error"` renamed | `apps/mcp/test/error-envelope-mount.test.ts` | **1 RED** (rename) / **2 RED** (whole block unmounted) |
| **CLI-7** the `--ca-bundle` transport | 339 green with `readFile: async () => ""` | `apps/cli/test/composition-root-transport.test.ts` | **3 RED** |
| **CLI-8a** `entry.endsWith("/index.ts")` | never executed by vitest at all | same file | **1 RED** |
| **CLI-8b** `entry.endsWith("/ferrogate")` | never executed by vitest at all | same file | **1 RED** |

**CLI-7 needed a host-shape simulation, and that is why nobody had gated it.**
`createTlsPolicy` short-circuits on `runtimeHonorsFetchTls()` — literally
`typeof globalThis.Bun !== "undefined"`. Vitest runs `apps/cli` under **Node**,
where that is `false`, so any `--ca-bundle` context throws *"cannot be honoured:
this runtime's fetch() ignores per-request TLS options"* **before**
`transport.readFile` is consulted. The seam is unreachable on the test host. The
new gate installs `globalThis.Bun` across the `createDefaultRuntime()` call —
the shipped artifact IS a Bun binary — and then discriminates on two refusals
that both land before any socket opens: a missing path gives
`failed to read CA bundle '<path>'` under the real reader and
`contains no certificates` under the mutated one; a REAL PEM written to a temp
file plus a deliberately un-parseable endpoint gives `invalid endpoint URL`
under the real reader and `contains no certificates` under the mutated one.

**CLI-8 is no longer NO-GATE.** Both arms are exercised by spawning `bun` on a
real argv shape: the source entry for the `/index.ts` arm, and a launcher file
named exactly `ferrogate` (no extension) in a temp dir for the `/ferrogate` arm,
which reproduces the compiled binary's `argv[1]` without a 40 MB build step.
That second arm is the one whose failure mode is a shipped binary that exits 0
and prints nothing.

### 3.5 WAVE-21 — the thirteen rows that named no gate, and what each turned out to be

Every measurement below was taken with the §5 protocol: mutate, `grep` the marker
back OFF DISK, run, restore, `sha256sum -c`, run again. RED counts are verbatim.

**Four had a perfectly good gate that nobody had written down.** The row named
prose ("every `SELF.fetch` suite") or a file that is not a test
(`test/d1.ts`, `test/fixtures.ts`) or a back-reference ("as MCP-T6", "same
three") or a path with a line suffix that had since moved
(`test/contract.test.ts:432` → 439). None of those resolve to anything a runner
can execute, so each row was unprovable *narrowly* while being perfectly well
guarded.

| Row | Mutation | Measured |
|---|---|---|
| **GW-E6** | `export default handler;` → `/*MUT*/ void handler;` | **2 RED** in `test/health.test.ts` — `TypeError: … src/worker.ts does not export a default entrypoint` |
| **CP-E3** | same | **3 RED** in `test/health.test.ts`, same TypeError |
| **AR-C11** | `export default app;` → `/*MUT*/ void app;` | **1 RED** in `test/health.test.ts`. The failure surfaces on `src/worker.ts` (AR-E1 re-exports this) and is a RUNTIME refusal, not a bundler error — §5 rule 4 holds |
| **CP-T3** | `MUT-4 [d1_databases]` | `test/d1-store.test.ts` errors at setup (`Failed to execute 'applyD1Migrations': parameter 1 is not of type 'D1Database'`, 36 specs unrun) + **2 RED** in `test/env-var-drift.test.ts` |
| **MCP-R2** | `/version` → `/*MUT*/ void PUBLIC_API_MAJOR;` | **1 RED** in `test/contract.test.ts` (`expected 404 to be 200`) |
| **MCP-T7** | delete `new_sqlite_classes = ["FerroGateMcpSession"]` | **2 RED** — `env-var-drift` §"introduces every bound DO class…" + `wrangler-bindings` §"introduces each bound class…" |
| **MCP-T9** | `FG_DEV_IN_MEMORY_PORTS` `"1"`→`"0"` | **2 RED**, both spelling gates. `test/health.test.ts` stayed GREEN, which is why this row is `DRIFT` and can be nothing else |
| **TEL-A8** | `/version` → `/*MUT*/ void PUBLIC_API_MAJOR;` | **3 RED** across `health.test.ts` + `routes.test.ts` |

**Three were ESC rows whose gate the tool could not even see**, because the old
parser matched `.test.ts` and nothing else. All three are now labelled `ESC` in
the Channel column and run with `--config`, which is the whole speed story:

| Row | Escalated command | Measured |
|---|---|---|
| **GW-C8** | `bunx vitest run --config test/tenancy/harness/vitest.config.ts test/tenancy/mount.spec.ts` | **1 RED of 8**, 2.5 s — `GATEWAY_MIDDLEWARE refuses an unprovisioned tenant` |
| **AR-P1** | `bunx vitest run --config test/durable/harness/vitest.config.ts test/durable/mount.spec.ts` | **5 RED of 7**, 1.7 s |
| **AR-P2** | same command | **5 RED of 7** |

**Two had no gate at all, and now do.**

- **TEL-T4** — the `[observability]` block. Carried
  as *"DEPLOY-ONLY, no gate"* through waves 15, 18, 19 and 20 on the reasoning
  that Workers Logs config has no local effect. That is true of the BEHAVIOUR and
  it left the one Worker whose entire job is observability able to ship with its
  own logs and traces off, silently, with every suite green. The new gate in
  `test/env-var-drift.test.ts` pins the three rot directions and was proven on
  each: whole block commented out ⇒ **2 RED**; `[observability.traces] enabled =
  false` ⇒ **1 RED** (`expected 2 to be 3`); `invocation_logs = true` ⇒ **1 RED**.
  Restored ⇒ 18/18 GREEN.
- **AR-C9** — the duplicate `AgentRunState` / `WorkerPlane` exports on
  `src/index.ts`. The row's *Expected RED* was the word "none", justified as
  *"kept because `vitest.config.ts` can point `main` at either"*. **That
  justification is wrong and the source says so**: `src/worker.ts`'s own docblock
  records that `main` cannot point at `src/index.ts`, because it exports
  `OWNED_OPERATIONS` (an array) and workerd rejects a non-function named export
  on the entry module. The new gate in `test/wrangler-bindings.test.ts` asserts
  what the row actually claims — that the two candidate modules AGREE — and
  asserts IDENTITY, not presence: deleting both lines ⇒ **1 RED**
  (`src/index.ts no longer re-exports AgentRunState`), and re-exporting
  `WorkerPlane as AgentRunState` ⇒ **1 RED** (`is a DIFFERENT class than
  src/worker.ts's`), which a `typeof === "function"` check would have passed.

**Two are NOT-MUTABLE or ungated by category, and are now labelled as such rather
than reading as "skipped".**

- **AR-T11** — `NONE · NOT-MUTABLE`. The seam is the ABSENCE of a
  `[[d1_databases]]` stanza; nothing on disk can be removed. The inverse
  assertion is deliberately not written: it would lock in the very posture the
  row exists to flag, which is what wave 15 did to `GW-C11`. Closing this row
  means adding the stanza.
- **CP-C13b** — `NONE`, and the ONLY unproven-and-gateable row left in the file.

---

## 4. HARNESS AUDIT — every chained suite, and what it can and cannot prove

There are exactly **three** chained vitest projects in the repo. The rule wave
17 stated and wave 18 measured: *a gate that constructs its own app or its own
`wrangler.toml` proves the FACTORY, never the MOUNT.*

| Harness | Own `wrangler.toml`? | Own `worker.ts`? | `main` points at | Verdict |
|---|---|---|---|---|
| `apps/gateway/test/ratelimit/harness/` | **YES** | **YES** | `worker.ts` (its own) | **Cannot see the deployed config or the deployed entry module.** Re-pointed below. |
| `apps/gateway/test/tenancy/harness/` | **YES** | **YES** | `worker.ts` (its own) | **Partly invalid.** Re-pointed below. |
| `apps/agent-runtime/test/durable/harness/` | YES | **NO** | `../../../src/worker.ts` — the REAL entry module | **Sound.** Nothing is substituted; only the bindings differ. |

### 4.1 `test/ratelimit/harness/` — two citations withdrawn

`harness/worker.ts` calls the real `createGatewayApp` and the real
`GATEWAY_ROUTE_MODULES`, but it also
(a) **re-exports `RateLimiterDurableObject` itself** from
`../../../src/ratelimit/index.js`, and
(b) mounts `rateLimitRouteModule({ perKeyRequestLimit, settleTokens: true })`,
two options the deployed `src/index.ts` does not use (it mounts a bare
`rateLimit()` in `GATEWAY_MIDDLEWARE`).

Consequences, measured:

- **GW-E3** — the wave-17 row cited `test/ratelimit/durable-object.spec.ts` as
  an escalation gate for `export { RateLimiterDurableObject }` on
  `src/worker.ts`. That citation is **invalid**: the harness supplies its own
  export, so deleting the deployed one is invisible to those 24 specs. Deleting
  it for real is **5 RED** in the app's OWN project —
  `test/wrangler-bindings.test.ts` §"resolves each bound class against the ENTRY
  module's exports" (which does `import * as entry from "../src/worker.js"`),
  `test/keys/credential-limits.test.ts`, `test/ratelimit/guards.test.ts` ×2 and
  `test/metering/usage-ledger.test.ts`. The row now cites those and nothing else.
- **GW-T8** — the `[[durable_objects.bindings]] name = "RATE_LIMIT"` stanza. The
  escalation spec reads `harness/wrangler.toml`, **a different file**. Wave 17
  already added the real gate (`it("binds each namespace under the NAME src/
  reads it by")`); the harness citation is withdrawn here.
- **GW-C6** — `rateLimit()` in `GATEWAY_MIDDLEWARE`. Because the harness mounts
  a differently-configured route module, the 24 specs prove the rate-limit
  ENGINE, not the deployed mount. The mount gates are
  `test/ratelimit/guards.test.ts` and `test/ratelimit/spend.test.ts` (whose
  docblock at line 300 records that it drives `SELF` → `src/worker.ts` →
  `GATEWAY_MIDDLEWARE`).

### 4.2 `test/tenancy/harness/` — the SELF cases prove the harness, one case proves the mount

`harness/worker.ts` passes `middleware: [tenantDatabase()]` — **its own array**,
not `GATEWAY_MIDDLEWARE`. So the six `SELF.fetch` cases in `mount.spec.ts`'s
first `describe` are satisfied by the harness regardless of what
`src/index.ts` does.

What saves **GW-C8** is the file's SECOND `describe` — "the DEPLOYED composition
root mounts tenantDatabase()" — which imports `GATEWAY_MIDDLEWARE` from
`../../src/index.js` and builds each case's app from it. Measured: deleting
`tenantDatabase(),` from `src/index.ts` is **exactly 1 RED of 42**, and that one
is `GATEWAY_MIDDLEWARE refuses an unprovisioned tenant`. The row now cites that
`describe` by name. The remaining 41 specs stay green, which is precisely the
false comfort the harness shape produces.

### 4.3 `test/durable/harness/` — clean

`main = "../../../src/worker.ts"`. Every request in `test/durable/*.spec.ts`
goes through the REAL entry module, the REAL `src/index.ts` app and the REAL
`src/middleware/auth.ts`; only the bindings differ (two D1 databases bound, the
`FG_DEV_*` bundle deliberately absent). **AR-P1** and **AR-P2** are soundly
gated by it. No re-pointing needed.

### 4.4 The other shape: a gate that reads a DIFFERENT file than the deploy

`apps/telemetry/vitest.config.ts` binds **no** `TEST_WRANGLER_TOML` (the other
four Workers do). Its `test/env-var-drift.test.ts` reads the committed config
through `import.meta.glob("../wrangler.toml", { query: "?raw" })` instead — a
Vite transform that inlines the real bytes at build time. That is a *different
channel*, not a missing one, and it reads the same committed file wrangler
deploys. Verified: it is the file, not a fixture (the test asserts so itself).

---

## 5. Mutation protocol (run this verbatim for every row)

```bash
ID=<row id>; APP=<app>; F=/home/dev/ferrogate-ts/apps/$APP/<file>
cp "$F" /tmp/seam.bak && sha256sum "$F" > /tmp/seam.sha
perl -0777 -i -pe '<the row's MUT expression>' "$F"
grep -nF -- '<the row's CONFIRM string>' "$F"   # MUST fire (or be empty, per the row)
bun scripts/seam-proof.mjs --id "$ID" --run     # MUST be RED
cp /tmp/seam.bak "$F" && sha256sum -c /tmp/seam.sha       # MUST say OK
bun scripts/seam-proof.mjs --id "$ID" --run     # MUST be GREEN
```

`seam-proof.mjs` reads the row's *Expected RED* and *Channel* cells and runs
**only** the tests that row names, with `--config <chained config>` when the
Channel says `ESC`. Measured wave 21: the three ESC rows together take **3.6 s**
this way, against two full chained `bun run test` invocations the old recipe
demanded. Whole-app `bun run test` is still the wave's regression sweep — it
answers a different question (did the mutation disturb anything else?) and is
run ONCE, not once per row.

**Four rules learned the hard way, all of which cost a wave:**

1. **`grep -F`, not `grep`.** A CONFIRM pattern containing `/*MUT*/` is a BRE in
   which `*` is a quantifier, so it silently matches nothing and a landed
   mutation reads as CONFIRM-FAIL. Wave 18 lost two runs to this.
2. **Read the file back OFF DISK.** A concurrent write can revert the edit
   before the build, and a mutation that never landed looks exactly like a
   vacuous test.
3. **`bun run test`, not `bunx vitest run`.** `apps/gateway` chains two extra
   projects and `apps/agent-runtime` chains one (§4). Under a bare `vitest run`
   those specs are not collected and the suite reports green.
4. **A RED from a parse error proves nothing.** Recipes that would orphan a
   block are written as `if (false as boolean) …` guards or as a
   `/*MUT*/ void <symbol>;` statement that keeps the import used, so the tree
   still compiles and the RED is an assertion failure.

### Recipe shorthand

| Tag | Expansion |
|---|---|
| `MUT-1 /RE/` | `perl -0777 -i -pe 's{RE}{/*MUT*/}'` — delete the matched line, leave a marker |
| `MUT-2 "OLD"→"NEW"` | `perl -0777 -i -pe 's{\QOLD\E}{NEW}'` — literal replace; NEW carries `/*MUT*/` |
| `MUT-3 «stanza»` | delete a contiguous TOML stanza verbatim |
| `MUT-4 [hdr]` | comment a whole TOML table out (`perl -i -pe 'if(/^\[\[?hdr/){$m=1}elsif(/^\[/){$m=0} s/^/#MUT / if $m'`) — the config gates drop `#` lines, so commenting ≡ deleting |
| `MUT-5 void` | `MUT-2` to `/*MUT*/ void <symbol>;` — unmounts without orphaning the import |

Every `MUT-2` replacement must carry a `/*MUT*/` token that is **absent from the
pristine file**, or "the new text is present" confirms nothing.

---

## 6. Risk tiers and proof channels

| Tier | Meaning |
|---|---|
| **T1** | money · auth · tenant isolation · Durable Object bindings · deploy-blocking config |
| **T2** | request-path behaviour |
| **T3** | cosmetic or redundant |

Every row carries a **Channel** cell, `RUN · QUALITY?`. It is machine-read by
`scripts/seam-proof.mjs`; §13.2 has the full census. Wave 21 added it because
every one of these facts already existed in prose inside the *Seam* cell, where
no tool could see it — which is how wave 20 had to rediscover by hand that
`AR-P1`/`AR-P2` need a chained config.

**RUN — how to run this row's gate. Exactly one, always present.**

| RUN | Meaning |
|---|---|
| `DEF` | RED under the app's own default vitest project |
| `ESC` | the gate is a `*.spec.ts` under a chained config (§4). Under a bare `vitest run` it is **not collected** and the suite reports green; the runner supplies `--config` |
| `NONE` | no local gate of any kind. The row states the category reason and §13.2 names all of them |

**QUALITY — how to READ the result. Optional; never affects the command.**

| QUALITY | Meaning |
|---|---|
| `DRIFT` | the committed value is overridden by a pinned binding, or is config the pool never reads, so only a NAME/PRESENCE gate is possible |
| `NOT-MUTABLE` | the seam cannot be mutated **by category** — an absent stanza, a duplicate export that resolves nothing. **Skipped ≠ unproven** |
| `WORKERD-REFUSAL` | the only proof is the runtime refusing to START; exercising it takes the suite to 0 collected tests. **No members since #666** — its two rows, MCP-T10 and AR-T10, turned out to be a harness limitation rather than a runtime one |
| `RETIRED` | a tombstone, kept for history. Not a seam |

Two labels the wave-18 table used are **gone on purpose**. `DEPLOY-ONLY` never
said how to run anything — it named a *residue*, the part of a row no local
runner reaches — so it is now recorded per-row and listed in §13.2 instead of
masquerading as a channel. `DEAD` has no members: `GW-C11` was the only one and
wave 18 fixed it (§3.2).

---

## 7. `apps/gateway` — 62 seams

### 7.1 Entry module `src/worker.ts` (6)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-E1 | `fetch: (request, env, ctx) => app.fetch(request, env, ctx),` (47) | `MUT-1 /fetch: \(request, env, ctx\)/` | `grep -nF 'app.fetch' src/worker.ts` → nothing | every `SELF.fetch` suite; `test/health.test.ts` | DEF | T1 |
| GW-E2 | `scheduled: (controller, env, ctx) => gatewayScheduled(controller, env, ctx),` (48) | `MUT-1 /scheduled: \(controller, env, ctx\)/` | `grep -nF 'gatewayScheduled(controller' src/worker.ts` → nothing | `test/metering/cron-mount.test.ts`; `test/cron-trigger.test.ts` | DEF | T1 |
| GW-E6 | `export default handler;` (51) | `MUT-2 "export default handler;"→"/*MUT*/ void handler;"` | marker present | `test/health.test.ts` — **2 RED**, `TypeError: apps/gateway/src/worker.ts does not export a default entrypoint`. Every other `SELF.fetch` suite in the app goes red the same way; one file is named so the row is provable NARROWLY (wave 21) | DEF | T1 |
| GW-E3 | `export { RateLimiterDurableObject } from "./ratelimit/index.js";` (70) | `MUT-2 "export { RateLimiterDurableObject } from \"./ratelimit/index.js\";"→"/*MUT-noexport*/"` | `grep -nF 'export { RateLimiterDurableObject }' src/worker.ts` → nothing (**not** a bare `RateLimiterDurableObject` grep — the docblock mentions it twice) | **5 RED, all in the app's own project**: `test/wrangler-bindings.test.ts` §"resolves each bound class against the ENTRY module's exports"; `test/keys/credential-limits.test.ts`; `test/ratelimit/guards.test.ts` ×2; `test/metering/usage-ledger.test.ts`. **NOT** ~~`test/ratelimit/durable-object.spec.ts`~~ (citation WITHDRAWN, §4.1) | DEF | T1 |
| GW-E4 | `export { ProviderCircuitDurableObject } from "./inference/index.js";` (87) | as GW-E3 | `grep -nF 'export { ProviderCircuitDurableObject }'` → nothing | `test/wrangler-bindings.test.ts`; `test/inference/reliability-mount.test.ts` | DEF | T1 |
| GW-E5 | `export { ShadowBudgetDurableObject } from "@ferrogate/routing/durable-objects";` (103) | as GW-E3 | `grep -nF 'export { ShadowBudgetDurableObject }'` → nothing | `test/wrangler-bindings.test.ts`; `test/inference/shadow-budget-binding.test.ts` | DEF | T1 |

### 7.2 Composition root `src/index.ts` (11 rows, **10 live** — `GW-C11` is a retired tombstone)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-C1 | `const usage = createMeteringUsageSink({ bindings: meteringBindingsFromEnv });` (58) | `MUT-2 "{ bindings: meteringBindingsFromEnv }"→"{}/*MUT*/"` | marker present | `test/metering/wiring.test.ts` (D1 row read back from `BILLING_DB`) | DEF | T1 |
| GW-C2 | `inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),` (97) | `MUT-1 /^  inferenceRouteModule\(.*$/m` | `grep -nF 'inferenceRouteModule({' src/index.ts` → nothing | `test/contract.test.ts` (31 owned ops); `test/inference/wiring.test.ts` | DEF | T1 |
| GW-C3 | `assetRouteModule({ depsFromEnv: assetDepsFromEnv }),` (98) | `MUT-1 /^  assetRouteModule\(.*$/m` | `grep -nF 'assetRouteModule({'` → nothing | `test/contract.test.ts`; `test/assets/routes.test.ts` | DEF | T2 |
| GW-C4 | `meteringDrain(usage),` — **index 0** of `GATEWAY_MIDDLEWARE` (178) | `MUT-1 /^  meteringDrain\(usage\),$/m` | `grep -nF 'meteringDrain(usage)'` → nothing | `test/metering/wiring.test.ts` (structural ORDER gate + behavioural D1 gate) | DEF | T1 |
| GW-C5 | `requestTelemetry(),` (200) | `MUT-1 /^  requestTelemetry\(\),$/m` | `grep -nF 'requestTelemetry(),'` → nothing | `test/telemetry/middleware-mount.test.ts` (non-inference op `putAsset`) | DEF | T2 |
| GW-C6 | `rateLimit(),` (203) | `MUT-1 /^  rateLimit\(\),$/m` | `grep -cF 'rateLimit()'` → 1 (docblock mention survives) | `test/ratelimit/guards.test.ts`; `test/ratelimit/spend.test.ts` (SELF-driven); `test/inference/wiring.test.ts`. **NOT** the ratelimit harness specs — §4.1 | DEF | T1 |
| GW-C6b | `attributionTags(),` — #678, **strictly between `rateLimit()` and `guardrails()`** | `MUT-1 /^  attributionTags\(\),$/m`; and the two ORDER mutations, which no delete can substitute for: MOVE the entry behind `guardrails(...)`, then MOVE it ahead of `rateLimit()` | `grep -cF 'attributionTags()'` → 1 (the import survives) | `test/attribution/enforcement.test.ts` — **9 RED of 13** on the delete; the two moves each turn the matching ladder case RED plus the structural mount gate (behind `guardrails`: the refusal comes back `guardrail_blocked`; ahead of `rateLimit`: the second, correctly tagged request answers 200 instead of 429, i.e. the untagged refusal was never counted) | DEF | T1 |
| GW-C7 | `guardrails(async (env) => ({ … })),` (211-230) | delete the whole entry from the array (a `\|\|`-prefix wrapper inserts a middleware that never calls `next()` and breaks every request — corrected wave 15) | `grep -nF 'guardrails(async'` → nothing | `test/guardrails/wiring.test.ts`; `test/guardrails/middleware.test.ts` | DEF | T1 |
| GW-C8 | `tenantDatabase(),` (232) — **ESC** | `MUT-1 /^  tenantDatabase\(\),$/m` | marker present at 232 | `test/tenancy/mount.spec.ts` §**"the DEPLOYED composition root mounts tenantDatabase()"** — **exactly 1 RED of 42** across the whole chained project, and **1 RED of 8** when that one file is run alone: `bunx vitest run --config test/tenancy/harness/vitest.config.ts test/tenancy/mount.spec.ts`, 2.5 s (wave 21). The other 7 SELF cases in that file are satisfied by the harness (§4.2) | ESC | T1 |
| GW-C9 | `const { app, router } = createGatewayApp({ modules: GATEWAY_ROUTE_MODULES, middleware: GATEWAY_MIDDLEWARE });` (235-238) | `MUT-2 "modules: GATEWAY_ROUTE_MODULES,"→"/*MUT*/"` | marker present | `test/contract.test.ts` (all 31 ids registered on the REAL router) | DEF | T1 |
| GW-C10 | `await usage.sweep({ env, ctx });` — the BODY of `gatewayScheduled` (269) | `MUT-1 /await usage\.sweep\(\{ env, ctx \}\);/` | `grep -nF 'usage.sweep'` → nothing | `test/metering/cron-mount.test.ts` — **this was GREEN across 1711 tests before that gate existed** | DEF | T1 |
| ~~GW-C11~~ | **FIXED in wave 18 — the row MOVED to §7.3 as `GW-R16`.** `/version` no longer lives in `src/index.ts`; it is registered inside `createGatewayApp`, above the fall-through. Nothing may be registered on `app` after `createGatewayApp` returns | — | — | see `GW-R16` | RETIRED | — |

### 7.3 Route registration `src/routes/index.ts` — `createGatewayApp` (16)

Four of these fifteen (**GW-R4, R8, R11, R14**) had never been a row in any wave.

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-R1 | `app.onError(gatewayErrorHandler);` (386) | `MUT-1` | anchor gone | `test/routes/trace.test.ts` (error envelope) | DEF | T2 |
| GW-R2 | `app.notFound(gatewayNotFoundHandler);` (387) | `MUT-1` | anchor gone | `test/contract.test.ts` (404 control probe) | DEF | T2 |
| GW-R3 | `app.use("*", requestId);` (388) — requestId + W3C traceparent ingress | `MUT-1` | anchor gone | `test/routes/trace.test.ts`; `test/routes/ingress-deployed.test.ts` | DEF | T2 |
| GW-R4 | `app.use("*", requestMetrics());` (396) — **NEW ROW** | `MUT-2 →"/*MUT*/ void requestMetrics;"` | marker present | `test/routes/metrics.test.ts` §"the counters have a PRODUCER" — **3 RED** | DEF | T2 |
| GW-R5 | `app.use("*", options.networkAccess ?? networkAccess());` (403) `??` — **pre-auth** | `MUT-2 →"/*MUT*/ void networkAccess;"` | marker present | `test/routes/network.test.ts`; `test/routes/ingress-deployed.test.ts` | DEF | T1 |
| GW-R6 | `app.use("*", contractAuth(options.deps ?? depsFromEnv));` (407) `??` | `MUT-2 "contractAuth(options.deps ?? depsFromEnv)"→"async (_c, n) => await n()/*MUT*/"` | marker present | `test/auth.test.ts`; `test/rbac.test.ts` | DEF | T1 |
| GW-R7 | `for (const middleware of options.middleware ?? []) { app.use("*", middleware); }` (411-413) | `MUT-1 /^    app\.use\("\*", middleware\);$/m` | anchor gone | `test/metering/wiring.test.ts` + every §7.2 middleware gate | DEF | T1 |
| GW-R8 | `app.use("*", options.nodeDrain ?? nodeDrainGate());` (421) `??` — **NEW ROW** | `MUT-2 →"/*MUT*/ void nodeDrainGate;"` | marker present | `test/routes/drain.test.ts` — **3 RED** (503 `node_draining` on the five spend-producing ops) | DEF | T1 |
| GW-R17 | **NEW, WAVE 22 (FC-1, the third and last leg).** The DURABLE half of the drain — `resolveDrainState` in `src/routes/readiness.ts` (`readDurableDrain` + `combineDrain`), which `nodeDrainGate` (GW-R8) and `readyzHandler` (GW-R10) both call. GW-R8 gates that the middleware is MOUNTED; this gates what it RESOLVES FROM. Before it, `POST /admin/v1/drain` shut `apps/mcp` and `apps/agent-runtime` and left `/v1/chat/completions` serving | `MUT-2` resolve the durable document and then IGNORE it: `await readDurableDrain(env?.CONTROL_DB); return combineDrain(NOT_DRAINING, drainStatus(env).draining);` — the var-only posture, broken at the DECISION rather than at the read | `MUTATION-W22-FC1-GW` present | `test/fleet-control-matrix.test.ts` — **2 RED** (§5.1 *the operator drained the fleet and the gateway kept accepting billable work*, `{status:400,code:"invalid_request"}` vs `{status:503,code:"node_draining"}`; §5.2 *lifting the drain lets work through again*). **Every source-text gate stays GREEN under that mutation** — the file still names `"runtime-state"` — which is why this row cites the BEHAVIOURAL file and not the ledger. The harder variant (point `RESOURCE_TABLE` / `DRAIN_COLLECTION` at private names) is **13 RED** across `fleet-control-matrix.test.ts`, `fleet-consistency.test.ts` and `env-var-drift.test.ts`, plus **1 RED** in `apps/mcp/test/drain-fleet.test.ts`. See `FLEET-CONSISTENCY.md` §7.4 M22/M23 | DEF | T1 |
| GW-R9 | `app.use("*", options.responseCache ?? responseCache());` (431) `??` | `MUT-2 →"/*MUT*/ void responseCache;"` | marker present | `test/cache/deployed.test.ts`; `test/cache/middleware.test.ts` | DEF | T2 |
| GW-R10 | `router.register("getHealthz", healthzHandler);` + `router.register("getReadyz", readyzHandler);` (436-437) | `MUT-1 /router\.register\("get(Healthz\|Readyz)".*$/m` | anchors gone | `test/health.test.ts`; `test/routes/readiness.test.ts` | DEF | T2 |
| GW-R11 | `router.register("getMetrics", metricsHandler);` (445) — **NEW ROW** | `MUT-2 →"/*MUT*/ void metricsHandler;"` | marker present | `test/contract.test.ts` (31-op mount) + `test/routes/metrics.test.ts` — **5 RED** | DEF | T2 |
| GW-R12 | `registerToolingRoutes(router);` (447) — skills, prompts, agent-discovery, 3× `registerNotImplemented` | `MUT-1 /^  registerToolingRoutes\(router\);$/m` | anchor gone | `test/routes/skills.test.ts`, `prompts.test.ts`, `agent-discovery.test.ts`; `test/contract.test.ts` | DEF | T2 |
| GW-R13 | `for (const module of options.modules ?? []) { module.register(router); }` (449-451) | `MUT-1 /^    module\.register\(router\);$/m` | anchor gone | `test/contract.test.ts` (24 of 31 ops vanish — the original defect) | DEF | T1 |
| GW-R14 | `app.get("/health", (c) => c.json({ ok: true }));` (455) — **NEW ROW** | `MUT-2 →"/*MUT*/"` | `grep -nF 'app.get("/health"'` → nothing | `test/health.test.ts` — **1 RED**. Also the positive control in `test/routes/registration-order.test.ts`: moving it BELOW GW-R15 is **2 RED** | DEF | T2 |
| GW-R16 | `app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));` (467) — **NEW ROW, wave 18.** This is the old `GW-C11`, moved here out of `src/index.ts` where it was **DEAD IN PRODUCTION** for seventeen waves (§3.2) | `MUT-2 →"/*MUT*/ void PUBLIC_API_MAJOR;"` | marker present | `test/routes/registration-order.test.ts` §"GET /version is served by the deployed gateway (GW-C11, fixed)" — **2 RED**, measured by the wave-18 integrate step. Before the move the same assertion was **404**, which is what the deployed gateway really answered | DEF | T3 |
| GW-R15 | `app.all("*", options.reverseProxy ?? reverseProxyFallThrough());` (471) `??` — **must stay LAST** | `MUT-2 →"/*MUT*/ void reverseProxyFallThrough;"` | marker present | `test/routes/reverse-proxy.test.ts`. **Its position is load-bearing: everything registered after it is dead (§3.2).** `test/routes/registration-order.test.ts` pins that rule | DEF | T2 |

### 7.4 Adapters `src/adapters.ts` — `depsFromEnv` (1096-1115) (4)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-A1 | `apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,` `??` | `MUT-2 →"apiKeys: /*MUT*/ configured,"` | marker present | `test/keys/resolver.test.ts` §"depsFromEnv — the gateway's credential path is wired to D1" (authenticates a secret that exists ONLY as a D1 row and asserts `source === "durable_native"`). **Before wave 14 this was a FAKE MOUNT: unwiring D1 from the whole credential path left all 43 tests in that file green, because they tested the FACTORY** | DEF | T1 |
| GW-A2 | `lifecycle: durableLifecycle === null ? configuredLifecycle : denyIfEitherDenies(durableLifecycle, configuredLifecycle),` | `MUT-2 "denyIfEitherDenies(durableLifecycle, configuredLifecycle)"→"/*MUT*/ configuredLifecycle"` | marker present | `test/lifecycle-chain.test.ts` | DEF | T1 |
| GW-A3 | `rbac: D1RbacAuthorizer.fromEnv(…, { fallback: configuredRbac }) ?? configuredRbac,` `??` | replace the whole ternary with `/*MUT*/ configuredRbac` | marker present (**the default "OLD absent" CONFIRM cannot fire here** — the replacement still contains `rbac:`; corrected wave 15) | `test/rbac.test.ts` | DEF | T1 |
| GW-A4 | `internalTransport: ConfiguredInternalTransport.fromEnv(env),` | `MUT-2 →"{ verify: () => ({ ok: true }) } as never/*MUT*/"` | marker present | `test/auth.test.ts` (worker-token 401/403 taxonomy) | DEF | T1 |

### 7.5 Asset binding adapter `src/assets/handlers.ts` (4)

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-A5 | `...(metadata !== null ? { metadata } : {}),` (603) | `MUT-1` | anchor gone | `test/assets/wiring.test.ts` (row read back from `stored_assets` in `DB`) | DEF | T1 |
| GW-A6 | `...(audit !== null ? { audit } : {}),` (604) | `MUT-1` | anchor gone | `test/assets/wiring.test.ts` | DEF | T1 |
| GW-A7 | `...(objects !== undefined ? { objects } : {}),` (602) | `MUT-1` | anchor gone | `test/assets/r2.test.ts`; `test/assets/routes.test.ts` | DEF | T2 |
| GW-A8 | `await serviceFor(context).flushAudit();` (748) — the COMMIT of the buffered audit sink | `MUT-1 /flushAudit\(\);/` | `grep -nF 'flushAudit()'` → nothing | `test/assets/wiring.test.ts` (third named mutation) | DEF | T1 |

### 7.6 Inference/ratelimit composition (2, wave 17)

| ID | File | Seam | Mutation | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-W1 | `src/inference/defaults.ts` | `deps.workflows ?? workflowCatalogFromEnv(env as WorkflowGateBindings)` `??` — the D2 graph gate's catalog | `MUT-2` the fallback → an always-empty catalog | `test/inference/workflow-mount.test.ts` (SELF-driven, **6 RED**) + `test/inference/workflow-ledger.test.ts` §"the mount". **Before `workflow-mount.test.ts` existed this was 1 RED of 1866 — no HTTP-level proof at all** | DEF | T1 |
| GW-W2 | `src/ratelimit/workflow.ts` | the run-id alias in `workflowDeclarationFrom` (`workflowRunId !== "" \|\| workflowId === "" ? … : AGENT_RUN_ID_HEADER`) | `MUT-2 →"const runId = workflowRunId;"` | `test/inference/workflow-mount.test.ts` — **6 RED**. `test/ratelimit/guards.test.ts` green either way, by design | DEF | T1 |

### 7.7 Deploy config `wrangler.toml` (19)

`apps/gateway/vitest.config.ts` does **not** override `main`, and it binds
`TEST_WRANGLER_TOML` with the committed bytes, so this app has the strongest
config gate of the five.

| ID | Seam (exact config) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| GW-T1 | `main = "src/worker.ts"` (2) | `MUT-2 "src/worker.ts"→"src/index.ts"` | mutated line present | `test/wrangler-bindings.test.ts` §"points main at the ENTRY module, not the composition root" (NAME gate, wave 17). The workerd entrypoint-shape refusal itself stays **DEPLOY-ONLY**: `wrangler dev --local` fails `Incorrect type for map entry 'EXPECTED_OPERATION_COUNT'`, and `e2e/` catches that | DEF · DRIFT | T1 |
| GW-T2 | `compatibility_flags = ["nodejs_compat"]` (4) | `MUT-1 /compatibility_flags/` | anchor gone | `test/wrangler-bindings.test.ts` §"the runtime contract at the top of the file" (NAME gate). **Behaviourally DEPLOY-ONLY** — the pool supplies its own flags; wave 17 measured GREEN across 1875 tests | DEF · DRIFT | T1 |
| GW-T19 | `compatibility_date = "2025-06-01"` (3) | `MUT-1 /compatibility_date/` | anchor gone | `test/wrangler-bindings.test.ts` §"pins a compatibility_date" | DEF · DRIFT | T1 |
| GW-T3 | `[[r2_buckets]]` / `binding = "ASSETS"` | `MUT-4 [r2_buckets]` | `grep -nF 'binding = "ASSETS"'` → nothing | `test/assets/r2.test.ts` (503 `asset_bucket_unavailable` instead of 200) | DEF | T2 |
| GW-T4 | `[[d1_databases]] binding = "DB"` + `migrations_dir = "../../sql/d1-ts/tenant"` | `MUT-3` the 5-line stanza | `grep -nF 'binding = "DB"'` → nothing | `test/keys/resolver.test.ts`, `test/assets/d1.test.ts`, `test/setup-d1.ts` (the pool cannot apply migrations) | DEF | T1 |
| GW-T5 | `[[d1_databases]] binding = "BILLING_DB"` | `MUT-3` | anchor gone | `test/metering/d1.test.ts`, `test/metering/wiring.test.ts` | DEF | T1 |
| GW-T6 | `[[d1_databases]] binding = "CONTROL_DB"` | `MUT-3` | anchor gone | `test/guardrails/d1.test.ts`, `test/rbac.test.ts`, `test/cache/deployed.test.ts` | DEF | T1 |
| GW-T7 | `[[queues.producers]] binding = "BILLING"` | `MUT-4 [queues.producers]` | anchor gone | `test/metering/durable.test.ts` (publish leg) | DEF | T1 |
| GW-T8 | `[[durable_objects.bindings]] name = "RATE_LIMIT"` / `class_name = "RateLimiterDurableObject"` | `MUT-3` the 3-line stanza | `grep -nF 'RATE_LIMIT'` → nothing | `test/wrangler-bindings.test.ts` §"binds each namespace under the NAME src/ reads it by" (wave 17 — before it, the file asserted `class_name` only and renaming the deployed BINDING was invisible). **NOT** ~~`test/ratelimit/durable-object.spec.ts`~~ (citation WITHDRAWN, §4.1) | DEF | T1 |
| GW-T9 | `[[migrations]] tag = "v1"` / `new_sqlite_classes = ["RateLimiterDurableObject"]` | `MUT-1` the `new_sqlite_classes` line | anchor gone | `test/wrangler-bindings.test.ts` §"introduces each bound class in a [[migrations]] new_sqlite_classes" — **GREEN across 1610 tests before that gate, and would have failed the first real `wrangler deploy`** | DEF · DRIFT | T1 |
| GW-T10 | `[[durable_objects.bindings]] name = "PROVIDER_CIRCUIT"` | `MUT-3` | anchor gone | `test/wrangler-bindings.test.ts`; `test/inference/reliability-mount.test.ts` | DEF | T1 |
| GW-T11 | `new_sqlite_classes = ["ProviderCircuitDurableObject"]` | `MUT-1` | anchor gone | `test/wrangler-bindings.test.ts` | DEF · DRIFT | T1 |
| GW-T12 | `[[durable_objects.bindings]] name = "SHADOW_BUDGET"` | `MUT-3` | anchor gone | `test/inference/shadow-budget-binding.test.ts`; `test/wrangler-bindings.test.ts` — **GREEN across 1390 tests before that gate** | DEF | T1 |
| GW-T13 | `new_sqlite_classes = ["ShadowBudgetDurableObject"]` | `MUT-1` | anchor gone | `test/wrangler-bindings.test.ts` | DEF · DRIFT | T1 |
| GW-T14 | `[[services]] binding = "TELEMETRY_COLLECTOR"` / `service = "ferrogate-telemetry"` | `MUT-3` | anchor gone | `test/wrangler-bindings.test.ts` §"is actually READABLE at runtime, not merely declared". **Also WORKERD-REFUSAL in the other direction**: with the target worker undefined the pool refuses to start (`binding "TELEMETRY_COLLECTOR" refers to a service "core:user:ferrogate-telemetry", but no such service is defined`) and every test file errors before import — which is why `vitest.config.ts` supplies a 204 stub worker | DEF | T2 |
| GW-T15 | `[triggers]` / `crons = ["* * * * *"]` | `MUT-2 "[triggers]"→"[disabled_triggers]"` | mutated line present | `test/cron-trigger.test.ts` — **GREEN across 1464 tests before that gate**; workerd never dispatches a scheduled event under vitest, so nothing behavioural can see a deleted Cron | DEF · DRIFT | T1 |
| GW-T16 | `[vars]` ×3: `FERROGATE_ASSET_REQUIRE_SIGNATURE`, `…_PUBLISHER_ED25519_KEYS`, `…_PUBLISHER_MINISIGN_KEYS` | `MUT-1 /^FERROGATE_ASSET_/` | anchors gone | `test/wrangler-bindings.test.ts` §"the asset publisher-signature policy vars" (drift + inert-OFF posture + name-is-read) | DEF · DRIFT | T1 |
| GW-T17 | `[vars]`: `GATEWAY_SKILL_PACKAGES = "[]"`, `GATEWAY_PROMPT_TEMPLATES = "[]"` | `MUT-1 /^GATEWAY_(SKILL_PACKAGES\|PROMPT_TEMPLATES)/` | anchors gone | `test/wrangler-bindings.test.ts` §"the operator config tables"; `test/env-var-drift.test.ts` — **drift-only** by design (the committed value is inert) | DEF · DRIFT | T3 |
| GW-T18 | the remaining **44** `[vars]` entries (`GATEWAY_NATIVE_API_KEYS` … `TELEMETRY_SIGNALS`; 49 keys total, minus GW-T16's 3 and GW-T17's 2) | `MUT-4 [vars]` | `grep -c '^GATEWAY_'` → 0 | `test/env-var-drift.test.ts` (wave 15) — **drift**. Behaviourally invisible: `vitest.config.ts` re-supplies every var that matters as an explicit binding, so commenting the whole table out was GREEN across `auth.test.ts`, `contract.test.ts` and `cache/config.test.ts`. Includes `GATEWAY_CACHE_SEMANTIC_THRESHOLD`, whose committed value IS the code's own fallback, so no behavioural gate is possible for it either | DEF · DRIFT | T2 |

---

## 8. `apps/control-plane` — 42 seams

### 8.1 Entry module `src/worker.ts` (3)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CP-E1 | `fetch: (request, env, ctx) => app.fetch(request, env, ctx),` (29) | `MUT-1` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | DEF | T1 |
| CP-E2 | `scheduled: (controller, env, ctx) => scheduled(controller, env, ctx),` (30) | `MUT-1 /scheduled: \(controller, env, ctx\)/` | `grep -nF 'scheduled:'` → nothing | `test/worker-entry.test.ts` | DEF | T1 |
| CP-E3 | `export default handler;` (33) | `MUT-2 →"/*MUT*/ void handler;"` | marker present | `test/health.test.ts` — **3 RED**, `TypeError: apps/control-plane/src/worker.ts does not export a default entrypoint`. Every other `SELF.fetch` suite goes red the same way; one file is named so the row is provable NARROWLY (wave 21) | DEF | T1 |

### 8.2 Composition root `src/index.ts` (19)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CP-C1 | `app.onError(controlPlaneErrorHandler);` (55) | `MUT-1` | anchor gone | `test/crud.test.ts` (error envelope shape) | DEF | T2 |
| CP-C2 | `app.notFound(controlPlaneNotFoundHandler);` (56) | `MUT-1` | anchor gone | `test/wiring.test.ts` (404 control probe) | DEF | T2 |
| CP-C3 | `app.use("*", requestId);` (58) | `MUT-1` | anchor gone | `test/crud.test.ts` (`request_id` in the envelope) | DEF | T2 |
| CP-C4 | `c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));` (69) | `MUT-2 "{ requestId: c.get(\"requestId\") }"→"{}/*MUT*/"` | marker present | `test/d1-store.test.ts` (`audit_events.request_id`); removing the whole `app.use` → `test/wiring.test.ts` | DEF | T1 |
| CP-C5 | `app.use("*", corsResponseHeaders);` (73) | `MUT-1` | anchor gone | `test/cors.test.ts` | DEF | T2 |
| CP-C6 | `app.use("*", adminCorsPreflight);` (74) — must precede `contractAuth` | `MUT-1` | anchor gone | `test/cors.test.ts` (OPTIONS not challenged) | DEF | T2 |
| CP-C7 | `app.use("*", contractAuth());` (75) | `MUT-1` | anchor gone | `test/auth.test.ts`; `test/rbac-d1.test.ts` | DEF | T1 |
| CP-C8 | `export const MOUNTED_ROUTES: readonly RegisteredRoute[] = registerRoutes(app);` (87) | `MUT-2 "registerRoutes(app)"→"[]/*MUT*/"` | marker present | `test/wiring.test.ts` (asserts Hono's OWN `app.routes`) — **`test/contract.test.ts` alone stays GREEN, which is why `wiring.test.ts` exists** | DEF | T1 |
| CP-C9 | **CORRECTED, WAVE 20.** `mountSharedProbes(app);` — in `src/routes/index.ts::registerRoutes`, **not** `src/index.ts`. The wave-20 health slice DELETED both inline `app.get("/healthz"/"/readyz")` handlers from the composition root and moved the pair into `src/routes/health.ts`, because leaving them would have made this Worker declare TWO health documents for one path. The old row's mutation regex now matches NOTHING, i.e. it was a row that could no longer fail — the stale-row failure mode this file exists to catch, found by the wave-20 seam pass rather than by reading | `MUT-1 /mountSharedProbes\(app\);/` | `grep -nF 'mountSharedProbes(app);' src/routes/index.ts` → nothing | `test/health.test.ts` — **3 RED** (wave-20 mutation M6, `404 no route for GET /healthz`) | DEF | T1 |
| CP-C12 | `app.get("/health", (c) => c.json({ ok: true }));` (127) | `MUT-1` | anchor gone | `test/wiring.test.ts` §"mounts NOTHING beyond the 197 + the shared probes + /health + /version" (`NON_CONTRACT_ROUTES` pins `GET /health`) | DEF | T3 |
| CP-C13 | `app.get("/version", (c) => c.json({ api, operations, registered, groups }));` (128-135) | `MUT-1` | anchor gone | `test/wiring.test.ts`, same `NON_CONTRACT_ROUTES` gate | DEF | T3 |
| CP-C13b | **NEW, WAVE 20.** The `/version` DOCUMENT's contents, as opposed to its registration. Swapping `api: PUBLIC_API_MAJOR` for `api: 0` leaves **687/687 GREEN**: `NON_CONTRACT_ROUTES` pins that the ROUTE exists and nothing reads what it answers. Deleting the registration outright IS red (1 RED), so CP-C13 above is sound as written — this is a strictly narrower hole, recorded rather than silently folded in | `MUT-2 "api: PUBLIC_API_MAJOR"→"api: 0"` | marker present | **NONE — GREEN, an unproven sub-seam.** A wave-21 gate should assert the three counts against `CONTROL_PLANE_OPERATIONS.length` / `CONTROL_PLANE_GROUPS.length` | NONE | T3 |
| CP-S1 | `export const MOUNTED_SESSION_ROUTES … = mountAdminConsoleSession(app);` (109-110) — **NEW ROW, wave 18.** The nine `/v1/admin/{register,login,refresh,logout,me,team*}` console-session routes, and the `app.use("/v1/admin/*", consoleCsrf)` they install. **Must stay FIRST of the three identity mounts**: Hono applies a `use` to handlers registered after it, so mounting it later leaves every `/v1/admin/*` route below without the cross-site guard | `MUT-2 →"= [];/*MUT*/ void mountAdminConsoleSession;"` | marker present | `test/identity-mount.test.ts` — **18 RED of 23**, incl. §1 "serves POST /v1/admin/login through the deployed Worker (not 404)". **NOT** ~~`test/console-session.test.ts`~~ (citation WITHDRAWN): that file builds its OWN Hono app and calls `app.request(...)`, so it proves the FACTORY and stayed green while the surface was unmounted (§4's rule, measured again here) | DEF | T1 |
| CP-S2 | `app.route("/", IDENTITY_APP);` (113), over `IDENTITY_APP = createIdentityRoutes((c) => resolveIdentityDeps(c))` (112) — **NEW ROW, wave 18.** OIDC (authorize + callback), SCIM 2.0 (Users, Groups) and the SCIM-token mint | `MUT-2 →"/*MUT*/ void IDENTITY_APP;"` | marker present | `test/identity-mount.test.ts` — **10 RED**, incl. `/scim/v2/Users` answering `401` (guard reached) rather than `404` (absent), and the whole OIDC ladder | DEF | T1 |
| CP-S3 | `export const MOUNTED_SSO_ROUTES … = mountSsoRoutes(app);` (115) — **NEW ROW, wave 18.** The two SAML legs and the SHARED `GET\|POST\|DELETE /v1/admin/team/sso-config` row | `MUT-2 →"= [];/*MUT*/ void mountSsoRoutes;"` | marker present | `test/identity-mount.test.ts` — **12 RED**, incl. §4 "routes /v1/admin/auth/saml/acs — a bare call is a SAML refusal, never 404" | DEF | T1 |
| CP-S4 | `handleSamlAcs(identity.saml, new URL(c.req.url).search.slice(1))` — `src/identity/routes.ts`. **NEW ROW, wave 18.** The HTTP-Redirect binding signs the RAW query octets; `c.req.query()` decodes, and a decoded or re-serialised query defeats the whole signature check | `MUT-2` wrap the argument in `decodeURIComponent(...)` | marker present | `test/identity-mount.test.ts` — **2 RED** (the real SAML login and the replay case) | DEF | T1 |
| CP-S5 | `DELETE FROM sso_pending_flows WHERE state = ? RETURNING *` — `src/identity/adapters.ts`. **NEW ROW, wave 18.** ONE statement: consume-and-read atomically. A `SELECT` then a `DELETE` reintroduces SAML/OIDC replay, and NO test in `packages/{sso,identity}` would notice — they exercise the in-memory map | `MUT-2 →` a `SELECT` | marker present | `test/sso-store-contract.test.ts` (the package's OWN exported contract, run against the durable twin) + `test/identity-mount.test.ts` — **5 RED** across the two | DEF | T1 |
| CP-C10 | `export default withAliasCanonicalization(app);` (141) | `MUT-2 →"/*MUT*/ app;"` | `grep -nF 'export default /*MUT*/ app;'` | `test/alias.test.ts` (`/control/v1/*` → 404) | DEF | T2 |
| CP-C11 | `export const CONTROL_PLANE_ROUTE_MODULES: readonly GroupModule[] = GROUP_MODULES;` (98) | `MUT-2 "= GROUP_MODULES"→"= []/*MUT*/"` | marker present | `test/wiring.test.ts` / `test/contract.test.ts` (the anti-drift gate reads this) | DEF | T3 |
| CP-P9 | **NEW, WAVE 22 (FC-1).** The platform-operator fence on `setAdminDrain` (`routes/admin_config_ops.ts`). The operator drain is DEPLOYMENT state that three Workers read by primary key, so a tenant-scoped `admin.write` holder minting it would drain the fleet for every other tenant | `MUT-2 "if (scope.kind !== \"platform_operator\")"→"if (false as boolean)"` | `MUTATION-FC1-CP` present | `test/drain.test.ts` — **1 RED** (*REFUSES a tenant-scoped admin with 403 tenant_scope_denied*). The second, independent defence — `tenant_id: null` pinned by `drainDocument`, and every enforcer ignoring a tenant-attributed document — is gated separately in the same file and in `apps/mcp/test/drain.test.ts` | DEF | T1 |

### 8.3 Route registration `src/routes/index.ts` (2)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CP-R1 | `export const GROUP_MODULES: readonly GroupModule[] = [ …31 modules… ];` | `MUT-1 /^  adminApiKeyRoutes,$/m` (drop any one entry) | `grep -nF 'adminApiKeyRoutes,'` → nothing | `test/contract.test.ts` + `test/wiring.test.ts`; `buildHandlerTable()` also throws `orphan group` at module load | DEF | T1 |
| CP-R2 | `app.on(operation.method, operation.honoPath, handler);` (226) inside `registerRoutes` | delete the statement | `grep -nF 'app.on('` → nothing | `test/wiring.test.ts` (`app.routes` empty) | DEF | T1 |

### 8.4 Adapters `src/adapters.ts` — `resolveDeps` (737-760) (11)

Every property of the returned object gets a row. **CP-A10/CP-A11 are new** —
they were derived by the §2 walk and had never been enumerated.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CP-A1 | `const store = resolveStore(env, context);` → `D1ControlPlaneStore` | `MUT-2 "resolveStore(env, context)"→"resolveStore({} as never/*MUT*/, context)"` | marker present | `test/d1-store.test.ts`, `test/store-conformance.test.ts` | DEF | T1 |
| CP-A2 | `apiKeys: resolveApiKeys(env),` | `MUT-2 →"resolveApiKeys({} as never/*MUT*/)"` | marker present | `test/api-keys-d1.test.ts`, `test/auth.test.ts` | DEF | T1 |
| CP-A3 | `lifecycle: resolveLifecycle(env, store),` | `MUT-2 →"resolveLifecycle({} as never/*MUT*/, store)"` | marker present | `test/lifecycle-d1.test.ts` | DEF | T1 |
| CP-A4 | `rbac: resolveRbac(env),` | `MUT-2 →"resolveRbac({} as never/*MUT*/)"` | marker present | `test/rbac-d1.test.ts` | DEF | T1 |
| CP-A5 | `tenantDatabases: resolveTenantDatabases(env),` | `MUT-2 →"undefined as never/*MUT*/,"` | marker present | `test/tenant-db.test.ts`, `test/native-key-tenant-db.test.ts` | DEF | T1 |
| CP-A6 | `controlDatabase: resolveControlDatabase(env),` | `MUT-2 →"null/*MUT*/"` | marker present | `test/billing-replay.test.ts`, `test/worker-registry.test.ts` | DEF | T1 |
| CP-A7 | `runtime: new StoreRuntimeStatus(store),` | `MUT-2 →"{ report: async () => ({}) } as never/*MUT*/"` | marker present | `test/runtime-status.test.ts` | DEF | T3 |
| CP-A8 | `txtResolver: resolveTxtResolver(env),` | `MUT-2 →"{ lookupTxt: async () => [] } as never/*MUT*/"` | marker present | `test/site-domain-cas.test.ts`, `test/wiring.test.ts` | DEF | T2 |
| CP-A9 | `corsAllowedOrigin: … ? null : corsAllowedOrigin,` | `MUT-2 "? null : corsAllowedOrigin"→"? null : null/*MUT*/"` | marker present | `test/cors.test.ts` | DEF | T2 |
| CP-A10 | `listDefaultLimit: positiveInt(env.ADMIN_LIST_DEFAULT_LIMIT, DEFAULT_ADMIN_LIST_LIMIT),` — **NEW ROW** | `MUT-2 →"listDefaultLimit: /*MUT*/ DEFAULT_ADMIN_LIST_LIMIT,"` | marker present | `test/env-var-drift.test.ts` — **3 RED** ("has no undeclared read outside the exception table"). **drift** — no behavioural test sets a non-default limit | DEF · DRIFT | T2 |
| CP-A11 | `listMaxLimit: positiveInt(env.ADMIN_LIST_MAX_LIMIT, DEFAULT_ADMIN_LIST_MAX_LIMIT),` — **NEW ROW** | as CP-A10 | marker present | `test/env-var-drift.test.ts` — **drift** | DEF · DRIFT | T2 |

### 8.5 Deploy config `wrangler.toml` (6)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CP-T1 | `main = "src/worker.ts"` | `MUT-2 →"src/index.ts"` | mutated line present | `test/env-var-drift.test.ts` (NAME gate, wave 17). The workerd refusal (`MOUNTED_ROUTES` is an array) stays **DEPLOY-ONLY** | DEF · DRIFT | T1 |
| CP-T2 | `compatibility_flags = ["nodejs_compat"]` | `MUT-1` | anchor gone | `test/env-var-drift.test.ts` §"the deploy config's unobservable lines" (NAME gate). Behaviourally **DEPLOY-ONLY** — wave 17 measured GREEN across 587 tests | DEF · DRIFT | T1 |
| CP-T6 | `compatibility_date = "2025-06-01"` | `MUT-1` | anchor gone | `test/env-var-drift.test.ts`, same section | DEF · DRIFT | T1 |
| CP-T3 | `[[d1_databases]] binding = "DB"` + `migrations_dir = "../../sql/d1-ts/control"` | `MUT-4 [d1_databases]` | `grep -nF 'binding = "DB"'` → nothing | `test/d1-store.test.ts` (the whole file errors at setup: `Failed to execute 'applyD1Migrations': parameter 1 is not of type 'D1Database'` — **1 file RED, 36 specs unrun**) + `test/env-var-drift.test.ts` — **2 RED** (`expected [] to deeply equal [ 'DB' ]`). Measured wave 21; the old cell named `test/d1.ts`, which is the SETUP helper and not a test file | DEF | T1 |
| CP-T4 | `[triggers]` / `crons = ["* * * * *"]` | `MUT-2 "[triggers]"→"[disabled_triggers]"` | mutated line present | `test/cron-trigger.test.ts` — **GREEN across 428 tests before that gate** | DEF · DRIFT | T1 |
| CP-T5 | `[vars]`: `CONTROL_PLANE_NATIVE_API_KEYS`, `CONTROL_PLANE_STATIC_API_KEYS`, `TENANCY_LIFECYCLE`, `TENANT_RBAC_ACTIONS`, `CONTROL_PLANE_SEED` (all fail-closed empties) | `MUT-4 [vars]` | `grep -c '^CONTROL_PLANE_'` → 0 | `test/env-var-drift.test.ts` (wave 15) — **drift**. `test/auth.test.ts` covers it only partially | DEF · DRIFT | T2 |

---

## 9. `apps/mcp` — 35 seams

### 9.1 Entry module `src/worker.ts` (3)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-E1 | `export { default } from "./index.js";` (19) | `MUT-1 /export \{ default \} from "\.\/index\.js";/` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | DEF | T1 |
| MCP-E2 | `export { McpOauthFlowClaim } from "./oauth-flow.js";` (20) | `MUT-1` | anchor gone | `test/oauth-flow-claim.test.ts` (namespace unreachable → workerd start error) | DEF | T1 |
| MCP-E3 | `export { FerroGateMcpSession } from "./session.js";` (21) | `MUT-1` | anchor gone | `test/durable-upstreams.test.ts` — the only file that touches `MCP_SESSION`. **`src/worker.ts`'s docblock still cites `test/session.test.ts`, which DOES NOT EXIST in the repo.** Stale citation, carried from wave 13; re-point it or add the file | DEF | T1 |

### 9.2 Composition root `src/index.ts` (3)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-C1 | `ingressRouteModule(),` (61) in `MCP_ROUTE_MODULES` | `MUT-1 /^  ingressRouteModule\(\),$/m` | anchor gone | `test/contract.test.ts` (`mcpJsonRpc`, `executeMcpTool` unreachable) | DEF | T1 |
| MCP-C2 | `identityRouteModule(),` (62) | `MUT-1 /^  identityRouteModule\(\),$/m` | anchor gone | `test/contract.test.ts`, `test/identity.test.ts` (4 identity ops) | DEF | T1 |
| MCP-C3 | `const { app, router } = createMcpApp({ modules: MCP_ROUTE_MODULES });` (65) | `MUT-2 "{ modules: MCP_ROUTE_MODULES }"→"{}/*MUT*/"` | marker present | `test/contract.test.ts` | DEF | T1 |
| MCP-P12 | **NEW, WAVE 22 (FC-1).** The operator-drain gate in `src/http.ts::authenticateRequest` — `if (spend.billable) { const refusal = drainRefusal(await resolveDrain(spend.env)); … }`. The durable `runtime-state/drain` document, re-read PER REQUEST | `MUT-2` resolve the drain and IGNORE the answer: `await resolveDrain(spend.env); // MUTATION-FC1-MCP` | marker present | `test/drain-fleet.test.ts` — **3 RED** (*both doors … BOTH are shut after it*, *the REST tool transport shuts on the same one write*, *lifting the drain re-opens both doors*). The FLEET gate, so it also fails if `apps/agent-runtime` regresses | DEF | T1 |
| MCP-P13 | **NEW, WAVE 22 (FC-1).** The drain term in `/readyz` — `readinessReport(c.env, await resolveDrain(c.env as DrainBindings))` in `src/routes/index.ts` | `MUT-2` discard the resolved state: `await resolveDrain(…); const report = readinessReport(c.env);` | `MUTATION-FC1-MCP-READYZ` present | `test/drain.test.ts` — **1 RED** (*/readyz answers 503 not_ready with readiness_reason operator_drain*). `/healthz` is deliberately NOT gated on the drain: liveness must have no backend dependency | DEF | T1 |

### 9.3 Route registration `src/routes/index.ts` — `createMcpApp` (6)

**MCP-R3 is a new row** (the `/health` scaffold probe was never enumerated).
The old table's `MCP-R4` (`app.onError`) is **MCP-R6** here, and it is now gated.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-R1 | `router.register("getHealthz", …)` / `router.register("getReadyz", …)` (224-225) | `MUT-1 /router\.register\("get(Healthz\|Readyz)"/` | anchors gone | `test/health.test.ts` | DEF | T2 |
| MCP-R3 | `app.get("/health", (c) => c.json({ ok: true }));` (229) — **NEW ROW** | `MUT-2 →"/*MUT*/"` | `grep -nF 'app.get("/health"'` → nothing | `test/contract.test.ts` §"keeps the non-contract legacy probes working" + `test/health.test.ts` — **2 RED** | DEF | T3 |
| MCP-R2 | `app.get("/version", …)` (273-279) | `MUT-2 →"/*MUT*/ void PUBLIC_API_MAJOR;"` (a bare `MUT-1` on the first line orphans the arrow body) | marker present | `test/contract.test.ts` — **1 RED** (`expected 404 to be 200` at the `/version` fetch). The old cell wrote `test/contract.test.ts:432`; the line suffix made the path unresolvable to the runner AND the line had since moved to 439 | DEF | T3 |
| MCP-R4 | `for (const module of options.modules ?? []) { module.register(router); }` (238-240) | `MUT-1 /^    module\.register\(router\);$/m` | anchor gone | `test/contract.test.ts` (all 6 owned ops vanish) | DEF | T1 |
| MCP-R5 | `app.notFound((c) => { … })` (242-245) | `if (false as boolean)` guard (a `MUT-1` line delete orphans the block and yields a PARSE error, not a behaviour change — corrected wave 15) | `grep -nF 'if (false as boolean)'` | `test/contract.test.ts` (404 control probe) | DEF | T2 |
| MCP-R6 | `app.onError((error, c) => { … })` (247-256) — the 500 envelope | `MUT-2 "\"internal_error\""→"\"MUT_internal\""` (rename) **or** `if (false as boolean)` guard (full unmount) | marker present | `apps/mcp/test/error-envelope-mount.test.ts` (**wave 18**) — **1 RED** on the rename, **2 RED** on the unmount. **Was NO GATE: `grep -rn internal_error apps/mcp/test` returned nothing and the rename was GREEN across 397 tests** | DEF | T2 |

### 9.4 Ports `src/ports.ts` — `resolvePorts` (1769-1794) (8)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-P1 | `const auth = durableAuth(env);` → `new D1McpAuth(env.DB, …)` | `MUT-2 "if (env.DB === undefined) return new UnboundAuth();"→"return new UnboundAuth();/*MUT*/"` | marker present | `test/d1-auth.test.ts` | DEF | T1 |
| MCP-P2 | `const approvals = durableApprovals(env);` → `new D1ToolApprovals(env.DB)` | `MUT-2 "return new D1ToolApprovals(env.DB);"→"return new AutoApproval();/*MUT*/"` | marker present | `test/approvals.test.ts` | DEF | T1 |
| MCP-P3 | `const secrets = secretResolverOverride ?? workerSecretResolver(env);` `??` | `MUT-2 "workerSecretResolver(env)"→"{ resolve: async () => undefined }/*MUT*/"` | marker present | `test/secrets-mount.test.ts` (the file that exists BECAUSE this was the stub) | DEF | T1 |
| MCP-P4 | the VAR leg of the tool guardrail — `deterministicManagedActionGuardrails(parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS))`, now passed as `durableManagedActionGuardrails`' fallback argument (**rewritten wave 22**, MCP-P8 is the durable leg) | `MUT-2 "parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS)"→"{}/*MUT*/"` | marker present | `test/guardrails.test.ts`. The default project binds `DB` but activates no policy, so the durable half resolves to an empty set and the recipe still bites | DEF | T2 |
| MCP-P8 | `const guardrails = durableManagedActionGuardrails(env, deterministicManagedActionGuardrails(…));` — the DURABLE leg, **NEW ROW** (wave 22, FLEET-CONSISTENCY FC-3) | `MUT-2 "const guardrails = durableManagedActionGuardrails(\n    env,\n    deterministicManagedActionGuardrails(parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS)),\n  );"→"const guardrails = /*MUT*/ deterministicManagedActionGuardrails(parseGuardrailVar(env.FG_DEV_MCP_GUARDRAILS));"` — i.e. drop the durable wrapper and keep only the var, which is the pre-wave-22 posture | `grep -c 'durableManagedActionGuardrails(' src/ports.ts` → **0** (import only) | `test/fleet-guardrail-activation.test.ts` — **2 RED of 15**, both naming the operator's own activated code: *ONE managed-action activation shuts the MCP door AND is live on the gateway, same code*, and *the SAME activation screens a matching tool RESULT*. Unmounted, a tenant moves the payload into an MCP `tools/call` argument or reads it back out of a tool RESULT and the activated revision never sees it — the fleet-consistency defect class (`FLEET-CONSISTENCY.md` FC-3). The gate pins `FG_DEV_MCP_GUARDRAILS = ""` for the whole file, so nothing in it can be satisfied by the var | DEF | T1 |
| MCP-P14 | `const lifecycle = durableLifecycle(env);` — the TENANCY LIFECYCLE gate, **NEW ROW** (wave 22, FLEET-CONSISTENCY FC-2). Consumed by `src/http.ts::authenticateRequest` AHEAD of `ports.admission.admit`, which is not cosmetic: a suspended tenant must not reach the step that authorizes spend | `MUT-2 "const lifecycle = durableLifecycle(env);"→"const lifecycle = /*MUT*/ ALWAYS_ADMIT_LIFECYCLE;"` — the module intact, the MOUNT gone, which is this repo's dominant defect shape | `grep -c 'durableLifecycle(env)' src/ports.ts` → **0** | `test/fleet-tenancy-suspension.test.ts` — **8 RED of 12**, incl. *shuts all three doors with the SAME status and code after ONE suspension*, *computes an EMPTY exploit set*, the suspended-ANCESTOR case, the fail-closed 503, and *resolvePorts binds the durable lifecycle gate in the posture this Worker deploys*. Unmounted, a tenant the operator suspended keeps its still-valid credential and spends through MCP `tools/call` — wave 16's admission bypass in a second control. See `FLEET-CONSISTENCY.md` §7.5 M26 | DEF | T1 |
| MCP-P15 | `const entitlements = durableEntitlements(env);` — the PLAN/RBAC tool-entitlement ladder, **NEW ROW** (wave 24, cluster **S5** / finding **A3/R1**). Consumed at BOTH transports: `src/tools.ts::toolsCall` (JSON-RPC) and `src/routes/ingress.ts::executeMcpTool` (REST), each of which already called `ports.entitlements.toolExecutionDenial` and was answered `undefined` by `InMemoryEntitlements` on every deployed posture | `MUT-2 "const entitlements = durableEntitlements(env);"→"const entitlements = /*MUT*/ inMemoryPorts().entitlements;"` — the module intact, the MOUNT gone, which is the exact shape R1 turned out to be | `grep -c 'durableEntitlements(env)' src/ports.ts` → **0** | `test/entitlements.test.ts` — **5 RED of 8**: *DENIES both transports when the tenant's plan disables MCP tool execution*, *ADMITS both transports when the SAME plan enables it*, *lets a bound ROLE lift a plan denial*, *grants nothing for a role naming an UNDECLARED permission*, *DENIES a registered tenant whose plan_id names no plan row*. Unmounted, `plans.mcp_enabled = 0` withdraws nothing and the tenant keeps executing tools and spending upstream money | DEF | T1 |
| MCP-P7 | `const admission = durableAdmission(env);` — **NEW ROW** (task #114) | `MUT-2 →"const admission = /*MUT*/ undefined as never;"` | marker present | `test/admission.test.ts`, `test/d1-auth.test.ts`, `test/server-catalog.test.ts` — **12 RED** (per-key RPM, TOK-12 `request_limit_per_minute`, monthly budget, the D1 catalog + auth ladder) | DEF | T1 |
| MCP-P5 | `credentials: new DurableCredentialStore(env.MCP_OAUTH_KV, env.DB, … DurableOauthFlowStore(env.MCP_OAUTH_FLOWS))` | `MUT-2 "if (durableIdentityBound(env)) {"→"if (false) {/*MUT*/"` | marker present | `test/durable-identity.test.ts` | DEF | T1 |
| MCP-P6 | `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY) as IdentityCipherPort,` | `MUT-1 /cipher: identityCipherFrom\(/` | anchor gone | `test/durable-identity.test.ts` §the wave-17 case sealing with `identityCipherFrom(KEY_HEX)` and opening with the cipher `resolvePorts` chose. **Before it: GREEN — the base bundle already sets `cipher: webCryptoIdentityCipher()` (src/ports.ts:1404), so the mutation swapped the operator's configured AEAD key for an ephemeral per-isolate one and every stored OAuth grant became undecryptable on isolate recycle, invisibly** | DEF | T1 |

### 9.5 Deploy config `wrangler.toml` (10)

`apps/mcp/vitest.config.ts` sets `main: "./src/worker.ts"` explicitly (needed:
the in-memory port singleton and `setMcpEnvVar` require `SELF` in the test's own
isolate), which OVERRIDES the toml's `main`. Since wave 14 it also binds
`TEST_WRANGLER_TOML`, so the committed bytes are assertable.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-T1 | `main = "src/worker.ts"` | `MUT-2 →"src/index.ts"` | mutated line present | `test/env-var-drift.test.ts` (NAME gate, wave 17) | DEF · DRIFT | T1 |
| MCP-T2 | `compatibility_flags = ["nodejs_compat"]` | `MUT-1` | anchor gone | `test/env-var-drift.test.ts` §"the deploy config's unobservable lines" (NAME gate). Behaviourally **DEPLOY-ONLY** — GREEN across 359 tests | DEF · DRIFT | T1 |
| MCP-T3 | `[[kv_namespaces]] binding = "MCP_OAUTH_KV"` | `MUT-4 [kv_namespaces]` | `grep -nF 'MCP_OAUTH_KV'` → nothing | `test/durable-identity.test.ts` | DEF | T1 |
| MCP-T4 | `[[durable_objects.bindings]] name = "MCP_OAUTH_FLOWS"` / `class_name = "McpOauthFlowClaim"` | `MUT-3` | anchor gone | `test/oauth-flow-claim.test.ts` | DEF | T1 |
| MCP-T5 | `[[durable_objects.bindings]] name = "MCP_SESSION"` / `class_name = "FerroGateMcpSession"` | `MUT-3` | anchor gone | `test/durable-upstreams.test.ts` | DEF | T1 |
| MCP-T6 | `[[migrations]] tag = "v1"` / `new_sqlite_classes = ["McpOauthFlowClaim"]` | `MUT-1`; **also the `new_classes` substitution variant `MCP-T6b`** | anchor gone | `test/env-var-drift.test.ts` / `test/wrangler-bindings.test.ts` (wave 14/17). **Was NO GATE + DEPLOY-ONLY for thirteen waves.** The pool builds the namespace from the binding alone; Cloudflare rejects at deploy (`Cannot create binding for class … not currently defined`), and `new_classes` in its place DEPLOYS while silently giving the class the key-value backend | DEF · DRIFT | T1 |
| MCP-T7 | `[[migrations]] tag = "v2"` / `new_sqlite_classes = ["FerroGateMcpSession"]` | as MCP-T6 (+ `MCP-T7b`) | anchor gone | `test/env-var-drift.test.ts` §"introduces every bound DO class in a new_sqlite_classes migration (MCP-T6/T7)" + `test/wrangler-bindings.test.ts` §"introduces each bound class in a [[migrations]] new_sqlite_classes" — **2 RED**, measured wave 21. The old cell said only "as MCP-T6", which names no file a runner can resolve | DEF · DRIFT | T1 |
| MCP-T8 | `[[d1_databases]] binding = "DB"` / `database_name = "ferrogate-control"` — **no `migrations_dir`, unlike every other D1 stanza in the repo** | `MUT-4 [d1_databases]` | anchor gone | `test/d1-auth.test.ts`, `test/approvals.test.ts`. **The missing `migrations_dir` means `wrangler d1 migrations apply` has no target for this Worker's database; it is intentional only if the control-plane owns the schema. Unresolved since wave 13 — resolve or document before deploy** | DEF | T1 |
| MCP-T9 | `[vars] FG_DEV_IN_MEMORY_PORTS = "1"` — **a dev flag COMMITTED to the deploy config** | `MUT-2 →"\"0\""` | mutated line present | `test/wrangler-bindings.test.ts` §"is still spelled exactly as CLOUD-VERIFICATION §B1 overrides it" + `test/env-var-drift.test.ts` §"records that BOTH committed values reach this runner unchanged" — **2 RED**, measured wave 21. The old cell named `test/fixtures.ts`, a fixture module, not a gate. **`docs/rewrite/CLOUD-VERIFICATION.md` §B1 requires overriding this to `"0"` for the live deploy; a deploy that inherits `"1"` runs the in-memory port bundle in production.** Nothing mechanical stops it, and the mutation `"1"`→`"0"` leaves `test/health.test.ts` GREEN — the gate is a spelling gate by necessity | DEF · DRIFT | T1 |
| MCP-T10 | the LIVE cross-script counter stanza: `name = "RATE_LIMIT"` / `class_name = "RateLimiterDurableObject"` / `script_name = "ferrogate-gateway"` | `MUT-1 /^script_name = "ferrogate-gateway"$/` | `grep -nF 'script_name' apps/mcp/wrangler.toml` → nothing | `test/env-var-drift.test.ts` §"keeps RATE_LIMIT LIVE, CROSS-SCRIPT, and claimed by no migration", `test/wrangler-bindings.test.ts` §"the BORROWED counter namespace (#666)", and — behaviourally — `test/shared-rate-limit.test.ts`, which charges the window through the binding as the gateway would and requires this Worker to find it spent. **NO LONGER WORKERD-REFUSAL (#666):** the stanza was committed COMMENTED because workerd refuses to start on a `script_name` it cannot resolve, but that is a property of the SESSION — `vitest.config.ts` now registers an auxiliary `ferrogate-gateway` worker carrying the gateway's real limiter, so the live binding boots and is behaviourally provable. The rot directions are unchanged: commented out, `script_name` dropped (⇒ a SECOND private counter namespace and double the RPM allowance), or a `new_sqlite_classes` added here for a class this script does not export | DEF | T1 |

Also read by this app's `[vars]`: `FG_DEV_MCP_GUARDRAILS = ""` — covered by the
`test/env-var-drift.test.ts` derived read/declare contract rather than a row of
its own, because MCP-P4 already gates the value's consumer.

### 9.6 Durable Object lifecycle `src/unified.ts` (1)

A mount that is neither a route nor a port slot: the thing that CALLS a method
which would otherwise never be called. #765 was exactly that shape one step past
the usual one — `FerroGateMcpUnifiedSession.close()` was written by #687, tested
by #687, and invoked by nothing, so every `initialize` minted a Durable Object
that lived forever.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| MCP-U1 | **NEW, #765.** The IDLE REAPER: `alarmArmedUnix: await this.#arm(…)` in `open`/`reconcile`(×2)/`recordUpstreamHealth`/`append` (5 call sites) plus `await this.close()` inside `override async alarm()`. Without the arming no alarm is ever scheduled and nothing evicts; without the `close()` the alarm fires and the session survives | `MUT-2` neutralise all five arms (replace `this.#arm(` with a function that returns the stored value unchanged); **and separately** `MUT-1` the `await this.close();` in `alarm()` | `grep -c 'MUTATION-765-ARM' src/unified.ts` → **5**; `grep -c 'MUTATION-765-CLOSE'` → 1 | `test/unified-session-eviction.test.ts` — **9 RED of 10** on the arming mutation (every behavioural one at `runDurableObjectAlarm` returning `false`; the survivor asserts constants only), **6 RED** on the `close()` deletion (the mount test at `expected 200 to be 400`: the resume is served as if the session were live). The refusal is TWO layers — the ingress answers off `store.status`, the object's own `replay` refuses with the same reason — and each has its own gate: dropping either alone is **1 RED**, dropping both is **3 RED**. The POLICY is pinned separately: 30min→5min is **1 RED**, and removing the renewal debounce is **1 RED** | DEF | T1 |

**Not rows, but recorded here because the next wave will ask.** #687 landed
`[[durable_objects.bindings]] MCP_CLIENT_SESSION` and `[[migrations]] tag = "v3"`
in `apps/mcp/wrangler.toml` and registered neither in §9.5, so this app's deploy
config has 12 seams and 10 rows. #765 did not add them: they are #687's to
enumerate with #687's mutations, and inventing rows for someone else's slice is
how a table stops meaning what it says.

---

## 10. `apps/agent-runtime` — 38 seams

### 10.1 Entry module `src/worker.ts` (3)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| AR-E1 | `export { default } from "./index.js";` (16) | **must DELETE the line.** Appending a named export beside it is a no-op and reads as a false GREEN (corrected wave 17) | `grep -nF 'export { default } from "./index.js"'` → nothing | every `SELF.fetch` suite; `test/health.test.ts` | DEF | T1 |
| AR-E2 | `export { AgentRunState } from "./runs/do.js";` (17) | `MUT-1` | `grep -cF 'export { AgentRunState }' src/worker.ts` → 0 | `test/lifecycle.test.ts`, `test/sse.test.ts`, `test/wrangler-bindings.test.ts` | DEF | T1 |
| AR-E3 | `export { WorkerPlane } from "./workers/plane.js";` (18) | `MUT-1` | `grep -cF 'export { WorkerPlane }' src/worker.ts` → 0 | `test/internal-auth.test.ts`, `test/cancel.test.ts`, `test/wrangler-bindings.test.ts` | DEF | T1 |

### 10.2 Composition root `src/index.ts` (11)

`AR-C8` of the old table is **deleted** — it described `app.get("/healthz"…)` /
`app.get("/readyz"…)` at lines 37-38, which no longer exist (§3.3). `AR-C10`
supersedes it.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| AR-C1 | `app.onError(errorHandler);` (33) | `MUT-1` | anchor gone | `test/contract.test.ts` (error envelope) | DEF | T2 |
| AR-C2 | `app.notFound(notFoundHandler);` (34) | `MUT-2 →"/*MUT*/ void notFoundHandler;"` | `grep -nF 'app.notFound('` → nothing | `apps/agent-runtime/test/routes/root-mounts.test.ts` (**wave 18**) — **3 RED**. **Was NO GATE:** `contractAuth` is mounted on `/v1/*` and `src/middleware/auth.ts:574,585` throws an identical `404 not_found` for an undocumented path inside an owned prefix, so this hook only ever fires OUTSIDE `/v1/*` — the region no test probed. Unmounted, Hono answers a plain-text 404 with no envelope and no correlation id | DEF | T2 |
| AR-C3 | `app.use("*", correlation);` (35) | `MUT-1` | anchor gone | `test/contract.test.ts` (`x-request-id`) | DEF | T2 |
| AR-C10 | `app.route("/", healthRoutes);` (44) — the three shared anonymous probes; must stay AHEAD of `app.use("/v1/*", contractAuth)` | `MUT-1 /app\.route\("\/", healthRoutes\);/` | anchor gone | `test/routes/health-contract.test.ts` §"the deployed Worker serves the contract probes" (drives `SELF`) **and** `test/contract.test.ts` — **5 RED** | DEF | T2 |
| AR-V1 | `app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR, operations: EXPECTED_OWNED_OPERATION_COUNT }));` (45-47) — **NEW ROW** | `MUT-2 →"/*MUT*/ void PUBLIC_API_MAJOR; void EXPECTED_OWNED_OPERATION_COUNT;"` | `grep -nF 'app.get("/version"'` → nothing | `apps/agent-runtime/test/routes/root-mounts.test.ts` (**wave 18**) — **2 RED**. **Was in no wave's table and gated by nothing**: deleting it was GREEN across all 436 tests, and unmounted it falls through to AR-C2's 404 | DEF | T3 |
| AR-C4 | `app.use("/v1/*", contractAuth);` (55) | `MUT-1` | anchor gone | `test/isolation.test.ts`, `test/internal-auth.test.ts` (tenant-vs-worker credential split) | DEF | T1 |
| AR-C5 | `app.route("/", runRoutes);` (57) | `MUT-1` | anchor gone | `test/lifecycle.test.ts`, `test/contract.test.ts` | DEF | T2 |
| AR-C6 | `app.route("/", agentRoutes);` (58) | `MUT-1` | anchor gone | `test/agents.test.ts`, `test/contract.test.ts` | DEF | T2 |
| AR-C7 | `app.route("/", workerRoutes);` (59) — the six `auth.kind: "internal"` callbacks | `MUT-1` | anchor gone | `test/internal-auth.test.ts`, `test/isolation-grant.test.ts` | DEF | T1 |
| AR-C9 | `export { AgentRunState } …` / `export { WorkerPlane } …` in **index.ts** (64-65) — duplicates AR-E2/E3 | `MUT-1` both, **and** the identity variant `MUT-2 "export { AgentRunState } from \"./runs/do.js\";"→"export { WorkerPlane as AgentRunState } from \"./workers/plane.js\"; /*MUT*/"` | anchors gone / marker present | `test/wrangler-bindings.test.ts` §"keeps the composition root's duplicate DO exports IDENTICAL to the entry module's (AR-C9)" (**wave 21**) — **1 RED** on deletion (`src/index.ts no longer re-exports AgentRunState`), **1 RED** on the identity variant (`is a DIFFERENT class than src/worker.ts's`). **The old cell's justification was WRONG**: `main` CANNOT point at `src/index.ts` — it exports `OWNED_OPERATIONS`, an array, and workerd rejects a non-function named export on the entry module (`src/worker.ts`'s own docblock says so). These two lines therefore never resolve a `class_name` in any configuration; what the gate pins is that the two candidate modules AGREE, which nothing asserted before | DEF · NOT-MUTABLE | T3 |
| AR-C11 | `export default app;` (67) | `MUT-2 →"/*MUT*/ void app;"` | marker present | `test/health.test.ts` — **1 RED**, `TypeError: apps/agent-runtime/src/worker.ts does not export a default entrypoint` (AR-E1 re-exports this, so the failure surfaces on the ENTRY module). A runtime refusal, not a bundler error — §5 rule 4 holds. One file is named so the row is provable NARROWLY (wave 21) | DEF | T1 |
| AR-P10 | **NEW, WAVE 22 (FC-1).** The operator-drain gate in `src/middleware/auth.ts::bearerAuth`, keyed on `isDrainGuardedOperation(operation.operationId)` (5 of the 15 owned operations). On the BEARER leg only, which is structurally why the six `auth.kind: "internal"` callbacks keep serving while draining | `MUT-2` resolve the drain and drop the refusal: `// MUTATION-FC1-AR: resolve the drain and then IGNORE the answer` | marker present | `test/durable/drain.spec.ts` — **4 RED**, incl. *REFUSES the A2A ingress too, not just the job verb*. **ESC**: the app's own default project has no `CONTROL_DB`, so the durable leg is only reachable under `test/durable/harness/` | DEF · ESC | T1 |
| AR-P11 | **NEW, WAVE 22 (FC-1).** The durable term in the `/readyz` conjunction — `!runtimeEnabled(env) \|\| operatorDrain.draining` in `src/routes/health.ts` | `MUT-2 →"const draining = !runtimeEnabled(env);"` | `MUTATION-FC1-READYZ` present | `test/durable/drain.spec.ts` — **1 RED** (*/readyz answers 503 not_ready with readiness_reason operator_drain*) | DEF · ESC | T1 |

### 10.3 Ports `src/ports.ts` — `resolveDeps` (9)

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| AR-P1 | `env.DB !== undefined ? d1ApiKeyPort(env.DB) :` — **ESC** | any edit removing the D1 leg | `grep -nF 'd1ApiKeyPort' src/ports.ts` → import only | `test/durable/mount.spec.ts` — **5 RED of 7**, and **only under the chained config; the app's own main project stays GREEN**. Narrow escalated command (1.7 s, wave 21): `bunx vitest run --config test/durable/harness/vitest.config.ts test/durable/mount.spec.ts`. The harness is SOUND (§4.3): its `main` is the real `src/worker.ts` | ESC | T1 |
| AR-P2 | `env.CONTROL_DB !== undefined ? d1WorkerIdentityPort(env.CONTROL_DB) :` — **ESC** | as AR-P1 | `grep -nF 'd1WorkerIdentityPort'` → import only | `test/durable/mount.spec.ts` — **5 RED of 7** under the same escalated command as AR-P1, escalation-only (wave 21) | ESC | T1 |
| AR-P3 | `if (apiKeys === undefined \|\| workerIdentities === undefined) return undefined;` — the FAIL-CLOSED gate | `MUT-1 /if \(apiKeys === undefined/` | anchor gone | `test/contract.test.ts` (dev flag unset + no D1 ⇒ 503 `agent_runtime_unavailable`) | DEF | T1 |
| AR-P8 | `admission: admissionFromEnv(env as AdmissionBindings),` — **NEW ROW** (task #115) | `MUT-2 →"admission: /*MUT*/ admissionFromEnv({} as AdmissionBindings),"` | marker present | `test/admission.test.ts` — **4 RED** (tenant-scope RPM across sibling keys, `rpm_limit = 0` is a stop not "unlimited", key-scope windows, `enabled:false` ⇒ 403 not 429) | DEF | T1 |
| AR-P4 | `governance: inMemoryGovernancePort({ governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS) }),` (the old `AR-G1` is the same line; merged) | `MUT-2 "parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS)"→"[]/*MUT*/"`. **The wave-13 recipe `→ ["*"]` is a NO-OP**: egress is matched with `allowedHosts.has(host)`, exact membership, so `"*"` is a wildcard for `grantableCapabilities` and a literal hostname for egress | marker present | `test/governance-mount.test.ts` (wave 14). **NOT** ~~`test/isolation-grant.test.ts`~~ (citation WITHDRAWN) — that file builds the port by hand eleven times and never calls `resolveDeps`, so #471's sealed-by-default guarantee was proven for the POLICY and not for the MOUNT | DEF | T1 |
| AR-P5 | the VAR leg of the upstream registry — `inMemoryAgentUpstreamPort(parseJsonVar(env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined), []))`, now passed as `agentUpstreamPortFromEnv`'s fallback argument (**rewritten wave 21**, AR-P9 is the durable leg) | `MUT-2 "env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined)"→"env.AGENT_UPSTREAMS/*MUT*/"` | marker present | `test/agents.test.ts` (14 A2A dispatch cases). The default project binds no `CONTROL_DB`, so `agentUpstreamPortFromEnv` returns exactly this port and the recipe still bites | DEF | T2 |
| AR-P9 | `upstreams: agentUpstreamPortFromEnv(env, inMemoryAgentUpstreamPort(…)),` — the DURABLE leg, **NEW ROW** (wave 21, cutover A3 leg 2) — **ESC** | `MUT-2 "agentUpstreamPortFromEnv(\n      env,\n      "→"((_e: unknown, p: AgentUpstreamPort) => p)(\n      env,\n      /*MUT*/ "` — i.e. drop the durable port and keep only the var fallback, which is the pre-wave-21 posture | `grep -nF 'agentUpstreamPortFromEnv' src/ports.ts` → import only | `test/durable/agent-upstream-withdrawal.spec.ts` — **10 RED of 13** under `bunx vitest run --config test/durable/harness/vitest.config.ts test/durable/agent-upstream-withdrawal.spec.ts`, and **the app's own main project stays GREEN — measured, 434/434** — which is why this row is ESC and not DEF. Two of the RED are the defect stated exactly: after the document is deleted, the dispatch is `422 egress_host_not_governed` naming `durable-and-var.upstream.invalid`, i.e. the var half resurrected an upstream the operator withdrew. The harness binds a MIGRATED `CONTROL_DB` and commits `AGENT_UPSTREAMS = "[]"`, whose inertness the spec asserts directly rather than in prose. Unmounted, a withdrawn upstream stays reachable for A2A dispatch — the fleet-consistency defect class (`FLEET-CONSISTENCY.md` §1, shipped defect #2). The FLEET EFFECT of the same withdrawal — both doors, one assertion path — is `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` (wave 21 INTEGRATE), which is where a regression on EITHER door lands in one test | ESC | T1 |
| AR-P6 | the VAR leg of the A2A guardrail — `deterministicGuardrailPort(parseJsonVar(env.FG_DEV_A2A_GUARDRAILS, {}))`, now passed as `durableA2aGuardrailPort`'s fallback argument (**rewritten wave 22**, AR-P10 is the durable leg) | `MUT-2 "env.FG_DEV_A2A_GUARDRAILS"→"undefined/*MUT*/"` | marker present | `test/guardrails.test.ts`. The default project binds no `CONTROL_DB`, so the durable half short-circuits to `allow` and the recipe still bites | DEF | T2 |
| AR-P12 | `guardrails: durableA2aGuardrailPort(env, deterministicGuardrailPort(…)),` — the DURABLE leg, **NEW ROW** (wave 22, FLEET-CONSISTENCY FC-3) — **ESC** | `MUT-2 "guardrails: durableA2aGuardrailPort(\n      env,\n      "→"guardrails: ((_e: unknown, p: GuardrailPort) => p)(\n      env,\n      /*MUT*/ "` — drop the durable port and keep only the var fallback, the pre-wave-22 posture | `grep -c 'durableA2aGuardrailPort(' src/ports.ts` → **0** (import only) | `test/durable/guardrail-policy-activation.spec.ts` — **3 RED of 7** under `bunx vitest run --config test/durable/harness/vitest.config.ts test/durable/guardrail-policy-activation.spec.ts`, and **the app's own main project stays GREEN — measured, 446/446** — which is why this row is ESC and not DEF. The RED states the defect exactly: an activated policy that should refuse `403 <operator code>` instead answers `422 egress_host_not_governed` naming `guardrail-probe.upstream.invalid`, i.e. the payload cleared every content control and was at the point of being forwarded. The harness binds a MIGRATED `CONTROL_DB` and commits `FG_DEV_A2A_GUARDRAILS = ""`, so nothing in the spec can be satisfied by the var | ESC | T1 |
| AR-P13 | `apiKeys: tenancyGatedApiKeyPort(resolvedApiKeys, d1LifecycleRowSource(env.CONTROL_DB, env.DB))` — the TENANCY LIFECYCLE gate, **NEW ROW** (wave 22, FLEET-CONSISTENCY FC-2) — **ESC**. It WRAPS the credential port rather than sitting beside it, so the durable leg AND the dev leg are both gated; the shipped defect was a lifecycle outcome only the dev table could produce | `MUT-2 ": tenancyGatedApiKeyPort(resolvedApiKeys, d1LifecycleRowSource(env.CONTROL_DB, env.DB));"→": /*MUT*/ resolvedApiKeys;"` | `grep -c 'tenancyGatedApiKeyPort(resolvedApiKeys' src/ports.ts` → **0** | `test/durable/guardrail-policy-activation.spec.ts`' sibling `test/durable/lifecycle.spec.ts` — **6 RED** under `bunx vitest run --config test/durable/harness/vitest.config.ts`, AND **7 RED in `apps/mcp/test/fleet-tenancy-suspension.test.ts`**. The second number is the one that matters: the FLEET gate fails for a regression on ANOTHER Worker, which is the property no per-Worker suite has. **ESC** because the app's default project binds no `CONTROL_DB`. See `FLEET-CONSISTENCY.md` §7.5 M27 | ESC | T1 |
| AR-P7 | `config: inMemoryConfigPort(configFromEnv(env)),` | `MUT-2 "configFromEnv(env)"→"configFromEnv({} as never/*MUT*/)"` | marker present | `test/budget.test.ts` (`AGENT_JOB_MAX_OPEN_PER_TENANT`, `…_DISPATCH_TTL_SECS`) | DEF | T2 |

### 10.4 Deploy config `wrangler.toml` (11)

`vitest.config.ts` sets `main: "./src/worker.ts"` explicitly and **pins
`FG_DEV_IN_MEMORY_PORTS`, `FG_REQUIRE_PRODUCTION_MTLS` and
`CONTAINER_GOVERNED_EGRESS_HOSTS` as miniflare bindings**, which win over the
toml. AR-T6/T7/T8 can therefore only ever be **drift** gates — §1 trap 4. Since
wave 14 it also binds `TEST_WRANGLER_TOML`.

**This app is NOT covered by `e2e/`** (only gateway + mcp are), so a
DEPLOY-ONLY row here has no `wrangler dev` fallback in CI either.

| ID | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| AR-T1 | `main = "src/worker.ts"` | `MUT-2 →"src/index.ts"` | mutated line present | `test/wrangler-bindings.test.ts` (NAME gate, wave 14) | DEF · DRIFT | T1 |
| AR-T2 | `compatibility_date = "2025-11-17"` + `compatibility_flags = ["nodejs_compat"]` | `MUT-1 /compatibility_(date\|flags)/` | anchors gone | `test/wrangler-bindings.test.ts` §"the runtime contract at the top of the file". **The flags alone are GREEN across 383 tests** (wave 17); the whole-suite RED comes from deleting the DATE — at 2025-11-17 the date CARRIES `enable_ctx_exports` | DEF · DRIFT | T1 |
| AR-T3 | `[[durable_objects.bindings]] name = "AGENT_RUN_STATE"` / `class_name = "AgentRunState"` | `MUT-3` | anchor gone | `test/lifecycle.test.ts`, `test/sse.test.ts`, `test/wrangler-bindings.test.ts` | DEF | T1 |
| AR-T4 | `[[durable_objects.bindings]] name = "WORKER_PLANE"` / `class_name = "WorkerPlane"` | `MUT-3` | anchor gone | `test/internal-auth.test.ts`, `test/cancel.test.ts`, `test/wrangler-bindings.test.ts` | DEF | T1 |
| AR-T5 | `[[migrations]] tag = "v1"` / `new_sqlite_classes = ["AgentRunState", "WorkerPlane"]` | `MUT-1`; **also the `new_classes` substitution variant `AR-T5b`** | anchor gone | `test/wrangler-bindings.test.ts` (wave 14). **Was NO GATE with NO local proof channel of any kind** — this app is not in `e2e/` either | DEF · DRIFT | T1 |
| AR-T6 | `[vars] FG_DEV_IN_MEMORY_PORTS = "1"` — dev flag committed to the deploy config | `MUT-2 →"\"0\""` | mutated line present | `test/wrangler-bindings.test.ts` + `test/env-var-drift.test.ts` — **drift only** (the binding is pinned). **CLOUD-VERIFICATION §B1 requires `"0"` at deploy** | DEF · DRIFT | T1 |
| AR-T7 | `[vars] FG_REQUIRE_PRODUCTION_MTLS = "0"` | `MUT-2 →"\"1\""` | mutated line present | `test/wrangler-bindings.test.ts` + `test/env-var-drift.test.ts` — **drift**. **NOT** ~~`test/mtls.test.ts`~~ (citation WITHDRAWN), which pins its own binding (corrected wave 17). **Committed OFF — must be `"1"` in production** | DEF · DRIFT | T1 |
| AR-T8 | `[vars] CONTAINER_GOVERNED_EGRESS_HOSTS = ""` (sealed by default, #471) | `MUT-2 →"\"*\""` | mutated line present | `test/env-var-drift.test.ts` — **drift**. The behavioural proof is AR-P4's `test/governance-mount.test.ts` | DEF · DRIFT | T1 |
| AR-T9 | `[vars] AGENT_RUNTIME_ENABLED`, `AGENT_JOB_MAX_OPEN_PER_TENANT`, `AGENT_JOB_DISPATCH_TTL_SECS` | `MUT-1 /^AGENT_(RUNTIME_ENABLED\|JOB_)/` | anchors gone | `test/env-var-drift.test.ts` (wave 15) — **drift**. `test/budget.test.ts` is weak here: absent ≈ default, so a deletion is behaviourally invisible | DEF · DRIFT | T2 |
| AR-T11 | **NO `[[d1_databases]]` stanza exists in this file.** `AR-P1`/`AR-P2` read `env.DB` / `env.CONTROL_DB`, which only the durable HARNESS binds | — | `grep -cF 'd1_databases' wrangler.toml` → 0 (uncommented) | **NONE, and NOT-MUTABLE BY CATEGORY — this is not the same as "unproven".** The seam is the ABSENCE of a stanza: there is nothing on disk to delete, so no mutation exists that could turn a gate red. The inverse — asserting that no `[[d1_databases]]` is declared — is deliberately NOT written, because it would lock in the very posture this row flags as a deploy blocker, the mistake wave 15 made on `GW-C11` (§3.2). As committed, a deployed agent-runtime has no D1, so `resolveDeps` takes the dev branch — and `FG_DEV_IN_MEMORY_PORTS = "1"` (AR-T6) is committed, so it *succeeds* with an in-memory credential table instead of failing closed. The exact stanzas to add are written out as comments in that file and in `src/ports.ts`'s WIRING block. **Closing this row means adding the stanza, not adding a test** | NONE · NOT-MUTABLE | T1 |
| AR-T10 | the LIVE cross-script counter stanza (`script_name = "ferrogate-gateway"`) | `MUT-1 /^script_name = "ferrogate-gateway"$/` | `grep -nF 'script_name' apps/agent-runtime/wrangler.toml` → nothing | `test/env-var-drift.test.ts` §"keeps RATE_LIMIT LIVE, CROSS-SCRIPT, and claimed by no migration", `test/wrangler-bindings.test.ts` §"the BORROWED counter namespace (#666)", and behaviourally `test/shared-rate-limit.test.ts` — same three rot directions as MCP-T10, and no longer WORKERD-REFUSAL for the same reason (#666). A `RateLimiterDurableObject` defined in THIS Worker instead would compile, deploy and pass every test while handing `/v1/agent-jobs` its own full RPM quota — a quieter version of the admission bypass wave 16 closed | DEF | T1 |

---

## 11. `apps/telemetry` — 17 seams

| ID | File | Seam | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|---|
| TEL-E1 | `src/worker.ts` | `export { default } from "./index.js";` (15) | `MUT-1` | anchor gone | every `SELF.fetch` suite; `test/health.test.ts` | DEF | T1 |
| TEL-C1 | `src/index.ts` | `const app = createTelemetryApp();` (40) + `export default app;` (42) | `MUT-2 "export default app;"→"/*MUT*/ void app;"` | `grep -nF 'export default app;'` → nothing | `test/routes.test.ts` (drives the DEFAULT EXPORT) | DEF | T1 |
| TEL-A1 | `src/app.ts` | `app.get("/healthz", …)` (94) | `MUT-1` | anchor gone | `test/routes.test.ts`, `test/health.test.ts` | DEF | T2 |
| TEL-A2 | `src/app.ts` | `app.get("/readyz", …)` returning **503 when the sink is unconfigured** (98-112) | `MUT-2 "configured ? 200 : 503"→"200/*MUT*/"` | marker present | `test/health.test.ts` | DEF | T2 |
| TEL-A7 | `src/app.ts` | `app.get("/health", (c) => c.json({ ok: true }));` (117) — **NEW ROW** | `MUT-2 →"/*MUT*/"` | `grep -nF 'app.get("/health"'` → nothing | `test/health.test.ts` + `test/routes.test.ts` §"registers each entry of TELEMETRY_ROUTES" / "serves every declared route through SELF" — **3 RED** | DEF | T3 |
| TEL-A8 | `src/app.ts` | `app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));` (118) — **NEW ROW** | `MUT-2 →"/*MUT*/ void PUBLIC_API_MAJOR;"` | marker present | `test/health.test.ts` §"GET /version reports the public API major" + `test/routes.test.ts` §"registers each entry of TELEMETRY_ROUTES on the exported app" / §"serves every declared route through SELF (never 404)" — **3 RED**, re-measured wave 21. The old cell said "same three", a back-reference no runner can resolve | DEF | T3 |
| TEL-A3 | `src/app.ts` | `for (const [path, signal] of Object.entries(OTLP_ROUTES)) { app.post(path, …) }` (122-127) | `if (false as boolean)` guard (a `MUT-1` line delete orphans the block — corrected wave 15) | marker present | `test/routes.test.ts`, `test/ingest.test.ts` | DEF | T1 |
| TEL-A4 | `src/app.ts` | `const denial = requireBearer(c.req.raw, c.env?.COLLECTOR_TOKEN); if (denial) return denial;` (124-125) | `MUT-1 /if \(denial\) return denial;/` | anchor gone | `test/ingest.test.ts` (anonymous ingest must be refused) | DEF | T1 |
| TEL-A5 | `src/app.ts` | `app.all(path, () => … 405 …)` (129-137) | `if (false as boolean)` guard | marker present | `test/routes.test.ts` (GET on an OTLP path ⇒ 405, not 404) | DEF | T3 |
| TEL-A6 | `src/app.ts` | `app.notFound((c) => json(errorBody(TelemetryErrorCode.NotFound, …), 404))` (140-145) | `if (false as boolean)` guard | marker present | `test/routes.test.ts` | DEF | T3 |
| TEL-P1 | `src/ports.ts` | `resolveSink(env)` → `return new AnalyticsEngineSink(dataset);` (45) | `MUT-2 →"return null;/*MUT*/"` | marker present | `test/ingest.test.ts`, `test/health.test.ts` (`/readyz` flips to 503) | DEF | T1 |
| TEL-T1 | `wrangler.toml` | `main = "src/worker.ts"` | `MUT-2 →"src/index.ts"` | mutated line present | `test/env-var-drift.test.ts` (NAME gate, wave 17). `vitest.config.ts` overrides `main` and telemetry is not in `e2e/`, so the workerd entrypoint check itself is **DEPLOY-ONLY with no CI fallback** | DEF · DRIFT | T1 |
| TEL-T5 | `wrangler.toml` | `compatibility_flags = ["nodejs_compat"]` | `MUT-1` | anchor gone | `test/env-var-drift.test.ts` §"the deploy config's unobservable lines" (NAME gate). Behaviourally **DEPLOY-ONLY** — GREEN across 104 tests | DEF · DRIFT | T1 |
| TEL-T6 | `wrangler.toml` | `compatibility_date = "2025-06-01"` | `MUT-1` | anchor gone | `test/env-var-drift.test.ts`, same section | DEF · DRIFT | T1 |
| TEL-T2 | `wrangler.toml` | `[[analytics_engine_datasets]] binding = "TELEMETRY"` | `MUT-4 [analytics_engine_datasets]` | `grep -nF 'TELEMETRY'` → nothing | `test/ingest.test.ts` (503 `telemetry_sink_unavailable`) | DEF | T1 |
| TEL-T3 | `wrangler.toml` | `[vars] MAX_BODY_BYTES = "4194304"` | `MUT-1 /^MAX_BODY_BYTES/` | anchor gone | `test/env-var-drift.test.ts` (wave 15) — **drift**. `vitest.config.ts` pins `"2048"`, so the committed value is never exercised | DEF · DRIFT | T2 |
| TEL-T4 | `wrangler.toml` | `[observability]` / `[observability.logs]` / `[observability.traces]` | `MUT-4 [observability]`, **and** the two narrower rot directions: `MUT-2 "[observability.traces]\nenabled = true"→"…false"`; `MUT-2 "invocation_logs = false"→"…true"` | anchors gone / mutated line present | `test/env-var-drift.test.ts` §"keeps Workers Logs and Traces enabled on the observability Worker (TEL-T4)" + §"declines invocation_logs, the billing decision the block records (TEL-T4)" (**wave 21**) — **2 RED** on the whole-block delete, **1 RED** on each narrower direction (`expected 2 to be 3`; `invocation_logs`). **Was DEPLOY-ONLY, NO GATE through waves 15/18/19/20** on the reasoning that Workers Logs config has no local effect — true of the BEHAVIOUR, and it left the one Worker whose whole job is observability able to ship with its own logs and traces off, silently. The behavioural half stays DEPLOY-ONLY; the committed bytes are now pinned on the same drift channel as TEL-T3 | DEF · DRIFT | T3 |

`apps/telemetry/vitest.config.ts` binds **no** `TEST_WRANGLER_TOML`; its drift
gate reads the committed file through `import.meta.glob("../wrangler.toml",
{ query: "?raw" })`. Different channel, same bytes — see §4.4.

---

## 12. `apps/cli` — 8 seams (a Bun binary, not a Worker)

Six live in `createDefaultRuntime()`; two are the shared transport and the
process-entry guard. Every one can be swapped for a legitimate TEST double
(`createTestRuntime`, `createInMemory*`, `createStructuralConfigValidator`,
`createMemoryContextStorage`) without breaking a compile — which is exactly why
each needs a gate only the PRODUCTION implementation can pass. Before wave 13
only `client` had one; **CLI-7 and CLI-8 were closed in wave 18.**

| ID | Seam (exact code) | Mutation | Confirm | Expected RED | Channel | Tier |
|---|---|---|---|---|---|---|
| CLI-1 | `const io = createNodeIo();` (38) | `MUT-2 →"createInMemoryIo({})/*MUT*/"` | marker present | `test/composition-root.test.ts` — "io.env IS process.env" (identity, not equality), real `readFile`, real CSPRNG, wall clock | DEF | T1 |
| CLI-2 | `client: createFetchControlPlaneClient(fetch, transport),` (45) | `MUT-2 →"createInMemoryControlPlaneClient()/*MUT*/"` | marker present | `test/transport.test.ts` §"the shipped runtime wires the real transports" | DEF | T1 |
| CLI-3 | `gatewayClient: createFetchGatewayClient(fetch, transport),` (46) | `MUT-2 →"createInMemoryGatewayClient()/*MUT*/"` | marker present | `test/composition-root.test.ts` — "a legacy `assets` verb reaches fetch, not the in-memory fake" | DEF | T2 |
| CLI-4 | `contextStorage: createFileContextStorage(io),` (47) | `MUT-2 →"createMemoryContextStorage()/*MUT*/"` | marker present | `test/composition-root.test.ts` — `contextStorage.path()` must be `$FERROGATE_CLI_HOME/contexts.toml`, resolved through the runtime's OWN `io.env` | DEF | T2 |
| CLI-5 | `configValidator: createFerrogateConfigValidator(),` (48) | `MUT-2 →"createStructuralConfigValidator()/*MUT*/"` | marker present | `test/composition-root.test.ts` — "rejects a document the structural validator would ACCEPT" (+ accepts a real Caddyfile, so the refusal is not blanket) | DEF | T2 |
| CLI-6 | `keyHasher: createNodeKeyHasher(),` (49) | `MUT-2 →"{ hash: async () => \"0\".repeat(128) }/*MUT*/"` | marker present | `test/composition-root.test.ts` — "hash() reproduces the gateway's stored BLAKE2b-512 construction" | DEF | T1 |
| CLI-7 | `const transport = { readFile: (path: string) => io.readFile(path) };` (42) — the `--ca-bundle` TLS seam shared by BOTH clients | `MUT-2 →"{ readFile: async () => \"\" }/*MUT*/"` | marker present | `apps/cli/test/composition-root-transport.test.ts` (**wave 18**) — **3 RED**. **Was NO GATE since wave 13**: `test/transport.test.ts` builds its OWN transport and never calls `createDefaultRuntime()`, and the seam is unreachable under the Node test host at all (see §3.4) | DEF | T2 |
| CLI-8 | `if (entry !== undefined && (entry.endsWith("/index.ts") \|\| entry.endsWith("/ferrogate"))) { process.exit(await main(…)); }` (137-140) | `MUT-2` each arm separately → `/*MUT*/ false` | marker present | `apps/cli/test/composition-root-transport.test.ts` (**wave 18**) — **1 RED per arm**, by spawning real `bun` processes on both argv shapes. **Was NO GATE since wave 13** — vitest imports `main` directly and never runs the guard | DEF | T2 |

---

## 13. Counts

**Every number in this section is produced by `bun scripts/seam-proof.mjs
--list`, which parses §7-§12 the same way a scripted pass does.** It is not
maintained by hand. Wave 21 found that the hand-maintained totals below had
drifted from what a parser actually sees — see §13.3, which is the reconciliation
and the reason the tool now EXITS NON-ZERO when the two disagree.

### 13.1 By app and tier

| App | Seams | T1 | T2 | T3 |
|---|---:|---:|---:|---:|
| `apps/gateway` | 62 | 44 | 16 | 2 |
| `apps/control-plane` | 42 | 26 | 11 | 5 |
| `apps/mcp` | 35 | 29 | 4 | 2 |
| `apps/agent-runtime` | 38 | 26 | 10 | 2 |
| `apps/telemetry` | 17 | 9 | 3 | 5 |
| `apps/cli` | 8 | 3 | 5 | 0 |
| **Total** | **202** | **137** | **49** | **16** |

Plus **1 RETIRED tombstone** (`GW-C11`, §3.2), which is a row but not a seam and
is excluded from every total above. 202 ID-bearing lines, 201 seams.

**#765 added `MCP-U1`** (§9.6, T1 — the idle reaper that finally calls the
unified session's `close()`), which is the +1 in both cells above. It does NOT
close §13.3's outstanding gap: `bun scripts/seam-proof.mjs --list` still reports
one more parsed row than claimed, and the extra one is in `apps/gateway` (63
parsed against 62 claimed), which predates this slice and belongs to whoever
added it.

**Wave 22 added TEN rows, all T1.** Five are FC-1 (the operator drain, joined
across the fleet): `MCP-P12`/`MCP-P13`, `AR-P10`/`AR-P11` and `CP-P9` — see
`docs/rewrite/FLEET-CONSISTENCY.md` §7.2 for their five mutations. Two are FC-3
(an activated guardrail policy reaching every screening door): `MCP-P8` and
`AR-P12`, the DURABLE legs that now wrap the pre-existing var legs `MCP-P4` and
`AR-P6` — whose recipes were re-checked and still bite, so both were rewritten
rather than retired. See §7.3 for their mutations. Every one of the seven was
proven by mutation before this table was touched.

The wave-22 **INTEGRATE** step added the remaining three, and proved each one
itself rather than taking a delivering agent's table on trust: `GW-R17` (FC-1's
third and last leg — the gateway's own durable drain resolver) and `MCP-P14` /
`AR-P13` (FC-2's two mounts, which the delivering slice landed and did not
register). `FLEET-CONSISTENCY.md` §7.4 and §7.5 carry their eight mutations.

Wave 18's INTEGRATE step added **five** control-plane rows (`CP-S1`…`CP-S5`, all
T1 — the enterprise-identity mounts) and moved `GW-C11` to `GW-R16` when it fixed
the dead route, leaving the gateway count unchanged. **Wave 20 added `CP-C13b`**
(the `/version` DOCUMENT, as opposed to its registration) and did not update this
table — which is the whole of the 188-vs-189 gap §13.3 reconciles.

Wave 17's table had 161 rows. The increase is **8 mount lines that were in no
table** (§3.1), **2 newly enumerated `resolveDeps` slots** (CP-A10/A11), **2
telemetry scaffold routes** (TEL-A7/A8), **5 identity mounts** (CP-S1…S5), **1
wave-20 sub-seam** (CP-C13b), and **11 rows created by finishing a decomposition
prior waves left partial** — every `export default`, every `compatibility_date`,
both halves of each app's `/health` + `/version` pair — minus `AR-C8`, deleted as
stale (§3.3). `AR-G1` was merged into `AR-P4` (same line).

### 13.2 By channel — the machine-readable *Channel* column

The column reads `RUN · QUALITY?`. **RUN says how to run the row's gate; QUALITY
says how to read the result.** They are separate on purpose: wave 20 had to
rediscover that AR-P1/AR-P2 need a chained config, because the only place that
was written down was prose inside the *Seam* cell, where no tool could see it.

| RUN | Meaning | Seams |
|---|---|---:|
| `DEF` | the app's own default vitest project — `bunx vitest run <files>` | 184 |
| `ESC` | a `*.spec.ts` under a CHAINED config (§4); the runner adds `--config`. Under a bare `vitest run` these specs are **not collected and the suite reports green** | 4 — GW-C8, AR-P1, AR-P2, AR-P9 |
| `NONE` | no local gate of any kind; nothing to run | 2 — AR-T11, CP-C13b |

| QUALITY | Meaning | Seams |
|---|---|---:|
| *(absent)* | the gate is behavioural | 152 |
| `DRIFT` | the committed value is overridden by a pinned miniflare binding, or is config the pool never reads (`[[migrations]]`, `[triggers]`, `compatibility_*`, `main`). The gate is a NAME/PRESENCE assertion and **cannot** be behavioural | 34 |
| `NOT-MUTABLE` | the seam cannot be mutated **by category** — an absent stanza (`AR-T11`), or a duplicate export that resolves nothing (`AR-C9`). **A skipped NOT-MUTABLE row is not an unproven row**, and telling those two apart is the reason this column exists | 2 — AR-C9, AR-T11 |
| `WORKERD-REFUSAL` | exercising the seam takes the runtime to a start-up refusal and the suite to 0 collected tests; only the rot directions are gated | **0 since #666** — MCP-T10 and AR-T10 left this class when their auxiliary-worker harness landed, and both are now behaviourally gated |
| `RETIRED` | a tombstone. Not a seam, never counted | 1 — GW-C11 |

**Every one of the 190 seams now resolves to something a runner can act on: 188
name at least one test file that exists on disk, and 2 declare `NONE` with the
category reason.** `bun scripts/seam-proof.mjs --list` exits non-zero if that
stops being true.

The two `NONE` rows, stated plainly rather than rounded away:

- **AR-T11** — `NONE · NOT-MUTABLE`. The seam is the ABSENCE of a
  `[[d1_databases]]` stanza. There is nothing on disk to remove, so no mutation
  exists that could turn a gate red, and the inverse assertion is deliberately
  NOT written because it would lock in the posture the row flags as a deploy
  blocker (the mistake wave 15 made on `GW-C11`, §3.2). **Closing it means adding
  the stanza, not adding a test.**
- **CP-C13b** — `NONE`, and this one IS gateable: `api: PUBLIC_API_MAJOR` → `api:
  0` leaves 687/687 green. It is the only *unproven-and-gateable* row in the
  file. The gate to write asserts the three counts in the `/version` document
  against `CONTROL_PLANE_OPERATIONS.length` / `CONTROL_PLANE_GROUPS.length`.

**DEPLOY-ONLY is no longer a channel, because it never described how to run
anything.** It described a *residue*: the part of a row no local runner reaches.
Three rows carry that residue and are named here rather than in the table, since
each has a local gate for everything except the named part —

- **MCP-T8** — the stanza is gated (`test/d1-auth.test.ts`, `test/approvals.test.ts`);
  the missing `migrations_dir` is not, and cannot be locally.
- **AR-T11** — above; the whole row is the residue.
- **TEL-T4** — **closed in wave 21.** The behavioural half stays unreachable
  locally, but the committed bytes are now pinned on the drift channel: **2 RED**
  on a whole-block delete, **1 RED** on `enabled = false`, **1 RED** on
  `invocation_logs = true`. It had been "DEPLOY-ONLY, no gate" since wave 15.

### 13.3 Reconciliation — claimed vs parsed vs gated

Wave 21 ran the inventory through its own tool and got three different numbers,
which is the finding, not the footnote:

| | Before wave 21 | After |
|---|---:|---:|
| rows **CLAIMED** by §13's total | 188 | **190** |
| rows **PARSED** by `seam-proof.mjs` | 170 | **190** |
| rows with a **RESOLVABLE GATE** | 157 | **188** (+2 `NONE` by design = 190) |

The *After* column is 190 rather than the 189 the repair slice reconciled to,
because the wave-21 INTEGRATE step added **`AR-P9`** — the durable
`agentUpstreamPortFromEnv` mount, the composition-root half of cutover item A3
leg 2. It is recorded here rather than folded silently into the totals so the
+1 has a named cause, which is the whole point of this subsection.

The 188-vs-170 gap was **18 rows whose ID cell was bold** (`| **GW-R4** |`), **1
row with a lowercase sub-ID** (`CP-C13b`, whose `[A-Z0-9]+` did not match), and
**1 struck-through tombstone** (`~~GW-C11~~`) — 20 rows a scripted full pass
silently skipped while reporting success. The 188-vs-189 gap was `CP-C13b`, added
by wave 20 without touching this table.

Both are now impossible to reintroduce quietly: the parser tolerates all three
spellings, and it compares its own count against the `**Total**` cell above and
**exits non-zero on a mismatch**. If you add a row, update that cell in the same
slice — the tool will tell you.

Counted mechanically off this file: `bun scripts/seam-proof.mjs --list`.

### 13.4 Two FALSE REDs the wave-21 INTEGRATE step found by actually RUNNING it

`--list` reconciled at 190/190/188 and exited 0. `--run` did not agree, and the
gap is the reminder that **a planner which resolves every row is not a runner
which executes every row**:

1. **`.test.ts` files inside a chained directory were routed to the chained
   config.** All three chained configs are `include: ["**/*.spec.ts"]`, and
   every chained directory also holds ordinary default-project tests —
   `test/ratelimit/guards.test.ts` sits beside `test/ratelimit/enforcement.spec.ts`.
   Routing the former under `--config …/ratelimit/harness/vitest.config.ts`
   collects **0 tests** and exits non-zero, so **GW-E3, GW-C6 and GW-W2 reported
   RED on a clean tree**. `chainedConfigFor` now requires `.spec.ts`.
2. **A cross-app citation was run from the citing app's directory.** `AR-P9`
   names the FLEET gate `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`
   — the only place a cross-Worker property can be asserted at all — and the
   runner invoked it from `apps/agent-runtime`, where it resolves no project.
   Same false RED. The planner now records each file's OWNING app and runs it
   there; `--list` prints `[in apps/gateway]` when they differ.

Both were **false REDs on correct code**, which is the failure mode this tool
must not have: a runner that cries wolf gets ignored, and the next RED that is
real gets waved through with it. Neither was reachable from `--list`, so the
rule is now explicit — **a wave that touches the inventory or the runner must
`--run` at least one full tier, not just `--list`.**

---

## 14. The incremental re-proof policy

A wave re-proves **(a)** every seam whose FILE it touched, and **(b)** every
**T1** seam, unconditionally. That is 124 rows rather than 189
(`bun scripts/seam-proof.mjs --tier T1 --list`).

**Wave 21 changed the arithmetic this policy trades against, and measured it
rather than estimating it.** `bun scripts/seam-proof.mjs --run` over ALL 189 rows
against a clean tree: **189 GREEN, 567 s of test time, 3 m 16 s wall clock** (the
six apps run in parallel). The three ESC rows together take 3.6 s, against the
two chained `bun run test` invocations the old recipe demanded.

The tier cut below was a wall-clock concession made when a full pass cost ~100
minutes of whole-suite runs. At three minutes it is no longer a concession worth
making. **Prefer the full pass**; `--tier T1` (124 rows) is now the exception,
not the default.

**This is an honest trade of coverage for wall-clock**, and wave 18 measured its
cost again: `GW-C11` and `CLI-7` — both in the set wave 14 skipped as T2/T3 —
were the two rows that turned out to be a live defect and a dead gate. A T2/T3
seam in an untouched file is assumed still mounted on the strength of its last
proof, and that assumption is wrong the moment a shared refactor moves a mount
without touching the row's file.

**Four triggers force a FULL pass over every row:**

1. before the single authorised live `wrangler deploy` — the DEPLOY-ONLY
   residues (§13.2) and the `WORKERD-REFUSAL` rows have never been exercised by
   any local runner;
2. before deleting the Rust tree (`crates/**`, `workers/**`) — after that there
   is no reference implementation left to re-derive a lost mount from;
3. whenever a `vitest.config.ts` changes — a pinned binding is exactly what
   turned three T1 config rows into no-ops without anyone editing the rows' file;
4. whenever a row's *Expected RED* file is renamed, deleted or rewritten — the
   gate is the seam's only proof.

**A fifth, added in wave 18: re-derive §2 mechanically at the start of every
full pass, and diff the derived line list against this table BEFORE trusting a
single row.** Eight of wave 18's findings were missing rows, and a missing row
cannot be found by re-proving the rows that exist.

**A sixth, added in wave 21: run `bun scripts/seam-proof.mjs --list` FIRST and
require exit 0.** It reconciles the §13.1 total against what a parser actually
sees and fails on a mismatch or on any row that names no gate and gives no
reason. Before wave 21 those two numbers were 188 and 170, and a "full" scripted
pass silently skipped 20 rows while reporting success — a pass that looks
complete but is not is strictly worse than one that admits it is partial.

---

## 15. Maintenance rules

1. **Adding a mount = adding a row here, in the same slice.** A mount with no
   row is a mount nobody will re-prove.
2. **Deleting a mount = deleting its row in the same slice.** `AR-C8` survived a
   refactor and read as coverage for a line that no longer existed.
3. Record the mutation VERBATIM, including the observed RED message and the
   RED **count**, in the slice's report — not just "went red". A count is what
   exposed §4.2's 1-of-42.
4. Never delete a row because its seam looks obvious. Eleven obvious mounts were
   already dead.
5. If a seam genuinely cannot be gated locally, keep the row, set its Channel
   RUN to `NONE` and give the category reason in the *Expected RED* cell.
   Closing six honestly beats "closing" thirty by deletion.
6. **A GREEN mutation has two readings — say which.** Either the seam is
   ungated (write the gate) or the seam is dead (report the defect). Wave 15
   conflated them on GW-C11 and the defect survived three more waves.
7. **A gate that builds its own app, its own `worker.ts`, or its own
   `wrangler.toml` proves the FACTORY, never the MOUNT.** Every T1 row needs at
   least one `SELF.fetch` assertion, or an assertion against a symbol imported
   from the composition root, or an explicit note saying why neither is possible.
8. **The *Expected RED* cell must name a FILE a runner can resolve** — a
   backticked path ending `.test.ts` or `.spec.ts`, no `:NNN` suffix, no
   back-reference ("as MCP-T6", "same three", "every `SELF.fetch` suite"). Wave
   21 found 13 rows that named none; four of them turned out to have a perfectly
   good gate nobody had written down, and two had no gate at all. If several
   suites go red, name one anyway and say the rest do too.
9. **Withdraw a citation with strikethrough, never by deleting it.** `**NOT**
   ~~`test/x.spec.ts`~~` keeps the reason visible to a reader and invisible to
   the runner. A withdrawn citation left in plain backticks is worse than none:
   the tool runs a suite that CANNOT go red for that seam and reports the row
   covered.
10. **Adding a row means updating §13.1's `**Total**` cell in the same slice.**
    `bun scripts/seam-proof.mjs --list` exits non-zero when they disagree, which
    is how wave 20's `CP-C13b` was caught a wave late rather than never.
