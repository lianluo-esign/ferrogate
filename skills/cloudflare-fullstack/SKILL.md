---
name: cloudflare-fullstack
description: Use when developing, testing or deploying anything on the Cloudflare Workers full stack — Bun (deps) + TypeScript + Hono (routing/streaming) + Zod (validation) + Wrangler (bundle/deploy), with D1, R2, KV, Durable Objects, Queues, Workers AI and Analytics Engine. Covers the toolchain division of labour (Bun installs, Wrangler bundles — never add a second bundler), the three testing layers (vitest + @cloudflare/vitest-pool-workers in real offline workerd, MSW for LLM/SSE upstream mocking, Playwright + wrangler dev for E2E), the LOCAL-FIRST rule (iterate on miniflare; spend exactly ONE live-cloud verification at the end), CF credential/permission diagnosis (error 10000 vs 10042), per-tenant D1 isolation, and the two defect classes that green test suites routinely hide (unmounted composition roots and vacuous assertions). Not for non-Cloudflare deployments.
---

# Cloudflare full-stack development

The toolchain, the test strategy, and the failure modes that survive a green suite.

## 1. Toolchain — one job each

| Tool | Job | Never |
|---|---|---|
| **Bun** | package manager, workspaces, running TS, compiling CLI binaries | — |
| **Wrangler** | THE bundler + dev server + deploy tool (CF official, built in) | do NOT add esbuild/tsup/vite/rollup for Workers |
| **Hono** | routing, middleware, streaming responses | — |
| **Zod** | every external request/response boundary | — |
| **vitest** + `@cloudflare/vitest-pool-workers` | unit + integration in real `workerd` | — |
| **Playwright** | black-box E2E against `wrangler dev` | — |

Workspace packages export `src/*.ts` **as source** — no per-package build step.
Bun runs TS directly and Wrangler bundles from source. A `build` script that
emits `dist/` for a Worker is a smell.

**Use the CF product, don't rebuild it:** D1 (SQLite), R2 (objects), KV
(edge cache/config), Durable Objects (coordination, per-key single-threaded
state, rate limits, sessions, long-lived runs), Queues (async/outbox),
Workers AI (inference), Analytics Engine (metrics — binding-only, there is no
HTTP ingest), Secrets Store, Service Bindings, Cache API.

## 2. Testing — three layers, local first

### Layer 1: unit + integration (the workhorse)

`@cloudflare/vitest-pool-workers` boots the **real local `workerd`** — the same
runtime `wrangler dev --local` uses. `c.env.DB` (D1), `c.env.KV`, R2 and DO
bindings are genuinely in effect: **do not mock them.** Runs fully offline, no
docker, no Cloudflare account.

```ts
// vitest.config.ts — check which API your installed version exposes.
// Newer lines use the cloudflareTest VITE PLUGIN; older ones exported
// defineWorkersConfig from "@cloudflare/vitest-pool-workers/config".
// Copy a config from a worker in the repo that already runs green.
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.toml" } })],
  test: { include: ["test/**/*.test.ts"] },
});
```

```ts
import { SELF } from "cloudflare:test";  // drives the REAL exported Worker
const res = await SELF.fetch("https://x.test/v1/chat/completions", {
  method: "POST", body: JSON.stringify({ model: "m", messages: [] }),
});
expect(res.status).toBe(401);
```

Pure-logic packages with no binding use plain vitest — faster, no pool needed.

**`tsconfig.json` must include `test/`.** A config with `"include": ["src"]`
typechecks ZERO test files, and vitest transpiles with esbuild without
typechecking — so every type error in every test file is invisible. Also add
`"types": ["@cloudflare/workers-types", "@cloudflare/vitest-pool-workers/types"]`
or `import ... from "cloudflare:test"` is TS2307.

### Layer 2: upstream mocking with MSW

Never call a real LLM/provider in the test suite — cost, latency, and
nondeterminism. Intercept the Worker's **outbound** `fetch` with `msw` and return
a canned **SSE stream**, so token counting, stream normalization and forwarding
are exercised against a deterministic typewriter.

Split SSE fixtures **mid-event and mid-UTF-8-multibyte-character** — that split
is a classic real-world streaming bug and a normalizer that passes only on clean
chunk boundaries is not proven.

### Layer 3: E2E with Playwright + `wrangler dev`

Treat the Worker as a black box. Use Playwright's `webServer` option to start
`wrangler dev` before the suite and tear it down after; use the `request`
fixture (no browser needed for API testing). Keep E2E out of the default `test`
script — it is slower and needs a live dev server.

### The LOCAL-FIRST rule

Iterate on **local** tooling (`wrangler dev --local` / miniflare / pool-workers);
local D1/KV/R2 are local simulations and consume nothing. Do **not** iterate
against the live account — it burns real resources. When the local suite is
green, spend exactly **ONE** live-cloud verification: `wrangler deploy` plus a
minimal real request. If that fails, fix locally and spend one more — never
loop against the cloud.

## 3. Credentials and permission diagnosis

Keep credentials in a mode-600 env file; load with
`set -a; . <file>; set +a`. **Never echo secret values** — print key names only.
Wrangler natively consumes `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN`.

Three CF gotchas that waste hours:

1. **`/user/tokens/verify` returns "Invalid API Token" for a perfectly valid
   ACCOUNT-scoped token.** That endpoint is user-scoped. Probe
   `GET /accounts/{id}` instead.
2. **Error `10000 Authentication error` ≠ error `10042 "Please enable X"`.**
   `10000` = the API token lacks that permission → fix by editing the token.
   `10042` = the PRODUCT is not subscribed on the account → fix by activating
   the plan in the Dashboard (R2 needs its monthly plan enabled even inside the
   free tier). Granting token permissions will never clear a 10042. If some
   products clear while one stays, that one is a subscription problem.
3. **Reproduce with the official tool before blaming your code**: if
   `bunx wrangler r2 bucket list` returns the same error as your API call, the
   problem is the account/token, not your request.

Probe capability before building against it:

```bash
for x in "R2:r2/buckets" "KV:storage/kv/namespaces" "AI:ai/models/search?per_page=1" \
         "D1:d1/database" "Queues:queues" "Scripts:workers/scripts"; do
  curl -s "https://api.cloudflare.com/client/v4/accounts/$A/${x#*:}" \
    -H "Authorization: Bearer $T" \
    | jq -c --arg n "${x%%:*}" 'if .success then {r:$n,ok:true}
        else {r:$n,ok:false,code:(.errors[0].code//null)} end'
done
```

## 4. Multi-tenant data on D1

D1 is SQLite: **no RLS, no cross-database joins, no `SELECT ... FOR UPDATE`.**
Isolate tenants with **one database per tenant** plus an account-global control
database.

The hard constraint: **bindings resolve at DEPLOY time.** There is no "open
tenant X's database by uuid at runtime" binding API. Options: the D1 **REST**
API with a runtime uuid (but REST cannot do interactive transactions), a proxy
Worker holding a native binding (this is why a `d1-proxy` Worker is a common
pattern — native `batch()`/`RETURNING` that REST cannot serve), or D1 Sessions.
Decide this before writing the storage layer.

Postgres → D1 translation to plan for: `JSONB`→`TEXT`, `BIGINT`→`INTEGER`,
`BYTEA`→base64 or R2, RLS→physical DB separation, `FOR UPDATE`→atomic `batch()`
or optimistic `UPDATE ... WHERE <unchanged> RETURNING` + retry, `GREATEST/LEAST`
→`max/min`. Keep money as integer minor units end-to-end — never float.

## 5. Two defect classes a green suite hides

These are the ones that actually bite. Check for both before believing "all tests pass."

### A. The unmounted composition root

Feature modules fully implemented and fully tested, but the **composition root**
(`src/index.ts`, the Worker's default export) never mounts them — so the routes
are unreachable in production. The suites pass because each test builds its
**own** router.

- **Test the app the Worker actually exports.** Export the production router/module
  list from `src/index.ts` and assert against *that*, or drive it via `SELF.fetch`.
  A test that constructs a bespoke app proves nothing about what ships.
- Add an **anti-drift gate**: assert every operation the contract assigns to this
  Worker is registered on the production app, failing with the missing ids.
- A reachability probe needs a **control**: also assert a path the Worker does
  NOT own returns 404 — otherwise "not 404" proves nothing.

### B. Vacuous assertions

Correct code, green tests, and the tests do not actually constrain the code.

**Mutation-test anything security- or money-critical.** Break the invariant on
purpose, confirm the suite goes RED, then restore and confirm GREEN:

```bash
cp src/x.ts /tmp/x.bak
# ... apply the mutation ...
grep -n '<marker>' src/x.ts     # CONFIRM the edit is actually in place
bunx vitest run                 # MUST be red
cp /tmp/x.bak src/x.ts && rm /tmp/x.bak
bunx vitest run                 # MUST be green
```

Always `grep` the mutation in place before concluding a test is vacuous — a
concurrent write can silently revert your edit and make a sound test look broken.
When an agent or teammate reports a decisive finding, re-read the exact
`file:line` yourself before acting on it.

## 6. Route contracts

If the API has a machine-readable contract (OpenAPI or similar), **drive routing
and auth from it** — one table-driven middleware enforcing every operation's
visibility / auth kind / scope / RBAC action, not N hand-written guards that
drift. Then assert `registeredRoutes.length === <contract op count>` so a
contract change cannot silently diverge from the implementation.
