# `@ferrogate/e2e` — layer 3: Playwright over real `wrangler dev`

The third testing layer from [`docs/rewrite/TESTING.md`](../docs/rewrite/TESTING.md).
It black-boxes the Workers as **real services**: `playwright.config.ts` starts one
`wrangler dev` per app from that app's **own** `wrangler.toml`, and the specs talk
to them over ordinary HTTP sockets. Nothing in `tests/` imports application code.

## Run it

```bash
bun install                 # once — installs @playwright/test at the repo root
bun run test:e2e            # from the repo root
# or, from this directory:
bun run --cwd e2e test:e2e
```

No browser download is needed. Every spec uses Playwright's `request` fixture
(API testing only), so `playwright install` is not part of the loop — the config
declares no `projects` / `browserName` and Chromium is never launched.

Targeting a single file or test:

```bash
bunx playwright test --config e2e/playwright.config.ts tests/mcp.spec.ts
bunx playwright test --config e2e/playwright.config.ts -g "messages"
```

`outputDir` is `e2e/.playwright/` (Playwright's own scratch space); it is
regenerated per run and should not be committed.

## It needs no Cloudflare account

Both dev servers run with `--local`, which pins execution to the `workerd` binary
that ships inside `wrangler`. There is no `wrangler login`, no `account_id`, no
remote binding, no billable request, and no outbound network call — the same
docker-free / offline property the other two layers have.

The bindings behave exactly as the committed `wrangler.toml` files declare them:

- `apps/gateway` gets its **fail-closed empty** `[vars]` and a local R2 stub, so
  the model registry is genuinely empty and no provider is ever contacted;
- `apps/mcp` gets `FG_DEV_IN_MEMORY_PORTS = "1"`, its in-memory port bundle.

Assertions are written against that real unconfigured-binding behavior. Where a
result is a consequence of a not-yet-wired binding (the empty model catalog; the
unreachable authenticated MCP methods), the spec says so at the assertion and
carries the `PORT-TODO` for tightening it once the binding lands — it is never
quietly skipped.

### The one injected value

`apps/gateway`'s `GATEWAY_NATIVE_API_KEYS` ships as `"[]"`, so a stock
`wrangler dev` resolves no credential at all and every authenticated route
answers `401 invalid_api_key` before its handler runs — you could never reach the
Zod-validation or `/v1/models` behavior from outside. The config therefore passes
one test key with `wrangler dev --var`, which is the CLI equivalent of the
`miniflare.bindings` the layer-1 `apps/gateway/vitest.config.ts` sets. It changes
nothing under `apps/**`, and the key lives in [`fixtures.ts`](./fixtures.ts) with
`scopes: []` — per `hasScope`, that grants data-plane scopes only and never
`admin.*`.

`apps/mcp` has no equivalent knob: its `InMemoryAuth` table is seeded only
in-process, so no black-box client can authenticate. `tests/mcp.spec.ts` explains
why that costs nothing here (the JSON-RPC codec runs **before** authentication,
so the whole envelope contract is assertable unauthenticated) and carries the
PORT-TODO for adding the authenticated round-trip once a real auth port lands.

## Why this is separate from the `vitest-pool-workers` layer

Layer 1 (`apps/*/test/**`, `SELF.fetch`) runs the Worker **inside the test
process's** `workerd` via miniflare. It is fast, it has real bindings, and it is
where the bulk of behavior is proven. What it structurally cannot observe is the
step a deploy actually performs: `wrangler` bundling the entry module and
`workerd` **registering it as a service**. A Worker can be entirely correct under
`SELF.fetch` and still refuse to start.

That is not hypothetical. Writing this layer immediately surfaced it — see
"Known blocker" below. It is the same class of defect as the empty
`GATEWAY_ROUTE_MODULES` bug: green tests over an artifact that is not the one
that ships.

The two layers are complementary, not redundant:

| | layer 1 (vitest-pool-workers) | layer 3 (this) |
|---|---|---|
| dispatch | in-process `SELF.fetch` | real TCP + HTTP |
| bundling | vite/vitest transform | `wrangler`'s own esbuild pipeline |
| service registration | bypassed | exercised |
| bindings | `miniflare.bindings` overrides | the committed `wrangler.toml` |
| fixture seeding | can reach in-memory ports | cannot — black box only |
| cost | ~seconds | ~1 min of server startup |

Because of that startup cost, `test:e2e` is **deliberately excluded from the
default `bun run test`**: `e2e/` is not listed in the root `workspaces`, so
`bun run --filter '*' test` cannot pick it up, and this package exposes no `test`
script at all — only `test:e2e`. Run it explicitly, and in CI as its own job.

### Iterating quickly

`reuseExistingServer` is on outside CI. Start a server by hand once and every
subsequent run attaches to it instead of paying ~40s of boot:

```bash
cd apps/mcp && bunx wrangler dev --local --ip 127.0.0.1 --port 8878 --inspector-port 9878
```

Ports live in [`fixtures.ts`](./fixtures.ts) — one source of truth for the config
and the specs, so a spec can never address a server the config did not start.
Note that **both** the serving port and the `--inspector-port` must be distinct
per app: every `wrangler dev` defaults its devtools socket to 9229, so two
concurrent instances on the default collide with
`Address already in use (127.0.0.1:9229)` and the second one dies.

## Known blocker (as of this slice)

`bun run test:e2e` **cannot pass yet**, and the reason is a genuine
deployment-blocking defect this layer found, not a problem with the suite:

```
service core:user:ferrogate-gateway: Uncaught TypeError:
  Incorrect type for map entry 'EXPECTED_OPERATION_COUNT':
  the provided value is not of type 'function or ExportedHandler'.
✘ The Workers runtime failed to start.
```

`workerd` requires every **named** export of a Worker entry module to be a
function / handler / entrypoint class. `apps/gateway/src/index.ts` ends with
`export * from "./contract.js"`, which re-exports plain constants
(`EXPECTED_OPERATION_COUNT`, `OPERATIONS`, `AUTH_KINDS`, …) from the entry
module, so `wrangler dev` — and `wrangler deploy` — refuse to start the Worker.
`apps/mcp` (`EXPECTED_APP_OPERATION_COUNT`) and `apps/telemetry`
(`AE_INDEXES_PER_POINT`) have the same defect; `apps/control-plane` and
`apps/agent-runtime` start cleanly.

Layer 1 does not catch it because vitest-pool-workers loads the module rather
than registering it as a workerd service — which is precisely the gap this layer
exists to close.

The fix is confined to the entry modules: move the value re-exports to a
non-entry module (e.g. a `src/public.ts` the tests import) and keep the entry's
named exports to types (erased at build) plus handler/DO classes. Verified
locally that with only `export default app` on the entry, both Workers boot and
every assertion in `tests/` holds.
