# `apps/gateway` — the FerroGate data plane Worker

The native TypeScript replacement for the Rust `ferrogate-gateway` +
`ferrogate-runtime` + the Pingora container (eliminated — no Rust in the request
path). A Hono streaming proxy that serves the **38 gateway-owned operations** of
`docs/openapi/runtime-api-contract.json`: 12 inference, 18 assets, 1 site, and
the 7-operation tools/skills/prompts/functions + `/.well-known/agent.json`
surface.

Routing and auth are contract-driven: `src/contract.ts` is the 281-operation
table, `src/middleware/auth.ts` is the single guard that enforces each
operation's `auth.kind` / `auth.scope` / `rbac_action`, and `src/routes/index.ts`
mounts what this Worker owns. The deployed module list is
`GATEWAY_ROUTE_MODULES` in `src/index.ts` — the anti-drift test imports **that
array**, never a bespoke copy.

Toolchain: **Bun** runs TypeScript, **Wrangler** is the only bundler and the only
deploy tool, **Hono** routes, **Zod** validates. There is no second bundler in
this project and none may be added.

## Bindings

Declared in [`wrangler.toml`](./wrangler.toml). Every one is read by code in
`src/**`; the comments there carry the same information inline, plus the list of
bindings deliberately **not** declared yet and the PORT-TODO that introduces
each.

| Binding | Kind | Read by | Without it |
|---|---|---|---|
| `GATEWAY_NATIVE_API_KEYS` | var (JSON array) | `ConfiguredApiKeyAuthenticator.fromEnv`, `src/adapters.ts` | No durable/native key resolves; every such bearer is `401 invalid_api_key`. |
| `GATEWAY_STATIC_API_KEYS` | var (JSON array) | `ConfiguredApiKeyAuthenticator.fromEnv`, `src/adapters.ts` | No operator/static key resolves. A static key with no `scopes` is a **wildcard** — treat this as secret material. |
| `SELF_HOSTED_WORKER_REGISTRY` | var (JSON array) | `ConfiguredInternalTransport.fromEnv`, `src/adapters.ts` | The only credential source for `auth.kind: "internal"`; empty ⇒ every `/v1/self-hosted-workers/*` callback is `401 invalid_self_hosted_worker_identity`. Contains real transport secrets. |
| `TENANCY_LIFECYCLE` | var (JSON map) | `ConfiguredTenancyLifecycleGate.fromEnv`, `src/adapters.ts` | A suspended/deleted tenant keeps serving: `403 tenancy_suspended` / `tenancy_deleted` has no source. |
| `TENANT_RBAC_ACTIONS` | var (JSON map) | `ConfiguredRbacAuthorizer.fromEnv`, `src/adapters.ts` | Every `rbac_action`-carrying operation is `403 rbac_denied` for a tenant credential (platform operators are unaffected). |
| `ASSET_ENTITLEMENTS` | var (JSON map) | `entitlementsFromEnv`, `src/assets/handlers.ts` | Fail-closed `NO_ASSET_HOSTING`: no tenant may publish assets. Reads of already-published assets still work. |
| `GATEWAY_PROVIDERS` | var (JSON array) | `modelCatalogFromEnv`, `src/inference/catalog.ts` | No provider exists, so no logical model resolves: every inference request is `400 model_not_found` and nothing is dispatched. |
| `GATEWAY_MODELS` | var (JSON array) | `modelCatalogFromEnv`, `src/inference/catalog.ts` | Same — this is the logical→physical mapping itself. `GET /v1/models` lists nothing. |
| *(per provider)* `api_key_var` target | **secret** | `buildModelCatalog`, `src/inference/catalog.ts` | A provider naming an unbound key var refuses the WHOLE catalog, rather than dispatching an unauthenticated request to a paid upstream. |
| `GATEWAY_DEV_AUTH` | var (`"true"`/`"false"`) | `developmentApiKeys`, `src/adapters.ts` | Ships as `"false"`; the local development key path stays closed. |
| `GATEWAY_DEV_API_KEY` | **secret** | `developmentApiKeys`, `src/adapters.ts` | No development key exists. Required *and* `GATEWAY_DEV_AUTH == "true"` *and* an `fg_dev_` prefix. |
| `ASSETS` | `[[r2_buckets]]` | `AssetObjectStore` (`src/assets/ports.ts`) — the port is R2-shaped, so a live `R2Bucket` satisfies it structurally | Falls back to `InMemoryAssetObjectStore`: bytes vanish with the isolate, so a push "succeeds" and a later read 404s. The presign family answers `503 asset_bucket_unavailable`. |

Notes that matter before you deploy:

- **The vars are fail-closed.** All five parse through `parseJsonVar`, which
  treats absent *and malformed* JSON as "nothing configured". A typo can only
  close access, never widen it. `wrangler.toml` ships them as `"[]"` / `"{}"`.
- **Secrets belong in `wrangler secret put`**, not in `wrangler.toml`.
  `GATEWAY_STATIC_API_KEYS` and `SELF_HOSTED_WORKER_REGISTRY` carry live
  credentials; a secret of the same name lands in the same `env` namespace and
  takes precedence over the var.
- **`bucket_name` / `preview_bucket_name` are placeholders**
  (`replace-at-deploy-ferrogate-assets…`). The deploy step substitutes the real
  bucket from the target account. No real Cloudflare resource id is committed.
- **`env.ASSETS` is declared but not yet dereferenced.** `src/index.ts` builds
  `assetRouteModule()` with its offline defaults today; the binding is the
  deploy-time half of the wiring and must exist in the account first. The code
  half is `assetRouteModule({ deps: { objects: env.ASSETS, presigner: new
  SigV4Presigner({...}), limits: { presignEnabled: true } } })` —
  PORT-TODO(inventory-request-path.md §1.6 "Object storage").
- **Presigning needs S3 credentials, not the R2 binding.** The Workers
  `R2Bucket` API has no presign method; R2 presigned URLs are an S3-API feature
  over `https://<account_id>.r2.cloudflarestorage.com`, which `src/assets/
  sigv4.ts` signs. Until those credentials are bound (Secrets Store), the
  presign family stays `503 asset_bucket_unavailable` — deliberately, so object
  bytes are never silently routed through the Worker.
- **D1 / KV / Durable Objects / Queues / Workers AI / Analytics Engine are not
  declared**, because nothing in `src/**` reads them yet. See the "NOT DECLARED"
  block at the bottom of `wrangler.toml`. In particular a DO binding names an
  exported class; this Worker exports none, so declaring `RATE_LIMIT` / `SESSION`
  early would fail the Worker at startup, tests included.
- `compatibility_date` / `compatibility_flags` are unchanged from the scaffold —
  no binding here requires a newer runtime.

## Run it locally

Dependencies are installed once at the repo root (`bun install`); this app is a
Bun workspace member.

```sh
cd apps/gateway
bun run dev          # == wrangler dev
```

`wrangler dev` defaults to local mode: the `ASSETS` bucket is simulated on disk
by Miniflare, so the placeholder `bucket_name` is fine and nothing touches your
Cloudflare account. Add `--remote` only when you want the real R2 bucket, which
requires the placeholders to be filled in first.

To exercise the auth taxonomy locally, override the vars with a `.dev.vars`
file, which Wrangler reads for local dev only and which wins over `[vars]`.
`.dev.vars` is gitignored at the repo root — it holds real tokens, so keep it
that way:

```ini
GATEWAY_NATIVE_API_KEYS=[{"key":"fg_dev","id":"key_dev","tenant_id":"tenant_a","scopes":["tools.read"]}]
TENANT_RBAC_ACTIONS={"tenant_a":["*"]}
ASSET_ENTITLEMENTS={"tenant_a":{"asset_hosting_enabled":true}}
```

```sh
curl -H 'Authorization: Bearer fg_dev' http://localhost:8787/v1/tools
curl http://localhost:8787/healthz      # anonymous
```

### Run the whole inference path locally, against a real upstream

Client → auth → Zod → resolve logical model → dispatch → stream → meter, with
nothing stubbed. Everything below goes in `apps/gateway/.dev.vars`; nothing goes
in `wrangler.toml`.

```ini
# --- the development credential ------------------------------------------
# ALL THREE conditions are required (see `developmentApiKeys`, src/adapters.ts):
# this var is exactly "true", the key is bound, and the key starts `fg_dev_`
# and is at least 30 characters. `wrangler.toml` ships GATEWAY_DEV_AUTH="false",
# which is the var a plain `wrangler deploy` carries, so this cannot leak into
# production by omission. The key grants the six inference scopes and nothing
# else — never `admin.*`.
GATEWAY_DEV_AUTH = "true"
GATEWAY_DEV_API_KEY = "fg_dev_<32 random characters you generate>"

# --- the provider table and the logical model registry --------------------
# `api_key_var` names the binding holding the credential; the credential value
# only ever appears on the last line, which is a secret in every real
# deployment (`wrangler secret put UPSTREAM_TOKEN`).
#
# `auth_scheme = "bearer"` is for an Anthropic-Messages-COMPATIBLE relay: it
# speaks the Anthropic body grammar but authenticates like OpenAI. Drop it for
# api.anthropic.com itself and the adapter uses `x-api-key`, as in Rust.
GATEWAY_PROVIDERS = '[{"name":"my-relay","kind":"anthropic","base_url":"https://<host>/v1","api_key_var":"UPSTREAM_TOKEN","auth_scheme":"bearer"}]'
GATEWAY_MODELS = '[{"name":"ferrogate-reasoning","provider":"my-relay","provider_model":"<the upstream's own model id>","capabilities":["chat","streaming","tools"]}]'
UPSTREAM_TOKEN = "<the provider credential>"
```

```sh
bunx wrangler dev --local --port 8799

# the registry, with no upstream call
curl -H "Authorization: Bearer $DEV_KEY" http://localhost:8799/v1/models

# the full path — the OpenAI ingress translated onto an Anthropic upstream
curl http://localhost:8799/v1/chat/completions \
  -H "Authorization: Bearer $DEV_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"ferrogate-reasoning","messages":[{"role":"user","content":"ping"}],"max_tokens":16}'

# the same, streamed (add -N so curl does not buffer the SSE)
curl -N http://localhost:8799/v1/chat/completions \
  -H "Authorization: Bearer $DEV_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"ferrogate-reasoning","messages":[{"role":"user","content":"ping"}],"max_tokens":16,"stream":true}'
```

`ferrogate-reasoning` is a LOGICAL name: it is not a model id any upstream
knows, and the gateway never forwards it. `GATEWAY_MODELS` maps it to
`provider_model`, and that is what goes on the wire — re-point it and every
client follows with no client change. A model name that is not in the table is
`400 model_not_found`; a table that is malformed, self-contradictory (duplicate
model, unknown provider, unported adapter family) or names an unbound
`api_key_var` is refused whole, so the gateway resolves nothing rather than
dispatching somewhere unintended.

## Test it

```sh
bunx tsc --noEmit    # or: bun run typecheck
bunx vitest run      # or: bun run test
```

The suite runs in real `workerd` via `@cloudflare/vitest-pool-workers` — offline,
docker-free — and drives the **exported Worker** through `SELF.fetch`, against
this exact `wrangler.toml`. It does not build its own router: a module dropped
from `GATEWAY_ROUTE_MODULES`, or a binding that disappears from this file, has
to show up as a failure.

`vitest.config.ts` seeds the five auth vars through `miniflare.bindings`, which
override the fail-closed `[vars]` for the duration of the suite. The R2 binding
is created locally by Miniflare; no account resource is needed.

## Deploy it

Wrangler bundles and deploys. Nothing else does, at any stage.

1. Create the bucket in the target account and replace both placeholder names in
   `wrangler.toml` (or set them per environment):

   ```sh
   bunx wrangler r2 bucket create <your-assets-bucket>
   ```

2. Load the credential material as secrets rather than vars:

   ```sh
   bunx wrangler secret put GATEWAY_STATIC_API_KEYS
   bunx wrangler secret put SELF_HOSTED_WORKER_REGISTRY
   ```

3. Verify the binding set without shipping anything — this prints every binding
   Wrangler resolved and exits:

   ```sh
   bunx wrangler deploy --dry-run
   ```

4. Ship:

   ```sh
   bun run deploy       # == wrangler deploy
   ```

A deploy with the placeholder `bucket_name` still in place fails at the R2 step;
that is intended — it is a loud failure instead of a Worker that quietly loses
every uploaded asset.
