# FerroGate — route map (261 operations → Hono apps)

Derived from the authoritative contract `docs/openapi/runtime-api-contract.json`
(`version: 1`, 261 operations, 37 route groups). **That JSON is the source of
truth** — this document only assigns each operation to a Worker and records the
auth/visibility invariants the Hono port must preserve.

## Split by app

| App | Ops | Surface |
|---|---:|---|
| `apps/control-plane` | **206** | `/admin/v1/**` (201) + `/admin`, `/admin/`, `/admin/dashboard`, `/admin/status`, `/metrics` |
| `apps/gateway` | **32** | inference `/v1/{chat/completions,messages,messages/count_tokens,responses,embeddings,images/generations,models}`, assets `/v1/assets/**` (18), tools/skills/prompts/functions, `/.well-known/agent.json` |
| `apps/agent-runtime` | **15** | `/v1/agent-jobs/**` (5), `/v1/agents/**` (3), `/v1/agent-runs` (1), `/v1/self-hosted-workers/**` (6) |
| `apps/mcp` | **6** | `/v1/mcp`, `/v1/mcp/tool/execute`, `/v1/mcp/identity/**` |
| shared | **2** | `/healthz`, `/readyz` — implemented in **every** Worker |
| **total** | **261** | |

`apps/telemetry` owns no contract route: it is the observability sink
(Analytics Engine / Logpush), fed by the other Workers.

## Invariants the port MUST preserve

**Auth kinds** (261): `bearer` 248 · `internal` 6 · `anonymous` 6 · `method_dependent` 1.
**Visibility**: `admin` 202 · `public` 52 · `internal` 7.
**Methods**: GET 119 · POST 81 · DELETE 26 · PUT 19 · PATCH 16.

> The 252nd operation is `countMessageTokens`
> (`POST /v1/messages/count_tokens`, issue #671): the Anthropic-native
> token-count pre-flight. It is bearer-`messages.create` — the SAME scope as
> the `createMessage` it pre-flights, so no already-provisioned key has to be
> re-scoped and no unauthenticated counting oracle exists.

1. **Every operation carries `visibility`, `auth.kind`, `auth.scope`, and
   `rbac_action`.** Port these as Hono middleware driven by the contract, not as
   hand-written per-route guards — one table-driven middleware keeps all 261 in sync.
2. **`auth.kind: "internal"`** — the 6 `/v1/self-hosted-workers/*` operations
   (`artifacts`, `checkpoints`, `events`, `heartbeat`, `runs/ack`, `runs/poll`)
   are worker-plane callbacks. They must NOT be reachable with a normal tenant
   bearer key.
3. **`auth.kind: "anonymous"`** — only `/healthz`, `/readyz`, `/admin`, `/admin/`,
   `/admin/dashboard`, `/.well-known/agent.json`. Nothing else may be unauthenticated.
4. **`method_dependent`** — 1 operation authenticates differently per method;
   read the contract entry rather than assuming.
5. **`GET /metrics` is `visibility: internal` but `auth.kind: bearer`** — internal
   surface, still bearer-guarded. Do not expose publicly, do not leave unauthenticated.
6. **401 vs 403**: preserve the Rust semantics — a *suspended* native API key
   returns 401, not 403 (see `docs/legacy/inventory-edge-control.md`; this was a
   real defect class in the Rust tree).
7. **`/control/v1/*` → `/admin/v1/*` alias canonicalization** must be kept
   (`ferrogate-admin`'s naming contract).

## Dynamic surfaces (NOT in the 261)

From `dynamic_surfaces` in the contract — these are data, not contract:

- **Operator-defined reverse-proxy routes** (`configured host/path routes`):
  matched at runtime from config, dispatched to arbitrary upstreams. In the Rust
  tree this was the `matchit` radix tree; in Hono use a catch-all resolved
  against the config snapshot.
- **`OPTIONS /admin/{*rest}`** — CORS preflight, exists only when an admin-console
  allowed origin is configured.

## Porting guidance

- Generate the route table from the JSON at build time (or import it directly)
  so a contract change can't silently drift from the implementation. Add a test
  asserting **`routes.length === 252`** and that every contract `operation_id`
  has a handler — this is the anti-drift gate.
- Zod schemas per operation live in `@ferrogate/schemas`; the validator is
  `@hono/zod-validator`.
- Streaming operations (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`,
  `/v1/agents/{name}/message:stream`, `/v1/agent-jobs/{run_id}/events`) must
  preserve upstream SSE framing byte-for-byte — see `docs/rewrite/TESTING.md`
  for the MSW-based streaming test approach.
