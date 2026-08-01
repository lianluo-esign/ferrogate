# FerroGate — Rust → TypeScript / Cloudflare Workers rewrite

**Goal:** a faithful **1:1 re-implementation** of the FerroGate AI Gateway in
TypeScript on the Cloudflare Workers platform. No feature regressions.

**Stack (fixed):** Bun (package manager / workspaces) · Wrangler (deploy) ·
Hono (routing + streaming proxy) · Zod (request/response validation). Use the
**full Cloudflare product suite** wherever a product fits — do not reinvent:
Workers, Durable Objects, Workers KV, R2, D1, Queues, Workers AI, **AI Gateway**,
Cache API, Service Bindings, Secrets Store, Analytics Engine / Logpush, the
Agents SDK, and `@cloudflare/sandbox`/containers for governed egress.

**Reference / parity spec (do not delete until parity is proven):**
- `crates/**` — the authoritative Rust implementation (also tagged `legacy-rs`).
- `docs/legacy/inventory-*.md` — per-cluster feature inventories (generated).
- `docs/legacy/issues-all.json` — 579 issues (acceptance criteria & edge cases).
- `docs/legacy/prs-all.json` — 83 PRs (implementation history).

## HARD RULE — the TS project is a clean-room replica, not a wrapper

The TypeScript project is an **outer replica** of the Rust project. The Rust code
is **read-only reference material only** — you read it to learn the behavior, then
**re-implement it from scratch in TypeScript**.

- **NEVER** import, link, FFI, `wasm-bindgen`/`wasm-pack`, subprocess, or
  container-host any Rust crate from the TS code. There is **zero Rust in the TS
  build graph and zero Rust in the runtime request path.**
- The Rust **Pingora** data plane (today hosted in a container behind the
  `gateway-front` TS shell) is **eliminated** and re-implemented natively as a
  Hono streaming proxy in `apps/gateway`. No Rust container in the hot path.
- `crates/**` stays checked out **solely** so agents can diff against it for
  parity. When parity is proven it is deleted outright (not "unplugged").
- Do not `cargo build` anything, do not add Rust build steps, do not ship `.wasm`
  compiled from this repo's Rust. If you feel tempted to reuse a Rust artifact,
  re-write the logic in TS instead.

## Current state (reference only — rewrite fresh)

The CF migration was already partially underway, but per directive the existing
`workers/*` are **reference material only**, exactly like `crates/**`: read them to
learn the intended CF behavior, then **re-implement fresh** in `apps/*` +
`packages/*`. They are NOT imported, NOT built on, NOT in the Bun workspace, and
are **deleted at parity**.

| Existing (`workers/`) | Behavior to replicate (reference) | Fresh home |
|---|---|---|
| `agent-gateway` | Agents SDK + Durable Object + `@cloudflare/sandbox`; governed container egress (`enable_ctx_exports`, #413/#471) | `apps/agent-runtime` |
| `d1-proxy` | Native D1 `batch()`/`RETURNING` behind bearer-auth HTTP API (#450) | `apps/control-plane` (or a D1 DO) |
| `gateway-front` | Veto-only shell over the container Pingora data plane (#470) | `apps/gateway` (native, no container) |
| `mcp-server` | MCP `@modelcontextprotocol/sdk` + OAuth + Zod + Agents SDK | `apps/mcp` |
| `telemetry-collector` | Observability ingest sink | `apps/telemetry` |
| `admin-console` (React/Vite) | Admin UI | rebuilt later (console = lowest priority) |

The single largest new build is replacing the **Rust Pingora data plane** with a
**TS Hono data plane** inside `apps/gateway` (streaming LLM proxy). The committed
**251-operation route contract** at `docs/openapi/runtime-api-contract.json` is the
authoritative source for every Hono route (path/method/visibility/auth/scope/rbac).

## Target monorepo topology

```
packages/*   → shared libraries (pure TS, no Worker entry)
apps/*       → deployable Workers / binaries authored fresh for this rewrite
workers/*    → LEGACY reference only (rewrite fresh into apps/*); deleted at parity
```

### Crate → TS package/app map

| Rust crate | Target | CF products |
|---|---|---|
| `ferrogate-cloudflare` | `packages/cloudflare` — **mostly superseded by native bindings**; see `docs/rewrite/cf-crate-assessment.md` for the per-slice verdict | R2 (bucket provisioning), API Tokens (scoped R2 creds), D1 (**database lifecycle**, not the query endpoint), account preflight, shared retry/backoff + error taxonomy |
| `ferrogate-core` | `packages/core` | — (types, errors) |
| `ferrogate-config` | `packages/config` | Workers vars/secrets |
| `ferrogate-policy` | `packages/policy` | — |
| `ferrogate-guardrails` | `packages/guardrails` | **AI Gateway guardrails**, Workers AI |
| `ferrogate-secrets` | `packages/secrets` | **Secrets Store** (deploy-time binding) |
| `ferrogate-providers` | `packages/providers` | AI Gateway, `fetch()` |
| `ferrogate-routing` | `packages/routing` | — |
| `ferrogate-storage` | `packages/storage` | **D1** (Postgres→SQLite), KV, R2 |
| `ferrogate-billing` | `packages/billing` | D1, Durable Objects (counters), Queues |
| `ferrogate-payments` | `packages/payments` | (x402/Solana deprioritized) |
| `ferrogate-observability` | `packages/observability` | Analytics Engine, Tail/Logpush |
| `ferrogate-sync-bridge` | `packages/sync-bridge` | Queues, Service Bindings |
| `ferrogate-gateway` + `ferrogate-runtime` + Pingora | `apps/gateway` | Workers, **DO** (rate-limit/session), Hono streaming |
| `ferrogate-admin` + `ferrogate-auth-service` + `ferrogate-control-plane-client` | `apps/control-plane` | Workers, D1, Hono, Secrets Store |
| `ferrogate-mcp` | `apps/mcp` | MCP SDK, Agents SDK, DO |
| `agent-worker` | `apps/agent-runtime` | Agents SDK, containers/sandbox |
| `ferrogate-cli` | `apps/cli` | Bun-compiled binary (not a Worker) |

> **This map must list EVERY crate — including the ones whose answer is
> "obsolete".** `ferrogate-cloudflare` appeared in no row for sixteen waves, so
> no wave ever owned it and nobody noticed that four of its slices had no TS
> equivalent anywhere. It took a cutover certification to find. A crate whose
> verdict is "superseded by a binding" still needs a row saying so; a crate with
> no row is a crate nobody is responsible for. If a new crate is discovered,
> add the row FIRST, then decide the verdict.

## Conventions

- Every deployable has `wrangler.toml`, `src/index.ts` (Hono app), `tsconfig.json`
  extending `../../tsconfig.base.json`, `vitest.config.ts` using
  `@cloudflare/vitest-pool-workers` (offline, docker-free — proven for the
  existing Workers).
- Every external request/response boundary is validated with a **Zod** schema in
  `packages/schemas` (or a co-located `schemas.ts`), shared between edge & control.
- Streaming (SSE / chunked) LLM responses proxy through Hono's streaming helpers;
  preserve upstream framing byte-for-byte.
- Postgres→D1: capture the full Supabase schema in `packages/storage`, translate
  to SQLite migrations, flag Postgres-only features (see data-billing inventory).

## Parity verification (definition of done, per domain)

1. Every public behavior in the crate's inventory has a TS equivalent.
2. Every acceptance criterion in the relevant `issues-all.json` items is met.
3. Tests pass under `@cloudflare/vitest-pool-workers` (offline).
4. Guardrail/isolation/auth semantics preserved (EICAR scan, cross-tenant
   isolation, native-api-key 401-vs-403 suspension, MCP `agent_run_id`).

**Only after** all domains reach parity: delete `crates/**` + `Cargo.*` + the
legacy `workers/**`, merge `main-ts` → `main`, and remove Rust from `main`.

## Porting waves (parallel sub-agents, worktree-isolated)

- **Wave 1 (foundations):** `core`, `schemas`, `config`, `storage` (D1 schema).
- **Wave 2 (libraries):** `policy`, `guardrails`, `secrets`, `providers`,
  `routing`, `observability`, `billing`, `sync-bridge`.
- **Wave 3 (data plane):** `apps/gateway` (the big one) + fold `gateway-front`.
- **Wave 4 (control/edge):** `apps/control-plane`, `mcp-server`, `agent-gateway`,
  `telemetry-collector`, `apps/cli`.
- **Wave 5:** integration, end-to-end parity tests, Rust removal, merge.
