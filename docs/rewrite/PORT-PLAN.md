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

## Current state (what already exists)

The CF migration was **already partially underway**. Preserve and fold in:

| Existing (`workers/`) | Role today | Disposition |
|---|---|---|
| `agent-gateway` | Agents SDK + Durable Object + `@cloudflare/sandbox`; governed container egress (`enable_ctx_exports`, #413/#471) | **Keep & extend** |
| `d1-proxy` | Native D1 binding behind bearer-auth HTTP API for the atomic control-plane hot path (#450) | **Keep**; becomes storage access layer |
| `gateway-front` | Veto-only shell in front of the container-hosted **Pingora (Rust)** data plane (#470) | **Fold into** `apps/gateway` |
| `mcp-server` | MCP server: `@modelcontextprotocol/sdk`, OAuth provider, Zod, Agents SDK | **Keep**; Hono-ify, wire `agent_run_id` |
| `telemetry-collector` | Observability sink | **Keep & extend** (Analytics Engine / Logpush) |
| `admin-console` (React/Vite) | Admin UI | Migrate to Bun later (console is lowest priority) |

The single largest new build is replacing the **Rust Pingora data plane** with a
**TS Hono data plane** inside `apps/gateway` (streaming LLM proxy).

## Target monorepo topology

```
packages/*   → shared libraries (pure TS, no Worker entry)
apps/*       → deployable Workers / binaries authored fresh for this rewrite
workers/*    → the 5 existing Workers (kept, migrated to Bun + Hono where noted)
```

### Crate → TS package/app map

| Rust crate | Target | CF products |
|---|---|---|
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
| `ferrogate-mcp` | `workers/mcp-server` | MCP SDK, Agents SDK, DO |
| `agent-worker` | `workers/agent-gateway` | Agents SDK, containers/sandbox |
| `ferrogate-cli` | `apps/cli` | Bun-compiled binary (not a Worker) |

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

**Only after** all domains reach parity: delete `crates/**` + `Cargo.*`,
merge `main-ts` → `main`, and remove Rust from `main`.

## Porting waves (parallel sub-agents, worktree-isolated)

- **Wave 1 (foundations):** `core`, `schemas`, `config`, `storage` (D1 schema).
- **Wave 2 (libraries):** `policy`, `guardrails`, `secrets`, `providers`,
  `routing`, `observability`, `billing`, `sync-bridge`.
- **Wave 3 (data plane):** `apps/gateway` (the big one) + fold `gateway-front`.
- **Wave 4 (control/edge):** `apps/control-plane`, `mcp-server`, `agent-gateway`,
  `telemetry-collector`, `apps/cli`.
- **Wave 5:** integration, end-to-end parity tests, Rust removal, merge.
