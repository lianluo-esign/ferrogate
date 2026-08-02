<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, TypeScript on Cloudflare Workers, agent-native AI traffic infrastructure.
-->

# FerroGate

**Language:** English | [简体中文](README.zh-CN.md)

FerroGate is an open-source AI gateway that runs entirely on Cloudflare
Workers. It is a control point for AI traffic: OpenAI-compatible and
Anthropic-native inference APIs, multi-vendor provider routing with canary and
shadow rollouts, virtual API keys with scopes and tenant isolation, policy and
guardrail screening, rate limits, quotas and prepaid wallets, durable token
metering and billing, an asset closed loop, an MCP server, agent runs, and a
~250-operation admin API.

It is written in TypeScript end to end and deploys as a fleet of Workers backed
by D1, R2, KV, Durable Objects, Queues and Analytics Engine.

The project is developed as the open-source gateway foundation behind
[Token4AI Cloud](https://token4ai.cloud).

## Architecture at a glance

Six deployables live under `apps/`. Five are Workers; the sixth is a CLI binary.

| Deployable | Worker name | What it is |
|---|---|---|
| `apps/gateway` | `ferrogate-gateway` | The **data plane**. A Hono streaming proxy for inference, plus the asset surface. Owns 31 contract operations. |
| `apps/control-plane` | `ferrogate-control-plane` | The **admin API** — 197 contract operations (192 under `/admin/v1/**`, plus the `/admin` pages and `/metrics`), and the admin-console session surface, SAML, OIDC and SCIM. |
| `apps/mcp` | `ferrogate-mcp` | Model Context Protocol server: JSON-RPC ingress, OAuth flow, sessions, governed tool execution. 6 contract operations. |
| `apps/agent-runtime` | `ferrogate-agent-runtime` | Agent runs and jobs, A2A agent upstreams, and the self-hosted worker plane. 15 contract operations. |
| `apps/telemetry` | `ferrogate-telemetry` | OTLP receiver that writes to Analytics Engine. Owns no contract route; the other Workers feed it over a service binding. |
| `apps/cli` | — | `ferrogate`, the management CLI. A Bun-compiled binary, not a Worker. |

`/healthz` and `/readyz` are implemented in every Worker.

### The gateway request path

A request to `apps/gateway` passes through one table-driven chain, in this
order:

1. **Request id** and request metrics.
2. **Network gate** — pre-auth IP allow/deny, so a flood never pays for a
   credential lookup.
3. **Contract auth** — one guard for all 251 operations, driven by the route
   contract's `auth.kind` / `auth.scope` / `rbac_action`.
4. **Admission** — rate limit (Durable Object counter), quota, monthly budget,
   prepaid wallet hold.
5. **Guardrails** — request-stage screening.
6. **Drain gate** — `503 node_draining` on spend-producing operations when the
   fleet is drained.
7. **Response cache** — exact-match or opt-in semantic (in-tree feature-hashing
   embedder and cosine similarity; no vector database), over the Cache API.
8. **Zod validation**, then the **model registry** (logical models, fallback,
   canary and shadow splits).
9. **Upstream dispatch** — provider adapters with a circuit breaker Durable
   Object, retry and failover; SSE framing is preserved byte-for-byte and a
   client disconnect aborts the upstream.
10. **Durable metering** — the ledger row and the billing-outbox row commit in
    the same D1 `batch()`, then publish onto a Queue.

Per-tenant D1 routing sits behind the auth step, so tenant state can live in an
isolated database per tenant.

### Shared packages

Fifteen packages under `packages/`. Each exports `src/*.ts` directly — there is
no per-package build step.

| Package | Responsibility |
|---|---|
| `core` | Request identity, tenant/workspace attribution, tool primitives, approval policy, redaction guard, boundary errors. |
| `schemas` | Zod wire envelopes and the OpenAPI contract registry. |
| `config` | The operator configuration model, loader and validation. |
| `policy` | Pure allow/deny rules, quota merge, workflow execution budgets. |
| `guardrails` | Detector contracts and runtimes with deadlines, bulkheads, circuit state and SSRF-safe endpoint validation. |
| `secrets` | Secret-reference resolution: `env://`, `vault://`, `cf://` (Cloudflare Secrets Store). |
| `providers` | Provider adapters — canonical plan in, upstream wire request out, normalized response/usage back. |
| `routing` | Route match plus deterministic canary/shadow rollout selection. |
| `storage` | The persistence boundary over D1/KV/R2. |
| `billing` | Rate cards, pricing, the idempotent ledger, outbox delivery. |
| `payments` | The x402 / Solana client-side wire contract (deprioritized). |
| `observability` | Logging, metrics and OTLP request construction. |
| `cloudflare` | The Cloudflare account-management REST surface (R2 buckets, scoped tokens, D1 database lifecycle). |
| `sso` | SAML 2.0 service provider. |
| `identity` | OIDC relying party and SCIM 2.0 provisioning. |

### Cloudflare products in use

- **D1** — one control database plus per-tenant databases. Migrations in
  `sql/d1-ts/{control,tenant}/`.
- **R2** — asset object storage.
- **KV** — MCP OAuth state.
- **Durable Objects** — 7 classes: rate limiter, provider circuit breaker,
  shadow budget (gateway); MCP OAuth flow claim and MCP session (mcp); agent
  run state and worker plane (agent-runtime).
- **Queues** — the billing-report outbox producer.
- **Cache API** — the response cache.
- **Analytics Engine** — the telemetry sink.
- **Service bindings** — gateway → telemetry.
- **Secrets Store** — `cf://` secret references, bound at deploy time.
- **Workers AI** — the Llama Guard guardrail detector adapter. The `[ai]`
  binding is supplied at deploy time; it is not declared in the committed
  configuration.

## The route contract

`docs/openapi/runtime-api-contract.json` is the authoritative source for the
runtime surface: **251 operations**, each carrying `path`, `method`,
`operation_id`, `visibility`, `auth.kind`, `auth.scope` and `rbac_action`.
Every Worker imports it directly rather than restating it, and each app's
contract test fails if an operation it owns is not registered.

The split is 193 admin, 51 public and 7 internal operations; auth kinds are 238
bearer, 6 internal (worker-plane callbacks), 6 anonymous and 1
method-dependent. `docs/rewrite/ROUTE-MAP.md` assigns each operation to a
Worker. Field-level request and response bodies for the admin surface are in
`docs/openapi/admin-api.openapi.json`.

## Capabilities deliberately not offered

Three operations are **mounted, guarded, and then refused** with
`501 capability_not_offered`:

- `POST /v1/functions/execute`
- `GET /v1/tools` and `POST /v1/tools/execute`

This is a product decision, not an outage, not unfinished work, and not a
platform limit — nothing in the backlog tracks it and it is not a bug. The
decision, its reasoning, and what a re-implementer would need are recorded in
[`docs/rewrite/DROPPED-CAPABILITIES.md`](docs/rewrite/DROPPED-CAPABILITIES.md),
and a test hard-codes the dropped set so the refusal cannot be softened without
recording a decision.

## Getting started

Prerequisites: [Bun](https://bun.sh) (the version is pinned by
`packageManager` in `package.json`). Wrangler and every other tool arrive as a
dev dependency — no global installs, no Cloudflare account, and no network
access are needed for the offline workflow below.

```bash
bun install
```

### Run the tests

```bash
bun run test        # every workspace
bun run typecheck   # tsc --noEmit, every workspace
bun run lint        # biome
```

`bun run test` fans out to each workspace's own `test` script, and **that
matters**: four workspaces chain a second (and `apps/gateway` a third) Vitest
run behind a non-default config — `apps/gateway` (rate-limit and tenancy
harnesses), `apps/agent-runtime` (durable harness), `packages/storage` (D1) and
`packages/routing` (Durable Objects). A bare `vitest run` at the repo root or
inside one of those workspaces silently under-reports.

To run one workspace:

```bash
bun run --filter '@ferrogate/app-gateway' test
```

### Run a Worker locally

`wrangler dev --local` boots the real `workerd` against local D1/KV/R2/DO
state. Apply the migrations first — `wrangler dev` provisions an empty SQLite
file per database id and does not run `migrations_dir`, and the gateway
correctly refuses to serve an empty schema:

```bash
cd apps/gateway
bunx wrangler d1 execute DB --local -y --file=../../sql/d1-ts/tenant/0001_init_tenant.sql
bunx wrangler d1 execute BILLING_DB --local -y --file=../../sql/d1-ts/control/0001_init_control.sql
bunx wrangler dev --local --ip 127.0.0.1 --port 8787
```

Each app also has `bun run dev` (`wrangler dev`) and `bun run deploy`
(`wrangler deploy`).

The committed `[vars]` are the **fail-closed empties**: with no credential
configured, every authenticated route answers `401` before its handler runs,
and with no provider or model configured the registry is empty and every model
answers `400 model_not_found`. Override them for a local session with `--var`
(the end-to-end harness does exactly this) or a gitignored `.dev.vars`.

### End-to-end

```bash
bun run test:e2e
```

Playwright starts a real `wrangler dev` per app from that app's production
`wrangler.toml`, applies the local D1 migrations, and drives the Workers over
HTTP. There is no browser — every spec uses the `request` fixture. A cold
`wrangler dev` takes 35–50s per app, so leave one running and the suite
attaches to it.

## Deploying

Wrangler is the only bundler and the only deploy tool. There is no separate
build step: `wrangler deploy` bundles `src/worker.ts` per app.

**Read [`docs/rewrite/CLOUD-VERIFICATION.md`](docs/rewrite/CLOUD-VERIFICATION.md)
before the first deploy.** It is the ordered runbook, and the order is not
arbitrary — a service binding is resolved by name at deploy time, so
`ferrogate-telemetry` must exist before `ferrogate-gateway` deploys, and the
cross-Worker rate-limit bindings must be attached after it. That document also
enumerates the preconditions the repository deliberately does not commit:

- Every `database_id`, bucket name, queue name and KV namespace id in
  `apps/*/wrangler.toml` is a placeholder. No real account id, database uuid or
  secret is committed.
- D1 migrations (`wrangler d1 migrations apply`) must be applied before the
  first authenticated request.
- Secrets go in with `wrangler secret put` — the admin-console JWT secret, and
  one per tenant SSO `env://` reference.
- Several committed `[vars]` are dev-posture defaults that must be overridden
  in the deploy environment rather than flipped in the committed file, because
  the offline suites drive the apps through them.

Durable Objects, Queues and Analytics Engine require a paid Cloudflare plan.

## Repository layout

```text
apps/          6 deployables — 5 Workers + the CLI binary
packages/      15 shared TypeScript libraries (source-only, no build step)
e2e/           Playwright black-box suite over real `wrangler dev`
sql/d1-ts/     D1 migrations: control/ and tenant/
docs/openapi/  the route contract + the admin OpenAPI document
docs/rewrite/  architecture, testing, deploy and parity records
```

Roughly 90k lines of TypeScript source and 114k lines of tests: 7,051 tests
across 385 files in 21 workspaces, plus 22 Playwright end-to-end tests.

## Testing strategy

Three layers, all of which run **offline and without Docker**. See
[`docs/rewrite/TESTING.md`](docs/rewrite/TESTING.md).

1. **Unit and integration** — Vitest on `@cloudflare/vitest-pool-workers`,
   which boots the real local `workerd`. D1, KV, R2 and Durable Object bindings
   genuinely work; they are not mocked. Integration tests dispatch through
   `SELF` from `cloudflare:test`.
2. **Upstream mocking** — MSW intercepts the gateway's outbound `fetch()` to
   provider hosts and returns canned SSE, so token counting, stream
   normalization and MCP forwarding are exercised deterministically. No real
   LLM is ever called.
3. **End-to-end** — Playwright over `wrangler dev`, which is the only layer
   that exercises Wrangler's own bundle and `workerd`'s service registration —
   a Worker can be correct under `SELF.fetch` and still fail to start as a
   service.

## Documentation

The current architecture is documented under `docs/rewrite/`:

- Architecture and package map: [`PORT-PLAN.md`](docs/rewrite/PORT-PLAN.md)
- Route ownership per Worker: [`ROUTE-MAP.md`](docs/rewrite/ROUTE-MAP.md)
- Testing strategy: [`TESTING.md`](docs/rewrite/TESTING.md)
- Deploy runbook and preconditions: [`CLOUD-VERIFICATION.md`](docs/rewrite/CLOUD-VERIFICATION.md)
- Capabilities not offered: [`DROPPED-CAPABILITIES.md`](docs/rewrite/DROPPED-CAPABILITIES.md)
- Current state, open findings and known gaps: [`CUTOVER-READINESS.md`](docs/rewrite/CUTOVER-READINESS.md)
- Cross-Worker consistency invariants: [`FLEET-CONSISTENCY.md`](docs/rewrite/FLEET-CONSISTENCY.md)
- Where each mounted surface is proven: [`MOUNT-SEAMS.md`](docs/rewrite/MOUNT-SEAMS.md)

The API contracts are in `docs/openapi/`. Other documents under `docs/` predate
the TypeScript implementation and describe the earlier system; treat
`docs/rewrite/` and the contracts as authoritative where they disagree.

## Contributing

FerroGate is built for human maintainers and AI coding agents working together.
The best contributions are small, issue-linked slices that can be reviewed,
tested, and explained from the operator's point of view. Day-to-day development
runs as cooperating agent roles — one generating code, one reviewing it, one
testing it end to end; the contract is in
[`docs/autonomous-dev-loop.md`](docs/autonomous-dev-loop.md).

Two conventions from it are worth knowing even for a one-off human patch:

- **Say what you did not verify.** Commits carry `Tested:` and `Not-tested:`
  trailers, and a handoff that reads as verified when it is not costs a whole
  review round.
- **Assert the behaviour, not the call.** A test that proves a guard was
  *invoked* while the guard itself could be inverted with the suite still green
  is the single most common defect this project has had to reject. If you add a
  guard, name the mutation that would break it.

Practical rules:

1. Keep behaviour in the owning package; avoid cross-cutting rewrites.
2. Ship tests in the same change as the logic.
3. A new runtime route needs a contract entry — the contract is imported, not
   restated, so a handler without one is unreachable and a contract entry
   without a handler fails its app's test.
4. Include exact verification commands and known gaps in the PR.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure process.
Report suspected vulnerabilities privately; do not open a public issue.

## Project history

FerroGate was previously implemented in Rust on Cloudflare Pingora. That
implementation was replaced by this one and is preserved at the git tag
`legacy-rs`.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
