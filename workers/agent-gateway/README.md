<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: FerroGate agent-gateway Worker — deploy + SDK-migration caveat (issue #413).
-->

# FerroGate agent-gateway Worker (issue #413)

The **required front for ALL Cloudflare agent operations**. Cloudflare exposes
**no first-party REST API** to create / start / stop / invoke / inspect / destroy
an individual agent (Durable Object) instance — the DO REST API is read-only at
instance granularity. Therefore every agent operation FerroGate drives must be
fronted by a Worker we write and deploy. This is that Worker.

See `docs/cloudflare-agent-gateway.md` for the full architecture and how #412 /
#414 / #426-428 build on it.

## What it contains

- **`AgentGateway`** — a Durable Object agent class (Agents SDK `Agent`),
  registered with a **`new_sqlite_classes`** DO migration (the SDK stores agent
  state in an embedded per-instance SQLite DB).
- **`routeAgentRequest(request, env, options)`** — path-routes
  `/agents/:agent/:name/...` to the DO, DIY-gated in
  `onBeforeRequest` / `onBeforeConnect`.
- **Explicit control routes** (`/control/*`) — each addresses an instance **by
  name** via `getAgentByName(ns, name)` and invokes an RPC method
  (`start` / `invoke` / `cancel` / `destroy` / `status`).
- **DIY auth** — bearer token compared (constant-time) against the
  `GATEWAY_CONTROL_TOKEN` secret in `onRequest` / `onBeforeRequest` / the control
  routes. mTLS and Cloudflare Access are documented stronger alternatives.

## Control-route contract

| Verb | Route | Body / query | Returns |
|------|-------|--------------|---------|
| start   | `POST /control/start`   | `{ sessionId, runId, workerTemplateId, frameworkAdapter, capabilityEnvelopeId }` | `{ runRef, status }` |
| invoke  | `POST /control/invoke`  | `{ runRef, workloadRef, args[] }` | `{ runRef, status, exitCode, message }` |
| cancel  | `POST /control/cancel`  | `{ runRef, reason }` | `{ runRef, status }` |
| destroy | `POST /control/destroy` | `{ runRef }` | `{ runRef, status }` |
| status  | `GET  /control/status`  | `?runRef=NAME` | `{ runRef, status, message }` |

`runRef` is the agent instance name (the `runId` supplied to `start`). All
routes require `Authorization: Bearer <GATEWAY_CONTROL_TOKEN>`. `GET /healthz`
is the only unauthenticated route.

The Rust side (`crates/ferrogate-runtime/src/cloudflare_gateway_control.rs`)
maps `CloudflareControlSurface` verbs onto exactly these routes.

## Deploy

```sh
npm install                       # installs the PINNED agents + wrangler versions
wrangler secret put GATEWAY_CONTROL_TOKEN   # seed the DIY auth secret
wrangler deploy                   # PUT the script + DO migration
```

Teardown: `wrangler delete` (or the Rust pipeline's script DELETE).

FerroGate can also deploy without the Wrangler CLI via the Workers **Script PUT**
API (`PUT /accounts/{account_id}/workers/scripts/{name}`) — see the Rust deploy
pipeline in `crates/ferrogate-runtime/src/cloudflare_gateway_deploy.rs`.

## Pinned versions

- `agents` (Agents SDK) — **pre-1.0**, pinned exactly in `package.json`
  (`0.0.109`). The pre-1.0 API surface (`routeAgentRequest`, `getAgentByName`,
  `Agent`) can change between patch releases, so the pin is exact, not a range.
- `wrangler` — pinned exactly (`4.20.5`).

## SDK migration caveat (exports vs. legacy `migrations`)

The DO class must be registered so the runtime knows to create it with a
SQLite backend. Two forms exist across wrangler/SDK versions:

1. **`[[migrations]]` array with `new_sqlite_classes`** (used in `wrangler.toml`
   here) — accepted by wrangler 4.x. Use `new_sqlite_classes`, **not**
   `new_classes` (the Agents SDK requires the SQLite storage backend).
2. **Top-level `exports` / newer `[migrations]` mechanism** — some Agents SDK
   templates surface DO classes this way.

**Verify against the pinned `agents` version at deploy time.** If `wrangler
deploy` reports an unknown migration key or "class not exported", switch the
`wrangler.toml` migration block to the form the pinned SDK documents. This is
called out here because the SDK is pre-1.0 and the two forms are not
interchangeable across all versions.

## Not runnable in the FerroGate sandbox

This Worker needs a real Cloudflare account/token and network to deploy and to
prove a live control round-trip. In the offline dev sandbox only
`npm run typecheck` (tsc) can be attempted, and only if dependencies are already
installed. The live deploy + round-trip are the test agent's to prove.
