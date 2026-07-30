<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: FerroGate-hosted MCP server Worker — deploy + OAuth/KV setup (issue #409).
-->

# FerroGate MCP server Worker (issue #409)

A **FerroGate-defined MCP server hosted on Cloudflare**. Where issue #408 lets
FerroGate *consume* Cloudflare's managed MCP servers, this Worker is the inverse:
FerroGate stands up a tenant's **own** MCP server on Cloudflare (Workers + Agents
SDK) and manages its lifecycle, so Cloudflare provides the hosting for a
FerroGate-defined tool surface. Live at
`https://<worker>.<account>.workers.dev/mcp`.

See `docs/cloudflare-mcp-hosting.md` for the architecture and how it relates to
consuming CF MCP servers.

## What it contains

- **`FerroGateMcp`** — an Agents SDK **`McpAgent`** Durable Object (stateful,
  per-session), registered with a **`new_sqlite_classes`** DO migration (the SDK
  stores session state in an embedded per-instance SQLite DB). Mounted at `/mcp`
  (Streamable HTTP) and `/sse` (legacy SSE).
- **Base tool surface** — three small, dependency-free example tools:
  `echo(message)`, `add(a, b)`, and `whoami()` (surfaces the authenticated
  principal + this session's call count). Swap these for a tenant's real tools.
- **OAuth** — `@cloudflare/workers-oauth-provider` fronts `/mcp` + `/sse` with
  the OAuth 2.1 flow (Cloudflare as the authorization server; grants persisted in
  the `OAUTH_KV` namespace). The interactive authorize/consent surface is the
  provider's `defaultHandler`.
- **Automation bearer** — an optional static credential that short-circuits
  OAuth and routes straight to the MCP transport, for CI / machine-to-machine
  callers. Sourced from the `MCP_BEARER_TOKEN_STORE` **Cloudflare Secrets Store**
  binding when one is declared, falling back to the `MCP_BEARER_TOKEN` Worker
  secret. With neither, OAuth is the only way in.

> Stateless alternative: if you don't need per-session state, the Agents SDK's
> `createMcpHandler()` (or a plain fetch handler) can replace the `McpAgent` DO —
> drop the DO binding + migration from `wrangler.toml`. This Worker uses the
> stateful `McpAgent` to exercise the full Durable-Object deploy path.

## Pinned versions

| Package | Version | Why pinned |
|---------|---------|-----------|
| `agents` | `0.0.109` | Agents SDK `McpAgent`; the DO migration key can move between releases. |
| `@modelcontextprotocol/sdk` | `1.29.0` | `McpServer` tool registration API (matches the version `agents` bundles, so the `McpAgent.server` types dedupe). |
| `@cloudflare/workers-oauth-provider` | `0.0.5` | Pre-1.0; the `OAuthProvider` options shape can change. |
| `zod` | `3.25.76` | Tool input schemas. |
| `wrangler` | `4.20.5` | Accepts the `new_sqlite_classes` migration form used here. |

## One-time setup

1. **Create the OAuth KV namespace** and paste its id into `wrangler.toml`
   (`[[kv_namespaces]] id = ...`):

   ```sh
   wrangler kv namespace create OAUTH_KV
   ```

2. **(Optional) provision the automation bearer** for machine-to-machine access.
   Preferred — the Cloudflare Secrets Store, so rotation needs no redeploy and
   the plaintext never passes through a FerroGate process:

   ```sh
   wrangler secrets-store store create ferrogate
   wrangler secrets-store secret create <STORE_ID> --name mcp-bearer-token
   ```

   Then declare the binding **on whichever side deploys this Worker**:

   | Deployed by | Declare the store binding in | Survives a Rust-side redeploy |
   |---|---|---|
   | FerroGate's Rust pipeline | `McpWorkerSpec::with_bearer_token_from_secrets_store(<STORE_ID>)` | yes — it is in every upload |
   | `wrangler deploy` | the `[[secrets_store_secrets]]` block in `wrangler.toml` | **no** — see below |

   > **A store binding declared only in `wrangler.toml` is erased by the next
   > deploy through the Rust pipeline.** A Workers Script-API `PUT` replaces the
   > script's entire binding set, and the upload's `keep_bindings` covers only
   > `secret_text`, not `secrets_store_secret` (`DEFAULT_KEEP_BINDINGS` in
   > `crates/ferrogate-mcp/src/mcp_worker_deploy.rs` records why). After such a
   > redeploy `env.MCP_BEARER_TOKEN_STORE` is `undefined` and the automation path
   > degrades to OAuth-only with no error and no log line. If both deploy paths
   > are in use, declare the same store id on both sides.

   The secret name is canonical `[a-z0-9-]+` on purpose: that is what lets the
   same secret also be referenced from the Rust gateway as
   `cf://ferrogate/mcp-bearer-token`. Canonical naming is **necessary but not
   sufficient** — Secrets Store values are write-only over REST, so resolving
   that reference additionally requires the value to reach the gateway process
   (`FERROGATE_CF_SECRET_MCP_BEARER_TOKEN`, or an injected `CfSecretBindings`).
   See `docs/cloudflare-secrets-resolution.md`.

   Fallback, where there is no Secrets Store:

   ```sh
   wrangler secret put MCP_BEARER_TOKEN
   ```

   This `secret_text` binding *does* survive a redeploy through the Rust pipeline
   because the upload metadata carries `keep_bindings: ["secret_text"]`; without
   that, a Script-API PUT would replace the whole binding set and silently
   disable the automation path.

   No secret is required for the OAuth flow itself — the provider issues and
   stores its own tokens in `OAUTH_KV`.

## Deploy

```sh
npm install
npm run typecheck   # tsc --noEmit
npm run deploy      # wrangler deploy
```

`wrangler deploy` performs the Workers Script-API multipart upload (module +
metadata declaring the `MCP_OBJECT` DO binding, the `OAUTH_KV` binding, and the
`new_sqlite_classes` migration). FerroGate's Rust pipeline
(`ferrogate_mcp::mcp_worker_deploy`) constructs the **same** upload against the
`ferrogate-cloudflare` transport seam; `wrangler deploy` is the documented live
fallback.

## Teardown

```sh
npm run teardown    # wrangler delete
```

## Auth: OAuth vs bearer

- **OAuth (default):** clients hit `/authorize` -> `/token` -> then `/mcp`. This
  reference **auto-approves** the grant for a single-tenant/dev deployment. A
  production server MUST render a consent screen and authenticate the end user in
  the `defaultHandler` before calling `completeAuthorization` — the recorded
  `props.userId` is delivered to the agent as `this.props.userId`.
- **Bearer (automation):** presenting `Authorization: Bearer <token>` bypasses
  OAuth and routes directly to `/mcp` (or `/sse`). The expected token is read
  from `MCP_BEARER_TOKEN_STORE` first, then `MCP_BEARER_TOKEN`. A Secrets Store
  read that fails is logged and degrades to OAuth-only rather than failing the
  request.

## SDK migration caveat

If `wrangler deploy` reports an unknown-migration-key or "class not exported"
error, the pinned Agents SDK surfaces its DO class through a newer
`exports`/`[migrations]` mechanism — switch the `[[migrations]]` block in
`wrangler.toml` to the form that SDK version documents. The Rust pipeline's
`migration_tag` / class name are parameterized to match.
