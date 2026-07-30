<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Hosting a FerroGate-defined MCP server on Cloudflare (issue #409): the McpAgent
  Worker, the Workers Script-API deploy flow, OAuth/KV setup, and how it relates to consuming
  Cloudflare's MCP servers (#408).
-->

# Hosting a FerroGate-defined MCP server on Cloudflare (issue #409)

FerroGate's MCP story has **two directions**:

1. **Consume** Cloudflare's managed MCP servers (**#408**) — register
   `https://mcp.cloudflare.com/mcp` (and product servers) as ordinary upstream
   `McpServerConfig`s over Streamable HTTP. FerroGate is the *client*; Cloudflare
   supplies the tools. (See the recipe at the top of `ferrogate-mcp/src/lib.rs`.)
2. **Host** a FerroGate-defined MCP server (**this doc, #409**) — stand up a
   tenant's **own** MCP server on Cloudflare (Workers + Agents SDK) and manage its
   lifecycle. FerroGate defines the *tool surface*; Cloudflare supplies the
   *hosting* (Workers + Durable Objects). The server goes live at
   `https://<worker>.<account>.workers.dev/mcp`.

This note covers direction 2.

## 1. The Worker: an `McpAgent` at `/mcp`

`workers/mcp-server/` is a TypeScript Worker built on the Cloudflare Agents SDK.
The MCP server is an **`McpAgent` Durable Object** (`FerroGateMcp`) — stateful and
**per-session**: each MCP session is its own DO instance, and the SDK keeps
session state in an embedded per-instance SQLite database. `McpAgent.serve("/mcp")`
mounts the Streamable HTTP transport (and `serveSSE("/sse")` the legacy SSE
transport).

The **base tool surface** is three small, dependency-free example tools —
`echo(message)`, `add(a, b)`, and `whoami()` — that prove the hosting path
end-to-end. A real tenant swaps these for its own tools (backed by R2 / D1 / an
external API, etc.).

> **Stateful vs stateless.** We use the stateful `McpAgent` DO to exercise the
> full Durable-Object deploy path (binding + `new_sqlite_classes` migration). If a
> tenant needs no per-session state, the SDK's `createMcpHandler()` (or a plain
> fetch handler) replaces the DO — drop the DO binding + migration from the deploy
> metadata. The Rust pipeline's binding/migration fields are parameterized, so a
> stateless spec just omits them.

## 2. OAuth + KV

`@cloudflare/workers-oauth-provider` fronts `/mcp` + `/sse` with the OAuth 2.1
flow — **Cloudflare is the authorization server**. The provider needs a **KV
namespace binding `OAUTH_KV`** to persist issued grants, tokens, and
dynamically-registered clients. Setup is one-time:

```sh
wrangler kv namespace create OAUTH_KV      # paste the id into wrangler.toml
```

The provider issues and stores its own tokens, so **no additional secret is
required for the OAuth flow itself**. The interactive authorize/consent surface is
the provider's `defaultHandler`; the reference **auto-approves** for a
single-tenant/dev deployment, and a production server MUST render a consent screen
+ authenticate the end user before calling `completeAuthorization`. The grant's
`props.userId` is delivered to the agent as `this.props.userId` (surfaced by the
`whoami` tool).

**Automation bearer.** An optional static credential short-circuits OAuth and
routes directly to the MCP transport — for CI and FerroGate's own
machine-to-machine calls. It is sourced through the **#423 Secrets Store seam**:
the deploy declares a `secrets_store_secret` binding (`MCP_BEARER_TOKEN_STORE`)
and the Worker reads it with `await env.MCP_BEARER_TOKEN_STORE.get()`. Rotating
the value in the store needs no redeploy, and the plaintext never passes through
a FerroGate process. A plain `wrangler secret put MCP_BEARER_TOKEN` remains the
fallback for accounts with no Secrets Store.

| Requirement | What | How |
|-------------|------|-----|
| KV namespace | `OAUTH_KV` binding | `wrangler kv namespace create OAUTH_KV`, id in `wrangler.toml` |
| OAuth secret | none (provider self-issues) | — |
| Automation bearer (optional, preferred) | `MCP_BEARER_TOKEN_STORE` secrets-store binding | `wrangler secrets-store secret create <STORE_ID> --name mcp-bearer-token`, then `McpWorkerSpec::with_bearer_token_from_secrets_store` (or the `[[secrets_store_secrets]]` block in `wrangler.toml`) |
| Automation bearer (fallback) | `MCP_BEARER_TOKEN` secret | `wrangler secret put MCP_BEARER_TOKEN` |

The secret's **name** is canonical (`mcp-bearer-token`, matching `^[a-z0-9-]+$`)
and the deploy pipeline rejects a non-canonical one. That is not cosmetic: the
`cf://` env convention (`FERROGATE_CF_SECRET_*`) is lossy, so only a canonical
name lets the *same* Secrets Store secret also be referenced as
`cf://<store>/<name>` from the Rust gateway. See
`docs/cloudflare-secrets-resolution.md`.

### `keep_bindings`: a redeploy must not strip the secret

A Workers Script-API `PUT` replaces the script's **entire** binding set, so a
`secret_text` binding seeded by `wrangler secret put` would be erased by the next
deploy through the Rust pipeline — silently disabling the automation path. The
upload metadata therefore carries `keep_bindings: ["secret_text"]`
(`McpWorkerSpec::keep_bindings`), which tells Cloudflare to carry those bindings
over from the live script.

## 3. The deploy flow

Deploying a module Worker is a **`multipart/form-data` PUT** to
`PUT /accounts/{account_id}/workers/scripts/{script_name}` carrying two parts:

- **`metadata`** (JSON): `main_module`, the **Durable Object binding** for the
  `McpAgent` class, the **`kv_namespace` binding** (`OAUTH_KV`), any
  **`secrets_store_secret` bindings**, the DO **`migrations`**
  (`new_sqlite_classes` — NOT `new_classes`; the Agents SDK requires the SQLite
  backend), `keep_bindings`, plus
  `compatibility_date`/`compatibility_flags`;
- the **module** part carrying the Worker's ES-module source.

Two ways to perform it:

- **Wrangler (live fallback, documented):** `cd workers/mcp-server && npm install
  && npm run deploy`. Wrangler bundles `src/index.ts` and wraps the same script
  PUT. Teardown: `npm run teardown` (`wrangler delete`).
- **FerroGate's Rust pipeline:** `ferrogate_mcp::mcp_worker_deploy`.
  [`McpWorkerSpec`] models the upload and produces the metadata JSON + multipart
  body **deterministically** (fixed boundary), so the exact request is
  unit-assertable. [`McpWorkerDeployer`] drives the lifecycle against the **#405
  `ferrogate-cloudflare` transport seam**:

  | Op | Call | Cloudflare |
  |----|------|-----------|
  | deploy | `deploy(&spec)` | `PUT .../workers/scripts/{name}` (multipart) |
  | list | `list()` | `GET .../workers/scripts` |
  | status | `status(name)` / `status_for(&spec)` | derived from `list()` (is the script present?) |
  | subdomain | `workers_dev_subdomain()` | `GET .../workers/subdomain` |
  | teardown | `teardown(name)` | `DELETE .../workers/scripts/{name}` |

  The read side (`list`/`status`/`subdomain`) is served by a `CloudflareClient`
  built from the same parts, so it inherits the shared retry/backoff +
  typed-error mapping. The whole pipeline is mock-tested with a scripted
  transport (no network); the live multipart upload is the deploy agent's to
  prove (Cloudflare account required).

### Reporting the deployed URL

`McpDeployOutcome::mcp_url` and `McpScriptStatus::mcp_url` carry
`https://<script>.<subdomain>.workers.dev/mcp` — exactly the shape the #408
upstream detector accepts, so a deployed server can be registered back as an
`McpServerConfig` upstream. The account's `workers.dev` subdomain is not
derivable from the script name, so it is resolved once
(`McpWorkerDeployer::workers_dev_subdomain`) and recorded on the spec
(`with_workers_dev_subdomain`). Without it the URL is `None` — a wrong upstream
URL registered on a tenant is worse than an absent one.

### Multipart content type

`ferrogate_cloudflare::ReqwestTransport` honors `HttpRequest::content_type`
(#411) and defaults to `application/json` only when it is `None`, and
`build_deploy_request` sets it to `McpWorkerSpec::content_type()` — so the
**production** multipart PUT goes out as
`multipart/form-data; boundary=…` end to end. The `wrangler deploy` fallback
above remains an equivalent CLI path, not a required one.

> Superseded: this section previously stated that `ReqwestTransport` hard-codes
> `application/json` and that production therefore *must* use `wrangler`. That
> stopped being true with `677433e` (#409) on top of #411; the correction is
> recorded here rather than deleted because operators were told to avoid the Rust
> deploy path on the strength of it.

### Duplication with the #413 agent-gateway deployer

The multipart script-upload construction here intentionally **mirrors**
`ferrogate_runtime::cloudflare_gateway_deploy` (#413, the agent-gateway Worker),
and is **copied** into `ferrogate-mcp` rather than shared.

> Correction: earlier revisions of this section justified the copy with "a
> dependency cycle". **There is no cycle** — `ferrogate-runtime` depends on
> `ferrogate-core` / `ferrogate-cloudflare` / `ferrogate-storage`, and the only
> crates depending on `ferrogate-mcp` are `ferrogate-gateway` and
> `ferrogate-config`. The real reason is weaker: `ferrogate-mcp` should not take
> a dependency on a *sibling deployer* to reach ~60 lines of multipart framing.

With three Worker deployers now on `main` (#409, #411, #413), the correct
destination is a shared `WorkerScriptUpload` builder in `ferrogate-cloudflare`
that all three move to — not a fourth copy.

## 4. Billing + placement

The hosted server bills as **Workers + Durable Objects** (the `McpAgent` DO plus
its SQLite storage), on top of KV reads/writes for the OAuth grants. Placement /
jurisdiction follow the standard Workers + DO location controls; there is no
MCP-specific knob.

## 5. Relationship to the rest of the Cloudflare initiative

- **#408 (consume):** the mirror image — FerroGate as MCP *client* of Cloudflare's
  servers. A tenant can both host its own server here **and** consume CF's managed
  servers; the two paths share no code beyond the `ferrogate-mcp` crate.
- **#413 (agent-gateway):** the same Workers Script-API deploy mechanism, for the
  agent DO Worker. The duplication note above tracks unifying the two.
- **#405 (`ferrogate-cloudflare`):** the shared client/transport/token seam every
  Cloudflare deploy path — including this one — is built on.
