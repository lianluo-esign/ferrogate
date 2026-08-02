# Legacy Inventory — EDGE & CONTROL cluster

Implementation-grade inventory of the Rust crates being rewritten 1:1 into
TypeScript on Cloudflare Workers (Bun + Hono + Zod + full CF product suite).
Scope: the edge/control-plane cluster plus the existing `workers/` (CF Worker
code) and `admin-console/` (React SPA). Every crate section covers purpose,
public surface, routes/commands, auth, external I/O, and a proposed CF/TS
mapping.

Crates covered:

- `crates/ferrogate-cli` — the `ferrogate` management CLI (priority)
- `crates/ferrogate-control-plane-client` — typed Control Plane API client + command registry
- `crates/ferrogate-cloudflare` — shared Cloudflare REST API client
- `crates/ferrogate-mcp` — MCP host/client manager + MCP-server Worker deploy
- `crates/ferrogate-auth-service` — standalone identity service (SSO/SAML/SCIM/console sessions)
- `crates/ferrogate-admin` — Control Plane API stability/naming contract
- `crates/ferrogate-sync-bridge` — async→sync bridge helper
- `crates/agent-worker` — standalone agent execution/isolation process
- `workers/` — existing CF Worker + Durable Object code (TS)
- `admin-console/` — existing React SPA (TS)

A one-line orientation on the product's two planes, because the whole cluster is
organized around it:

- **Control plane** = `/admin/v1/*` (canonical alias `/control/v1/*`): tenancy,
  IAM, config, agents, workers, MCP, guardrails, assets, billing, evidence, ops.
  This is what `ferrogate ctl`, `ferrogate-control-plane-client`, `ferrogate-admin`,
  and `admin-console` all target.
- **Data plane** = OpenAI-compatible inference (`/v1/chat/completions`,
  `/v1/responses`), MCP/tool execution, agent invoke/messaging. Structurally
  **out of scope** for the control-plane client (enforced by a parity gate).

---

## 1. `crates/ferrogate-cli` — the `ferrogate` management CLI

**Purpose.** The single shipped management binary (`ferrogate`). It parses one
big clap tree, then either serves a subsystem (gateway/auth/control-api/billing)
or acts as a client of the Control Plane API. Per project direction the CLI is a
port priority.

**Entry points.** `src/main.rs` is 11 lines → `ferrogate_cli::run()`.
`src/lib.rs::run()` installs the rustls ring provider, inits tracing, installs a
Linux test-guardian fd watcher, then:

1. Builds the full command via `command_tree::assembled_command(&registry)` =
   the derived `Cli` clap tree **+** the generic `ctl` subtree derived from the
   `ferrogate-control-plane-client` registry.
2. If the matched subcommand is `ctl`, dispatches to `ctl::run_resource` and
   `process::exit`s on a stable exit class.
3. Otherwise parses `Cli` and matches the native subcommands.

### 1.1 Native subcommands (hand-written in `cli.rs`)

| Command (alias) | Purpose | Key flags / env |
|---|---|---|
| `run` (`gateway`) | Start the Pingora gateway server | `-c/--config` (`FERROGATE_CONFIG`, default `Ferrogate/Caddyfile`), `--upgrade` |
| `auth serve` | Run the tenant/RBAC + admin-console identity service | `--listen` (`:8090`), `--data` YAML, `--supabase-dsn`, `--supabase-tls-mode`, `--supabase-tls-ca-cert-path`, `--supabase-schema` (default `auth`), `--supabase-init-schema`, `--admin-jwt-secret(-env)`, `--cors-allowed-origin` |
| `control-api serve` | Run the standalone Control Plane API reverse-proxy service (issue #359) | `-c/--config` (`[control_api]`/`[admin_api]` section) |
| `admin-api serve` | **DEPRECATED** alias of `control-api serve` (prints deprecation) | `-c/--config` |
| `billing serve` | Run the token-usage billing REST service | `--listen` (`:8092`), `--pricing`, `--credits-per-usd`, `--token(-env)`, `--supabase-*` |
| `storage migrate-to-supabase` | Migrate legacy durable state into Supabase | `--source-provider`, `--source-postgres-dsn(-env)`, `--target-supabase-dsn(-env)`, `--postgres-schema`, `--postgres-tls-mode`, `--postgres-tls-ca-cert-path`, `--dry-run`/`--execute` |
| `validate` (`check`) | Validate config + auth-posture gate; print summary | `-c/--config` |
| `reload` | Validate a candidate config or hot-reload a running gateway | `-c/--config`, `--admin-url` (`FERROGATE_ADMIN_URL`), `--admin-token` (`FERROGATE_ADMIN_TOKEN`), `--graceful-upgrade` |
| `hash-key` | Hash a virtual API key secret for durable config | `--secret` (`FERROGATE_KEY_SECRET`) |
| `assets push` | Upload a local file as a new asset version | `--gateway-url` (`FERROGATE_GATEWAY_URL`), `--api-key` (`FERROGATE_API_KEY`), `<path>`, `--type`, `--name`, `--version`, `--content-type`, `--platform`, `--channel` |
| `assets pull` | Download an asset to a file/stdout | connection + `--type`, `--name`, `--version` (exact/channel/semver-range), `--platform`, `--output` |
| `assets list` | List a tenant's assets | connection + `--type` |
| `assets delete` | Delete one asset version | connection + `--type`, `--name`, `--version`, `--platform` |
| `plans create` | Create a sellable subscription plan | connection + `--id`, `--name`, `--slug`, feature toggles (`--mcp-enabled`, `--self-hosted-workers-enabled`, `--asset-hosting-enabled`, `--extension-tools-enabled`), default limits (`--default-rpm-limit`, `--default-tpm-limit`, `--default-monthly-budget-usd`) |
| `plans list` | List all plans | connection |
| `plans assign` | Assign a plan to a tenant | connection + `--tenant-id`, `--plan-id` |
| `context create` | Create/replace a named Control Plane API client context | `<name>`, `--endpoint`, `--tenant`, `--project`, `--workspace`, `--token-env`, `--token-stdin`, `--ca-bundle`, `--insecure-skip-tls-verify`, `--use`, `--overwrite` |
| `context list/show/use/delete` | Manage contexts (current marked `*`) | `<name>` |
| `ops status` | Show Control Plane API status via the shared typed client | global args (`--context`, `--endpoint`, `--token-env`, `--output`, …) |
| `completions <shell>` | Emit shell completion for the full assembled tree | bash/zsh/fish/powershell/elvish |
| `ctl <group> <verb>` | Generic Control Plane resource families (see §2) | per-verb; built entirely from registry metadata |

**Notes for the port:**
- `assets`/`plans` are legacy gateway-direct commands using `--gateway-url` +
  `--api-key` and their own SigV4/asset handlers (`assets_cli.rs`,
  `plans_cli.rs`). `ctl assets`/`ctl plans` are the newer registry-driven paths
  hitting `/admin/v1/*`. Both are shipped (namespaced under `ctl` so nouns can't
  collide with the top-level `assets`/`plans`).
- `context`, `tenant`/`project`/`workspace` defaults are **recorded but not
  honored server-side today** (stderr note fires); a straight port should
  preserve that honesty note.
- `--sort` and `--offset` on cursor-paginated endpoints are deliberately called
  out as not-honored / refused; these are intentional CLI UX contracts, not bugs.

### 1.2 The `ctl` generic dispatcher (`src/ctl/`)

`ctl/resource_cmd.rs` is the heart: it builds the `ctl <group> <verb>` tree
purely from `Registry` metadata and routes every matched command through the
shared `build_request` seam. Key mechanisms to reproduce:

- **`ResourceArgs`** (per verb): positional id `segments`, `--data`/`--file`
  JSON body, `--limit`/`--offset`/`--filter KEY=VALUE`/`--sort`/`--all-pages`,
  `--dry-run`, and (for confirmation verbs) `--yes`.
- **Render gate (#505):** read verbs render the body; **mutating verbs can only
  emit a `MutationReceipt`** — enforced by the type system (a `ReceiptRenderer`
  has no `render(Value)`). `--dry-run` builds a receipt without opening a socket.
- **Action identity (#548):** one `ClientActionIdentity` minted per invocation
  (OS-CSPRNG `action_id` + client fingerprint + server time token), threaded to
  transport and mutation plan; shared across `--all-pages`.
- **Precedence** (`ctl/dispatch.rs`): flag > env > context > default, resolved
  once into `EffectiveContext`. Credentials come from `AuthSource` (env var name
  or stdin), never stored token values.
- Output: stdout = data (table or `--output json`), stderr = diagnostics
  (request-id, trace-id, truncation/cursor notices).

### 1.3 Dependencies & I/O

Depends on nearly every crate: `ferrogate-gateway` (serve/lifecycle/state),
`ferrogate-config`, `ferrogate-control-plane-client`, `ferrogate-auth-service`,
`ferrogate-billing`, `ferrogate-storage`, `ferrogate-runtime`, `pingora`,
`rustls`, `reqwest`, `tokio`. Linux `libc` for the SIGKILL test guardian.

### 1.4 Proposed CF/TS mapping

The CLI is **not** a Worker — it is a developer/operator binary. Port it as a
standalone **Bun CLI** (not Hono):

- clap → a TS arg parser (`commander`/`clipanion`/`cac`) or a hand-rolled
  registry-driven parser mirroring the `ctl` approach. Keep the registry-driven
  generic tree so adding a resource family stays code-free in the CLI.
- Zod: validate `--data`/`--file` JSON bodies and every response envelope.
- The `serve` subcommands (`run`, `auth serve`, `control-api serve`,
  `billing serve`) have **no clean CF-CLI equivalent** — on CF these become
  deployed Workers, so the CLI's "serve" verbs collapse to deploy/health commands
  (`wrangler deploy` wrappers) or are dropped. Flag: the CLI's identity as a
  process launcher does not survive the port; only the **client** half (`ctl`,
  `ops`, `context`, `assets`, `plans`) maps to a CLI that calls Worker HTTP.
- `MutationReceipt` render gate, action-identity minting, precedence resolver,
  cursor/offset honesty notices: port verbatim as pure TS modules (highly
  testable, no CF dependency).

---

## 2. `crates/ferrogate-control-plane-client` — typed Control Plane API client + registry

**Purpose.** The reusable typed **client** for the Control Plane API: transport,
credential/context resolution, the `MutationReceipt` envelope, and the
compile-time **command registry** the CLI composes into `ferrogate ctl`. Binds
no listener; depends on no `ferrogate-*` crate (only `clap`, `http`, `reqwest`,
`serde`, `serde_json`, `sha2`, `getrandom`).

### 2.1 Modules

| Module | Role |
|---|---|
| `command` | `Registry`, `GroupDescriptor`, `VerbDescriptor` (effect: Read/Mutating/Local; confirmation policy; response mode Structured/Raw; positional query arity), coverage manifest of OpenAPI `operationId`s |
| `transport` | One typed transport: `prepare_request`, `classify`, pagination (offset + cursor), `ReqwestTransport`, `ControlPlaneClient`, raw-export path |
| `context` | Named server profiles, `ContextStore`, precedence resolver (`resolve`) |
| `auth` | `AuthSource` (env/stdin/none), self-redacting `Credential`, `resolve_credential` |
| `action_identity` | `ClientActionIdentity` (`action_id`, fingerprint, client clock, server time token) — a **required** transport arg so no verb is unattributable |
| `receipt` | `MutationReceipt`, `MutationPlan`/`MutationReport`, render gate (`RenderGate::Bare`/`Receipt`), `--dry-run` plan |
| `dispatch` | Generic `<group> <verb>` → `RequestSpec` router + read-only secret redaction |
| `output` | Stable JSON + human `Table` |
| `parity` | #365 parity gate: places data-plane operations structurally outside the client via the `x-ferrogate-data-plane` OpenAPI extension |
| `version` | CLI/API version + fail-closed contract-version compatibility check |
| `registry_helpers`, `resource` | `ResourceInput`, `ListParams`, family builder helpers |

### 2.2 The full `ctl` resource surface (registry)

`register_resource_families` registers 12 family modules → 39 command groups.
Verbs are `list/get/create/replace/update/delete` variants unless noted; each
maps to one OpenAPI `operationId`.

- **organization** (`organization.rs`): `tenant-accounts` (+`suspend`),
  `tenants`, `projects`, `workspaces`, `plans`, `quota-policies`
- **iam** (`iam.rs`): `virtual-keys` (+`rotate`/`enable`/`disable`),
  `api-keys`, `roles`, `permissions`, `access-policies`, `tenant-roles`
  (`bind`/`unbind`)
- **agent** (`agent.rs`): `agent-workflows`, `agent-schedules`,
  `agent-upstreams`, `agent-runs` (`start`), `agent-jobs`
  (submit/status/logs/cancel)
- **worker** (`worker.rs`): `self-hosted-workers`, `managed-workers`,
  `managed-worker-sessions`, `self-hosted-worker-records`, `self-hosted-runs`
- **mcp** (`mcp.rs`): `mcp-servers`, `mcp-identity` (grant/get/revoke),
  `tool-sessions`, `tools`
- **tool_approval** (`tool_approval.rs`): `tool-approvals` (approve/deny)
- **guardrail** (`guardrail.rs`): `guardrail-policies` (activate/rollback/
  dry-run/revisions), `guardrail-evaluations`, `investigations`
- **asset** (`asset.rs`): `assets` (put/delete/yank), `asset-transfer`,
  `asset-channels` (`set` with positional version), `site-domains`
  (bind/verify/unbind)
- **catalog** (`catalog.rs`): `prompt-templates`, `skill-packages`, `plugins`,
  `catalog` (read-only models/providers/extensions), `dashboard` (aggregate reads)
- **billing** (`billing.rs`): `wallets` (+ confirmation-gated credit/debit),
  `payment-methods`, `billing-events`, `usage` (reports), `payment-attempts`
- **evidence** (`evidence.rs`): `request-logs` (+ raw export), `audit-events`,
  `observed-agent-activity`
- **ops** (`ops.rs`): `system` (status/ready/health), `provider-health`,
  `config` (validate/apply), `drain` (confirmation-gated), `gateway-configs`

### 2.3 Proposed CF/TS mapping

- Port the whole crate as a **framework-neutral TS library** consumed by the CLI
  (and reusable by any Worker calling the control plane). Nothing here is Worker-
  specific.
- Registry → a TS data structure of group/verb descriptors; Zod schemas can
  replace the `operationId`-only coverage with actual request/response types
  generated from `docs/openapi/admin-api.openapi.json` (admin-console already
  does this with `openapi-typescript`).
- `ReqwestTransport` → `fetch`. The receipt render-gate and action-identity are
  pure logic; port verbatim. The parity gate (data-plane exclusion) should become
  a build-time test against the OpenAPI doc.

---

## 3. `crates/ferrogate-cloudflare` — shared Cloudflare REST API client

**Purpose.** The foundation every FerroGate CF integration builds on (issue
#405): auth, retries, error mapping written once. Pure client library, no
product logic. `reqwest` + `serde` + `sha2` + `rustls`.

### 3.1 Surface

- **`CloudflareConfig`** (`config.rs`): `account_id`, `api_token` (a *reference*,
  redacted `Debug`), per-tenant `tenant_tokens`, `api_base_url` (default
  `https://api.cloudflare.com/client/v4`), `ai_gateway_base_url`, optional
  `r2_s3_endpoint` (default `https://<account>.r2.cloudflarestorage.com`).
- **`TokenResolver`** seam (`resolver.rs`): `EnvTokenResolver` resolves
  `env://VAR` and inline plaintext. **`cf://` (Secrets Store) is permanently
  refused here** — owned by `ferrogate-secrets` (dependency-cycle + write-only
  REST + bootstrap circularity); inside a Worker a `cf://` secret arrives as
  `env://FERROGATE_CF_SECRET_<NAME>`.
- **`CloudflareClient`** (`client.rs`): Bearer auth, `{account_id}` templating,
  `CloudflareEnvelope` decode, typed `CloudflareError`, deterministic
  retry/backoff honoring the ~1,200 req/5-min global limit. `HttpTransport` +
  `Clock` are injectable seams. Methods: `request_json`, `request_json_with`
  (multipart/bearer-override), `get_json`, `get_json_paged` (cursor),
  `request_ack`, `preflight` (names missing permission groups).
- **`scopes.rs`**: `REQUIRED_TOKEN_PERMISSION_GROUPS` — AI Gateway, Secrets
  Store, D1, Workers Scripts, Workers R2 Storage, API Tokens, Cloudflare Pages,
  Workflows.

### 3.2 Wrapped CF APIs

| Area | Endpoints wrapped | Notes |
|---|---|---|
| **D1 REST** (`d1.rs`) | `POST/GET/DELETE /d1/database`, `GET .../{uuid}`, `POST .../{uuid}/query` | Admin/low-volume path (create/list/delete/query). Params are strings; page-walks `list_databases`. **No multi-statement transaction / `RETURNING`** — that's the proxy Worker. |
| **D1 proxy** (`d1_proxy.rs`) | `POST /d1/batch`, `POST /d1/query` on the deployed `d1-proxy` Worker | Atomic hot path (batch/`RETURNING`). Own bearer, own base URL, per-request `database` binding selector (`TENANT_DB_*`). |
| **R2 buckets** (`r2.rs`) | `POST/GET/DELETE /r2/buckets` | Idempotent create (`10004`/`10073` = already-exists), cursor-walked list, injective per-tenant bucket naming `ferrogate-{slug}-{sha256(len-prefixed tenant)}`. Control plane only — **no S3 data-plane client here.** |
| **R2 scoped tokens** (`r2_token.rs`) | `POST/DELETE /accounts/{acct}/tokens` | Mints bucket-scoped API token; Access Key ID = token `id`, Secret = hex SHA-256 of one-time token `value`. Not idempotent (fresh secret per call). |
| **Worker deploy** | see `ferrogate-mcp::mcp_worker_deploy` (multipart script PUT) | Duplicated construction rather than shared (cycle avoidance). |

### 3.3 Proposed CF/TS mapping

- **Inside a Worker most of this collapses to native bindings.** D1 REST/proxy →
  `env.DB` D1 binding (`prepare/bind/batch/RETURNING` directly, no HTTP). R2 →
  `env.BUCKET` R2 binding (no SigV4). Secrets → Secrets Store binding / Worker
  secret / env var. The whole retry/backoff/envelope layer exists to make raw
  REST usable from a non-Worker process; that need mostly disappears on CF.
- **What still needs a REST client:** operations with no binding — D1/R2 bucket
  **provisioning** (create database/bucket), **API-token minting**, Workers
  **script deploy**, Pages/Workflows management. Port `CloudflareClient` as a thin
  `fetch`-based TS module for the deploy/provision control path (a "management
  Worker" or the CLI). Keep the retry/backoff and typed error mapping; add Zod
  envelope schemas.
- Per-tenant bucket-name derivation (SHA-256, injective) → port verbatim (pure).
- **Flag:** the crate's careful `cf://`-is-not-resolvable boundary is a hint about
  the target architecture — inside Workers, secrets are always bindings, so the
  `TokenResolver` seam largely dissolves into `env`.

---

## 4. `crates/ferrogate-mcp` — MCP host/client manager + MCP-server Worker deploy

**Purpose.** FerroGate's MCP host: owns long-lived upstream MCP **server
sessions** (the gateway applies auth/policy/billing/audit before calling in),
speaks Streamable HTTP / SSE / stdio, and also **deploys** a FerroGate-hosted MCP
server Worker to Cloudflare.

### 4.1 The host (`manager.rs`, `http_client.rs`, `stdio_client.rs`)

- **`McpManager`** owns `HashMap<name, McpSession>`. Each session connects,
  negotiates protocol, lists tools (deny-by-default via `tools_to_execute`
  allowlist), and exposes: `statuses`, `tools`, `tool_by_name`,
  `health_check_and_reconnect`, `execute_tool_with_headers`,
  `dispatch_cleanup_handle` (timeout → kill stdio child + mark unavailable).
- Tool namespacing: `{server_name}-{remote_name}`, longest-prefix match resolves
  hyphenated names.
- **Transports** (`McpTransport`): `StreamableHttp`, `Sse`, `Stdio`. HTTP client
  is raw `TcpStream`/`rustls` with a 16 MiB response cap and incremental SSE JSON
  parsing (returns on first complete `data:` value).
- **Auth types** (`McpAuthType`): `None`, `SharedHeaders`, `Oauth`,
  `PerUserOauth`, `OriginalBearer`, `FerrogateSignedJwt`. Per-request identity is
  threaded via **`McpDispatchHeaders`** (an `Authorization: Bearer` value,
  redacted `Debug`) passed into `call_tool` — this is how per-user identity /
  the resolved MCP identity grant reaches the upstream. A `401` upstream →
  `McpExecutionError::Unauthorized` (`mcp_upstream_unauthorized`).

### 4.2 Protocol negotiation (`protocol.rs`)

- Modern candidate revision **`2026-07-28`** (adds `Mcp-Method`/`Mcp-Name`
  Streamable-HTTP routing headers, `_meta` request meta, `server/discover`); no
  `initialize` handshake. Legacy `2025-11-25` and fallback `2025-06-18` negotiate
  via `initialize`.
- `verify_routing_headers` fails a request closed when `Mcp-Method`/`Mcp-Name`
  disagree with the JSON-RPC body (so a caller can't be metered as one op while
  executing another). `encode_mcp_header_value` base64-wraps unsafe values.

### 4.3 Cloudflare-managed MCP (`cloudflare.rs`)

- Consume CF's managed MCP servers (`mcp.cloudflare.com/mcp`,
  `<product>.mcp.cloudflare.com/mcp`, tenant `*.workers.dev/mcp|/sse`) as ordinary
  upstreams. Bearer (`cloudflare_bearer_header`) or per-user OAuth (CF as OAuth
  provider). `is_cloudflare_managed_mcp_url` gates config guardrails at load time.

### 4.4 MCP-server Worker deploy (`mcp_worker_deploy.rs`)

Deploys `workers/mcp-server` (an Agents-SDK `McpAgent` Durable Object at `/mcp`
with a `@cloudflare/workers-oauth-provider` OAuth front). Constructs a
deterministic `multipart/form-data` `PUT /accounts/{acct}/workers/scripts/{name}`
carrying: metadata (`main_module`, `durable_object_namespace` binding for the DO,
`kv_namespace` binding `OAUTH_KV`, `new_sqlite_classes` migration,
compatibility date/flags) + module part. Read side (status/list) via the #405
client; write side via the transport directly (multipart). Teardown = `DELETE`.

### 4.5 Proposed CF/TS mapping

- **The MCP-server hosting half already exists as `workers/mcp-server` (TS).**
  See §9.2. The Rust `mcp_worker_deploy` becomes a deploy script / `wrangler
  deploy` wrapper.
- **The MCP host (consuming upstream MCP servers)** ports to TS using
  `@modelcontextprotocol/sdk` clients. On CF, long-lived per-session state →
  **Durable Object** (one DO per MCP session, mirroring the existing McpAgent
  pattern). Streamable HTTP/SSE → `fetch` + `ReadableStream` (workerd supports
  SSE). Stdio transport has **no CF equivalent** (Workers can't spawn processes)
  — self-hosted stdio MCP servers must run outside CF or in a Container.
- Protocol negotiation, routing-header verification, tool allowlisting, protocol
  version constants: port verbatim (pure logic + Zod).
- `McpDispatchHeaders` identity threading → a per-request header map; the
  per-user OAuth grant is stored in KV (as the existing OAuth provider does).

---

## 5. `crates/ferrogate-auth-service` — standalone identity service

**Purpose.** The optional external identity **service** (binary `ferrogate-auth`)
the gateway talks to over HTTP: virtual-API-key resolution, RBAC, admin-console
sessions, SSO (OIDC), SAML, SCIM. Distinct from the gateway's in-process request
authenticator. Hardened thread-per-connection HTTP server (no async framework —
raw `TcpListener` + hand-rolled HTTP), optional rustls TLS, Supabase/Postgres
backing.

### 5.1 HTTP routes (`server.rs::route_request`)

All JSON; `OPTIONS` → 204 (CORS handled in `to_bytes`). Admin/RBAC/SCIM/SSO
routes require the admin-console feature (else 503 `admin_console_not_configured`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz`, `/v1/healthz` | Liveness (`service: ferrogate-auth`) |
| GET | `/v1/tenants` | List tenant records |
| POST | `/v1/auth/resolve-api-key` | Resolve a presented virtual key → `AuthDecision` (401 on miss) |
| POST | `/v1/auth/authorize` | RBAC decision (`AuthorizeRequest` → `AuthorizationDecision`) |
| POST | `/v1/admin/register` | Console: register (provisions tenant/project/workspace + gateway virtual key) |
| POST | `/v1/admin/login` / `refresh` / `logout` | Console session lifecycle (JWT access + durable refresh) |
| GET | `/v1/admin/me` | Current session identity (bearer) |
| GET | `/v1/admin/team` | List team members |
| POST | `/v1/admin/team/invite` | Invite a member |
| POST/DELETE | `/v1/admin/team/members/{user_id}` | Change role / revoke member |
| GET/POST | `/v1/rbac/roles`; DELETE `/v1/rbac/roles/{id}` | Runtime role CRUD (owner-gated) |
| GET/POST | `/v1/rbac/bindings`; DELETE `/v1/rbac/bindings/{id}` | Runtime binding CRUD |
| POST | `/v1/admin/team/scim-token` | Mint a SCIM provisioning virtual key |
| GET/POST | `/scim/v2/Users`, `/scim/v2/Groups`; GET/PATCH/PUT/DELETE `/scim/v2/Users/{id}` | SCIM 2.0 provisioning (tenant-scoped) |
| POST/GET/DELETE | `/v1/admin/team/sso-config` | Per-tenant SSO config |
| GET | `/v1/admin/auth/sso/authorize` / `sso/callback` | OIDC Authorization Code + PKCE |
| GET | `/v1/admin/auth/saml/authorize` / `saml/acs` | SAML 2.0 SP-initiated (HTTP-Redirect binding) |

### 5.2 Auth / tenancy model

- **Virtual API keys** (`api_key.rs`): format `fg_<hex>`, stored as
  `sha256:`/`blake2b:` hash + `key_prefix` (16 chars) + `last4`.
  `StorageApiKeyAuthenticator` looks up by prefix, checks
  `enabled && !revoked && !expired`, constant-time verifies, and returns
  `AuthDecision { tenant, subject, scopes, allowed_models/providers, budgets }`.
- **RBAC** (`rbac.rs`): `Role` (per-tenant namespaced, `tenant_id: None` = global
  read-only), `PolicyBinding` (subject × tenant × role), `PolicySubject`
  (User/ServiceAccount/ApiKey). `authorize` resolves the binding's role within
  its own tenant first, then global; wildcard `*` on action/resource/tenant
  fields. Static `AuthApiKey` path uses constant-time secret compare.
- **Membership tiers** (`membership_role.rs`, issue #517): `Owner > Admin >
  Member > Viewer`, case-sensitive parse, each with a scope ladder — the
  console-minted gateway virtual key is scoped to the tier (a `viewer` gets no
  `.write` scope). This is the mechanism behind the noted **native-api-key
  401-vs-403 suspension semantics**: a *missing/invalid* key is 401
  (`invalid_api_key`); a *known but suspended/insufficient* principal is a
  distinct authorization failure — the port must keep "unauthenticated (401)" and
  "authenticated-but-forbidden/suspended (403)" separate (a known repeat defect).
- **SAML** (`saml.rs`): HTTP-Redirect binding, detached RSA signature over the
  URL query octet string (`ring` verify + `x509-parser`), then `quick-xml` parse.
  Fails closed on bad signature / status / audience / `InResponseTo` / time window.
- **SSO** (`sso.rs`): OIDC Authorization Code + PKCE, `jsonwebtoken` id-token
  verify, pending-flow state in storage.

### 5.3 External I/O

Supabase/Postgres via `ferrogate-storage` (`RuntimeStorageRepositories`),
`block_on_sync_bridge` from `ferrogate-auth-service::util` (sync HTTP handlers →
async repo calls), rustls TLS, JWT (HS256 console sessions), argon2 password
hashing, blake2/sha2 key hashing.

### 5.4 Proposed CF/TS mapping

- Port to a **Hono Worker** — the route table maps cleanly to Hono routers. Zod
  for every request body.
- Storage → **D1** (via binding) instead of Supabase/Postgres; the schema already
  has a D1 twin (`control_plane_store_d1`). The whole `block_on_sync_bridge`
  layer **disappears** (Workers are already async).
- JWT (console session) → `jose`/`hono/jwt`; refresh tokens in D1 or KV. Argon2 →
  `hash-wasm`/WebCrypto PBKDF2 (argon2 in workerd needs a WASM build — **flag**).
- **SAML is the hardest sub-port:** raw RSA-SHA1/SHA256 signature verification
  over query octets + X.509 parsing. WebCrypto can do RSA verify + can import
  SPKI, but X.509 cert parsing (`x509-parser`) needs a WASM/JS lib (`@peculiar/
  x509`). Deflate (`flate2`) → `DecompressionStream`. Achievable but delicate;
  **flag as high-risk**.
- SCIM/SSO/OIDC: straightforward Hono routes + `jose`.

---

## 6. `crates/ferrogate-admin` — Control Plane API stability/naming contract

**Purpose.** Typed source of truth for the Control Plane API's **name**
("FerroGate Control Plane API", legacy alias "Admin API") and **stability
contract** (`Stable` vs `Internal` operations, covered by the OpenAPI baseline
gate). Tiny: `serde` only.

### 6.1 Surface (`control_plane.rs`)

- Constants: `CONTROL_PLANE_API_TITLE`, `ADMIN_API_LEGACY_TITLE`,
  `DEPRECATED_ALIAS` (`admin-api`), `PUBLIC_API_MAJOR` (`v1`),
  `STABLE_PATH_PREFIX` (`/admin/v1`), `ALIAS_PATH_PREFIX` (`/control/v1`).
- **`canonicalize_alias_path(path)`**: single source of truth folding
  `/control/v1/...` → `/admin/v1/...` (whole-segment match only). Used by both the
  in-process gateway ingress **and** the `control-api serve` reverse proxy.
- `PROMOTED_OPERATIONS`: the promoted public-stable guardrail-policy operations
  (`operationId`/method/path table), `is_promoted`, `public_surface()`.

### 6.2 Proposed CF/TS mapping

Port as a small TS constants + helper module shared by the Control Plane Worker
and CLI. `canonicalize_alias_path` → a pure TS function; the stability table →
data validated at build time against the OpenAPI doc. No CF-specific concerns.

---

## 7. `crates/ferrogate-sync-bridge` — async→sync bridge

**Purpose.** One function, `block_on_sync_bridge(future)`: runs an async call
from a synchronous call path (Pingora filter hooks, thread sweep loops, the Unix
external-action authorizer). Uses `block_in_place` on an ambient multi-thread
runtime, else a throwaway current-thread runtime on a scoped thread. Sole dep:
`tokio`.

**CF/TS mapping.** **This crate has no reason to exist on CF** — Workers are
uniformly async, so every caller becomes a plain `await`. Drop it during the
port; each Rust `block_on_sync_bridge(x.await-ing())` call site becomes `await x`.

---

## 8. `crates/agent-worker` — standalone agent execution / isolation process

**Purpose.** The customer/host-side process that actually **runs agent
workloads** under isolation, enforces the gateway's capability boundary, and
speaks a signed management protocol. One binary, two modes (`--worker-type
cloud|self-hosted`) — a policy toggle, not two programs (issue #132). This is
the largest crate in the cluster (~34k LOC).

### 8.1 CLI surface (`main.rs`)

Binary `agent-worker`, global `--worker-type`, hidden Firecracker guest-agent
entrypoints (`--ferrogate-guest-agent-{probe,start,serve-vsock}`). Subcommands
group into: **diagnostics** (`worker-type`, `probe-handlers`, `protocol-smoke`),
**Firecracker** (`firecracker-{prepare-plan,host-preflight,guest-agent-preflight,
guest-launch-plan,boot-smoke,lifecycle-smoke,agent-exec-smoke}`), **handler
smokes** (`smoke-handler-{binary,task}`), **governed execution smokes**
(`governed-{cli,tool,mcp-tool,skill,memory,secret,network-egress,browser,rest,
filesystem}-*-smoke`, plus timeout/cancel), **external-action** (`external-action-
smoke`, `accept-external-action-json`, `governed-target-execution-unix-smoke`),
**management servers** (`accept-management-json`, `serve-management-unix`,
`serve-management-http`), and **self-hosted report-only** smokes.

`self_hosted_command_support` classifies each command Diagnostic / ReportOnly /
FailClosed for `--worker-type self-hosted`.

### 8.2 Isolation backends (implement runtime `IsolationBackendLifecycle`)

| Backend | File | Mechanism |
|---|---|---|
| **Firecracker microVM** | `backends.rs`, `firecracker_guest_exec.rs` | KVM microVM; guest agent over AF_VSOCK enforces the capability envelope **inside** the VM |
| **Docker** | `docker_backend.rs` | `docker` CLI, `--network none`, resource/fs flags |
| **local-process** | `local_process_backend.rs` | `unshare -U -r -m -n -p -f` (user/mount/pid/net namespaces), loopback-only net, tmpfs shrouds |
| **Cloudflare Containers/Sandbox** | `cloudflare_container_backend.rs`, `cloudflare_container_lifecycle.rs` | **Gateway-driven** — no local host; every op driven remotely through the `agent-gateway` Worker's `/container/*` routes via `ContainerControlClient`. Egress sealed by default (`ContainerEgressPosture`); snapshot advertised off (no CF primitive) |

### 8.3 Other concerns

- **Management protocol** (`management.rs`, `handler_runtime.rs`, `lifecycle.rs`,
  `state.rs`): signed (MAC keyed by `key_id`/shared secret) JSON envelopes over
  Unix socket or HTTP; worker-owned lifecycle dispatch + framework-handler
  execution; idempotent action-outcome store (trait, in-memory now).
- **External-action gate** (`external_actions.rs`, 6.5k LOC): every handler
  action (tools/MCP/CLI/REST/filesystem/browser/secrets/memory/network egress)
  must be authorized by the gateway over a **kernel-authenticated Unix socket**
  (SO_PEERCRED PID check) before execution; ALLOW decisions bind to a
  canonical-target fingerprint.
- **Events** (`events.rs`): one normalized `NormalizedWorkerEvent` schema
  (`session.started`, `run.completed`, …) across all framework adapters
  (Claude Code / Codex / Hermes / native).
- **x402** (`x402_client.rs`): non-custodial pay.sh/x402 — on a `402`, presents
  spend evidence to the gateway; never self-authorizes, never holds keys, signing
  stays behind an external authority.
- **Recorded evidence** (`recorded_evidence.rs`): central redaction of any bytes
  the worker records (bearer/cookie headers, excerpts).

Deps: `ferrogate-runtime`, `ferrogate-policy`, `ferrogate-payments`, Linux
`rustix`. No async framework — hand-rolled Unix/HTTP transports.

### 8.4 Proposed CF/TS mapping

- **The Cloudflare backend is already the CF-native path** — a CF port collapses
  most of this crate to the `agent-gateway` Worker (§9.1): the Agent Durable
  Object + `@cloudflare/sandbox` Container is the isolation tier. Firecracker,
  Docker, and local-process backends have **no CF equivalent** (Workers can't
  boot VMs/containers or `unshare`) — they stay as a self-hosted Rust/host binary,
  OR are replaced by CF Containers.
- Management/lifecycle/events/external-action-gate logic → port the **decision**
  logic (capability envelope evaluation, canonical-target fingerprinting, event
  normalization, evidence redaction, x402 spend-authorization) as pure TS. The
  **transports** change: Unix socket + SO_PEERCRED authorization has **no CF
  equivalent**; on CF, worker↔gateway auth is a bearer token / service binding
  (as the existing `agent-gateway` and `git-credential` broker already do).
- **Flag the hardest items:** (a) Firecracker/vsock/KVM path is unportable to CF;
  (b) SO_PEERCRED kernel-authenticated Unix authorizer → replace with signed
  bearer/service-binding trust; (c) `unshare`-based local isolation → CF
  Containers/Sandbox with `enableInternet=false`.

---

## 9. Existing `workers/` — CF Worker + Durable Object code (TS)

Five deployed Workers already exist (wrangler 4.x, `@cloudflare/vitest-pool-
workers` tests). These are the **reference implementations** the Rust side drives
and the port should build on, not replace.

### 9.1 `workers/agent-gateway` (issue #413) — the required agent front

Cloudflare exposes **no** first-party REST API to create/start/stop/invoke/
inspect/destroy an individual agent instance, so every agent op is fronted by
this Worker. `agents@0.0.109` + `@cloudflare/sandbox@0.12.4`.

- **`AgentGateway`** — an Agents-SDK `Agent` **Durable Object** (`new_sqlite_
  classes`), addressed by name (`getAgentByName`). Persistent `AgentGatewayState`
  (status, run/session/capability ids, resolved model/tools/prompt, cancel latch).
  RPC verbs: `start` (lazy-create, run-conflict guard, idempotent re-start),
  `invoke`, `cancel` (cooperative `AbortSignal` + durable latch), `destroyRun`,
  `status`.
- **HTTP routes** (`index.ts` `fetch`, all bearer-gated by `GATEWAY_CONTROL_
  TOKEN`): `/healthz`, `POST /control/{start,invoke,cancel,destroy}` +
  `GET /control/status`, `/memory/*` (§427: synced state / DO-SQLite / chat
  history — `memory.ts`), `/schedule/*` (§426: in-DO SQLite scheduler multiplexed
  through one alarm — `schedule.ts`), `/container/*` (§415: per-tenant Sandbox
  lifecycle — `container.ts`), `/git-credential/*` (§475: brokers per-op GitHub
  App installation tokens so nothing GitHub-shaped rests in the container —
  `git-credential.ts`), and path-routed `/agents/:agent/:name/...`.
- **`AgentSandbox extends Sandbox`** — Container/Sandbox DO with
  `enableInternet=false` + `interceptHttps=true` pinned (load-bearing #471 egress
  control); governed allowlist opened at runtime via `setAllowedHosts`.
  `ContainerProxy` re-exported (required for `ctx.exports`).
- Placement: `locationHint` honored on `start`; `jurisdiction` **refused** (would
  change DO identity and hide the run from the kill switch).

### 9.2 `workers/mcp-server` (issue #409) — a tenant's own hosted MCP server

`FerroGateMcp extends McpAgent` (Agents SDK, `new_sqlite_classes`) mounted at
`/mcp` (Streamable HTTP) + `/sse`. Base tools (`echo`/`add`/`whoami`) via
`@modelcontextprotocol/sdk` + Zod. Front door is `@cloudflare/workers-oauth-
provider` (OAuth 2.1, grants in `OAUTH_KV`) with an optional static
`MCP_BEARER_TOKEN` automation bypass. This is the target the Rust
`mcp_worker_deploy` uploads.

### 9.3 `workers/d1-proxy` (issue #450/#455) — atomic D1 hot path

Bearer-gated (`D1_PROXY_TOKEN`) HTTP front over a native `env.DB` D1 binding.
Two routes: `POST /d1/batch` (atomic `env.DB.batch([...])`) and `POST /d1/query`
(single `prepare().bind().all()` with `RETURNING`) — the primitives the D1 REST
API lacks. Per-tenant `TENANT_DB_*` bindings selected by `database` field
(no runtime open-by-id; onboarding = add binding + redeploy). Returns the same
`{results,success,meta}` envelope the REST endpoint does.

### 9.4 `workers/gateway-front` (issue #470) — veto-only data-plane shell

Pure-transport Worker in front of the container-hosted Pingora data plane. Reads
the body once, runs `decideShell` (deny/defer only — can turn an origin ALLOW
into an edge DENY via `EDGE_DENY_LIST` SHA-256 digests, or a body-over-limit
reject), forwards otherwise. `origin` binding is a stub (501) pending #472.
`/__conformance/decide` drives the shared shell from the governed-decision corpus.

### 9.5 `workers/telemetry-collector` (issue #520) — OTLP ingest → Analytics Engine

Bearer-gated (`COLLECTOR_TOKEN`) OTLP/HTTP+JSON receiver (`/v1/{metrics,traces,
logs}`) writing to an **Analytics Engine** dataset binding (`writeDataPoint()` —
the only write path CF offers; the dataset HTTP API is read-only). Body-cap 413,
OTLP parsing in `otlp.ts`.

### 9.6 CF primitives already in use (a shopping list for the port)

Durable Objects (Agents SDK `Agent`/`McpAgent`, embedded SQLite via
`new_sqlite_classes`, alarms), Containers/Sandbox (`@cloudflare/sandbox`, egress
interception), KV (`OAUTH_KV`), D1 (native binding + per-tenant bindings),
Analytics Engine, Workers OAuth Provider, Secrets Store / Worker secrets,
Vectorize + Workers AI (semantic-memory pilot, default off), `compatibility_
flags` (`nodejs_compat`, `enable_ctx_exports`). Deploy via `wrangler`; DIY bearer
auth (`requireBearer`, constant-time) is the pervasive worker↔worker trust.

---

## 10. Existing `admin-console/` — React SPA (TS)

**Purpose.** A standalone **Vite + React + TS + Tailwind + shadcn/ui** SPA
covering the whole control plane. Deployed as its own service (nginx), **not on
CF** today. It is the GUI twin of `ferrogate ctl`.

- **Backends** (`lib/config.ts`, runtime `/env-config.js` override): the auth
  service (`/v1/admin/{register,login,refresh,logout,me}` — `lib/auth-client.ts`)
  and the Control Plane API (`/admin/v1/*` or the dedicated `admin-api serve`
  service — `lib/gateway-client.ts`), authenticated with a virtual API key minted
  on login.
- **Types**: `lib/api-types.generated.ts` generated from
  `docs/openapi/admin-api.openapi.json` via `openapi-typescript` (single source
  of truth, drift-gated).
- **Stack**: `@tanstack/react-query` (data), `@tanstack/react-table`,
  `react-router-dom`, `react-hook-form` + `@hookform/resolvers` + `zod`, Radix
  UI, i18n (`i18n/locales/en`). ~40 pages (`src/pages/`) + ~40 resource configs
  (`src/resources/`) covering tenancy, IAM, agents, workers, MCP, guardrails,
  assets, billing, evidence, ops — the same families as the `ctl` registry.
- Playwright e2e (`e2e/`) + axe accessibility, vitest + MSW unit tests, bundle
  budget + api-type-drift gates.

**CF/TS mapping.** The console is already TS. To move it onto CF: deploy as
**Cloudflare Pages** (or a static-assets Worker). The runtime-config pattern
(`window.__ENV__`) maps to Pages env/`_worker.js`. Its API contract is unchanged
— it consumes the same `/admin/v1/*` surface the ported Control Plane Worker will
expose, and the generated OpenAPI types are directly reusable by the CLI/Worker
port (share `api-types.generated.ts`). No hard blockers.

---

## 11. Cross-cutting CF/TS mapping summary

| Concern (Rust) | CF/TS target | TS lib | Notes / risk |
|---|---|---|---|
| `ferrogate` CLI client half (`ctl`/`ops`/`context`/`assets`/`plans`) | Bun CLI calling Worker HTTP | `cac`/`commander`, `zod`, `jose` | Straightforward |
| CLI `serve` verbs | `wrangler deploy` wrappers | — | **No CF-CLI equivalent**; process-launcher identity is lost |
| `ferrogate-control-plane-client` | Framework-neutral TS lib | `zod`, `openapi-typescript`, `fetch` | Registry + receipt gate + action-identity port cleanly |
| `ferrogate-cloudflare` REST client | Mostly native CF bindings; thin `fetch` client for provision/deploy | `zod` | D1/R2/secrets become bindings; only provisioning/token-mint/deploy need REST |
| `ferrogate-mcp` host | Durable Object per session + `fetch`/SSE | `@modelcontextprotocol/sdk`, `zod` | **stdio transport has no CF equivalent** |
| `ferrogate-mcp` server deploy | Already `workers/mcp-server` | `agents`, `@cloudflare/workers-oauth-provider` | Deploy script only |
| `ferrogate-auth-service` | Hono Worker + D1 | `hono`, `zod`, `jose`, `hash-wasm`/WebCrypto, `@peculiar/x509` | **SAML sig-verify + X.509 + argon2 = high risk** |
| `ferrogate-admin` contract | TS constants + build-time OpenAPI check | — | Trivial |
| `ferrogate-sync-bridge` | **Deleted** | — | Workers are async |
| `agent-worker` decision logic | Pure TS modules | `zod` | Capability envelope, fingerprint, events, x402, redaction |
| `agent-worker` isolation | CF Containers/Sandbox (already `agent-gateway`) | `@cloudflare/sandbox` | **Firecracker/Docker/`unshare` have no CF equivalent** |
| `agent-worker` Unix SO_PEERCRED authorizer | Bearer / service binding | — | **No CF equivalent**; trust model changes |
| `admin-console` | CF Pages / static Worker | (unchanged) | Reuse generated OpenAPI types |

### Top hardest things to port (whole-cluster view)

1. **The `agent-worker` isolation + kernel-trust boundary.** Firecracker
   microVMs (KVM + AF_VSOCK guest agent), Docker `--network none`, and
   `unshare`-based namespace isolation have **no Cloudflare equivalent** — CF's
   only isolation primitive is Containers/Sandbox. The SO_PEERCRED
   kernel-authenticated Unix authorizer (the whole external-action trust anchor)
   likewise cannot exist on CF and must be re-founded on bearer/service-binding
   trust. This is the deepest re-architecture in the cluster.
2. **`ferrogate-auth-service` SAML 2.0.** Detached RSA-SHA1/SHA256 signature
   verification over raw URL query octets + X.509 certificate parsing +
   DEFLATE, all fail-closed. WebCrypto covers RSA verify but X.509 parsing and
   argon2 password hashing need WASM/JS libs in workerd; the "fail closed on any
   mismatch" surface is unforgiving and must be re-proven.
3. **The MCP host's stdio transport (and generally, "spawn a process").** Workers
   can't fork; every stdio MCP server, and every place the CLI/worker shells out,
   has no CF path — those upstreams must move to Containers or stay off-CF, which
   fractures the "one MCP host" model.

Runner-up worth flagging: keeping the **`ctl`/console/OpenAPI parity** intact — the
Rust `MutationReceipt` render-gate, action-identity attribution (#548), and the
data-plane parity gate (#365) are subtle correctness contracts that a naive port
can silently drop (turning green tests vacuous).
