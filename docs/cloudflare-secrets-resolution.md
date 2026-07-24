<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-24
  description: Token4AI Cloud, FerroGate AI Gateway, decision record + operator
  guide for cf:// Cloudflare Secrets Store value resolution (issue #423):
  Worker-binding resolution, the FERROGATE_CF_SECRET_* convention, and the
  write/manage-only scoping of the REST resolver.
-->

# Cloudflare Secrets Store: `cf://` value resolution (decision #423)

**Status: decided and implemented** (issue #423, building on the #417
`CloudflareSecretResolver` in `crates/ferrogate-secrets`).

## The constraint

Cloudflare Secrets Store secret **values are write-only over the REST API**.
Every documented endpoint (`GET .../secrets_store/stores`,
`GET .../stores/{id}/secrets`, `GET .../stores/{id}/secrets/{id}`) returns
metadata only — no endpoint ever returns a stored value. The **only** way a
stored value reaches a consumer is a **Workers binding**: the secret is bound
to a Worker in its deploy config and the Worker reads it from its environment
at runtime.

Consequence: a FerroGate gateway running **outside** a Worker binding can
create and manage Secrets Store secrets, but can never fetch a value back for
load-time `cf://` resolution. Fabricating a value or silently treating the
secret as unset would both be wrong.

## The options considered

- **Option A — Worker-binding resolution.** `cf://` values resolve only from
  the Worker-binding runtime context. The REST client is scoped to
  write/manage (create secrets, existence checks) and errors precisely on any
  attempted value read.
- **Option B — readable backend for out-of-Worker resolution.** Self-hosted
  gateways keep the resolvable copy of each secret in a REST-readable backend
  (the existing HashiCorp Vault seam, or plain env), and Cloudflare Secrets
  Store is reserved for Worker-bound secrets.

## Decision

**Option A is the `cf://` value path; Option B is the documented self-hosted
alternative using the seams that already exist (`vault://`, `env://`).**
Rationale:

- Option A is the only mechanism Cloudflare actually supports for reading a
  Secrets Store value — any "readable `cf://`" emulation would have to store a
  second copy elsewhere, at which point it *is* Option B under a misleading
  scheme name.
- Option B needs no new machinery: `vault://` and `env://` references already
  resolve everywhere the gateway runs. Making `cf://` silently fall back to a
  shadow copy would hide which system is authoritative for a credential.
- Either way the failure mode outside a Worker binding must be a precise,
  actionable error — never a fabricated or empty value.

`cf://` load-time value resolution is therefore **unsupported outside a
Worker-binding context, by design**, and the resolver's errors say so and
point at the supported paths below.

## How a `cf://` value reaches the consumer

`ferrogate_secrets::SecretResolverRegistry::resolve("cf://<store>/<name>")`
consults, in order:

1. **The Worker-binding context** (`CfSecretBindings`, always installed —
   zero network, no Cloudflare API token needed):
   1. an **injected binding map** — embedding glue that already holds the
      bound values (e.g. Worker glue enumerating its env) hands them over via
      `CfSecretBindings::from_map` / `insert` and
      `SecretResolverRegistry::with_cf_bindings`;
   2. the **environment convention** — the variable
      `FERROGATE_CF_SECRET_<NAME>`, where `<NAME>` is the secret name
      uppercased with every non-alphanumeric character replaced by `_`
      (`ferrogate_secrets::cf_binding_env_var`). Example:
      `cf://provider-keys/openai-api-key` reads
      `FERROGATE_CF_SECRET_OPENAI_API_KEY`. Empty/whitespace values count as
      unset. Only the secret *name* keys the lookup — the store segment does
      not — because the Secrets Store beta allows exactly one store per
      account; the convention can grow a store qualifier if that cap lifts.
2. **The REST backend** (`CloudflareSecretResolver`, requires
   `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN`) — an **existence check
   only**: missing store/secret resolves to "not found" (`Ok(None)`, mirrors
   Vault), while an *existing* secret yields the precise unsupported-resolve
   error, since the value is unreadable over REST.
3. Neither configured / both miss → a clear error naming the exact
   `FERROGATE_CF_SECRET_*` variable that was checked and the configuration
   options.

### Deployment recipes

**FerroGate components deployed as Cloudflare Workers** (e.g. the agent
gateway / MCP server Workers): bind the secret in the Worker's `wrangler`
config —

```jsonc
// wrangler.jsonc of the consuming Worker
{
  "secrets_store_secrets": [
    {
      "binding": "OPENAI_API_KEY",
      "store_id": "<secrets-store-id>",
      "secret_name": "openai-api-key"
    }
  ]
}
```

— and read it from the Worker `env` at runtime. That is native Worker-binding
consumption; no `cf://` reference or REST call is involved inside the Worker.

**The Rust gateway itself** (Cloudflare Containers, or any host where the
platform/operator can inject environment): have the deploy glue that receives
the bound value export it as `FERROGATE_CF_SECRET_<NAME>`, and reference it in
FerroGate config as `cf://<store>/<name>`. The same config file then works in
every environment that provides the binding, and fails loudly (not silently)
in one that does not.

**Self-hosted gateway with no Worker-binding path at all** (Option B): keep
the resolvable copy in HashiCorp Vault or the environment and reference it as
`vault://<mount>/<path>#<field>` or `env://VAR`. Reserve Cloudflare Secrets
Store for secrets consumed by Workers; FerroGate can still *manage* those over
REST (`CloudflareSecretResolver::create_secret`, which also enforces the beta
1024-byte value cap client-side).

## Resolver scoping (acceptance box 2)

`CloudflareSecretResolver` is explicitly **write/manage-only plus existence
checks**. Its REST resolve path never decodes a `value` field (none exists),
and an existing secret produces an error stating that Secrets Store values are
write-only over REST, naming the exact `FERROGATE_CF_SECRET_*` variable to
set for Worker-binding resolution, and pointing at `vault://`/`env://` for
self-hosted gateways. FerroGate never fabricates a value.

## Test coverage

`crates/ferrogate-secrets/src/cloudflare_test.rs` (no live network; the REST
API is scripted through `ferrogate-cloudflare`'s `HttpTransport` seam):

- binding env-var naming convention;
- value resolution from an injected binding map and from the
  `FERROGATE_CF_SECRET_*` environment convention, including through the
  registry with **no** Cloudflare REST credentials configured;
- binding precedence: with both configured, the binding value wins and no
  REST request is issued;
- REST existence checks: missing store/secret → `Ok(None)`; existing secret →
  the precise write-only error naming the binding variable and the
  readable-backend alternative;
- the manage plane: secret create over REST + client-side beta value-size cap.

**Not testable locally** (requires a live Cloudflare account): an end-to-end
Worker binding actually delivering a Secrets Store value into a deployed
Worker/Container environment, and live REST behavior of the Secrets Store
endpoints.
