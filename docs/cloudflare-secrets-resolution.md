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
      **The env convention accepts only canonical secret names** — see the
      next section.
2. **The REST backend** (`CloudflareSecretResolver`, requires
   `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN`) — an **existence check
   only**: missing store/secret resolves to "not found" (`Ok(None)`, mirrors
   Vault), while an *existing* secret yields the precise unsupported-resolve
   error, since the value is unreadable over REST.
3. Neither configured / both miss → a clear error naming the exact
   `FERROGATE_CF_SECRET_*` variable that was checked and the configuration
   options.

### Name your secrets `[a-z0-9-]+` — the env convention refuses anything else

`FERROGATE_CF_SECRET_<NAME>` is a **lossy** encoding: it uppercases and
collapses every non-alphanumeric character to `_`. So these four *distinct*
Cloudflare secrets all name one variable:

| Secret name | Environment variable |
| --- | --- |
| `openai-api-key` | `FERROGATE_CF_SECRET_OPENAI_API_KEY` |
| `openai.api.key` | `FERROGATE_CF_SECRET_OPENAI_API_KEY` |
| `openai_api_key` | `FERROGATE_CF_SECRET_OPENAI_API_KEY` |
| `OpenAI-API-Key` | `FERROGATE_CF_SECRET_OPENAI_API_KEY` |

Reading that variable for all four would let a `cf://` reference silently
resolve to **a credential the operator did not name** — the worst failure mode
a secret resolver has.

The encoding is injective exactly on the **canonical shape `^[a-z0-9-]+$`**
(lowercase letters, digits and `-` land in disjoint parts of `[A-Z0-9_]`), so:

- a **canonical** name resolves from the environment convention as documented;
- a **non-canonical** name is **refused with an error** naming the shared
  variable and both remedies — it is never resolved from the ambiguous
  variable. The predicate is
  `ferrogate_secrets::cf_binding_name_is_unambiguous`.

Two remedies:

1. **Rename the Secrets Store secret** to the canonical shape (e.g.
   `openai-api-key`). This is Cloudflare's own naming style and what every
   example here uses.
2. **Inject the value under its exact name** via
   `CfSecretBindings::from_map` / `insert` +
   `SecretResolverRegistry::with_cf_bindings`. That map is keyed by the exact
   name, never collapses, and therefore works for any name Cloudflare accepts
   — including two colliding spellings side by side.

The refusal happens in the binding context, **before** the REST fallback, so an
ambiguous reference never reaches the network either.

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

## Credential handling inside the resolver

Two rules the slice holds itself to, both regression-tested:

- **No secret material in a `Debug` rendering.** `CfSecretBindings` holds
  *resolved plaintext values* and is reachable from `SecretResolverRegistry`'s
  derived `Debug`, so it hand-writes a `Debug` that prints the bound secret
  *names* (not secret — they are written verbatim in config) and `<redacted>`
  for the values. Same rule as `VaultConfig` (issue #492), `ResolvedToken` and
  `HttpRequest.bearer_token`.
- **The Cloudflare API token is held as a reference, never as a value.**
  `CfSecretsStoreConfig::from_env` only *probes* `CLOUDFLARE_API_TOKEN` for
  presence and stores the reference `env://CLOUDFLARE_API_TOKEN` in
  `api_token_ref`; that reference is what reaches
  `ferrogate_cloudflare::CloudflareConfig` (a `Debug + Serialize` struct). The
  live token is materialized by `EnvTokenResolver` per request, at the
  `Authorization` header and nowhere else — #405's design. Side benefit:
  rotating `CLOUDFLARE_API_TOKEN` takes effect without rebuilding the client.

`ferrogate-cloudflare`'s own `EnvTokenResolver` **rejects** `cf://` token
references permanently (not "deferred"): `cf://` is owned by
`ferrogate-secrets`, which already depends on `ferrogate-cloudflare`, so
resolving it there would be a dependency cycle; Secrets Store values are
unreadable over REST anyway; and a token that authenticates *to* the Cloudflare
API cannot bootstrap itself from a Cloudflare-API-managed store. Inside a
Worker-bound runtime, spell it `env://FERROGATE_CF_SECRET_<NAME>` instead.

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
- the manage plane: secret create over REST + client-side beta value-size cap;
- the aliasing guard: canonical vs non-canonical name classification, four
  colliding spellings refused (with the canonical owner's value proven absent
  from the error), exact-map injection resolving two colliding names to their
  own distinct values, and the registry refusing an ambiguous ref before any
  REST call;
- credential redaction: `CfSecretBindings` `Debug` (direct and nested through
  `SecretResolverRegistry`), `CfSecretsStoreConfig` `Debug` for an inline
  token, and `from_env` storing `env://CLOUDFLARE_API_TOKEN` with the token
  value absent from `CloudflareConfig`'s `Debug` *and* its `Serialize` output.

**Not testable locally** (requires a live Cloudflare account): an end-to-end
Worker binding actually delivering a Secrets Store value into a deployed
Worker/Container environment, and live REST behavior of the Secrets Store
endpoints.
