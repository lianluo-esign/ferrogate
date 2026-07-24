<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-24
  description: Token4AI Cloud, FerroGate AI Gateway, decision record for
  multi-tenant credential storage around the Cloudflare Secrets Store beta
  caps (issue #418): hybrid tenancy, cap math, BYOK for the AI path,
  guardrails, and the multi-store GA migration plan.
-->

# Cloudflare Secrets Store: multi-tenant credential tenancy (decision #418)

**Status: decided and implemented** (issue #418, building on the #423 value-
resolution decision in `docs/cloudflare-secrets-resolution.md` and the #421
Secrets Store survey in `docs/cloudflare-integration.md` §5).

## The constraint

Cloudflare Secrets Store is in **beta** with hard per-account caps:

| Cap | Value | Code constant (`ferrogate-secrets`) |
|---|---|---|
| Stores per account | **1** | `CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT` |
| Secrets per account | **100** | `CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT` |
| Bytes per secret value | **1024** | `CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES` |

Two further constraints compound the caps:

- **Values are write-only over REST** (decision #423): the only read path is a
  Workers binding, declared **statically per secret** in the consuming
  Worker's deploy config (`secrets_store_secrets` in `wrangler.jsonc`). A
  secret nobody binds is write-only storage with no reader.
- **Scopes are store-wide, not per-secret-consumer**: every secret carries the
  single `workers` scope; there is no per-tenant isolation primitive inside
  the one store.

Naive per-tenant vaulting ("one CF secret per tenant provider key") therefore
hits three ceilings at once: the count cap, the static-binding deploy model,
and the absence of tenant isolation within the store.

## Options evaluated

1. **Per-request BYOK (no storage) for the AI path.** Each tenant's provider
   key travels on the request; FerroGate never stores it. Eliminates the cap
   problem for exactly one (large) class of credential, but is not a general
   answer: scheduled/agent workloads, webhooks, and platform-owned
   credentials still need at-rest storage.
2. **Namespaced naming + scopes inside the single store for everything.**
   Per-tenant secrets as `tenant-<id>-<name>` entries. Rejected as the
   general strategy: the cap math below shows the 100-secret budget dies at
   ~40 tenants even at 2 keys/tenant, and every tenant secret would need a
   per-tenant Worker binding — i.e. a Worker redeploy per tenant onboarding
   (#423 makes bindings the *only* value read path). Scopes provide no
   tenant isolation, so a compromise of any bound Worker exposes every
   tenant's keys.
3. **Hybrid.** System/platform secrets (bounded, enumerable, each with a
   known Worker consumer) go to the single CF store under a namespaced
   naming convention; per-tenant secrets stay in the existing readable
   backends; the AI path prefers BYOK so most tenant provider keys are never
   stored at all. Revisit when CF ships multi-store + store-level bindings.

## Decision

**Option 3 — hybrid — incorporating option 1 for the AI path and option 2's
namespacing for the bounded system set.**

### What goes where

| Credential class | Home | Why |
|---|---|---|
| FerroGate **system/platform** secrets consumed by our Workers (agent gateway, MCP server) — control-plane DSNs, service tokens, HMAC/AEAD master keys, platform-default provider keys | **CF Secrets Store** (the single store), names prefixed `ferrogate-<area>-<name>`, e.g. `ferrogate-core-postgres-dsn`, `ferrogate-auth-admin-jwt-secret`, `ferrogate-provider-openai-api-key` | Bounded set (~25 today, see cap math); each has a known Worker consumer to bind; values fit 1024 B |
| **Per-tenant** credentials (tenant provider keys the gateway holds, per-user MCP identities, tenant webhook secrets) | **Existing backends, unchanged**: the Postgres at-rest AEAD path (XChaCha20-Poly1305, e.g. per-user MCP identity in `crates/ferrogate-cli/src/state_mcp_identity.rs`, master-keyed by `FERROGATE_MCP_IDENTITY_KEY`), or `vault://` (HashiCorp Vault KV v2 seam in `crates/ferrogate-secrets`) | Unbounded cardinality; needs load-time *reads* (impossible over CF REST); needs tenant-scoped isolation and instant revocation without a Worker redeploy |
| Tenant provider keys on the **AI request path** | **Per-request BYOK — not stored** | The tenant sends its own provider key per request; FerroGate proxies it through and never persists it, so the largest per-tenant class exerts zero storage pressure anywhere |
| Anything **> 1024 bytes** (RSA private-key PEMs, GCP service-account JSON, minisign key registries) | Existing backends only | Cannot fit the CF value cap regardless of tenancy |

`cf://<store>/<name>` references remain reserved for the system set, resolved
per #423 (Worker binding / `FERROGATE_CF_SECRET_<NAME>`; REST is
write/manage-only). Per-tenant material never gets a `cf://` reference.

## Cap math

### The 100-secret budget

System/platform secrets FerroGate needs today (from the code, non-test):

- Control plane: `FERROGATE_POSTGRES_DSN`, `FERROGATE_AUTH_SUPABASE_DSN`,
  `FERROGATE_BILLING_SUPABASE_DSN` — 3
- Service/auth tokens: `FERROGATE_ADMIN_TOKEN`, `FERROGATE_API_KEY`,
  `FERROGATE_AUTH_ADMIN_JWT_SECRET`, `FERROGATE_BILLING_TOKEN`,
  `FERROGATE_METERING_TOKEN` — 5
- Crypto master keys: `FERROGATE_MCP_IDENTITY_KEY` (AEAD),
  `FERROGATE_GUARDRAIL_EVIDENCE_HMAC_KEY`, `FERROGATE_ASSET_BUCKET_SECRET`,
  `AGENT_WORKER_MANAGEMENT_SHARED_SECRET` — 4
- Infra tokens: `CLOUDFLARE_API_TOKEN`, `VAULT_TOKEN` (when Vault is
  enabled) — 2
- Platform-default provider keys (OpenAI, Anthropic, DeepSeek, OpenRouter,
  Bedrock key pair, Workers AI, …) — ~8 and slowly growing
- Reserve for near-term features — ~3

**Total ≈ 25 of 100** (one FerroGate environment per Cloudflare account —
the account is the cap unit, so staging/production live in separate accounts
and each gets the full budget). That is **4× headroom** for the system set —
comfortable, but only because the set is bounded by *features shipped*, not
by *tenants onboarded*.

Per-tenant storage in the same store, for contrast: 100 − 25 = **75 free
slots ÷ 2 keys/tenant ≈ 37 tenants**, each requiring a `wrangler.jsonc` edit
+ Worker redeploy to become readable (#423). The ceiling arrives at the first
few dozen tenants, which is why option 2 is rejected as the general strategy.

Guardrail thresholds: hard cap 100 (fail-fast on creating a new secret at the
budget), soft warning at **90** — 10 slots of headroom is several features'
worth of warning time for a set that grows by ones, not by tenants.

### The 1024-byte value cap

| Fits | Typical size |
|---|---|
| Provider API keys (OpenAI/Anthropic/DeepSeek/OpenRouter…) | 40–200 B |
| 64-hex AEAD master keys, HMAC keys | 64–128 B |
| Postgres/Supabase DSNs | 100–300 B |
| Service tokens / JWT signing secrets | 32–512 B |
| Ed25519 private-key PEM | ~120–300 B |

| Does **not** fit | Typical size |
|---|---|
| RSA-2048 private-key PEM (e.g. a `FERROGATE_SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM` value if RSA) | ~1.7 KB |
| GCP service-account JSON | ~2.3 KB |
| Multi-key registries (`FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS`) | unbounded |

Everything in the "does not fit" class stays in the readable backends (or is
referenced by path, as the mTLS CA key already supports via its `_PATH`
variant). The write-path guardrail rejects an oversized value **before any
API call**, naming the exact byte count.

## BYOK on the AI path

For tenant-supplied provider keys on inference requests, the key arrives on
the request (tenant's own `Authorization`/provider header), is used for the
single upstream call, and is never written to any secret backend. This is the
default posture for multi-tenant AI traffic: it removes the highest-
cardinality credential class from storage entirely, keeps tenant keys out of
FerroGate's blast radius, and is unaffected by every CF cap. Stored per-
tenant keys (for scheduled agents/workflows that run without the tenant on
the wire) use the per-tenant backends above — never the CF store.

## Guardrails (implemented, `crates/ferrogate-secrets`)

`CfSecretsCapacityPolicy` (`src/cloudflare_caps.rs`), enforced by
`CloudflareSecretResolver::create_secret` (`src/cloudflare.rs`):

- **Value size, fail-fast:** a value over the byte cap errors *before any
  network call*, stating the exact byte count, the cap, and where oversized
  credentials belong. UTF-8 **bytes**, not characters, are counted.
- **Secret-count budget:** the write path counts the store's secrets via the
  existing manage-plane listing. Creating a **new** secret at/above the hard
  budget fails before the create request (overwriting an existing name
  consumes no slot and stays allowed — rotation never gets bricked by a full
  store); a write landing at/above the soft threshold logs a
  `CfSecretsCapacityWarning` (`tracing::warn`) with used/budget numbers.
- **Configurable thresholds, beta-cap defaults:**
  `FERROGATE_CF_SECRETS_MAX_SECRETS` (default 100),
  `FERROGATE_CF_SECRETS_WARN_AT` (default 90, clamped to the hard budget),
  `FERROGATE_CF_SECRETS_MAX_VALUE_BYTES` (default 1024) — so operators can
  reserve headroom below the beta caps today and lift the limits when
  Cloudflare does, without a code change.

Unit tests: `src/cloudflare_caps_test.rs` (pure policy) and
`src/cloudflare_test.rs` (resolver write path over the scripted mock
transport — no live Cloudflare).

## Migration note: when CF multi-store + store-level bindings land

The single store is the cap unit *and* the isolation unit; GA multi-store
changes both. When Cloudflare ships multiple stores per account (and,
ideally, store-level bindings / per-store tokens):

1. **Re-evaluate per-tenant storage** — a `tenant-<id>` store per tenant (or
   per tenant tier) with store-scoped access would remove both the count
   ceiling and the shared-blast-radius objection to option 2. The decision
   gate: per-store secret caps, per-store token scoping, and whether bindings
   can be attached without a full Worker redeploy.
2. **The `cf://<store>/<name>` reference syntax already carries the store
   segment**, so config needs no schema change — today the store segment is
   effectively constant; post-GA it becomes meaningful. The
   `FERROGATE_CF_SECRET_<NAME>` binding convention is name-keyed only and
   will need a store qualifier once two stores can hold the same name
   (anticipated in `docs/cloudflare-secrets-resolution.md`).
3. **Raise the guardrail thresholds via the env overrides first** (no
   deploy), then update the `CF_SECRETS_STORE_BETA_*` constants and the
   policy defaults in `cloudflare_caps.rs` when the new limits are published.
4. **Migration of tenant secrets, if pursued, is copy-forward**: per-tenant
   values live in readable backends (Postgres AEAD / Vault), so they can be
   written into per-tenant CF stores via the existing
   `CloudflareSecretResolver::create_secret` manage plane; nothing needs to
   be read back out of CF.

Until then: system secrets in the one store, tenants in the readable
backends, BYOK on the AI path — nothing in FerroGate's tenancy scales against
a beta cap.
