/**
 * `@ferrogate/secrets` — secret-reference resolution across three backends:
 * `env://NAME`, `vault://<mount>/<path>#<field>` (HashiCorp Vault KV v2), and
 * `cf://<store>/<name>` (Cloudflare Secrets Store).
 *
 * Faithful clean-room port of the Rust crate `ferrogate-secrets`. The Rust
 * `SecretResolver` trait is synchronous (`Result<Option<String>>`); the TS
 * surface is `async` (`Promise<string | null>`, `null` = not found, throw =
 * genuine failure) because the Vault and Cloudflare backends do I/O, and the
 * Rust `block_on_cloudflare` sync/async bridge collapses away entirely.
 *
 * The Cloudflare split — REST is write/manage-only, values resolve from a
 * Worker binding at runtime (decision #423) — maps directly onto the Workers
 * Secrets Store binding model.
 */

// Core domain model + parse.
export type {
  SecretRef,
  EnvRef,
  VaultRef,
  CfSecretRef,
  ByokRef,
} from "./secret-ref.js";
export {
  parseSecretRef,
  isSecretRef,
  describeSecretRef,
  BYOK_ALIAS_PATTERN,
} from "./secret-ref.js";

// Per-tenant BYOK (issue #682) — `byok://<alias>`, resolved against the
// AUTHENTICATED caller's tenant. Read `./byok.ts` before using any of it: the
// tenant fence lives in the shape of these types, not in a call-site check.
export type {
  SealedTenantCredential,
  TenantCredentialInput,
  TenantCredentialStore,
  TenantByokResolverOptions,
} from "./byok.js";
export {
  ByokKeyring,
  TenantByokResolver,
  byokKeyringFromEnv,
  byokKeyringFromEnvAsync,
  generateByokMasterKey,
  openTenantCredential,
  sealTenantCredential,
  BYOK_MASTER_KEY_ENV,
  BYOK_KEY_VERSION_ENV_PREFIX,
} from "./byok.js";

// Resolver contract + env backend.
export type { SecretResolver } from "./resolver.js";
export { EnvSecretResolver } from "./resolver.js";

// Environment helpers. `EnvLike` admits BOTH Worker slot shapes — a plain
// string and a `[[secrets_store_secrets]]` binding — and `readEnvSecret` is the
// async reader that serves either (inventory-policy-core §4.8).
export type { EnvLike, SecretsStoreBinding } from "./env.js";
export { defaultEnv, nonEmptyEnv, readEnvSecret, isSecretsStoreBinding } from "./env.js";

// Minimal HTTP client (Rust `http_get`/`http_post`).
export type { Header, HttpOptions } from "./http.js";
export { httpGet, httpPost } from "./http.js";

// Vault backend.
export { VaultConfig, VaultSecretResolver } from "./vault.js";

// Cloudflare Secrets Store — REST manage plane.
export { CfSecretsStoreConfig, CloudflareSecretResolver, fetchTransport } from "./cloudflare.js";
export {
  CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT,
  CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT,
  CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
  CF_ACCOUNT_ID_ENV,
  CF_API_TOKEN_ENV,
  CF_API_BASE_URL_ENV,
} from "./cloudflare-consts.js";

// Cloudflare Secrets Store — Worker-binding value resolution (decision #423).
export {
  CfSecretBindings,
  cfBindingEnvVar,
  cfBindingNameIsUnambiguous,
  CF_BINDING_ENV_PREFIX,
} from "./cloudflare-bindings.js";

// Cloudflare Secrets Store — write-path capacity guardrails (issue #418).
export {
  CfSecretsCapacityPolicy,
  CfSecretsCapacityWarning,
  CF_SECRETS_MAX_SECRETS_ENV,
  CF_SECRETS_WARN_AT_ENV,
  CF_SECRETS_MAX_VALUE_BYTES_ENV,
  DEFAULT_CF_SECRETS_WARN_AT,
} from "./cloudflare-caps.js";

// Minimal Cloudflare REST client seam. PORT_TODO(4.6/4.7): a package relocation
// (to a not-yet-existing `@ferrogate/cloudflare`), NOT a platform limit — see
// the module header in `./cloudflare-client.ts`.
export type {
  HttpMethod,
  HttpRequest,
  HttpResponse,
  HttpTransport,
  TokenResolver,
} from "./cloudflare-client.js";
export {
  CloudflareClient,
  CloudflareConfig,
  CloudflareError,
  EnvTokenResolver,
  DEFAULT_API_BASE_URL,
} from "./cloudflare-client.js";

// The dispatching registry.
export { SecretResolverRegistry } from "./registry.js";
