/**
 * Cloudflare Secrets Store constants (beta caps + env var names). Kept in a
 * standalone module so `cloudflare-caps.ts` and `cloudflare.ts` can share them
 * without a circular import.
 */

/** At most **one** Secrets Store per account (beta). */
export const CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT = 1;
/** At most **100** secrets per account (beta). */
export const CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT = 100;
/** At most **1024 bytes** per secret value (beta). */
export const CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES = 1024;

/** Env var naming the Cloudflare account the Secrets Store lives in. */
export const CF_ACCOUNT_ID_ENV = "CLOUDFLARE_ACCOUNT_ID";
/** Env var holding a Cloudflare API token with Secrets Store Read/Write. */
export const CF_API_TOKEN_ENV = "CLOUDFLARE_API_TOKEN";
/** Optional `client/v4` base override. */
export const CF_API_BASE_URL_ENV = "CLOUDFLARE_API_BASE_URL";
