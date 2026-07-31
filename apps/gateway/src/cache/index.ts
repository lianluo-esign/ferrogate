/**
 * `src/cache` — the exact-match AI response cache.
 *
 * The port of Rust `AiResponseCache` (`state.rs:3345`) and the seam it was
 * consulted from (`server/chat.rs:481` / `:1976`), split into the four concerns
 * a Worker needs them as:
 *
 *  - `config`      — the `[cache]` section off Worker vars + Rust
 *                    `ai_cache_enabled`'s four-level opt-out.
 *  - `key`         — `ai_response_cache_key`: the tenant/credential/body/policy
 *                    digest that IS the isolation boundary.
 *  - `fingerprint` — the guardrail-policy (#233) and model-registry digests
 *                    that invalidate entries when the rules change.
 *  - `store`       — the Cloudflare Cache API (production) and the faithful
 *                    TTL+LRU port of the Rust structure (tests / fallback).
 *  - `metrics`     — the first producer for
 *                    `ferrogate_ai_cache_requests_total`, which read 0 forever.
 *
 * The middleware that binds them is `../middleware/response-cache.ts`; it is
 * mounted by `createGatewayApp`, and `test/cache/middleware.test.ts` fails if
 * that mount is removed.
 */
export * from "./config.js";
export * from "./fingerprint.js";
export * from "./key.js";
export * from "./metrics.js";
export * from "./store.js";
