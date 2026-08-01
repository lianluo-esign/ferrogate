import { defineConfig } from "vitest/config";

/**
 * Pure-logic package: the Cloudflare account-MANAGEMENT REST surface. Every
 * test drives an injected `FetchLike` transport and an injected clock, so there
 * is no network, no real sleep, no Cloudflare binding and no live account —
 * hence plain vitest rather than `@cloudflare/vitest-pool-workers`.
 *
 * The one platform dependency is `crypto.subtle` (SHA-256), which is ambient in
 * both workerd and Node ≥ 18, so it needs no pool.
 */
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
