import { defineConfig } from "vitest/config";

// Pure-logic package: env/Vault/Cloudflare backends are exercised through
// injected env maps and an in-memory HTTP transport seam, so no Cloudflare
// binding (and no `@cloudflare/vitest-pool-workers`) is needed — plain vitest.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
