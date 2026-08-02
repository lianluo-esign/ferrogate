import { defineConfig } from "vitest/config";

// Pure-logic package (no Cloudflare binding) → plain vitest, no pool-workers.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
