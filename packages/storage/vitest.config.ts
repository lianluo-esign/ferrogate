import { defineConfig } from "vitest/config";

// Pure-logic package (no Cloudflare binding) → plain vitest, no pool-workers.
// Every ported algorithm has a synchronous in-memory reference backend, so the
// concurrency invariants are exercised directly without a real D1 SQLite.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
