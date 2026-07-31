import { defineConfig } from "vitest/config";

// `ferrogate` is a Bun binary, NOT a Worker — plain vitest, no pool-workers and
// no `cloudflare:test`. Every seam is injected (see `src/ports.ts`), so the
// suite runs offline with no filesystem, socket, clock, or RNG access.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
