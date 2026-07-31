import { defineConfig } from "vitest/config";

// `@ferrogate/sync-bridge` is a pure-logic package with no Cloudflare bindings,
// so it runs under plain Vitest (node) rather than the
// @cloudflare/vitest-pool-workers runner used by the deployable Workers in apps/*.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
  },
});
