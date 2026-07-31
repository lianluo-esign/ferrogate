import { defineConfig } from "vitest/config";

// `@ferrogate/routing` is a pure-logic package with no Cloudflare bindings, so
// it runs under plain Vitest (node) rather than the @cloudflare/vitest-pool-workers
// runner used by the deployable Workers in apps/*.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // `test/do/**` needs a real Durable Object; it runs under vitest.do.config.ts.
    exclude: ["test/do/**"],
  },
});
