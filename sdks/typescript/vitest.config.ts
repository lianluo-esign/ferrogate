import { defineConfig } from "vitest/config";

// A plain HTTP client with an injected `fetch` — no Cloudflare binding, so no
// pool-workers. Every case here runs against a stub transport: the SDK must be
// provable with no server, no account and no credentials.
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
