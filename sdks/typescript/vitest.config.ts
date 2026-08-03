import { defineConfig } from "vitest/config";

// A plain HTTP client with an injected `fetch` — no Cloudflare binding, so no
// pool-workers. Every case here runs against a stub transport: the SDK must be
// provable with no server, no account and no credentials.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The drift gate shells out to openapi-typescript and renders the complete
    // 2 MiB client before comparing it. It exceeded Vitest's 5s default under
    // CPU contention, and sampling the contract would weaken the drift proof.
    // 30s keeps that deliberate work viable while still failing a real hang.
    testTimeout: 30_000,
  },
});
