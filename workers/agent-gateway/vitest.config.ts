// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Docker-free Worker E2E harness for the agent-gateway control surface
//   (issue #413). Boots the real Worker (src/index.ts) in workerd via
//   @cloudflare/vitest-pool-workers + miniflare — NO Docker, NO live Cloudflare
//   account, NO network. An INLINE miniflare config (not wrangler.toml) binds ONLY
//   the AgentGateway Durable Object with SQLite storage (new_sqlite_classes), so the
//   #415 container/sandbox bindings (paid, image-backed) are excluded from the boot.
//
//   Config shape targets vitest-pool-workers >= 0.18 (vitest 4): the workers pool is
//   registered as the `cloudflareTest(...)` Vite plugin (the older
//   `defineWorkersConfig`/`poolOptions.workers` form was removed for vitest 4).

import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate: "2025-06-01",
        compatibilityFlags: ["nodejs_compat"],
        // The Agents SDK stores agent state in a per-instance embedded SQLite DB,
        // so the DO class MUST use SQLite storage (mirrors the deploy metadata's
        // `new_sqlite_classes` migration).
        durableObjects: {
          AGENT_GATEWAY: { className: "AgentGateway", useSQLite: true },
        },
        bindings: {
          GATEWAY_CONTROL_TOKEN: "test-control-secret",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
