// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: The #424 Cloudflare Containers PoC, executed docker-free. Boots
//   the PoC Worker in workerd via @cloudflare/vitest-pool-workers + miniflare --
//   the same runtime `wrangler dev --local` uses -- in front of a REAL spawned
//   `ferrogate run`. No Docker, no live Cloudflare account, no Workers Paid plan.
//
//   What this cannot cover, stated here rather than discovered later: miniflare
//   cannot back a Durable Object with an actual container, so the harness
//   entrypoint reaches the origin over loopback instead of through the container
//   binding, and Cloudflare's outbound *interception* (a container's plain HTTP
//   request being routed to an `outboundByHost` handler) has no local
//   equivalent. Those two remain runbook steps P4-P8 in
//   docs/cloudflare-deploy-topology.md §9.

import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

import { ensurePorts } from "./test/ports";

export default defineConfig(async () => {
  const ports = await ensurePorts();

  return {
    plugins: [
      cloudflareTest({
        // NOT src/index.ts: that module constructs a `Container` Durable Object,
        // which miniflare can only back with Docker. The harness entrypoint
        // imports the same src/origin.ts and src/shim.ts, so the code under test
        // is shared rather than reimplemented.
        main: "./src/harness-entry.ts",
        miniflare: {
          compatibilityDate: "2025-06-01",
          bindings: {
            FERROGATE_ORIGIN_URL: `http://127.0.0.1:${ports.gateway}`,
          },
          // A real workerd KV namespace, so the §6 shim handlers are exercised
          // against an actual binding rather than a hand-written double.
          kvNamespaces: ["POC_KV"],
        },
      }),
    ],
    test: {
      include: ["test/**/*.test.ts"],
      globalSetup: ["./test/global-setup.ts"],
      // Spawning a release-mode gateway and waiting for its first upstream
      // dispatch is slower than the pure-Worker suites in this repo.
      testTimeout: 30_000,
      hookTimeout: 60_000,
    },
  };
});
