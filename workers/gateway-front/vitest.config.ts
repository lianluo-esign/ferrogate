// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Runner B of the #470 governed-decision conformance suite. Boots the
//   real gateway-front Worker in workerd via @cloudflare/vitest-pool-workers +
//   miniflare -- the same runtime `wrangler dev --local` uses -- with NO Docker, NO
//   live Cloudflare account and NO network. The repo-root corpus is inlined by Vite
//   at build time because workerd has no filesystem, which is why `server.fs.allow`
//   is widened to the repository root.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

const workerDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(workerDir, "../..");

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate: "2025-06-01",
        bindings: {
          // The conformance route is 404 unless this is exactly "1".
          CONFORMANCE: "1",
          INFERENCE_BODY_MAX_BYTES: "1048576",
          EDGE_DENY_LIST: "",
        },
      },
    }),
  ],
  // The corpus is committed at the repository root so neither host owns it.
  // Vite must be allowed to read it in order to inline it into the worker
  // bundle.
  server: { fs: { allow: [repoRoot] } },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
