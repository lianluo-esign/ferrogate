// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Docker-free Worker E2E harness for the agent-gateway control surface
//   (issue #413) and the #471 governed-egress suite. Boots the real Worker in workerd via
//   @cloudflare/vitest-pool-workers + miniflare — NO Docker, NO live Cloudflare account.
//
//   Config shape targets vitest-pool-workers >= 0.18 (vitest 4): the workers pool is
//   registered as the `cloudflareTest(...)` Vite plugin (the older
//   `defineWorkersConfig`/`poolOptions.workers` form was removed for vitest 4).
//
//   ENTRYPOINT (#471): `main` is a TEST-ONLY module that re-exports the production Worker
//   verbatim and adds the `ProbeSandbox` Durable Object — `AgentSandbox` plus an
//   observable stand-in for the container platform API, which workerd cannot provide
//   without a container engine. See test/harness/worker.ts. Production still binds
//   `AgentSandbox`; test/container-egress.test.ts asserts wrangler.toml says so.
//
//   COMPATIBILITY (#471): the runtime date and flags are READ FROM wrangler.toml rather
//   than restated here. `setAllowedHosts`/`setDeniedHosts` resolve their interceptor
//   through `ctx.exports`, which is off before compatibility date 2025-11-17 unless
//   `enable_ctx_exports` is set — so a suite running on different compatibility settings
//   than the deployment would prove nothing about the deployment.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

const workerDir = path.dirname(fileURLToPath(import.meta.url));
const wranglerToml = readFileSync(path.join(workerDir, "wrangler.toml"), "utf8");

function requiredMatch(pattern: RegExp, what: string): string {
  const match = pattern.exec(wranglerToml);
  if (!match) throw new Error(`wrangler.toml: could not read ${what}`);
  return match[1];
}

/** The deployed compatibility date, verbatim. */
const compatibilityDate = requiredMatch(
  /^compatibility_date\s*=\s*"([^"]+)"/m,
  "compatibility_date",
);

/** The deployed compatibility flags, verbatim. */
const compatibilityFlags = [
  ...requiredMatch(/^compatibility_flags\s*=\s*\[([^\]]*)\]/m, "compatibility_flags").matchAll(
    /"([^"]+)"/g,
  ),
].map((match) => match[1]);

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./test/harness/worker.ts",
      miniflare: {
        compatibilityDate,
        compatibilityFlags,
        // The Agents SDK stores agent state in a per-instance embedded SQLite DB,
        // so the DO class MUST use SQLite storage (mirrors the deploy metadata's
        // `new_sqlite_classes` migration).
        durableObjects: {
          // #414: `ProbeAgentGateway` IS `AgentGateway` — it inherits the whole
          // lifecycle surface and overrides only `dispatchWorkload`, the seam a
          // real framework harness overrides, and only for the `probe:sleep`
          // workload. It exists because "a cancelled run stops doing work"
          // cannot be observed against a workload that finishes in one tick.
          // Production binds `AgentGateway`; control.test.ts asserts wrangler.toml
          // says so. See test/harness/worker.ts.
          AGENT_GATEWAY: { className: "ProbeAgentGateway", useSQLite: true },
          // #471: the container tier is bound so the egress posture the Worker applies
          // is observable. `ProbeSandbox` IS `AgentSandbox` (see the harness).
          CONTAINER_SANDBOX: { className: "ProbeSandbox", useSQLite: true },
        },
        bindings: {
          GATEWAY_CONTROL_TOKEN: "test-control-secret",
          // #471: the ONLY host this deployment authorizes `/container/start` to open.
          // Production ships it EMPTY (sealed); the suite sets one so the tethered path
          // is exercised, and covers the empty case by overriding the var per call.
          CONTAINER_GOVERNED_EGRESS_HOSTS: "gw.ferrogate.test",
          // Issue #475: `/git-credential/*` fails closed with 501 unless a
          // GitHub App is bound, so the route tests must bind one to reach the
          // authorization logic at all. The key is a placeholder — every test
          // here stops on a denial or a capability check, and none of them
          // reaches the mint (vitest-pool-workers 0.18 has no outbound fetch
          // mock, so a real mint would need a live GitHub).
          GITHUB_APP_ID: "123456",
          GITHUB_APP_PRIVATE_KEY:
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-tests-never-sign\n-----END PRIVATE KEY-----",
          GITHUB_API_BASE_URL: "https://api.github.invalid",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
