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
//   CONSOLE (#559): `test.disableConsoleIntercept` is ON, and the suite cannot terminate
//   without it. The reason is written out in full at the option itself, below.
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
    // ISSUE #559 — WITHOUT THIS LINE THE WHOLE SUITE HANGS FOREVER. Do not remove it
    // without reading the rest of this comment; the failure mode it prevents is a
    // runner that never terminates, which reads to CI as "still running", not as red.
    //
    // WHAT VITEST DOES BY DEFAULT. `disableConsoleIntercept: false` replaces
    // `globalThis.console` with a custom Console that buffers writes and then ships each
    // line to the Vitest node process as an `onUserConsoleLog` RPC, so the reporter can
    // attribute it to the test that produced it (vitest/dist/chunks/console.*.js).
    //
    // WHY THAT IS FATAL HERE. Inside vitest-pool-workers the node process is reached
    // through a WebSocket owned by the runner Durable Object, so a log emitted from a
    // DIFFERENT Durable Object cannot send it directly — the pool catches workerd's
    // "Cannot perform I/O on behalf of a different Durable Object" and re-sends through
    // `runInRunnerObject(...)`, an outbound RPC made from the logging object
    // (@cloudflare/vitest-pool-workers/dist/worker/index.mjs, `init({ post })`).
    // `POST /control/destroy` ends in the Agents SDK's `destroy()`, whose last step is
    // `ctx.abort("destroyed")` (see SDK_DESTROY_ABORT_REASON in src/index.ts). Aborting
    // the object breaks its output gate, so that pending outbound RPC can never
    // complete. Vitest's run promise waits on the outstanding console RPC, the runner
    // never sends `testfileFinished`, and the pool waits forever — `npm test` in this
    // Worker never returns. workerd stays alive and ignores SIGTERM throughout; only
    // SIGKILL ends it.
    //
    // WHAT THE DISCRIMINATOR IS, measured rather than reasoned about. Aborting a DO is
    // NOT enough on its own: `deleteAll()` + `ctx.abort()` with no logging in the same
    // request terminates in ~2s, and so does the SDK's `destroy()` called directly
    // (its own observability emit runs AFTER the abort, so it never executes). Add ONE
    // `console.log` before the abort — which is exactly what `destroyRun`'s
    // `setState()` does, via the Agents SDK's default `genericObservability.emit`
    // (agents@0.0.109 chunk-3IQQY2UH.js:1234) — and the runner hangs. That is the whole
    // mechanism: console output emitted from an object that then aborts itself.
    //
    // WHY THIS SIDE AND NOT THE PRODUCTION SIDE. `ctx.abort("destroyed")` is the point
    // of #482 — it is what deletes the alarm and stops in-flight work, and reverting
    // `destroyRun` to `ctx.storage.deleteAll()` would re-open that issue. On real
    // Cloudflare a log line before an abort is simply dropped; the round trip that
    // cannot finish exists only because the test runner lives inside the same runtime.
    // So the harness is what changes. Nothing about the Worker's behaviour is altered,
    // and no assertion is weakened: `destroy-alarm.test.ts` still reads the platform
    // alarm after a real `POST /control/destroy`.
    //
    // WHAT IT COSTS. Console output from tests and from the Worker is no longer
    // attributed to the test that emitted it — it goes to workerd's own stdio and
    // arrives interleaved, unlabelled. `vi.spyOn(console, ...)` is unaffected.
    disableConsoleIntercept: true,
  },
});
