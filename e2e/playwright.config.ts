/**
 * Layer 3 of `docs/rewrite/TESTING.md` — black-box the Workers as REAL services.
 *
 * Playwright's `webServer` array starts one `wrangler dev` per app before the
 * suite and tears both down after. There is no browser here: every spec uses the
 * `request` fixture, so this config declares no `projects`/`browserName` and
 * Playwright never launches Chromium.
 *
 * ## Why this layer exists next to `@cloudflare/vitest-pool-workers`
 *
 * Layer 1 imports the Worker module inside the test process and dispatches to it
 * through `SELF`. That proves routing/auth/handler behavior, but it never
 * exercises **`wrangler`'s own bundle + `workerd` service registration** — the
 * step a real `wrangler deploy` performs. A Worker can be perfectly correct
 * under `SELF.fetch` and still refuse to start as a service. Only a real
 * `wrangler dev` catches that, which is the whole reason this file runs the
 * production `wrangler.toml` of each app rather than a bespoke entry point.
 *
 * ## Startup cost
 *
 * A cold `wrangler dev` in this repo takes ~35-50s (esbuild bundle + workerd
 * boot), so `timeout` is generous and `reuseExistingServer` is on locally: leave
 * `wrangler dev` running by hand and the suite attaches to it instead of paying
 * the boot cost per run. CI always starts its own.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";

import {
  GATEWAY_BASE_URL,
  GATEWAY_INSPECTOR_PORT,
  GATEWAY_NATIVE_API_KEYS,
  GATEWAY_PORT,
  MCP_BASE_URL,
  MCP_INSPECTOR_PORT,
  MCP_PORT,
} from "./fixtures.js";

/** Absolute repo root, so `cwd` below is correct no matter where the runner started. */
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const appDir = (name: string): string =>
  fileURLToPath(new URL(`../apps/${name}/`, import.meta.url));

const isCi = process.env.CI !== undefined && process.env.CI !== "";

/**
 * Apply the D1 migrations to the LOCAL SQLite files before any `wrangler dev`
 * starts.
 *
 * `apps/gateway/wrangler.toml` declares `DB` (tenant) and `BILLING_DB` /
 * `CONTROL_DB` (control). `wrangler dev --local` honours those bindings by
 * provisioning an EMPTY SQLite file per database id — it does not run
 * `migrations_dir`. An empty file is not a state any real deployment is ever in
 * (`wrangler deploy` is paired with `wrangler d1 migrations apply`), and the
 * gateway is right to refuse to serve one: the quota-policy read is on the hot
 * path of every authenticated request, and `d1QuotaPolicySource` fails CLOSED —
 * a lookup error is `503 quota_resolution_unavailable`, never "no policies",
 * because an outage that reads as "no policies" is unlimited traffic for every
 * caller. So the schema has to exist before the first authenticated request,
 * exactly as it does in production.
 *
 * WHY THIS RUNS AT MODULE LOAD AND NOT IN `globalSetup`. Playwright orders
 * `createGlobalSetupTasks` as plugin-setup FIRST, then `globalSetup` — and the
 * `webServer` array is a plugin. A `globalSetup` seed would therefore land
 * AFTER `wrangler dev` has already opened the database. Config evaluation is
 * the only hook that is guaranteed to precede the servers.
 *
 * Both migrations are `CREATE TABLE IF NOT EXISTS` throughout, so this is
 * idempotent and safe against the `reuseExistingServer` path and against a
 * `.wrangler/state` left over from a previous run.
 */
function applyLocalD1Migrations(): void {
  const seeds: readonly [binding: string, sql: string][] = [
    ["DB", "sql/d1-ts/tenant/0001_init_tenant.sql"],
    ["BILLING_DB", "sql/d1-ts/control/0001_init_control.sql"],
  ];
  for (const [binding, sql] of seeds) {
    execFileSync(
      "bunx",
      ["wrangler", "d1", "execute", binding, "--local", "-y", `--file=${repoRoot}${sql}`],
      { cwd: appDir("gateway"), stdio: "pipe" },
    );
  }
}

applyLocalD1Migrations();

/**
 * Common `wrangler dev` flags.
 *
 *  - `--local` pins the local `workerd` — never the global Cloudflare network.
 *    THIS is what makes the layer account-free: no `wrangler login`, no
 *    `account_id`, no remote bindings, no billable request.
 *  - `--ip 127.0.0.1` keeps the dev server off the LAN. It is serving an
 *    injected API key; do not bind 0.0.0.0.
 *  - `--inspector-port` must be distinct per app: every `wrangler dev` defaults
 *    the devtools socket to 9229, so two concurrent instances collide on it and
 *    the second exits with `Address already in use (127.0.0.1:9229)`.
 */
function wranglerDev(port: number, inspectorPort: number, extra = ""): string {
  const flags = `--local --ip 127.0.0.1 --port ${port} --inspector-port ${inspectorPort}`;
  return `bunx wrangler dev ${flags}${extra}`;
}

/**
 * `apps/gateway`'s committed `[vars]` are the FAIL-CLOSED empties, so a stock
 * `wrangler dev` resolves no credential at all and every authenticated route
 * answers 401 before its handler runs. `--var` overrides one of them for the
 * duration of the dev server — the CLI equivalent of the `miniflare.bindings`
 * the layer-1 `vitest.config.ts` sets, and it leaves `apps/**` untouched.
 *
 * `wrangler` splits `--var` on the FIRST colon only (`collectKeyValues`), so a
 * JSON value containing colons round-trips intact. The single quotes are POSIX
 * shell quoting; the JSON itself contains none.
 *
 * `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` are pinned EMPTY for a different
 * reason: `wrangler dev` also loads `apps/gateway/.dev.vars`, which is
 * gitignored local developer state. A machine with a real provider + model
 * configured there (for the separate cloud verification) made
 * `gateway.spec.ts`'s "empty registry ⇒ `data: []`" assertion fail on an
 * otherwise correct tree. `--var` beats `.dev.vars`, so the registry the suite
 * sees is the one the suite states — on a laptop and in CI alike.
 */
const gatewayVarFlag = [
  ` --var 'GATEWAY_NATIVE_API_KEYS:${JSON.stringify(GATEWAY_NATIVE_API_KEYS)}'`,
  " --var 'GATEWAY_PROVIDERS:[]'",
  " --var 'GATEWAY_MODELS:[]'",
].join("");

export default defineConfig({
  testDir: "./tests",
  outputDir: "./.playwright",

  /* One shared dev server per app: run serially so a spec's assertions are not
     interleaved with another spec's traffic through the same single isolate. */
  fullyParallel: false,
  workers: 1,

  forbidOnly: isCi,
  retries: 0,
  /* Each assertion is a local HTTP round-trip; anything slower is a real hang. */
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: isCi ? "github" : "list",

  use: {
    /* API-only. No browser is launched; specs take absolute URLs from
       `fixtures.ts` because this suite talks to TWO servers. */
    extraHTTPHeaders: { accept: "application/json" },
    ignoreHTTPSErrors: false,
  },

  webServer: [
    {
      command: wranglerDev(GATEWAY_PORT, GATEWAY_INSPECTOR_PORT, gatewayVarFlag),
      cwd: appDir("gateway"),
      /* `/healthz` is `anonymous` in the contract, so readiness polling needs no
         credential and cannot be confused with an auth failure. */
      url: `${GATEWAY_BASE_URL}/healthz`,
      timeout: 180_000,
      reuseExistingServer: !isCi,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: wranglerDev(MCP_PORT, MCP_INSPECTOR_PORT),
      cwd: appDir("mcp"),
      url: `${MCP_BASE_URL}/healthz`,
      timeout: 180_000,
      reuseExistingServer: !isCi,
      stdout: "pipe",
      stderr: "pipe",
    },
  ],

  metadata: { repoRoot },
});
