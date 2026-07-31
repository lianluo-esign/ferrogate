// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Worker-side test harness for the FerroGate-hosted MCP server (issue #409).
//   Boots the REAL Worker in workerd via @cloudflare/vitest-pool-workers + miniflare — the
//   same runtime `wrangler dev --local` uses — with NO Docker, NO live Cloudflare account,
//   NO network.
//
//   Config shape targets vitest-pool-workers >= 0.18 (vitest 4): the workers pool is
//   registered as the `cloudflareTest(...)` Vite plugin (the older
//   `defineWorkersConfig`/`poolOptions.workers` form was removed for vitest 4).
//
//   The compatibility date/flags are READ FROM wrangler.toml rather than restated here, so
//   the suite can never drift onto different runtime semantics than the deployment.
//
//   NOT BOUND HERE: `MCP_BEARER_TOKEN_STORE`. miniflare has no Secrets Store emulation, and
//   the branches under test are exactly the ones a real store cannot be made to take on
//   demand (a read that throws, a read that returns ""). The suite therefore passes a stub
//   binding per test — which additionally makes the read COUNTABLE, and "an anonymous
//   request performs no store read" is only assertable against a counter.

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

/**
 * The deployed Durable Object class name, verbatim.
 *
 * Read from EVERY `class_name` key and required to be unambiguous rather than
 * taking the first match: `class_name` is not unique to the binding this suite
 * cares about (a second `[[durable_objects.bindings]]` block would introduce
 * another), and silently binding `MCP_OBJECT` to whichever one happens to come
 * first in the file would run the whole suite against the wrong class.
 */
const doClassNames = [
  ...new Set(
    [...wranglerToml.matchAll(/^class_name\s*=\s*"([^"]+)"/gm)].map((match) => match[1]),
  ),
];
if (doClassNames.length !== 1) {
  throw new Error(
    `wrangler.toml: expected exactly one durable object class_name, found ${JSON.stringify(
      doClassNames,
    )} — point this harness at the intended class explicitly`,
  );
}
const doClassName = doClassNames[0];

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate,
        compatibilityFlags,
        durableObjects: {
          // The Agents SDK keeps per-session state in an embedded SQLite DB, so
          // the class MUST use SQLite storage — this mirrors the deploy
          // metadata's `new_sqlite_classes` migration and wrangler.toml.
          MCP_OBJECT: { className: doClassName, useSQLite: true },
        },
        // `@cloudflare/workers-oauth-provider` refuses to construct without a KV
        // namespace to persist grants in, so the OAuth front door cannot be
        // reached at all unless this is bound.
        kvNamespaces: ["OAUTH_KV"],
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
