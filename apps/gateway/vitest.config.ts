import { readFileSync } from "node:fs";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** The committed deploy config, read here because workerd has no filesystem. */
const WRANGLER_TOML = readFileSync(new URL("./wrangler.toml", import.meta.url), "utf8");

/**
 * THE `[ai]` STANZA AND THIS POOL (issue #673, corrected).
 *
 * This config used to generate a DERIVED `wrangler.vitest.toml` — the committed
 * file minus its `[ai]` stanza — on the belief that an offline pool cannot load
 * that stanza at all. That reading was wrong in the same way #666's was: what
 * wrangler refuses is the explicit `remote = false` on an AI binding
 * ("AI bindings do not support local development", thrown by `warnOrError`
 * before anything starts), not the binding itself. With no `remote` key
 * `wrangler.toml` loads here exactly as it loads in `wrangler dev --local` and
 * in `wrangler deploy`, `env.AI` is a real `Ai` object, and calling `.run()` on
 * it throws `Binding AI needs to be run remotely` rather than reaching the
 * network — measured, wrangler 4.116, no credentials in the environment.
 *
 * So there is no second deploy config any more: the pool boots from the
 * COMMITTED file, which is the property `test/wrangler-bindings.test.ts`,
 * `test/cron-trigger.test.ts` and `test/env-var-drift.test.ts` have always
 * wanted, and `test/inference/workers-ai.test.ts` pins the link directly (the
 * committed `[ai]` stanza is the one that produced this pool's `env.AI`).
 */

/**
 * The REAL tenant-database migration, read from the same directory
 * `wrangler.toml`'s `migrations_dir` points `wrangler d1 migrations apply` at.
 * `test/setup-d1.ts` applies it to `env.DB` before every test file.
 *
 * This is not optional plumbing. `wrangler.toml` now declares
 * `[[d1_databases]] binding = "DB"`, which makes `depsFromEnv` build the D1
 * key resolver as the PRIMARY credential source — and a bound `DB` whose
 * `api_keys` table does not exist raises `ApiKeyStoreUnavailable`, i.e. every
 * bearer request in this suite would answer 503 instead of falling through to
 * the config keys below. Running the deployed migration rather than a fixture
 * copy is also what keeps the tests honest: a column rename in the migration
 * breaks them, instead of them passing against a private schema.
 */
const migrations = await readD1Migrations("../../sql/d1-ts/tenant");

/**
 * The FULL control-migration set, wrangler-style. `test/setup-d1.ts` used to
 * apply a hand-curated subset of `sql/d1-ts/control/` and the list rotted:
 * `0012_tenant_storage_provisioning.sql` (the `storage_backend` column the
 * tenancy resolver reads on EVERY authenticated request since #819 turned
 * `durable_object` routing on) was never added, so the whole suite answered
 * `503 quota_resolution_unavailable` — ~199 failures with one cause.
 * `readD1Migrations` + `applyD1Migrations` is the same name-bookkept
 * application `wrangler d1 migrations apply` performs in production and the
 * same shape the mcp and storage harnesses already use; there is no list here
 * to forget.
 */
const controlMigrations = await readD1Migrations("../../sql/d1-ts/control");

/**
 * Test fixtures for the contract-driven auth middleware.
 *
 * The default adapters (`src/adapters.ts`) read their key/tenancy/worker tables
 * out of Worker vars, so the whole 401-vs-403 taxonomy is exercisable in real
 * `workerd` with no bindings and no network. Production supplies the same ports
 * from D1 / Secrets Store instead.
 */
const NATIVE_API_KEYS = [
  // A healthy durable/native key.
  {
    key: "fg_tenant_tools",
    id: "key_tools",
    tenant_id: "tenant_a",
    scopes: ["tools.read", "tools.execute"],
  },
  // SUSPENDED native key — must answer 401 `invalid_api_key`, never 403.
  {
    key: "fg_tenant_suspended",
    id: "key_suspended",
    tenant_id: "tenant_a",
    scopes: ["tools.read"],
    enabled: false,
  },
  // Authenticated but under-scoped — must answer 403 `scope_denied`.
  {
    key: "fg_tenant_readonly",
    id: "key_readonly",
    tenant_id: "tenant_a",
    scopes: ["skills.read"],
  },
  // Healthy key belonging to a SUSPENDED TENANT — 403 `tenancy_suspended`.
  {
    key: "fg_tenant_b_tools",
    id: "key_tenant_b",
    tenant_id: "tenant_b",
    scopes: ["tools.read"],
  },
  // Durable key with an EMPTY scope set: data-plane scopes only, never admin.
  { key: "fg_tenant_unscoped", id: "key_unscoped", tenant_id: "tenant_a", scopes: [] },
];

const STATIC_API_KEYS = [
  // Operator-authored static key, no scopes listed => all access.
  { key: "fg_root", id: "key_root", platform_operator: true },
  // Static keys report their state: disabled/expired are 403, not 401.
  { key: "fg_static_disabled", id: "key_static_disabled", tenant_id: "tenant_a", enabled: false },
  {
    key: "fg_static_expired",
    id: "key_static_expired",
    tenant_id: "tenant_a",
    expires_at_unix: 1,
  },
];

const SELF_HOSTED_WORKER_REGISTRY = [
  {
    worker_id: "worker_1",
    tenant_id: "tenant_a",
    workspace_id: "workspace_1",
    identity_fingerprint: "fingerprint_1",
    transport_secret: "worker_secret_1",
  },
];

/**
 * The auxiliary Worker `[[services]] binding = "TELEMETRY_COLLECTOR"` names.
 *
 * NOT optional plumbing, and not a stand-in for a test double. `wrangler.toml`
 * declares the service binding to `ferrogate-telemetry` (`apps/telemetry`), and
 * miniflare resolves a service binding against the set of workers it was given:
 * with the target undefined the RUNTIME REFUSES TO START —
 *
 *   Worker "core:user:vitest-pool-workers-runner-"'s binding
 *   "TELEMETRY_COLLECTOR" refers to a service "core:user:ferrogate-telemetry",
 *   but no such service is defined.
 *
 * — and every test file in this project errors before it is imported. (Real
 * `wrangler dev` is more forgiving: it boots and reports the binding as
 * `[not connected]`.)
 *
 * It answers 204 and records nothing on purpose. The gateway emits ONLY when
 * `TELEMETRY_TOKEN` is set, and this config sets no token, so nothing here is
 * ever reached in the default suite — `test/telemetry/mount.test.ts` installs
 * its own RECORDING collector plus a token on `env` and asserts against that.
 * Making this one recording as well would create a second, ambient sink whose
 * contents no test reads.
 */
const TELEMETRY_COLLECTOR_STUB = {
  name: "ferrogate-telemetry",
  modules: true,
  script: "export default { fetch: () => new Response(null, { status: 204 }) };",
} as const;

export default defineConfig({
  plugins: [
    cloudflareTest({
      // The COMMITTED config — the same file `wrangler deploy` uploads and
      // `wrangler dev --local` boots. See the `[ai]` note at the top.
      wrangler: { configPath: "./wrangler.toml" },
      // No remote-binding proxy, and this is LOAD-BEARING now that `[ai]` is
      // loaded here: an AI binding is classified remote-only, so flipping this
      // to `true` makes the pool open a proxy session against the live
      // Cloudflare API and the suite dies before collection with "it's
      // necessary to set a CLOUDFLARE_API_TOKEN environment variable"
      // (measured 2026-08-02). `false` keeps it hermetic — `env.AI` exists and
      // throws `Binding AI needs to be run remotely` if a test ever calls it
      // for real instead of installing a double.
      remoteBindings: false,
      miniflare: {
        bindings: {
          // The main suite's D1 fixtures intentionally exercise the rollback
          // posture. Production defaults to CONTROL_DATA in wrangler.toml;
          // control-data.test.ts covers that default with a namespace double.
          GATEWAY_CONTROL_STORAGE: "d1_compat",
          GATEWAY_NATIVE_API_KEYS: JSON.stringify(NATIVE_API_KEYS),
          GATEWAY_STATIC_API_KEYS: JSON.stringify(STATIC_API_KEYS),
          SELF_HOSTED_WORKER_REGISTRY: JSON.stringify(SELF_HOSTED_WORKER_REGISTRY),
          TENANCY_LIFECYCLE: JSON.stringify({ tenant_b: "suspended" }),
          TENANT_RBAC_ACTIONS: JSON.stringify({ tenant_a: ["guardrails.policy.read"] }),
          // Pinned EMPTY so the suite is hermetic. `wrangler: { configPath }`
          // makes miniflare load `apps/gateway/.dev.vars` too, and that file is
          // gitignored local developer state — a machine that has one
          // configured with a real provider/model (for the separate cloud
          // verification) made `test/contract.test.ts`'s "empty registry ⇒
          // `{object:"list",data:[]}`" assertion fail on an otherwise correct
          // tree. An explicit binding wins over `.dev.vars`, so the registry the
          // suite sees is the one the suite states, on every machine.
          GATEWAY_PROVIDERS: "[]",
          GATEWAY_MODELS: "[]",
          TEST_D1_SCHEMA: migrations,
          TEST_CONTROL_D1_SCHEMA: controlMigrations,
          // The COMMITTED deploy config, verbatim, so a test can assert against
          // the parts of it that no binding surfaces. `[triggers] crons` is the
          // one that matters: workerd never dispatches a scheduled event under
          // vitest, so the whole suite stays green on a Worker whose Cron was
          // deleted — the billing-outbox recovery would simply never fire in
          // production. `test/cron-trigger.test.ts` reads this.
          TEST_WRANGLER_TOML: WRANGLER_TOML,
        },
        workers: [TELEMETRY_COLLECTOR_STUB],
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["./test/setup-d1.ts"],
  },
});
