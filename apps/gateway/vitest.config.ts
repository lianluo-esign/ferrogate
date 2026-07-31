import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

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

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
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
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["./test/setup-d1.ts"],
  },
});
