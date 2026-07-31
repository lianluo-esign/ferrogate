import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

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
        },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
