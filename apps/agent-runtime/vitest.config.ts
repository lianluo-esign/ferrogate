/**
 * Offline, docker-free Worker tests (`docs/rewrite/TESTING.md`).
 *
 * The Worker runs in the real local `workerd`, so `AGENT_RUN_STATE` and
 * `WORKER_PLANE` are REAL Durable Objects — the run lifecycle, the lease queue
 * and the SSE fan-out are exercised against the runtime that will serve them,
 * not a mock.
 *
 * The dev fixtures below live here rather than in `wrangler.toml` on purpose:
 * an API-key table and a worker-identity table are test data, and a deploy must
 * not inherit them. `wrangler.toml` ships NO `FG_DEV_API_KEYS` /
 * `FG_DEV_SELF_HOSTED_WORKERS`, so a production deploy has an empty registry
 * and admits nobody — fail closed.
 */
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * A 64-hex CSPRNG-shaped transport secret, the shape Rust
 * `generate_transport_token_secret` produces. It is deliberately NOT derived
 * from `token_id`: the pre-fix Rust wiring reused the public identity
 * fingerprint as the secret, which made the AEAD/bearer key public.
 */
const WORKER_A_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const WORKER_B_SECRET = "0f9e8d7c6b5a49382716f5e4d3c2b1a00f9e8d7c6b5a49382716f5e4d3c2b1a0";

const DEV_API_KEYS = [
  {
    key: "sk-tenant-a",
    subject: "key-a",
    tenantId: "tenant-a",
    workspaceId: "ws-a",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  {
    key: "sk-tenant-b",
    subject: "key-b",
    tenantId: "tenant-b",
    workspaceId: "ws-b",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // Read-only: proves the scope gate, not just the credential gate.
  {
    key: "sk-tenant-a-readonly",
    subject: "key-a-ro",
    tenantId: "tenant-a",
    workspaceId: "ws-a",
    scopes: ["agent.runs.read"],
  },
  // A SUSPENDED native key must be indistinguishable from an unknown one (401).
  {
    key: "sk-tenant-a-suspended",
    subject: "key-a-susp",
    tenantId: "tenant-a",
    workspaceId: "ws-a",
    scopes: ["*"],
    state: "suspended",
  },
];

const DEV_SELF_HOSTED_WORKERS = [
  {
    tenant_id: "tenant-a",
    workspace_id: "ws-a",
    worker_id: "worker-a",
    framework_adapter: "native",
    token_id: "tok-a",
    token_secret: WORKER_A_SECRET,
    capabilities: ["coding"],
  },
  {
    tenant_id: "tenant-b",
    workspace_id: "ws-b",
    worker_id: "worker-b",
    framework_adapter: "native",
    token_id: "tok-b",
    token_secret: WORKER_B_SECRET,
    capabilities: ["coding"],
  },
  // Registered but INACTIVE: 403, distinct from the 401 an unknown worker gets.
  {
    tenant_id: "tenant-a",
    workspace_id: "ws-a",
    worker_id: "worker-a-retired",
    framework_adapter: "native",
    token_id: "tok-a-retired",
    token_secret: WORKER_A_SECRET,
    active: false,
  },
];

const DEV_AGENT_UPSTREAMS = [
  {
    id: "helper",
    enabled: true,
    url: "https://upstream.test/a2a",
    visibleToTenantIds: [],
    operatorOnly: false,
  },
  {
    id: "operator-only",
    enabled: true,
    url: "https://upstream.test/a2a",
    visibleToTenantIds: [],
    operatorOnly: true,
  },
  {
    id: "disabled",
    enabled: false,
    url: "https://upstream.test/a2a",
    visibleToTenantIds: [],
    operatorOnly: false,
  },
];

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          FG_DEV_IN_MEMORY_PORTS: "1",
          FG_REQUIRE_PRODUCTION_MTLS: "0",
          // Sealed by default (#471): with no governed host, no egress may be
          // opened. Tests assert the refusal rather than configuring it away.
          CONTAINER_GOVERNED_EGRESS_HOSTS: "",
          FG_DEV_API_KEYS: JSON.stringify(DEV_API_KEYS),
          FG_DEV_SELF_HOSTED_WORKERS: JSON.stringify(DEV_SELF_HOSTED_WORKERS),
          FG_DEV_AGENT_UPSTREAMS: JSON.stringify(DEV_AGENT_UPSTREAMS),
        },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
