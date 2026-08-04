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
import { readFileSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { gatewayRateLimiterAuxWorker } from "../gateway/test/support/rate-limit-aux-worker.js";

/**
 * The COMMITTED deploy config, bound verbatim so a test can assert against the
 * parts of it that no binding surfaces (workerd has no filesystem).
 *
 * Until wave 14 this app had NO committed-`wrangler.toml` gate at all: `main`
 * is named explicitly above, which overrides the toml, and nothing under
 * `test/` read the file. `docs/rewrite/MOUNT-SEAMS.md` §9.4 recorded the
 * consequence — deleting `new_sqlite_classes = ["AgentRunState", "WorkerPlane"]`
 * left all 342 agent-runtime tests green, and this app is not covered by `e2e/`
 * either, so there was NO local proof channel of any kind. Cloudflare rejects a
 * bound `class_name` no migration introduced; and `new_classes` in its place
 * deploys fine while giving the run state and the lease queue the key-value
 * backend instead of the SQLite one they assume.
 */
const WRANGLER_TOML = readFileSync(new URL("./wrangler.toml", import.meta.url), "utf8");

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
  // ------------------------------------------------------------------------
  // ADMISSION fixtures (`test/admission.test.ts`) — the port of the Rust
  // `finalize_auth` ladder. Each one lives in ITS OWN TENANT and carries its
  // own `subject`, because the counter key is `"key:{subject}"` (per-key caps)
  // or `"{scope}:{id}"` (quota-chain caps): sharing either id across tests
  // would make one test's charges another's, and a suite that shares a rate
  // limit window is a suite that flakes.
  // ------------------------------------------------------------------------
  // TOK-12 `api_keys.request_limit_per_minute` — a per-CREDENTIAL cap that
  // needs no quota policy at all.
  {
    key: "sk-rpm-perkey",
    subject: "key-rpm-perkey",
    tenantId: "tenant-rpm",
    workspaceId: "ws-rpm",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
    requestLimitPerMinute: 2,
  },
  // The same cap at 1, spent on a READ: admission is charged on every
  // authenticated request, not only on the write verb.
  {
    key: "sk-rpm-read",
    subject: "key-rpm-read",
    tenantId: "tenant-rpm-read",
    workspaceId: "ws-rpm",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
    requestLimitPerMinute: 1,
  },
  // A TENANT-scope `rpm_limit` from the quota chain: one aggregate window
  // shared by every key beneath the tenant.
  {
    key: "sk-quota-rpm",
    subject: "key-quota-rpm",
    tenantId: "tenant-quota-rpm",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // The SECOND key under that same tenant. It proves the aggregate really is
  // shared: charging it must exhaust the same window the first key charged.
  {
    key: "sk-quota-rpm-sibling",
    subject: "key-quota-rpm-sibling",
    tenantId: "tenant-quota-rpm",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // `enabled = false` anywhere in the chain — a hard 403, never a throttle.
  {
    key: "sk-quota-disabled",
    subject: "key-quota-disabled",
    tenantId: "tenant-quota-disabled",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // `rpm_limit = 0` is a real Rust value meaning "refuse every request", NOT
  // "unlimited". A `??`/`||` fallback anywhere in the port turns it into the
  // latter, so it gets its own credential.
  {
    key: "sk-quota-zero",
    subject: "key-quota-zero",
    tenantId: "tenant-quota-zero",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // A KEY-scope policy: the window must be `"key:{api_key_id}"`, never the
  // bare, tenant-controllable id. See `src/admission/keys.ts`.
  {
    key: "sk-quota-keyscope",
    subject: "key-quota-keyscope",
    tenantId: "tenant-quota-keyscope",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
  // ------------------------------------------------------------------------
  // SHARED-COUNTER fixtures (`test/shared-rate-limit.test.ts`, #666). They are
  // separate credentials from the ones above for the reason stated there: the
  // pool keeps ONE workerd for the project, so a window shared with another
  // file's test would make either file's assertion depend on run order.
  // ------------------------------------------------------------------------
  // Charged once by the test AS THE GATEWAY before its first request here.
  {
    key: "sk-shared-rpm-spent",
    subject: "key-shared-rpm-spent",
    tenantId: "tenant-shared-rpm-spent",
    workspaceId: "ws-shared",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
    requestLimitPerMinute: 1,
  },
  // Two slots: one spent through this Worker, then the gateway side must find
  // exactly one left.
  {
    key: "sk-shared-rpm-split",
    subject: "key-shared-rpm-split",
    tenantId: "tenant-shared-rpm-split",
    workspaceId: "ws-shared",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
    requestLimitPerMinute: 2,
  },
  // The negative control: never charged, must not be affected by the two above.
  {
    key: "sk-shared-rpm-untouched",
    subject: "key-shared-rpm-untouched",
    tenantId: "tenant-shared-rpm-untouched",
    workspaceId: "ws-shared",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
    requestLimitPerMinute: 1,
  },
  // Ungoverned: no per-key cap, no policy row anywhere in its chain. The
  // negative control — every refusal above must NOT fire for this one.
  {
    key: "sk-admission-free",
    subject: "key-admission-free",
    tenantId: "tenant-admission-free",
    workspaceId: "ws-q",
    scopes: ["agents.invoke", "agent.runs.create", "agent.runs.read"],
  },
];

/**
 * DEV/TEST quota policies (`FG_DEV_QUOTA_POLICIES`), in the snake_case wire
 * shape `StoredQuotaPolicy` rows use. The DURABLE source is `CONTROL_DB`'s
 * `quota_policies` table (`test/durable/admission.spec.ts` proves that leg);
 * this var is the dev fallback, exactly as `FG_DEV_API_KEYS` is for `api_keys`.
 *
 * NOTHING is declared for `tenant-a` / `tenant-b`, so every pre-existing test
 * in this suite keeps running under an unlimited quota.
 */
const DEV_QUOTA_POLICIES = [
  { scope_type: "tenant", scope_id: "tenant-quota-rpm", rpm_limit: 1 },
  { scope_type: "tenant", scope_id: "tenant-quota-disabled", enabled: false },
  { scope_type: "tenant", scope_id: "tenant-quota-zero", rpm_limit: 0 },
  { scope_type: "key", scope_id: "key-quota-keyscope", rpm_limit: 1 },
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
  /**
   * Vitest's 5s default is too tight for this workspace under contention.
   *
   * A 29-way concurrent root sweep moved otherwise unrelated event-feed
   * and upstream-withdrawal bodies to 5.974s and 5.089s, while the intentional
   * TTL body reached 7.702s. Which default-budget body gets starved varies with
   * scheduling, and setup hooks reached their inherited 10s wall when that
   * root sweep shared eight cores with four pinned CPU burners, so inline
   * timeouts cannot identify the failure population.
   *
   * 30s leaves almost four times the highest observed loaded cost while still
   * surfacing a genuine hang promptly. Individually slow wall-clock tests keep
   * inline budgets to document their inherent cost.
   */
  test: { include: ["test/**/*.test.ts"], testTimeout: 30_000, hookTimeout: 30_000 },
  plugins: [
    cloudflareTest({
      main: "./src/worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // The `ferrogate-gateway` script this Worker's committed
        // `[[durable_objects.bindings]] RATE_LIMIT` points at with
        // `script_name`. Without it workerd refuses to START the session
        // ("binding RATE_LIMIT refers to a service core:user:ferrogate-gateway,
        // but no such service is defined"), which is why that stanza used to be
        // committed COMMENTED OUT and uncommented by hand at deploy time —
        // issue #666, the defect being that the committed tree was the broken
        // configuration. The auxiliary worker carries the gateway's REAL
        // `RateLimiterDurableObject`, so `test/shared-rate-limit.test.ts` can
        // charge a window as the gateway and watch THIS Worker find it spent.
        workers: [gatewayRateLimiterAuxWorker(new URL("../gateway/", import.meta.url))],
        bindings: {
          TEST_WRANGLER_TOML: WRANGLER_TOML,
          FG_DEV_IN_MEMORY_PORTS: "1",
          FG_REQUIRE_PRODUCTION_MTLS: "0",
          // Sealed by default (#471): with no governed host, no egress may be
          // opened. Tests assert the refusal rather than configuring it away.
          CONTAINER_GOVERNED_EGRESS_HOSTS: "",
          FG_DEV_API_KEYS: JSON.stringify(DEV_API_KEYS),
          FG_DEV_SELF_HOSTED_WORKERS: JSON.stringify(DEV_SELF_HOSTED_WORKERS),
          FG_DEV_AGENT_UPSTREAMS: JSON.stringify(DEV_AGENT_UPSTREAMS),
          FG_DEV_QUOTA_POLICIES: JSON.stringify(DEV_QUOTA_POLICIES),
        },
      },
    }),
  ],
});
