/**
 * THE anti-drift gate for the app this Worker EXPORTS.
 *
 * Modelled on `apps/gateway/test/contract.test.ts`, and written against the
 * defect that suite was added to catch: `apps/gateway` shipped a composition
 * root with an EMPTY module list, so 24 of its 31 contract operations were
 * unreachable in the deployed Worker while every test passed — because each
 * suite built its OWN router and never exercised the app the Worker exports.
 *
 * This app's pre-existing `test/contract.test.ts` is *nearly* that same trap.
 * It asserts against `registeredRoutes()` and `registeredOperationIds()` from
 * `src/routes/index.ts` — but `registeredRoutes()` is literally
 * `CONTROL_PLANE_OPERATIONS.map(...)`, a projection of the contract, and the
 * handler table is built at module load whether or not anyone ever calls
 * `registerRoutes(app)`. Delete the `registerRoutes(app)` line from
 * `src/index.ts` and every assertion in that file still passes. So it proves
 * handlers EXIST; it cannot prove they are MOUNTED.
 *
 * Everything below is anchored to one of two things that cannot be faked:
 *
 *  1. `app.routes` — Hono's OWN routing table on the instance `src/index.ts`
 *     puts under `export default`. It is appended to by `app.on(...)` itself.
 *  2. `SELF.fetch` — the real `export default` in real `workerd`.
 *
 * plus `MOUNTED_ROUTES`, the value `registerRoutes` RETURNED for that app: one
 * entry appended per `app.on(...)` actually performed.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_GROUPS,
  CONTROL_PLANE_OPERATIONS,
  EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
  type HttpMethod,
  controlPlaneOperationIds,
  operationById,
} from "../src/contract.js";
import {
  CONTROL_PLANE_ROUTE_MODULES,
  IDENTITY_APP,
  MOUNTED_OPERATION_IDS,
  MOUNTED_ROUTES,
  MOUNTED_SESSION_ROUTES,
  MOUNTED_SSO_ROUTES,
  app,
} from "../src/index.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

// ---------------------------------------------------------------------------
// Hono's own routing table, read off the exported instance
// ---------------------------------------------------------------------------

interface HonoRoute {
  readonly path: string;
  readonly method: string;
}

/** Every route Hono itself recorded, minus the `app.use("*", …)` middleware. */
const HONO_ROUTES: readonly HonoRoute[] = (
  app as unknown as { routes: readonly HonoRoute[] }
).routes.filter((route) => route.method !== "ALL");

const HONO_KEYS = new Set(HONO_ROUTES.map((route) => `${route.method} ${route.path}`));

/**
 * The routes `src/index.ts` mounts that are not among the 203 operations this
 * app OWNS. They are named here so the "nothing extra is mounted" assertion
 * below is exact rather than a tolerance.
 *
 * `/healthz` and `/readyz` ARE contract operations, but shared ones — every
 * Worker implements them and no single app owns them, so they are outside
 * `CONTROL_PLANE_OPERATIONS` while still being routes that must exist. This app
 * shipped without them until a real `wrangler dev --local` boot answered
 * `404 not_found` on `/healthz`; listing them here is what keeps them from
 * being dropped again.
 *
 * `/health` and `/version` are not contract operations at all.
 */
const PROBE_ROUTES = ["GET /healthz", "GET /readyz", "GET /health", "GET /version"] as const;

/**
 * The enterprise-identity mounts (wave 18): the nine admin-console session
 * routes, the OIDC + SCIM sub-app, and the SAML legs + shared `sso-config` row.
 *
 * NOT hardcoded, deliberately. Each is the registry the composition root's own
 * mount function RETURNED — one entry per `app.on(...)` it actually performed —
 * so this list cannot drift from what was mounted, and the comparison below
 * stays a comparison between two independent things (Hono's table vs. what the
 * root says it did) rather than a restatement of one of them.
 *
 * The consequence is the point: unmount `mountAdminConsoleSession(app)` and
 * `MOUNTED_SESSION_ROUTES` empties WHILE Hono's table loses the same nine, so
 * the count assertion still balances — which is why the SELF-driven mount
 * assertions further down, not this one, are the seam's real gate.
 */
const IDENTITY_MOUNTS: readonly string[] = [
  ...MOUNTED_SESSION_ROUTES.map((route) => `${route.method} ${route.path}`),
  ...IDENTITY_APP.identityRoutes.map((route) => `${route.method} ${route.path}`),
  ...MOUNTED_SSO_ROUTES.map((route) => `${route.method} ${route.path}`),
];

const NON_CONTRACT_ROUTES = [...PROBE_ROUTES, ...IDENTITY_MOUNTS] as const;

function contractKey(operationId: string): string {
  const operation = operationById(operationId);
  if (operation === undefined) throw new Error(`${operationId} is not in the contract`);
  return `${operation.method} ${operation.honoPath}`;
}

describe("the app src/index.ts exports has all 203 operations in its ROUTING TABLE", () => {
  it("mounts every contract operation this app owns — naming any that fell off", () => {
    // THE gate. `HONO_KEYS` comes from Hono, not from the contract, so this is
    // a comparison between two independent things.
    const missing = CONTROL_PLANE_OPERATIONS.filter(
      (operation) => !HONO_KEYS.has(`${operation.method} ${operation.honoPath}`),
    ).map((operation) => `${operation.operationId} (${operation.method} ${operation.path})`);

    expect(
      missing,
      `${missing.length} contract operation(s) are NOT mounted on the exported app: ${missing.join(", ")}`,
    ).toEqual([]);
  });

  it("mounts NOTHING beyond the 203 + the shared probes + /health + /version", () => {
    const expected = new Set<string>([
      ...CONTROL_PLANE_OPERATIONS.map((operation) => `${operation.method} ${operation.honoPath}`),
      ...NON_CONTRACT_ROUTES,
    ]);
    const stray = [...HONO_KEYS].filter((key) => !expected.has(key)).sort();
    expect(stray, `routes with no contract operation: ${stray.join(", ")}`).toEqual([]);
    // …and the table is exactly that set, so a duplicate mount is visible too.
    const extra = NON_CONTRACT_ROUTES.length;
    expect(HONO_ROUTES).toHaveLength(EXPECTED_CONTROL_PLANE_OPERATION_COUNT + extra);
    expect(HONO_KEYS.size).toBe(EXPECTED_CONTROL_PLANE_OPERATION_COUNT + extra);
  });

  it("mounts each operation at the contract's own template, in Hono syntax", () => {
    // A parameterised path is the easiest thing to fat-finger; spot the shapes
    // explicitly rather than trusting the loop that produced them.
    expect(HONO_KEYS.has(contractKey("getQuotaPolicy"))).toBe(true);
    expect(contractKey("getQuotaPolicy")).toBe(
      "GET /admin/v1/quota-policies/:scope_type/:scope_id",
    );
    expect(contractKey("getGuardrailPolicyRevision")).toBe(
      "GET /admin/v1/guardrail-policies/:policy_id/revisions/:revision",
    );
    expect(HONO_KEYS.has(contractKey("getGuardrailPolicyRevision"))).toBe(true);
    // `/admin` and `/admin/` are two distinct contract operations and must not
    // collapse into one Hono route.
    expect(HONO_KEYS.has("GET /admin")).toBe(true);
    expect(HONO_KEYS.has("GET /admin/")).toBe(true);
  });
});

describe("the mount record the composition root returned", () => {
  it("records one mount per contract operation, in contract order", () => {
    expect(MOUNTED_ROUTES).toHaveLength(EXPECTED_CONTROL_PLANE_OPERATION_COUNT);
    expect([...MOUNTED_OPERATION_IDS]).toEqual([...controlPlaneOperationIds()]);
  });

  it("is corroborated by Hono — every recorded mount is really in the table", () => {
    // Guards against the record becoming a fiction: if `registerRoutes` ever
    // reports a mount it did not perform, these two disagree.
    const unrecorded = MOUNTED_ROUTES.filter(
      (route) => !HONO_KEYS.has(`${route.method} ${route.honoPath}`),
    ).map((route) => route.operationId);
    expect(unrecorded).toEqual([]);
  });

  it("exports the PRODUCTION module list, covering exactly the 31 owned groups", () => {
    expect(CONTROL_PLANE_ROUTE_MODULES).toHaveLength(CONTROL_PLANE_GROUPS.length);
    expect(CONTROL_PLANE_ROUTE_MODULES.map((module) => module.group).sort()).toEqual([
      ...CONTROL_PLANE_GROUPS,
    ]);
  });

  it("mounts at least one operation from every owned group", () => {
    const mountedGroups = new Set(MOUNTED_ROUTES.map((route) => route.group));
    const unserved = CONTROL_PLANE_GROUPS.filter((group) => !mountedGroups.has(group));
    expect(unserved, `groups with no mounted route: ${unserved.join(", ")}`).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The deployed Worker: SELF.fetch through `export default`
// ---------------------------------------------------------------------------

interface ErrorEnvelope {
  readonly error: { readonly message: string; readonly code: string };
}

async function envelope(response: Response): Promise<{ code: string; message: string }> {
  const text = await response.text();
  try {
    return (JSON.parse(text) as ErrorEnvelope).error;
  } catch {
    // The dashboard HTML and the Prometheus exposition are not JSON.
    return { code: "<non-json>", message: text.slice(0, 40) };
  }
}

/**
 * The app's "no route" answer, verbatim from `controlPlaneNotFoundHandler`.
 * A handler's own 404 (`quota policy tenant:x not found`) is a DIFFERENT thing
 * and must not be mistaken for an unmounted route — hence matching the message
 * and not merely the status.
 */
function isRouterMiss(status: number, error: { code: string; message: string }): boolean {
  return status === 404 && error.code === "not_found" && error.message.startsWith("no route for");
}

/**
 * Sample values for the contract's path parameters. `scope_type` is the Rust
 * `QuotaScopeKind` enum and the route deliberately answers the router's own
 * 404 for a value outside it, so an opaque placeholder there would look like an
 * unmounted route. Everything else is an opaque id.
 */
const PATH_SAMPLES: Readonly<Record<string, string>> = { scope_type: "tenant" };
const DEFAULT_SAMPLE = "probe";

function concretePath(template: string): string {
  return template
    .split("/")
    .map((segment) => {
      if (!segment.startsWith("{") || !segment.endsWith("}")) return segment;
      const name = segment.slice(1, -1).replace(/^\*/, "");
      return PATH_SAMPLES[name] ?? DEFAULT_SAMPLE;
    })
    .join("/");
}

function probeInit(
  method: string,
  secret: string,
  extra: Record<string, string> = {},
): RequestInit {
  const init: RequestInit = {
    method,
    headers: { ...bearer(secret), "content-type": "application/json", ...extra },
  };
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    (init as { body?: string }).body = "{}";
  }
  return init;
}

beforeEach(() => {
  arm({
    staticKeys: [operatorKey],
    nativeKeys: [
      // Under-scoped: authenticates, then fails every admin scope check.
      tenantKey("tenant-readonly", "tenant_a", ["skills.read"]),
      // Suspended: must be indistinguishable from an unknown credential.
      { ...tenantKey("tenant-suspended", "tenant_a"), enabled: false },
      // Scoped for the metrics scrape only.
      tenantKey("tenant-metrics", "tenant_a", ["admin.read"]),
    ],
  });
});

describe("the DEPLOYED Worker serves every mounted operation", () => {
  it("answers no contract operation with the app's own 'no route' 404", async () => {
    // The full 203. Every request goes through `export default` in workerd with
    // a credential that clears the guard, so anything that comes back as
    // `no route for …` is a route that is not mounted.
    const unreachable: string[] = [];
    for (const operation of CONTROL_PLANE_OPERATIONS) {
      const path = concretePath(operation.path);
      const response = await SELF.fetch(
        `${BASE}${path}`,
        probeInit(operation.method, operatorKey.secret),
      );
      const error = await envelope(response);
      if (isRouterMiss(response.status, error)) {
        unreachable.push(`${operation.operationId} (${operation.method} ${path})`);
      }
    }
    expect(
      unreachable,
      `${unreachable.length} operation(s) 404 as unmounted on the deployed Worker: ${unreachable.join(", ")}`,
    ).toEqual([]);
  });
});

/**
 * One representative operation per contract group, with the status the group's
 * OWN pipeline produces on a clean store. "Not 404" alone would be weak, so the
 * exact status is asserted alongside it: a 200 `AdminList` can only come from
 * the list handler, and a 400 `invalid_request_body` can only come from that
 * group's Zod chain.
 */
const GROUP_PROBES: readonly (readonly [string, string, HttpMethod, string, number])[] = [
  ["admin_agent_cost_burn", "listAdminAgentCostBurn", "GET", "/admin/v1/agent-cost-burn", 200],
  ["admin_agent_schedule", "listAdminAgentSchedules", "GET", "/admin/v1/agent-schedules", 200],
  ["admin_agent_upstream", "listAdminAgentUpstreams", "GET", "/admin/v1/agent-upstreams", 200],
  ["admin_agent_workflow", "listAdminAgentWorkflows", "GET", "/admin/v1/agent-workflows", 200],
  ["admin_api_key", "listAdminApiKeys", "GET", "/admin/v1/api-keys", 200],
  ["admin_config_ops", "validateAdminConfig", "POST", "/admin/v1/config/validate", 200],
  ["admin_gateway_config", "listAdminGatewayConfigs", "GET", "/admin/v1/gateway-configs", 200],
  ["admin_managed_worker", "listAdminManagedWorkers", "GET", "/admin/v1/managed-workers", 200],
  ["admin_mcp_server", "listAdminMcpServers", "GET", "/admin/v1/mcp-servers", 200],
  ["admin_model", "listAdminModels", "GET", "/admin/v1/models", 200],
  ["admin_overview", "getAdminOverview", "GET", "/admin/v1/overview", 200],
  ["admin_plugin", "listAdminPlugins", "GET", "/admin/v1/plugins", 200],
  ["admin_policy", "listAdminPolicies", "GET", "/admin/v1/policies", 200],
  ["admin_provider", "listAdminProviders", "GET", "/admin/v1/providers", 200],
  ["admin_request_log", "listAdminRequestLogs", "GET", "/admin/v1/request-logs", 200],
  ["admin_tool", "listAdminTools", "GET", "/admin/v1/tools", 200],
  ["admin_virtual_key", "listVirtualKeys", "GET", "/admin/v1/virtual-keys", 200],
  ["agent_run", "listAdminAgentRuns", "GET", "/admin/v1/agent-runs", 200],
  ["billing", "listAdminBillingEventsCompat", "GET", "/admin/v1/billing-events", 200],
  ["guardrail_policy", "listGuardrailPolicyRevisions", "GET", "/admin/v1/guardrail-policies", 200],
  ["payment_attempt", "listPaymentAttempts", "GET", "/admin/v1/payment-attempts", 200],
  ["plans", "listPlans", "GET", "/admin/v1/plans", 200],
  ["prompt", "listAdminPromptTemplates", "GET", "/admin/v1/prompt-templates", 200],
  ["quota_policy", "listQuotaPolicies", "GET", "/admin/v1/quota-policies", 200],
  ["rbac", "listPermissions", "GET", "/admin/v1/permissions", 200],
  ["self_hosted_worker", "listAdminSelfHostedWorkers", "GET", "/admin/v1/self-hosted-workers", 200],
  [
    "semantic_cache_policy",
    "listSemanticCachePolicies",
    "GET",
    "/admin/v1/semantic-cache-policies",
    200,
  ],
  ["site_domain", "listSiteDomains", "GET", "/admin/v1/site-domains", 200],
  ["skill", "listAdminSkillPackages", "GET", "/admin/v1/skill-packages", 200],
  ["tenant_hierarchy", "listAdminTenants", "GET", "/admin/v1/tenants", 200],
  ["wallets", "listWallets", "GET", "/admin/v1/wallets", 200],
  ["x402_spend_policy", "listX402SpendPolicies", "GET", "/admin/v1/x402-spend-policies", 200],
];

describe("every contract GROUP is reachable on the deployed Worker", () => {
  it("covers all 32 owned groups — a new group cannot slip past this table", () => {
    expect(new Set(GROUP_PROBES.map(([group]) => group))).toEqual(new Set(CONTROL_PLANE_GROUPS));
    expect(GROUP_PROBES).toHaveLength(CONTROL_PLANE_GROUPS.length);
  });

  it("states each probe in the contract's own terms", () => {
    // The probe table cannot drift from the contract: a renamed operation, a
    // moved path or a regrouped route breaks this before the fetch below.
    for (const [group, operationId, method, path] of GROUP_PROBES) {
      const operation = operationById(operationId);
      expect(operation, operationId).toBeDefined();
      expect(operation?.group, operationId).toBe(group);
      expect(operation?.method, operationId).toBe(method);
      expect(operation?.path, operationId).toBe(path);
    }
  });

  it("serves a representative operation from each group", async () => {
    for (const [group, operationId, method, path, status] of GROUP_PROBES) {
      const response = await SELF.fetch(`${BASE}${path}`, probeInit(method, operatorKey.secret));
      const error = await envelope(response);
      expect(isRouterMiss(response.status, error), `${group}/${operationId} is not mounted`).toBe(
        false,
      );
      expect(response.status, `${group}/${operationId} ${method} ${path}`).toBe(status);
    }
  });
});

describe("CONTROL: a path this Worker does NOT own really is a 404 here", () => {
  // Without these, "not 404" above would prove nothing: it has to be possible
  // to get a 404 from this Worker with the very same credential.
  it("404s contract operations that ROUTE-MAP assigns to apps/gateway", async () => {
    for (const [operationId, method, path] of [
      ["listModels", "GET", "/v1/models"],
      ["createChatCompletion", "POST", "/v1/chat/completions"],
      ["listAssets", "GET", "/v1/assets"],
    ] as const) {
      // These ARE contract operations — just not this app's.
      expect(operationById(operationId), operationId).toBeDefined();
      expect(controlPlaneOperationIds()).not.toContain(operationId);

      const response = await SELF.fetch(`${BASE}${path}`, probeInit(method, operatorKey.secret));
      const error = await envelope(response);
      expect(response.status, path).toBe(404);
      expect(isRouterMiss(response.status, error), path).toBe(true);
    }
  });

  it("404s an undocumented sibling under this app's OWN prefix", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/plans-that-do-not-exist`,
      probeInit("GET", operatorKey.secret),
    );
    expect(response.status).toBe(404);
    expect(isRouterMiss(response.status, await envelope(response))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Auth invariants — asserted across the WHOLE surface, not one spot check
// ---------------------------------------------------------------------------

describe("the guard is universal: it holds on EVERY group, not on one path", () => {
  it("a suspended native key is 401 invalid_api_key on every group — never 403", async () => {
    // ROUTE-MAP invariant 6. A per-route guard would let one group drift into
    // 403 (disclosing that the key exists); the table-driven guard cannot.
    const wrong: string[] = [];
    for (const [group, , method, path] of GROUP_PROBES) {
      const suspended = await SELF.fetch(`${BASE}${path}`, probeInit(method, "tenant-suspended"));
      const unknown = await SELF.fetch(`${BASE}${path}`, probeInit(method, "no-such-key"));
      const suspendedError = await envelope(suspended);
      const unknownError = await envelope(unknown);
      if (
        suspended.status !== 401 ||
        suspendedError.code !== "invalid_api_key" ||
        // Byte-identical to a typo: no key state is disclosed.
        suspended.status !== unknown.status ||
        suspendedError.code !== unknownError.code
      ) {
        wrong.push(`${group}: ${suspended.status} ${suspendedError.code}`);
      }
    }
    expect(wrong, `suspended-key leaks on: ${wrong.join(", ")}`).toEqual([]);
  });

  it("an under-scoped key is 403 scope_denied on every group — never 401", async () => {
    const wrong: string[] = [];
    for (const [group, , method, path] of GROUP_PROBES) {
      const response = await SELF.fetch(`${BASE}${path}`, probeInit(method, "tenant-readonly"));
      const error = await envelope(response);
      if (response.status !== 403 || error.code !== "scope_denied") {
        wrong.push(`${group}: ${response.status} ${error.code}`);
      }
    }
    expect(wrong, `wrong denial for an under-scoped key on: ${wrong.join(", ")}`).toEqual([]);
  });

  it("no group is reachable with NO credential at all", async () => {
    const wrong: string[] = [];
    for (const [group, , method, path] of GROUP_PROBES) {
      const response = await SELF.fetch(`${BASE}${path}`, {
        method,
        headers: { "content-type": "application/json" },
        ...(method === "GET" ? {} : { body: "{}" }),
      });
      const error = await envelope(response);
      if (response.status !== 401 || error.code !== "missing_api_key") {
        wrong.push(`${group}: ${response.status} ${error.code}`);
      }
    }
    expect(wrong, `unguarded group(s): ${wrong.join(", ")}`).toEqual([]);
  });
});

describe("GET /metrics: internal visibility, still bearer-guarded (invariant 5)", () => {
  it("is declared internal-but-bearer in the contract and is mounted", () => {
    const metrics = operationById("getMetrics");
    expect(metrics?.visibility).toBe("internal");
    expect(metrics?.auth.kind).toBe("bearer");
    expect(metrics?.auth.scope).toBe("admin.read");
    expect(HONO_KEYS.has("GET /metrics")).toBe(true);
  });

  it("refuses an unauthenticated scrape and an under-scoped one", async () => {
    const anonymous = await SELF.fetch(`${BASE}/metrics`);
    expect(anonymous.status).toBe(401);
    expect((await envelope(anonymous)).code).toBe("missing_api_key");

    const underScoped = await SELF.fetch(`${BASE}/metrics`, probeInit("GET", "tenant-readonly"));
    expect(underScoped.status).toBe(403);
    expect((await envelope(underScoped)).code).toBe("scope_denied");
  });

  it("serves the Prometheus exposition to an admin.read scrape", async () => {
    const response = await SELF.fetch(`${BASE}/metrics`, probeInit("GET", "tenant-metrics"));
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("ferrogate_control_plane_up 1");
  });
});

describe("/control/v1 → /admin/v1 canonicalization holds for the WHOLE surface", () => {
  it("folds the alias onto the same operation for every versioned group probe", async () => {
    // Invariant 7. The fold happens at the fetch boundary, so this also proves
    // `export default` is the wrapper and not the bare Hono app.
    const drifted: string[] = [];
    for (const [group, , method, path] of GROUP_PROBES) {
      if (!path.startsWith("/admin/v1")) continue;
      const aliasPath = `/control/v1${path.slice("/admin/v1".length)}`;
      const canonical = await SELF.fetch(`${BASE}${path}`, probeInit(method, operatorKey.secret));
      const alias = await SELF.fetch(`${BASE}${aliasPath}`, probeInit(method, operatorKey.secret));
      if (alias.status !== canonical.status) {
        drifted.push(`${group}: ${alias.status} vs ${canonical.status}`);
        continue;
      }
      // Never a redirect — an alias is the SAME operation, not another location.
      if (alias.redirected || alias.headers.get("location") !== null) {
        drifted.push(`${group}: alias redirected`);
      }
    }
    expect(drifted, `alias drift on: ${drifted.join(", ")}`).toEqual([]);
  });

  it("applies the SAME guard through the alias", async () => {
    const response = await SELF.fetch(`${BASE}/control/v1/plans`);
    expect(response.status).toBe(401);
    expect((await envelope(response)).code).toBe("missing_api_key");
  });

  it("does not capture a path that merely shares the alias prefix", async () => {
    const response = await SELF.fetch(
      `${BASE}/control/v1x/plans`,
      probeInit("GET", operatorKey.secret),
    );
    expect(response.status).toBe(404);
    expect(isRouterMiss(response.status, await envelope(response))).toBe(true);
  });
});
