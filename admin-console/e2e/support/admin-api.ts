import type { Page, Route } from "@playwright/test";
import type { components } from "../../src/lib/api-types.generated";
import type { StoredSession } from "../../src/lib/session-storage";
import {
  adminOverview,
  adminStatus,
  overviewSectionUnavailable,
  providerHealth,
} from "../../src/test/fixtures/ops";

type AdminProject = components["schemas"]["AdminProject"];
type AdminTenantAccount = components["schemas"]["AdminTenantAccount"];
type AdminPermission = components["schemas"]["AdminPermission"];
type AdminRole = components["schemas"]["AdminRole"];
type AdminApiKey = components["schemas"]["AdminApiKey"];
type AdminWorkspace = components["schemas"]["AdminWorkspace"];
type McpServerStatus = components["schemas"]["McpServerStatus"];
type ToolApprovalRecord = components["schemas"]["ToolApprovalRecord"];
type RequestLog = components["schemas"]["RequestLog"];
type AdminUsageReportRow = components["schemas"]["AdminUsageReportRow"];
type AdminVirtualApiKey = components["schemas"]["AdminVirtualApiKey"];
type AdminSelfHostedWorkerRecord = components["schemas"]["AdminSelfHostedWorkerRecord"];
type TokenMeteringEvent = components["schemas"]["TokenMeteringEvent"];

interface AdminApiOptions {
  failPaths?: string[];
  /**
   * Return the control-plane overview with its `control_plane` section marked
   * unavailable (a 200 with a failed SECTION, not a transport error) so the
   * cockpit's partial-failure-not-zero path can be exercised in the browser.
   */
  partialOverview?: boolean;
}

const ADMIN_API_PATTERN = "http://localhost:8080/admin/v1/**";
const SESSION_KEY = "ferrogate-admin-session";

const projects: AdminProject[] = Array.from({ length: 52 }, (_, index) => {
  const sequence = String(index + 1).padStart(2, "0");
  return {
    id:
      index === 0
        ? "project_prod_payments_01HZZZZZZZZZZZZZZZZZZZZZZZ"
        : `project_${sequence}_cross_region_01HZZZZZZZZZZZZZZZZZZ`,
    tenant_id: "tenant_enterprise_acme_01HZZZZZZZZZZZZZZZZZZZZ",
    name:
      index === 0
        ? "Production payments routing with long operator-visible context"
        : `Project ${sequence} cross-region inference operations`,
    slug: index === 0 ? "production-payments-routing" : `project-${sequence}-cross-region-inference`,
    status: "active",
    created_at_unix: 1_720_000_000 + index,
    updated_at_unix: 1_720_086_400 + index,
  };
});

const tenantAccounts: AdminTenantAccount[] = Array.from({ length: 24 }, (_, index) => {
  const sequence = index + 1;
  return {
    id: `tenant-${sequence}`,
    name: `Tenant ${sequence} operations`,
    slug: `tenant-${sequence}`,
    status: "active",
    plan_id: "enterprise",
    created_at_unix: 1_720_000_000 + index,
    updated_at_unix: 1_720_086_400 + index,
  };
});

const permissions: AdminPermission[] = [
  {
    id: "permission-admin-read",
    key: "admin.read",
    name: "Read administration",
    description: "Read control-plane resources",
    created_at_unix: 1_720_000_000,
    updated_at_unix: 1_720_086_400,
  },
  {
    id: "permission-admin-write",
    key: "admin.write",
    name: "Write administration",
    description: "Change control-plane resources",
    created_at_unix: 1_720_000_001,
    updated_at_unix: 1_720_086_401,
  },
];

const roles: AdminRole[] = [];

const mcpServers: McpServerStatus[] = [
  {
    name: "incident-tools",
    transport: "streamable_http",
    connected: true,
    health: "ok",
    tools: 6,
    reconnect_attempts: 0,
    last_error: null,
    last_connected_at_unix: 1_720_086_400,
    next_reconnect_backoff_secs: 0,
  },
];

const apiKeys: AdminApiKey[] = [
  {
    id: "gateway-key-production-automation-01HZZZZZZZZZZZZZZZZZZ",
    name: "Production automation gateway key",
    enabled: true,
    key_source: "env",
    scopes: ["admin.read", "gateway.invoke", "billing.read"],
    allowed_models: [],
    denied_models: [],
    allowed_providers: [],
    denied_providers: [],
    log_bodies: false,
  },
];
const workspaces: AdminWorkspace[] = [];

const virtualKeys: AdminVirtualApiKey[] = [
  {
    id: "virtual-key-production-automation-01HZZZZZZZZZZZZZZZ",
    workspace_id: "workspace-enterprise-production-01HZZZZZZZZZZZZZZ",
    tenant_id: "tenant-e2e",
    project_id: "project-e2e",
    name: "Production deployment automation",
    key_prefix: "fg-live-production",
    last4: "9xyz",
    enabled: true,
    scopes: ["admin.read", "gateway.invoke"],
    allowed_models: [],
    allowed_providers: [],
    monthly_token_budget: 2_000_000,
    request_limit_per_minute: 600,
    created_at_unix: 1_752_000_000,
    updated_at_unix: 1_752_000_100,
    rotated_at_unix: null,
    expires_at_unix: null,
    revoked_at_unix: null,
  },
];

const workerRecords: AdminSelfHostedWorkerRecord[] = [
  {
    id: "self-hosted-worker-enterprise-edge-01HZZZZZZZZZZZZZZZZ",
    tenant: { organization_id: "organization-enterprise-acme-01HZZZZZZZZZZ" },
    workspace_id: "workspace-enterprise-production-01HZZZZZZZZZZZZZZ",
    worker_name: "enterprise-edge-runner-us-east-production",
    status: "active",
    identity_fingerprint: "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
    identity_expires_at_unix: null,
    orchestration_enabled: true,
    registered_at_unix: 1_752_000_000,
    last_seen_at_unix: 1_752_000_200,
    trust_level: "reported_by_self_hosted_worker",
    latest_heartbeat: null,
    telemetry_event_count: 142,
    artifact_count: 8,
    checkpoint_count: 17,
    latest_event_at_unix: 1_752_000_200,
    latest_artifact_at_unix: 1_752_000_190,
    latest_checkpoint_at_unix: 1_752_000_195,
    stale: false,
    stale_after_unix: 1_752_000_500,
    stale_threshold_secs: 300,
  },
];

const billingEvents: TokenMeteringEvent[] = [
  {
    request_id: "request-billing-enterprise-01HZZZZZZZZZZZZZZZZZZZZZZ",
    tenant: { organization_id: "organization-enterprise-acme-01HZZZZZZZZZZ" },
    logical_model: "production-reasoning-model-with-long-name",
    provider: "openai",
    provider_model: "gpt-4.1-2026-07-01",
    usage: { prompt_tokens: 12_000, completion_tokens: 4_000, total_tokens: 16_000 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1_752_000_200,
  },
];

const toolApprovals: ToolApprovalRecord[] = [
  {
    id: "approval-e2e",
    request_id: "req-approval-e2e",
    trace_id: "trace-approval-e2e",
    tenant: { project_id: "project-e2e", api_key_id: "key-e2e" },
    actor_api_key_id: "key-e2e",
    tool_name: "deploy_production",
    server_name: "release-tools",
    route: "/v1/tools/call",
    approval_policy: "always",
    approval_timeout_secs: 300,
    fingerprint: "sha256:invocation-e2e",
    arguments_summary: "environment=production",
    risk_reason: "production mutation",
    status: "pending",
    reviewer_api_key_id: null,
    reviewer_authority: null,
    terminal_reason: null,
    requested_at_unix: 1_752_000_000,
    expires_at_unix: 1_752_000_300,
    decided_at_unix: null,
  },
];

const requestLogs: RequestLog[] = [
  {
    request_id: "req-dashboard-success",
    provider: "openai",
    logical_model: "gpt-4.1-mini",
    status_code: 200,
    started_at_unix: 1_752_000_100,
  },
  {
    request_id: "req-dashboard-failed",
    provider: "anthropic",
    logical_model: "claude-sonnet-4",
    status_code: 503,
    error_code: "provider_unavailable",
    started_at_unix: 1_752_000_200,
  },
];

const usageReports: AdminUsageReportRow[] = [
  {
    period_month: "2026-07",
    scope_type: "tenant",
    scope_id: "tenant-e2e",
    prompt_tokens: 90_000,
    completion_tokens: 60_000,
    total_tokens: 150_000,
    cost_usd: 12.3456,
    request_count: 860,
    error_count: 4,
  },
];

const session: StoredSession = {
  accessToken: "e2e-access-token",
  refreshToken: "e2e-refresh-token",
  expiresAt: Date.now() + 60 * 60 * 1000,
  gatewayApiKey: "e2e-gateway-key",
  user: {
    id: "user-e2e",
    email: "operator@example.com",
    display_name: "E2E Operator",
  },
  tenant: {
    id: "tenant-e2e",
    name: "Acme Operations",
    role: "owner",
  },
};

async function handleAdminRequest(route: Route, options: AdminApiOptions): Promise<void> {
  const request = route.request();
  const url = new URL(request.url());

  if (options.failPaths?.includes(url.pathname)) {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "e2e_forced_failure", message: "forced browser-contract failure" },
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/overview") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        adminOverview(
          options.partialOverview
            ? {
                control_plane: overviewSectionUnavailable(
                  "control-plane store unreachable (browser contract)",
                ),
              }
            : {},
        ),
      ),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/status") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(adminStatus()),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/provider-health") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: [
          providerHealth(),
          providerHealth({
            name: "anthropic",
            kind: "anthropic",
            status: "error",
            reachable: false,
            circuit_open: true,
            consecutive_failures: 3,
            error: "connect timeout",
          }),
        ],
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/tool-approvals") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: toolApprovals }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/request-logs") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: requestLogs,
        total: requestLogs.length,
        offset: 0,
        limit: 50,
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/usage-reports") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: usageReports }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/projects") {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 25);
    const search = (url.searchParams.get("search") ?? "").toLowerCase();
    const tenantId = url.searchParams.get("tenant_id");
    const filtered = projects.filter(
      (project) =>
        (!tenantId || project.tenant_id === tenantId) &&
        `${project.id} ${project.name} ${project.slug}`.toLowerCase().includes(search),
    );
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: filtered.slice(offset, offset + limit),
        total: filtered.length,
        offset,
        limit,
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname.startsWith("/admin/v1/projects/")) {
    const projectId = decodeURIComponent(url.pathname.slice("/admin/v1/projects/".length));
    const project = projects.find((item) => item.id === projectId);
    await route.fulfill({
      status: project ? 200 : 404,
      contentType: "application/json",
      body: JSON.stringify(
        project
          ? { object: "project", project }
          : { error: { code: "project_not_found", message: "project not found" } },
      ),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/tenant-accounts") {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? tenantAccounts.length);
    const search = (url.searchParams.get("search") ?? "").toLowerCase();
    const filtered = tenantAccounts.filter((tenant) =>
      `${tenant.id} ${tenant.name} ${tenant.slug}`.toLowerCase().includes(search),
    );
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: filtered.slice(offset, offset + limit),
        total: filtered.length,
        offset,
        limit,
      }),
    });
    return;
  }

  if (
    request.method() === "GET" &&
    url.pathname.startsWith("/admin/v1/tenant-accounts/")
  ) {
    const tenantId = decodeURIComponent(
      url.pathname.slice("/admin/v1/tenant-accounts/".length),
    );
    const tenant = tenantAccounts.find((item) => item.id === tenantId);
    await route.fulfill({
      status: tenant ? 200 : 404,
      contentType: "application/json",
      body: JSON.stringify(
        tenant
          ? { object: "tenant", tenant }
          : { error: { code: "tenant_not_found", message: "tenant not found" } },
      ),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/permissions") {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? permissions.length);
    const search = (url.searchParams.get("search") ?? "").toLowerCase();
    const filtered = permissions.filter((permission) =>
      `${permission.id} ${permission.key} ${permission.name} ${permission.description}`
        .toLowerCase()
        .includes(search),
    );
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: filtered.slice(offset, offset + limit),
        total: filtered.length,
        offset,
        limit,
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/roles") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: roles }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/mcp-servers") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: mcpServers,
        total: mcpServers.length,
        offset: 0,
        limit: 200,
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/api-keys") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: apiKeys }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/virtual-keys") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: virtualKeys }),
    });
    return;
  }

  if (
    request.method() === "GET" &&
    url.pathname === "/admin/v1/self-hosted-worker-records"
  ) {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: workerRecords,
        total: workerRecords.length,
        offset: 0,
        limit: 25,
      }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/billing-events") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: billingEvents,
        total: billingEvents.length,
        offset: 0,
        limit: 25,
      }),
    });
    return;
  }

  if (
    request.method() === "GET" &&
    (url.pathname === "/admin/v1/guardrail-policies" ||
      url.pathname === "/admin/v1/wallets")
  ) {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ object: "list", data: [] }),
    });
    return;
  }

  if (request.method() === "GET" && url.pathname === "/admin/v1/workspaces") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: workspaces,
        total: workspaces.length,
        offset: 0,
        limit: 200,
      }),
    });
    return;
  }

  await route.fulfill({
    status: 501,
    contentType: "application/json",
    body: JSON.stringify({
      error: {
        code: "unmocked_e2e_route",
        message: `${request.method()} ${url.pathname} is not mocked by the browser contract`,
      },
    }),
  });
}

export async function installAuthenticatedAdminApi(
  page: Page,
  options: AdminApiOptions = {},
): Promise<void> {
  await page.addInitScript(
    ({ key, value }) => localStorage.setItem(key, JSON.stringify(value)),
    { key: SESSION_KEY, value: session },
  );
  await page.route(ADMIN_API_PATTERN, (route) => handleAdminRequest(route, options));
}
