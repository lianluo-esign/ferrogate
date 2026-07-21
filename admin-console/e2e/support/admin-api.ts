import type { Page, Route } from "@playwright/test";
import type { components } from "../../src/lib/api-types.generated";
import type { StoredSession } from "../../src/lib/session-storage";

type AdminProject = components["schemas"]["AdminProject"];
type AdminApiKey = components["schemas"]["AdminApiKey"];
type AdminWorkspace = components["schemas"]["AdminWorkspace"];
type McpServerStatus = components["schemas"]["McpServerStatus"];

const ADMIN_API_PATTERN = "http://localhost:8080/admin/v1/**";
const SESSION_KEY = "ferrogate-admin-session";

const projects: AdminProject[] = [
  {
    id: "project_prod_payments_01HZZZZZZZZZZZZZZZZZZZZZZZ",
    tenant_id: "tenant_enterprise_acme_01HZZZZZZZZZZZZZZZZZZZZ",
    name: "Production payments routing",
    slug: "production-payments-routing",
    status: "active",
    created_at_unix: 1_720_000_000,
    updated_at_unix: 1_720_086_400,
  },
];

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

const apiKeys: AdminApiKey[] = [];
const workspaces: AdminWorkspace[] = [];

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

async function handleAdminRequest(route: Route): Promise<void> {
  const request = route.request();
  const url = new URL(request.url());

  if (request.method() === "GET" && url.pathname === "/admin/v1/projects") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        object: "list",
        data: projects,
        total: projects.length,
        offset: 0,
        limit: 200,
      }),
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

export async function installAuthenticatedAdminApi(page: Page): Promise<void> {
  await page.addInitScript(
    ({ key, value }) => localStorage.setItem(key, JSON.stringify(value)),
    { key: SESSION_KEY, value: session },
  );
  await page.route(ADMIN_API_PATTERN, handleAdminRequest);
}
