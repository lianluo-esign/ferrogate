import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import ToolSessionsPage from "@/pages/tool-sessions";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type StoredAuditEvent = AdminSchema<"StoredAuditEvent">;

function event(overrides: Partial<StoredAuditEvent> = {}): StoredAuditEvent {
  return {
    id: "evt-1",
    request_id: "req-1",
    trace_id: null,
    agent_run_id: null,
    cluster_id: null,
    node_id: null,
    actor_api_key_id: null,
    tenant: { organization_id: "org-acme" },
    action: "tool.execute",
    target: "github-mcp/search_repo",
    outcome: "allow",
    message: "tool executed",
    occurred_at_unix: 1000,
    ...overrides,
  } as StoredAuditEvent;
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <ToolSessionsPage />
        </QueryClientProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("ToolSessionsPage", () => {
  it("inspects a session and renders its audit timeline", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/tool-sessions/sess-1"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            event(),
            event({ id: "evt-2", action: "tool.deny", outcome: "deny", message: "denied" }),
          ],
          total: 2,
          offset: 0,
          limit: 50,
        }),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Session id"), "sess-1");
    await user.click(screen.getByRole("button", { name: "Inspect" }));

    const row = await screen.findByTestId("session-event-evt-1");
    expect(within(row).getByText("tool.execute")).toBeInTheDocument();
    expect(within(row).getByText("github-mcp/search_repo")).toBeInTheDocument();
    expect(within(row).getByText("allow")).toBeInTheDocument();

    const denyRow = screen.getByTestId("session-event-evt-2");
    expect(within(denyRow).getByText("deny")).toBeInTheDocument();
  });

  it("shows an empty state for a session with no events", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/tool-sessions/sess-empty"), () =>
        HttpResponse.json({ object: "list", data: [], total: 0, offset: 0, limit: 50 }),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Session id"), "sess-empty");
    await user.click(screen.getByRole("button", { name: "Inspect" }));

    expect(await screen.findByText("No audit events for this session.")).toBeInTheDocument();
  });
});
