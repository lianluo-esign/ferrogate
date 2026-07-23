import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import ManagedWorkerSessionsPage from "@/pages/managed-worker-sessions";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type Session = AdminSchema<"AdminManagedWorkerSession">;

function session(overrides: Partial<Session> = {}): Session {
  return {
    id: "mws-1",
    run_id: "run-1",
    tenant: { organization_id: "org-acme" },
    workspace_id: "ws-1",
    worker_template_id: "tmpl-1",
    agent_worker_instance_id: "inst-1",
    status: "completed",
    isolation_backend_kind: "firecracker_microvm",
    microvm_id: "vm-1",
    capability_envelope_id: "cap-1",
    requested_at_unix: 100,
    started_at_unix: 110,
    completed_at_unix: 200,
    cleanup_completed_at_unix: 210,
    lifecycle_events: [
      {
        id: "lce-1",
        session_id: "mws-1",
        run_id: "run-1",
        status: "running",
        action: "exec_or_attach",
        outcome: "attached",
        occurred_at_unix: 110,
        agent_worker_instance_id: "inst-1",
      },
      {
        id: "lce-2",
        session_id: "mws-1",
        run_id: "run-1",
        status: "cleaned_up",
        action: "cleanup",
        outcome: "released",
        occurred_at_unix: 210,
        agent_worker_instance_id: "inst-1",
      },
    ],
    ...overrides,
  };
}

function mockSessions(sessions: Session[]): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/managed-worker-sessions"), () =>
      HttpResponse.json({
        object: "list",
        data: sessions,
        total: sessions.length,
        offset: 0,
        limit: 50,
      }),
    ),
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <ManagedWorkerSessionsPage />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("ManagedWorkerSessionsPage", () => {
  it("lists managed worker sessions with status and isolation backend", async () => {
    mockSessions([session()]);
    renderPage();

    expect(await screen.findByText("mws-1")).toBeInTheDocument();
    const row = screen.getByText("mws-1").closest("tr")!;
    expect(within(row).getByText("completed")).toBeInTheDocument();
    expect(within(row).getByText("firecracker_microvm")).toBeInTheDocument();
  });

  it("shows the empty state when no sessions exist", async () => {
    mockSessions([]);
    renderPage();

    expect(
      await screen.findByText("No managed worker sessions recorded yet."),
    ).toBeInTheDocument();
  });

  it("opens a session's lifecycle event detail", async () => {
    mockSessions([session()]);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("mws-1");
    await user.click(screen.getByRole("button", { name: "Details" }));

    expect(await screen.findByText("Session mws-1")).toBeInTheDocument();
    expect(screen.getByTestId("lifecycle-event-lce-1")).toBeInTheDocument();
    const cleanup = screen.getByTestId("lifecycle-event-lce-2");
    expect(within(cleanup).getByText("cleanup")).toBeInTheDocument();
    expect(within(cleanup).getByText("released")).toBeInTheDocument();
  });
});
