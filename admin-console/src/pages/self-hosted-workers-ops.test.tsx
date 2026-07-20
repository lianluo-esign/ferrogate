import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import SelfHostedWorkersOpsPage from "@/pages/self-hosted-workers-ops";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, mockAdminError, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type WorkerRecord = AdminSchema<"AdminSelfHostedWorkerRecord">;

function worker(overrides: Partial<WorkerRecord> = {}): WorkerRecord {
  return {
    id: "shw-1",
    tenant: { organization_id: "org-acme" },
    workspace_id: "ws-1",
    worker_name: "edge-runner-01",
    status: "active",
    identity_fingerprint: "sha256:aaaabbbbccccddddeeeeffff0000",
    identity_expires_at_unix: null,
    orchestration_enabled: true,
    registered_at_unix: 100,
    last_seen_at_unix: 200,
    trust_level: "reported_by_self_hosted_worker",
    latest_heartbeat: null,
    telemetry_event_count: 4,
    artifact_count: 2,
    checkpoint_count: 3,
    latest_event_at_unix: 200,
    latest_artifact_at_unix: 190,
    latest_checkpoint_at_unix: 195,
    stale: false,
    stale_after_unix: 500,
    stale_threshold_secs: 300,
    ...overrides,
  };
}

function mockRecords(records: WorkerRecord[]): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/self-hosted-worker-records"), () =>
      HttpResponse.json({
        object: "list",
        data: records,
        total: records.length,
        offset: 0,
        limit: 50,
      }),
    ),
  );
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/app/workers/self-hosted"]}>
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <Routes>
            <Route
              path="/app/workers/self-hosted"
              element={<SelfHostedWorkersOpsPage />}
            />
          </Routes>
        </QueryClientProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("SelfHostedWorkersOpsPage", () => {
  it("renders the worker registry with status and counts", async () => {
    mockRecords([worker()]);
    renderPage();

    expect(await screen.findByText("edge-runner-01")).toBeInTheDocument();
    const row = screen.getByText("edge-runner-01").closest("tr")!;
    expect(within(row).getByText("active")).toBeInTheDocument();
    // telemetry / checkpoint / artifact counts
    expect(within(row).getByText("4")).toBeInTheDocument();
    expect(within(row).getByText("3")).toBeInTheDocument();
    expect(within(row).getByText("2")).toBeInTheDocument();
  });

  it("shows the empty state when no workers are registered", async () => {
    mockRecords([]);
    renderPage();

    expect(
      await screen.findByText("No self-hosted workers registered yet."),
    ).toBeInTheDocument();
  });

  it("surfaces a list load error", async () => {
    mockAdminError(
      "get",
      "/admin/v1/self-hosted-worker-records",
      500,
      "boom",
      "storage unavailable",
    );
    renderPage();

    expect(
      await screen.findByText(/Failed to load self-hosted workers/),
    ).toBeInTheDocument();
  });

  it("registers a worker and reveals the identity fingerprint exactly once", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    mockRecords([]);

    let captured: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/self-hosted-workers"), async ({ request }) => {
        captured = await request.json();
        return HttpResponse.json(
          {
            object: "self_hosted_worker",
            worker: worker({ identity_fingerprint: "sha256:rotated-secret-value" }),
          },
          { status: 201 },
        );
      }),
    );

    renderPage();
    await screen.findByText("No self-hosted workers registered yet.");

    await user.click(screen.getByRole("button", { name: "Register worker" }));
    await user.type(screen.getByLabelText("Worker name"), "edge-runner-01");
    await user.type(screen.getByLabelText("Workspace id"), "ws-1");
    await user.type(
      screen.getByLabelText("Identity fingerprint"),
      "sha256:supplied-fp",
    );
    await user.click(screen.getByRole("button", { name: "Register" }));

    // secret-shown-once dialog
    expect(await screen.findByText("Worker identity registered")).toBeInTheDocument();
    const revealed = screen.getByTestId("revealed-credential");
    expect(revealed).toHaveTextContent("sha256:rotated-secret-value");
    expect(
      screen.getByText("This value will not be shown again. Store it somewhere safe."),
    ).toBeInTheDocument();

    // the request carried the typed identity fingerprint
    expect(captured).toMatchObject({
      worker_name: "edge-runner-01",
      workspace_id: "ws-1",
      identity_fingerprint: "sha256:supplied-fp",
    });

    // copy button copies the revealed value
    await user.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("sha256:rotated-secret-value"),
    );
  });

  it("blocks registration when required fields are missing", async () => {
    const user = userEvent.setup();
    mockRecords([]);
    renderPage();
    await screen.findByText("No self-hosted workers registered yet.");

    await user.click(screen.getByRole("button", { name: "Register worker" }));
    await user.click(screen.getByRole("button", { name: "Register" }));

    expect(
      await screen.findByText(
        "Worker name, workspace id, and identity fingerprint are required.",
      ),
    ).toBeInTheDocument();
  });
});
