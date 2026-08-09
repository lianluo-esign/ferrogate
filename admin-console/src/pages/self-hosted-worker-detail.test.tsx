import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";
import SelfHostedWorkerDetailPage from "@/pages/self-hosted-worker-detail";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

type WorkerRecord = AdminSchema<"AdminSelfHostedWorkerRecord">;

function worker(overrides: Partial<WorkerRecord> = {}): WorkerRecord {
  return {
    id: "shw-1",
    tenant: { organization_id: "org-acme" },
    workspace_id: "ws-1",
    worker_name: "edge-runner-01",
    status: "active",
    identity_fingerprint: "sha256:original-fp",
    identity_expires_at_unix: null,
    orchestration_enabled: true,
    registered_at_unix: 100,
    last_seen_at_unix: 200,
    trust_level: "reported_by_self_hosted_worker",
    latest_heartbeat: {
      id: "hb-1",
      status: "healthy",
      reported_at_unix: 200,
      observed_at_unix: 201,
    },
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

function eventStream() {
  return {
    object: "self_hosted_worker_event_stream",
    worker_id: "shw-1",
    trust_level: "reported_by_self_hosted_worker",
    data: [
      {
        id: "ev-1",
        worker_id: "shw-1",
        session_id: "sess-1",
        run_id: "run-1",
        kind: "tool_call",
        trust_level: "reported_by_self_hosted_worker",
        occurred_at_unix: 150,
        ingested_at_unix: 151,
        event_json: JSON.stringify({ request_id: "req-shw-1", trace_id: "trace-shw-1" }),
      },
    ],
    total: 1,
    limit: 100,
    after_event_id: null,
    next_after_event_id: null,
  };
}

function mockWorker(record: WorkerRecord): void {
  server.use(
    http.get(gatewayUrl(`/admin/v1/self-hosted-workers/${record.id}`), () =>
      HttpResponse.json(record),
    ),
    http.get(gatewayUrl(`/admin/v1/self-hosted-workers/${record.id}/events`), () =>
      HttpResponse.json(eventStream()),
    ),
  );
}

function renderDetail(workerId: string) {
  return render(
    <MemoryRouter initialEntries={[`/app/workers/self-hosted/${workerId}`]}>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route
                path="/app/workers/self-hosted/:workerId"
                element={<SelfHostedWorkerDetailPage />}
              />
            </Routes>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("SelfHostedWorkerDetailPage", () => {
  it("renders overview, checkpoint/artifact counts, and reported events", async () => {
    mockWorker(worker());
    const user = userEvent.setup();
    renderDetail("shw-1");

    expect(await screen.findByRole("heading", { name: "edge-runner-01" })).toBeInTheDocument();

    // checkpoint + artifact count cards
    expect(screen.getByTestId("count-checkpoints")).toHaveTextContent("3");
    expect(screen.getByTestId("count-artifacts")).toHaveTextContent("2");

    // heartbeat surfaced on overview
    expect(screen.getByText(/healthy @/)).toBeInTheDocument();

    // events tab lists the reported event + its parsed correlation
    await user.click(screen.getByRole("tab", { name: /Events/ }));
    expect(await screen.findByTestId("worker-event-ev-1")).toBeInTheDocument();
    const eventRow = screen.getByTestId("worker-event-ev-1");
    expect(within(eventRow).getByText("tool_call")).toBeInTheDocument();
    expect(within(eventRow).getByText("req-shw-1")).toBeInTheDocument();
    expect(within(eventRow).getByText("trace-shw-1")).toBeInTheDocument();
  });

  it("rotates the identity and reveals the new fingerprint once", async () => {
    mockWorker(worker());
    server.use(
      http.post(gatewayUrl("/admin/v1/self-hosted-workers/shw-1/rotate"), () =>
        HttpResponse.json({
          object: "self_hosted_worker_identity_rotation",
          worker: worker({ identity_fingerprint: "sha256:new-rotated-fp" }),
          previous_identity_fingerprint: "sha256:original-fp",
          previous_identity_expires_at_unix: null,
          rotated_at_unix: 300,
        }),
      ),
    );
    const user = userEvent.setup();
    renderDetail("shw-1");

    await screen.findByRole("heading", { name: "edge-runner-01" });
    await user.click(screen.getByRole("button", { name: "Rotate identity" }));
    await user.type(screen.getByLabelText("New identity fingerprint"), "sha256:new-rotated-fp");
    await user.click(screen.getByRole("button", { name: "Rotate" }));

    expect(await screen.findByText("Identity rotated")).toBeInTheDocument();
    expect(screen.getByTestId("revealed-credential")).toHaveTextContent("sha256:new-rotated-fp");
    expect(
      screen.getByText("This value will not be shown again. Store it somewhere safe."),
    ).toBeInTheDocument();
  });
});
