import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import SelfHostedRunsPage from "@/pages/self-hosted-runs";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

const PARENT_FP =
  "sha256:parentparentparentparentparentparentparentparentparentparent0000";

function timeline() {
  return {
    object: "self_hosted_run_timeline",
    run_id: "run-9",
    session_ids: ["sess-9"],
    worker_ids: ["shw-1"],
    trust_level: "reported_by_self_hosted_worker",
    reported_event_count: 2,
    lifecycle_event_count: 1,
    first_seen_unix: 100,
    last_seen_unix: 200,
    latest_lifecycle_state: "completed",
    events: [
      {
        id: "rev-1",
        worker_id: "shw-1",
        session_id: "sess-9",
        run_id: "run-9",
        kind: "lifecycle",
        trust_level: "reported_by_self_hosted_worker",
        occurred_at_unix: 100,
        ingested_at_unix: 101,
        event_json: JSON.stringify({
          request_id: "req-run-9",
          trace_id: "trace-run-9",
          agent_run_id: "agent-run-9",
          parent_action_fingerprint: PARENT_FP,
        }),
      },
      {
        id: "rev-2",
        worker_id: "shw-1",
        session_id: "sess-9",
        run_id: "run-9",
        kind: "tool_call",
        trust_level: "reported_by_self_hosted_worker",
        occurred_at_unix: 150,
        ingested_at_unix: 151,
        event_json: "not valid json {",
      },
    ],
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <SelfHostedRunsPage />
        </QueryClientProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("SelfHostedRunsPage", () => {
  it("prompts for a run id before any lookup", () => {
    renderPage();
    expect(
      screen.getByText(/Enter a run id reported by a self-hosted worker/),
    ).toBeInTheDocument();
  });

  it("surfaces the correlation triple and parent action fingerprint from event_json", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/self-hosted-runs/run-9"), () =>
        HttpResponse.json(timeline()),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Run id"), "run-9");
    await user.click(screen.getByRole("button", { name: "Inspect" }));

    expect(await screen.findByText("Run run-9")).toBeInTheDocument();

    // aggregated correlation triple (#305) + parent fingerprint (#307) header.
    // req/trace also appear on the rev-1 event row, so match all occurrences.
    expect(screen.getAllByText("req-run-9").length).toBeGreaterThan(0);
    expect(screen.getAllByText("trace-run-9").length).toBeGreaterThan(0);
    expect(screen.getByText("agent-run-9")).toBeInTheDocument();
    // parent action fingerprint present (full value kept in the title attr)
    expect(screen.getAllByTitle(PARENT_FP).length).toBeGreaterThan(0);

    // per-event rows: the malformed-json event still renders (no crash)
    expect(screen.getByTestId("run-event-rev-1")).toBeInTheDocument();
    const secondRow = screen.getByTestId("run-event-rev-2");
    expect(within(secondRow).getByText("tool_call")).toBeInTheDocument();
  });

  it("shows an error when the run lookup fails", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/self-hosted-runs/missing"), () =>
        HttpResponse.json(
          { error: { code: "not_found", message: "no such run" } },
          { status: 404 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Run id"), "missing");
    await user.click(screen.getByRole("button", { name: "Inspect" }));

    expect(await screen.findByText(/Failed to load run missing/)).toBeInTheDocument();
  });
});
