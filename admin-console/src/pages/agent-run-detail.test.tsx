import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import AgentRunDetailPage, { type AgentRunTimeline } from "@/pages/agent-run-detail";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

const FULL_FINGERPRINT =
  "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";

/** Timeline fixture: lifecycle -> capability(allow) -> guardrail(deny) agent
 *  events plus one audit event, deliberately out of order across the two
 *  arrays so the merge-by-occurred_at is observable. */
function timeline(): AgentRunTimeline {
  const tenant = { organization_id: "org-acme" };
  return {
    object: "agent_run_timeline",
    id: "run-1",
    run: {
      id: "run-1",
      request_id: "req-run-1",
      trace_id: "trace-run-1",
      tenant,
      status: "completed",
      provider: "native_harness",
      turns_executed: 2,
      output_recorded: true,
      started_at_unix: 100,
      completed_at_unix: 130,
    },
    summary: {
      object: "agent_run",
      id: "run-1",
      tenant,
      status: "completed",
      request_count: 1,
      billing_event_count: 1,
      audit_event_count: 1,
      agent_event_count: 3,
      first_seen_unix: 100,
      last_seen_unix: 130,
    },
    agent_events: [
      {
        id: "ev-1",
        run_id: "run-1",
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        tenant,
        turn: 0,
        kind: "run_started",
        target: "agent",
        outcome: "started",
        message: "run started",
        occurred_at_unix: 100,
      },
      {
        id: "ev-2",
        run_id: "run-1",
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        tenant,
        turn: 1,
        kind: "capability.allowed",
        target: "tool:web_search",
        outcome: "allowed",
        message: "capability granted",
        occurred_at_unix: 110,
        action_fingerprint: FULL_FINGERPRINT,
        decision: "allow",
        decision_reason: "capability_allowed",
        output_disposition: "returned",
      },
      {
        id: "ev-3",
        run_id: "run-1",
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        tenant,
        turn: 2,
        kind: "guardrail.policy_block",
        target: "tool:shell",
        outcome: "blocked",
        message: "guardrail blocked shell",
        occurred_at_unix: 125,
        decision: "deny",
        decision_reason: "guardrail:fail:block:enforced",
        output_disposition: "withheld",
      },
    ],
    requests: [
      {
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        agent_run_id: "run-1",
        tenant,
        route: "/v1/agent-runs",
        provider: "native_harness",
        logical_model: "agent-default",
        status_code: 200,
        started_at_unix: 100,
        completed_at_unix: 130,
      },
    ],
    billing_events: [
      {
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        agent_run_id: "run-1",
        tenant,
        logical_model: "agent-default",
        provider: "openai",
        provider_model: "gpt-test",
        usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        usage_source: "provider_usage",
        status_code: 200,
        occurred_at_unix: 120,
      },
    ],
    audit_events: [
      {
        id: "aud-1",
        request_id: "req-run-1",
        trace_id: "trace-run-1",
        agent_run_id: "run-1",
        tenant,
        action: "tool.execute",
        target: "tool:web_search",
        outcome: "redacted",
        message: "output redacted by audit policy",
        occurred_at_unix: 115,
        decision: "degrade",
        decision_reason: "audit_redacted",
        output_disposition: "redacted",
      },
    ],
  };
}

function mockTimeline(fixture: AgentRunTimeline): void {
  server.use(
    http.get(gatewayUrl(`/admin/v1/agent-runs/${fixture.id}`), () =>
      HttpResponse.json(fixture),
    ),
  );
}

function renderDetail(runId: string) {
  return render(
    <MemoryRouter initialEntries={[`/app/agent-runs/${runId}`]}>
      <I18nProvider>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route path="/app/agent-runs/:runId" element={<AgentRunDetailPage />} />
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

describe("AgentRunDetailPage", () => {
  it("renders agent + audit events merged in occurred_at order with family badges", async () => {
    mockTimeline(timeline());

    renderDetail("run-1");

    expect(await screen.findByText("guardrail blocked shell")).toBeInTheDocument();
    // merge order: run_started(100) -> capability(110) -> audit(115) -> guardrail(125)
    const rowIds = screen
      .getAllByTestId(/^timeline-/)
      .map((row) => row.getAttribute("data-testid"));
    expect(rowIds).toEqual([
      "timeline-agent-ev-1",
      "timeline-agent-ev-2",
      "timeline-audit-aud-1",
      "timeline-agent-ev-3",
    ]);
    // family badges distinguish the event kinds
    expect(within(screen.getByTestId("timeline-agent-ev-2")).getByText("capability")).toBeInTheDocument();
    expect(within(screen.getByTestId("timeline-agent-ev-3")).getByText("guardrail")).toBeInTheDocument();
    expect(within(screen.getByTestId("timeline-audit-aud-1")).getByText("audit")).toBeInTheDocument();
    expect(within(screen.getByTestId("timeline-agent-ev-1")).getByText("lifecycle")).toBeInTheDocument();
  });

  it("renders the #304 structured columns: decision, reason, output disposition", async () => {
    mockTimeline(timeline());

    renderDetail("run-1");

    const capabilityRow = within(await screen.findByTestId("timeline-agent-ev-2"));
    expect(capabilityRow.getByText("allow")).toBeInTheDocument();
    expect(capabilityRow.getByText("capability_allowed")).toBeInTheDocument();
    expect(capabilityRow.getByText("returned")).toBeInTheDocument();

    const guardrailRow = within(screen.getByTestId("timeline-agent-ev-3"));
    expect(guardrailRow.getByText("deny")).toBeInTheDocument();
    expect(guardrailRow.getByText("guardrail:fail:block:enforced")).toBeInTheDocument();
    expect(guardrailRow.getByText("withheld")).toBeInTheDocument();

    const auditRow = within(screen.getByTestId("timeline-audit-aud-1"));
    expect(auditRow.getByText("degrade")).toBeInTheDocument();
    expect(auditRow.getByText("audit_redacted")).toBeInTheDocument();
  });

  it("truncates action fingerprints and copies the full value", async () => {
    const user = userEvent.setup();
    mockTimeline(timeline());

    renderDetail("run-1");

    const capabilityRow = within(await screen.findByTestId("timeline-agent-ev-2"));
    // truncated display, full value only via title/copy
    expect(capabilityRow.getByText(`${FULL_FINGERPRINT.slice(0, 18)}…`)).toBeInTheDocument();
    expect(capabilityRow.queryByText(FULL_FINGERPRINT)).not.toBeInTheDocument();

    await user.click(capabilityRow.getByRole("button", { name: "Copy action fingerprint" }));
    // userEvent.setup() installs a clipboard stub we can read back
    await expect(window.navigator.clipboard.readText()).resolves.toBe(FULL_FINGERPRINT);
  });

  it("shows the run's correlation ids (request_id / trace_id) in the summary", async () => {
    mockTimeline(timeline());

    renderDetail("run-1");

    // request/trace ids repeat per correlated row; assert at least one render
    expect((await screen.findAllByText("req-run-1")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("trace-run-1").length).toBeGreaterThan(0);
    // summary labels ("Request ID" also heads the Requests table)
    expect(screen.getAllByText("Request ID").length).toBeGreaterThan(0);
    expect(screen.getByText("Trace ID")).toBeInTheDocument();
  });
});
