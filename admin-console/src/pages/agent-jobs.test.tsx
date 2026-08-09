import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import AgentJobsPage from "@/pages/agent-jobs";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
// Console coverage for the #474 async agent-job protocol page: submit ->
// durable run id -> observe -> collect. The two properties worth locking in are
// the ones the protocol is judged on and the ones a UI can silently lose: a
// retried submit is reported as the ORIGINAL job (never a second run), and the
// result is only collected once the runtime settled the run.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

const RUN_ID = "job-0123456789abcdef0123456789abcdef";

function jobStatus(overrides: Record<string, unknown> = {}) {
  return {
    object: "agent_job",
    run_id: RUN_ID,
    status: "queued",
    terminal: false,
    provider: "ferrogate.agent-job",
    turns_executed: 0,
    output_recorded: false,
    event_count: 1,
    started_at_unix: 100,
    completed_at_unix: null,
    first_seen_unix: 100,
    last_seen_unix: 100,
    runtime_reported_state: null,
    runtime_reported_event_count: 0,
    request_id: "fg-1",
    ...overrides,
  };
}

function eventPage() {
  return {
    object: "agent_job_event_page",
    run_id: RUN_ID,
    data: [
      {
        id: `agent-job-submitted:${RUN_ID}`,
        run_id: RUN_ID,
        request_id: "fg-1",
        trace_id: null,
        tenant: {},
        turn: 0,
        kind: "job_submitted",
        target: `agent_run:${RUN_ID}`,
        outcome: "accepted",
        tool_call_id: null,
        message: "fix the flaky test",
        occurred_at_unix: 100,
      },
    ],
    limit: 100,
    after_event_id: null,
    next_after_event_id: `100:agent-job-submitted:${RUN_ID}`,
    has_more: false,
    cursor_reset: false,
    request_id: "fg-2",
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <AgentJobsPage />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("AgentJobsPage", () => {
  it("prompts before any job is tracked", () => {
    renderPage();
    expect(screen.getByText(/Submit a job above/)).toBeInTheDocument();
  });

  it("reports a retried submit as the ORIGINAL job rather than a second run", async () => {
    server.use(
      http.post(gatewayUrl("/v1/agent-jobs"), () =>
        HttpResponse.json(
          {
            object: "agent_job",
            run_id: RUN_ID,
            status: "queued",
            idempotency_key: "fix-flaky-test",
            idempotency_key_source: "body",
            deduplicated: true,
            terminal: false,
            submitted_at_unix: 100,
            status_url: `/v1/agent-jobs/${RUN_ID}`,
            events_url: `/v1/agent-jobs/${RUN_ID}/events`,
            result_url: `/v1/agent-jobs/${RUN_ID}/result`,
            request_id: "fg-1",
          },
          { status: 200 },
        ),
      ),
      http.get(gatewayUrl(`/v1/agent-jobs/${RUN_ID}`), () => HttpResponse.json(jobStatus())),
      http.get(gatewayUrl(`/v1/agent-jobs/${RUN_ID}/events`), () => HttpResponse.json(eventPage())),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Task"), "fix the flaky test");
    await user.type(screen.getByLabelText("Idempotency key"), "fix-flaky-test");
    await user.click(screen.getByRole("button", { name: "Submit" }));

    expect(
      await screen.findByText(`Duplicate submission — this is the original job ${RUN_ID}.`),
    ).toBeInTheDocument();
    // The page then follows that same original id.
    expect(await screen.findByText(`Job ${RUN_ID}`)).toBeInTheDocument();
    expect(screen.getByText("job_submitted")).toBeInTheDocument();
  });

  it("collects the runtime's output only once the job is terminal", async () => {
    server.use(
      http.get(gatewayUrl(`/v1/agent-jobs/${RUN_ID}`), () =>
        HttpResponse.json(
          jobStatus({
            status: "completed",
            terminal: true,
            turns_executed: 5,
            output_recorded: true,
            completed_at_unix: 200,
            runtime_reported_state: "completed",
          }),
        ),
      ),
      http.get(gatewayUrl(`/v1/agent-jobs/${RUN_ID}/events`), () => HttpResponse.json(eventPage())),
      http.get(gatewayUrl(`/v1/agent-jobs/${RUN_ID}/result`), () =>
        HttpResponse.json({
          object: "agent_job_result",
          run_id: RUN_ID,
          status: "completed",
          terminal: true,
          turns_executed: 5,
          output_recorded: true,
          output: "opened https://example.test/pr/4711",
          artifacts: [],
          request_count: 0,
          billing_event_count: 0,
          completed_at_unix: 200,
          request_id: "fg-3",
        }),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Job (run) id"), RUN_ID);
    await user.click(screen.getByRole("button", { name: "Track" }));

    expect(await screen.findByText(`Job ${RUN_ID}`)).toBeInTheDocument();
    expect(await screen.findByText("opened https://example.test/pr/4711")).toBeInTheDocument();
    // A terminal job cannot be cancelled again.
    expect(screen.getByRole("button", { name: "Cancel job" })).toBeDisabled();
  });

  it("surfaces a failed lookup instead of rendering an empty job", async () => {
    server.use(
      http.get(gatewayUrl("/v1/agent-jobs/job-missing"), () =>
        HttpResponse.json(
          {
            error: { code: "agent_job_not_found", message: "agent job job-missing was not found" },
          },
          { status: 404 },
        ),
      ),
      http.get(gatewayUrl("/v1/agent-jobs/job-missing/events"), () =>
        HttpResponse.json(
          {
            error: { code: "agent_job_not_found", message: "agent job job-missing was not found" },
          },
          { status: 404 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Job (run) id"), "job-missing");
    await user.click(screen.getByRole("button", { name: "Track" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/Could not read job job-missing/);
  });
});
