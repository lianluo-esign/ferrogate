import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import AgentSchedulesPage, {
  type AdminAgentSchedule,
  type AdminAgentScheduleFire,
} from "@/pages/agent-schedules";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

function schedule(overrides: Partial<AdminAgentSchedule> = {}): AdminAgentSchedule {
  return {
    object: "agent_schedule",
    id: "sched-1",
    tenant_id: "tenant-1",
    workspace_id: "ws-1",
    name: "Nightly report",
    enabled: true,
    spec_kind: "cron",
    cron_expr: "0 2 * * *",
    timezone: "UTC",
    interval_secs: null,
    target_kind: "agent_run",
    target: {},
    overlap_policy: "skip",
    catchup_policy: "skip_missed",
    jitter_secs: 0,
    next_fire_at_unix: 1_752_100_000,
    last_fire_at_unix: null,
    created_at_unix: 1,
    updated_at_unix: 1,
    revision: 1,
    ...overrides,
  };
}

function fire(overrides: Partial<AdminAgentScheduleFire> = {}): AdminAgentScheduleFire {
  return {
    object: "agent_schedule_fire",
    fire_id: "fire-1",
    schedule_id: "sched-1",
    scheduled_fire_at_unix: 1_752_000_000,
    fired_at_unix: 1_752_000_001,
    node_id: "node-a",
    outcome: "dispatched",
    dispatch_id: "disp-123",
    run_id: null,
    detail: null,
    ...overrides,
  };
}

beforeEach(() => {
  seedSession();
});

describe("AgentSchedulesPage", () => {
  it("lists schedules with spec and enablement", async () => {
    mockAdminList("/admin/v1/agent-schedules", [
      schedule(),
      schedule({
        id: "sched-2",
        name: "Interval sweep",
        enabled: false,
        spec_kind: "interval",
        cron_expr: null,
        interval_secs: 300,
        target_kind: "self_hosted_dispatch",
      }),
    ]);

    renderWithProviders(<AgentSchedulesPage />);

    expect(await screen.findByText("Nightly report")).toBeInTheDocument();
    expect(screen.getByText("Interval sweep")).toBeInTheDocument();
    expect(screen.getByText("cron 0 2 * * * (UTC)")).toBeInTheDocument();
    expect(screen.getByText("every 300s")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
  });

  it("creates a cron schedule posting the contract mutation body", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/agent-schedules", []);
    let createdBody: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/agent-schedules"), async ({ request }) => {
        createdBody = await request.json();
        return HttpResponse.json(
          { object: "agent_schedule", agent_schedule: schedule() },
          { status: 201 },
        );
      }),
    );

    renderWithProviders(<AgentSchedulesPage />);
    await screen.findByText("No schedules yet.");

    await user.click(screen.getByRole("button", { name: "New schedule" }));
    await user.type(await screen.findByLabelText("Name"), "Nightly report");
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(screen.getByLabelText("Workspace ID"), "ws-1");
    await user.type(screen.getByLabelText("Cron expression"), "0 2 * * *");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(createdBody).toEqual({
        name: "Nightly report",
        tenant_id: "tenant-1",
        workspace_id: "ws-1",
        enabled: true,
        spec_kind: "cron",
        cron_expr: "0 2 * * *",
        timezone: "UTC",
        target_kind: "agent_run",
        target: {},
        overlap_policy: "skip",
        catchup_policy: "skip_missed",
        jitter_secs: 0,
      }),
    );
  });

  it("fires run-now only after confirmation and surfaces the recorded fire", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/agent-schedules", [schedule()]);
    let runNowCalls = 0;
    server.use(
      http.post(gatewayUrl("/admin/v1/agent-schedules/sched-1/run-now"), () => {
        runNowCalls += 1;
        return HttpResponse.json(
          { object: "agent_schedule_fire", fire: fire() },
          { status: 202 },
        );
      }),
    );

    renderWithProviders(<AgentSchedulesPage />);
    await screen.findByText("Nightly report");

    await user.click(screen.getByRole("button", { name: "Run now" }));
    // confirmation dialog first; nothing fired yet
    expect(await screen.findByText("Run schedule now?")).toBeInTheDocument();
    expect(runNowCalls).toBe(0);

    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Run now" }));

    await waitFor(() => expect(runNowCalls).toBe(1));
    // 202 response fire surfaced: outcome + dispatch id
    const card = await screen.findByTestId("last-manual-fire");
    expect(within(card).getByText("dispatched")).toBeInTheDocument();
    expect(within(card).getByText("dispatch disp-123")).toBeInTheDocument();
    expect(within(card).getByText("fire fire-1")).toBeInTheDocument();
  });

  it("does not fire run-now when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/agent-schedules", [schedule()]);
    let runNowCalls = 0;
    server.use(
      http.post(gatewayUrl("/admin/v1/agent-schedules/sched-1/run-now"), () => {
        runNowCalls += 1;
        return HttpResponse.json(
          { object: "agent_schedule_fire", fire: fire() },
          { status: 202 },
        );
      }),
    );

    renderWithProviders(<AgentSchedulesPage />);
    await screen.findByText("Nightly report");

    await user.click(screen.getByRole("button", { name: "Run now" }));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));

    await waitFor(() =>
      expect(screen.queryByText("Run schedule now?")).not.toBeInTheDocument(),
    );
    expect(runNowCalls).toBe(0);
  });

  it("shows a schedule's fire history", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/agent-schedules", [schedule()]);
    mockAdminList("/admin/v1/agent-schedules/sched-1/fires", [
      fire(),
      fire({
        fire_id: "fire-2",
        outcome: "skipped_overlap",
        dispatch_id: null,
        detail: "previous fire still running",
      }),
    ]);

    renderWithProviders(<AgentSchedulesPage />);
    await screen.findByText("Nightly report");

    await user.click(screen.getByRole("button", { name: "Fires" }));

    expect(await screen.findByText("Fire history — Nightly report")).toBeInTheDocument();
    expect(await screen.findByText("fire-1")).toBeInTheDocument();
    expect(screen.getByText("fire-2")).toBeInTheDocument();
    expect(screen.getByText("dispatched")).toBeInTheDocument();
    expect(screen.getByText("skipped_overlap")).toBeInTheDocument();
    expect(screen.getByText("previous fire still running")).toBeInTheDocument();
  });

  it("deletes a schedule after confirmation", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/agent-schedules", [schedule()]);
    let deleteCalls = 0;
    server.use(
      http.delete(gatewayUrl("/admin/v1/agent-schedules/sched-1"), () => {
        deleteCalls += 1;
        return HttpResponse.json({ object: "agent_schedule", id: "sched-1", deleted: true });
      }),
    );

    renderWithProviders(<AgentSchedulesPage />);
    await screen.findByText("Nightly report");

    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Delete schedule?")).toBeInTheDocument();
    expect(deleteCalls).toBe(0);

    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete" }),
    );

    await waitFor(() => expect(deleteCalls).toBe(1));
  });
});
