import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { useSearchParams } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import AgentRunsPage, { type AgentRunSummary } from "@/pages/agent-runs";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

/** Surfaces the live URL query string so URL-state assertions can read it. */
function SearchProbe() {
  const [params] = useSearchParams();
  return <span data-testid="search">{params.toString()}</span>;
}

function run(overrides: Partial<AgentRunSummary> = {}): AgentRunSummary {
  return {
    object: "agent_run",
    id: "run-1",
    tenant: { organization_id: "org-acme" },
    status: "completed",
    request_count: 3,
    billing_event_count: 2,
    audit_event_count: 1,
    agent_event_count: 7,
    first_seen_unix: 1_752_000_000,
    last_seen_unix: 1_752_000_100,
    ...overrides,
  };
}

function mockRuns(runs: AgentRunSummary[]): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/agent-runs"), () =>
      HttpResponse.json({
        object: "list",
        data: runs,
        total: runs.length,
        offset: 0,
        limit: 50,
      }),
    ),
  );
}

beforeEach(() => {
  seedSession();
});

describe("AgentRunsPage", () => {
  it("lists agent runs with status and correlated counts", async () => {
    mockRuns([
      run(),
      run({ id: "run-2", status: "blocked", tenant: { project_id: "proj-beta" } }),
    ]);

    renderWithProviders(<AgentRunsPage />);

    expect(await screen.findByText("run-1")).toBeInTheDocument();
    expect(screen.getByText("run-2")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("blocked")).toBeInTheDocument();
    expect(screen.getByText("org-acme")).toBeInTheDocument();
    // correlated agent-event counts render (both fixture rows share 7)
    expect(screen.getAllByText("7").length).toBeGreaterThan(0);
  });

  it("filters by status client-side (contract exposes only offset/limit)", async () => {
    const user = userEvent.setup();
    mockRuns([
      run(),
      run({ id: "run-2", status: "blocked" }),
      run({ id: "run-3", status: "failed" }),
    ]);

    renderWithProviders(<AgentRunsPage />);
    await screen.findByText("run-1");

    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "Blocked" }));

    expect(await screen.findByText("run-2")).toBeInTheDocument();
    expect(screen.queryByText("run-1")).not.toBeInTheDocument();
    expect(screen.queryByText("run-3")).not.toBeInTheDocument();

    // round-trip back to all statuses
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "All statuses" }));
    expect(await screen.findByText("run-1")).toBeInTheDocument();
    expect(screen.getByText("run-3")).toBeInTheDocument();
  });

  it("filters by tenant id substring", async () => {
    const user = userEvent.setup();
    mockRuns([
      run(),
      run({ id: "run-2", tenant: { project_id: "proj-beta" } }),
    ]);

    renderWithProviders(<AgentRunsPage />);
    await screen.findByText("run-1");

    await user.type(screen.getByLabelText("Tenant"), "proj-beta");

    expect(await screen.findByText("run-2")).toBeInTheDocument();
    expect(screen.queryByText("run-1")).not.toBeInTheDocument();
  });

  it("writes the status and tenant filters to the URL query state", async () => {
    const user = userEvent.setup();
    mockRuns([run(), run({ id: "run-2", status: "blocked" })]);

    renderWithProviders(
      <>
        <AgentRunsPage />
        <SearchProbe />
      </>,
    );
    await screen.findByText("run-1");

    // Selecting a status writes the contract token to the URL while the select
    // keeps DISPLAYING the localized human label.
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "Blocked" }));
    await waitFor(() =>
      expect(screen.getByTestId("search")).toHaveTextContent("status=blocked"),
    );

    // The free-text tenant correlation filter also persists to the URL.
    await user.type(screen.getByLabelText("Tenant"), "proj-beta");
    await waitFor(() =>
      expect(screen.getByTestId("search")).toHaveTextContent("tenant=proj-beta"),
    );

    // Returning to the default status prunes the param (clean canonical URL).
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "All statuses" }));
    await waitFor(() =>
      expect(screen.getByTestId("search")).not.toHaveTextContent("status="),
    );
  });

  it("links each run to its timeline detail page", async () => {
    mockRuns([run()]);

    renderWithProviders(<AgentRunsPage />);

    const link = await screen.findByRole("link", { name: "run-1" });
    expect(link).toHaveAttribute("href", "/app/agent-runs/run-1");
  });
});
