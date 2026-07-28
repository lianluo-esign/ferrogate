import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { useSearchParams } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import AgentRunsPage, {
  type AgentRunSummary,
  type ObservedAgentActivity,
  type ObservedPresenceFeed as PresenceFeed,
} from "@/pages/agent-runs";
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

function activity(
  overrides: Partial<ObservedAgentActivity> = {},
  evidenceOverrides: Partial<ObservedAgentActivity["evidence"]> = {},
): ObservedAgentActivity {
  return {
    id: "observed:tenant-acme:key-1",
    source: "virtual_api_key",
    identity_status: "unattributed",
    display_name: "Unknown",
    status: "running",
    status_basis: "recent_api_key_activity",
    tenant_id: "tenant-acme",
    api_key_id: "key-1",
    first_seen_at_unix: 1_752_000_000,
    last_seen_at_unix: 1_752_000_100,
    running_ttl_seconds: 300,
    ...overrides,
    evidence: {
      evidence_source: "request_logs",
      request_count: 12,
      seconds_since_last_seen: 30,
      running_ttl_seconds: 300,
      within_running_window: true,
      durable_presence_backed: true,
      presence_feed_status: "available",
      presence_unavailable_reason: null,
      usage_evidence_available: true,
      prompt_tokens: 1_000,
      completion_tokens: 3_321,
      total_tokens: 4_321,
      cost_usd: 1.25,
      reason: "12 requests in the last 30s (ttl 300s)",
      ...evidenceOverrides,
    },
  };
}

function mockObservedActivity(
  rows: ObservedAgentActivity[],
  presenceFeed: PresenceFeed = {
    status: "available",
    unavailable_reason: null,
    rows_may_be_incomplete: false,
  },
): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/observed-agent-activity"), () =>
      HttpResponse.json({
        object: "list",
        data: rows,
        total: rows.length,
        offset: 0,
        limit: 50,
        presence_feed: presenceFeed,
      }),
    ),
  );
}

function mockObservedActivityWithoutPresenceFeed(rows: ObservedAgentActivity[]): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/observed-agent-activity"), () =>
      HttpResponse.json({
        object: "list",
        data: rows,
        total: rows.length,
        offset: 0,
        limit: 50,
      }),
    ),
  );
}

/** Opens the Unattributed tab on a page whose runs list is already mocked. */
async function openUnattributedTab(user: ReturnType<typeof userEvent.setup>) {
  renderWithProviders(<AgentRunsPage />);
  await user.click(await screen.findByRole("tab", { name: "Unattributed" }));
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

// #464: the unattributed ("Unknown" virtual-API-key) activity tab over
// GET /admin/v1/observed-agent-activity. These assertions guard the TRUTHFULNESS
// of the surface, which is the whole point of #357: a derived "running" that
// expires into inactive WITHOUT a stop event, usage that is unknown rather than
// zero, and evidence the operator can open to see why a row says what it says.
describe("AgentRunsPage — unattributed activity", () => {
  beforeEach(() => {
    mockRuns([run()]);
  });

  it("lists observed unattributed activity as a category, not a named agent", async () => {
    const user = userEvent.setup();
    mockObservedActivity([
      activity(),
      activity({ id: "observed:tenant-beta:key-2", tenant_id: "tenant-beta", api_key_id: "key-2" }),
    ]);

    await openUnattributedTab(user);

    expect(await screen.findByText("observed:tenant-acme:key-1")).toBeInTheDocument();
    expect(screen.getByText("observed:tenant-beta:key-2")).toBeInTheDocument();
    expect(screen.getByText("tenant-acme")).toBeInTheDocument();
    expect(screen.getByText("key-2")).toBeInTheDocument();
    // Presented as an identity CATEGORY — never as an agent named "Unknown".
    expect(screen.getAllByText("Unknown identity")).toHaveLength(2);
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument();
    // The running row states the recency window it was derived from.
    expect(screen.getAllByText("Running").length).toBeGreaterThan(0);
    expect(
      screen.getAllByText("Derived from activity within the last 300s").length,
    ).toBeGreaterThan(0);
  });

  it("renders unavailable usage as unavailable, never as zero", async () => {
    const user = userEvent.setup();
    mockObservedActivity([
      activity({}, {
        usage_evidence_available: false,
        prompt_tokens: undefined,
        completion_tokens: undefined,
        total_tokens: undefined,
        cost_usd: undefined,
        reason: "no usage rows recorded for this key",
      }),
    ]);

    await openUnattributedTab(user);
    await screen.findByText("observed:tenant-acme:key-1");

    const unavailable = screen.getAllByLabelText(
      "Usage evidence unavailable for this activity — unknown, not zero",
    );
    // Both the token and the cost cell say "unknown".
    expect(unavailable).toHaveLength(2);
    for (const cell of unavailable) {
      expect(cell).toHaveTextContent("—");
      expect(cell).not.toHaveTextContent("0");
    }
    // Nothing anywhere in the row fabricated a zero token count or $0.00 spend.
    expect(screen.queryByText("0")).not.toBeInTheDocument();
    expect(screen.queryByText("$0.00")).not.toBeInTheDocument();
  });

  it("renders an out-of-window row as inactive with no fabricated stop time", async () => {
    const user = userEvent.setup();
    mockObservedActivity([
      activity(
        { status: "inactive" },
        {
          within_running_window: false,
          seconds_since_last_seen: 4_000,
          reason: "last request 4000s ago exceeds the 300s running window",
        },
      ),
    ]);

    await openUnattributedTab(user);
    await screen.findByText("observed:tenant-acme:key-1");

    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.queryByText("Running")).not.toBeInTheDocument();
    // The expiry is stated as an absence of evidence, not as an end time.
    expect(
      screen.getByText(
        "Recency window expired — no stop event was recorded, so there is no end time",
      ),
    ).toBeInTheDocument();
    // Only the contract's first/last-seen timestamps are rendered — the row has
    // no "ended at" column and the last-seen value is never relabelled as one.
    expect(screen.queryByText(/ended/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/stopped at/i)).not.toBeInTheDocument();
  });

  // #494: a presence READ FAILURE must not reach the operator as "Inactive" —
  // that is the rendering that gets a live agent restarted.
  it("renders an undecidable row as unknown, never as inactive", async () => {
    const user = userEvent.setup();
    mockObservedActivity(
      [
        activity(
          { status: "unknown", status_basis: "presence_feed_unavailable" },
          {
            within_running_window: null,
            durable_presence_backed: null,
            presence_feed_status: "unavailable",
            presence_unavailable_reason: "presence_read_failed",
            seconds_since_last_seen: 4_000,
            reason: "durable presence feed unavailable (presence_read_failed)",
          },
        ),
      ],
      {
        status: "unavailable",
        unavailable_reason: "presence_read_failed",
        rows_may_be_incomplete: true,
      },
    );

    await openUnattributedTab(user);
    await screen.findByText("observed:tenant-acme:key-1");

    expect(screen.getByText("Unknown", { selector: "div" })).toBeInTheDocument();
    expect(screen.queryByText("Inactive")).not.toBeInTheDocument();
    expect(screen.queryByText("Running")).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Presence feed unavailable (presence_read_failed) — this activity may still be running; it is NOT reported inactive",
      ),
    ).toBeInTheDocument();
    // The list itself says the answer may be incomplete, so an empty page can
    // never read as "nothing is running".
    expect(screen.getByRole("status")).toHaveTextContent(
      "The durable presence feed could not be read (presence_read_failed).",
    );
  });

  it("treats a missing presence-feed qualifier as degraded", async () => {
    const user = userEvent.setup();
    mockObservedActivityWithoutPresenceFeed([]);

    await openUnattributedTab(user);

    expect(await screen.findByRole("status")).toHaveTextContent(
      "The durable presence feed could not be read (read failed).",
    );
  });

  it("renders inconsistent and unexpected row states as unknown", async () => {
    const user = userEvent.setup();
    mockObservedActivity(
      [
        activity(
          { status: "running" },
          {
            within_running_window: null,
            presence_feed_status: "unavailable",
            presence_unavailable_reason: "presence_read_failed",
          },
        ),
        activity(
          {
            id: "observed:tenant-acme:key-2",
            api_key_id: "key-2",
            status: "future_status" as ObservedAgentActivity["status"],
          },
          { within_running_window: true },
        ),
      ],
      {
        status: "unavailable",
        unavailable_reason: "presence_read_failed",
        rows_may_be_incomplete: true,
      },
    );

    await openUnattributedTab(user);
    await screen.findByText("observed:tenant-acme:key-1");

    expect(screen.getAllByText("Unknown", { selector: "div" })).toHaveLength(2);
    expect(screen.queryByText("Inactive")).not.toBeInTheDocument();
    expect(screen.queryByText("Running")).not.toBeInTheDocument();
  });

  it("makes the evidence behind the derived status reachable", async () => {
    const user = userEvent.setup();
    mockObservedActivity([activity()]);

    await openUnattributedTab(user);
    await screen.findByText("observed:tenant-acme:key-1");

    const toggle = screen.getByRole("button", {
      name: "Show the evidence for observed:tenant-acme:key-1",
    });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Requests observed")).not.toBeInTheDocument();

    await user.click(toggle);

    expect(await screen.findByText("Requests observed")).toBeInTheDocument();
    expect(screen.getByText("Seconds since last seen")).toBeInTheDocument();
    expect(screen.getByText("Running window (seconds)")).toBeInTheDocument();
    expect(screen.getByText("Within running window")).toBeInTheDocument();
    expect(screen.getByText("Reason")).toBeInTheDocument();
    expect(
      screen.getByText("12 requests in the last 30s (ttl 300s)"),
    ).toBeInTheDocument();
    expect(screen.getByText("request_logs")).toBeInTheDocument();
    expect(screen.getByText("recent_api_key_activity")).toBeInTheDocument();
    expect(toggle).toHaveAttribute("aria-expanded", "true");

    await user.click(screen.getByRole("button", { name: /evidence for observed/ }));
    await waitFor(() =>
      expect(screen.queryByText("Requests observed")).not.toBeInTheDocument(),
    );
  });

  it("keeps the open view in the URL query state", async () => {
    const user = userEvent.setup();
    mockObservedActivity([activity()]);

    renderWithProviders(
      <>
        <AgentRunsPage />
        <SearchProbe />
      </>,
    );
    await user.click(await screen.findByRole("tab", { name: "Unattributed" }));
    await waitFor(() =>
      expect(screen.getByTestId("search")).toHaveTextContent("view=unattributed"),
    );

    // Back to the default tab prunes the param (clean canonical URL).
    await user.click(screen.getByRole("tab", { name: "Runs" }));
    await waitFor(() =>
      expect(screen.getByTestId("search")).not.toHaveTextContent("view="),
    );
  });
});
