import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import DashboardPage from "@/pages/dashboard";
import { translate } from "@/i18n";
import { formatNumber } from "@/i18n/format";
import {
  adminOverview,
  overviewControlPlaneData,
  overviewRuntimeData,
  overviewSectionOk,
  overviewSectionUnavailable,
  overviewUsageData,
} from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import type { AdminSchema } from "@/lib/gateway-client";

type AdminOverview = AdminSchema<"AdminOverview">;

function mockOverview(overview: AdminOverview) {
  server.use(http.get(gatewayUrl("/admin/v1/overview"), () => HttpResponse.json(overview)));
}

function mockOverviewError() {
  server.use(
    http.get(gatewayUrl("/admin/v1/overview"), () =>
      HttpResponse.json(
        { error: { code: "aggregate_failed", message: "overview aggregate failed" } },
        { status: 503 },
      ),
    ),
  );
}

/** An overview whose four sections are all real zeros (a brand-new install). */
function emptyOverview(): AdminOverview {
  const now = Math.floor(Date.now() / 1000);
  return adminOverview({
    runtime: overviewSectionOk(
      overviewRuntimeData({
        providers: { total: 0, enabled: 0 },
        models: { total: 0, enabled: 0 },
        static_api_keys: 0,
        prompt_templates: 0,
        upstreams: { total: 0, enabled: 0 },
        routes: { total: 0, enabled: 0 },
        plugins: { total: 0, active: 0 },
        tools: 0,
        mcp_servers: { total: 0, connected: 0, disconnected: 0 },
      }),
      "runtime_config",
      now,
    ),
    control_plane: overviewSectionOk(
      overviewControlPlaneData({
        tenants: 0,
        projects: 0,
        workspaces: 0,
        virtual_keys: { total: 0, enabled: 0 },
        assets: {
          count: 0,
          storage_bytes: 0,
          referenced: 0,
          unreferenced: 0,
          storage_quota_bytes: null,
        },
        agent_runs: { total: 0, by_status: {} },
        self_hosted_workers: { total: 0, by_status: {} },
        pending_tool_approvals: 0,
        quota_pressure: [],
        policy_governance: {
          guardrail_policy_revisions: 0,
          guardrail_policy_bindings: 0,
          quota_policies: 0,
          policy_rules: 0,
        },
      }),
      "control_plane_store",
      now,
    ),
    usage: overviewSectionOk(
      overviewUsageData({
        lifetime: {
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
          cost_usd: 0,
          request_count: 0,
          error_count: 0,
        },
        current_month: {
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
          cost_usd: 0,
          request_count: 0,
          error_count: 0,
        },
      }),
      "control_plane_store",
      now,
    ),
    alerts: overviewSectionOk(
      { total: 0, truncated: false, unavailable_sources: [], entries: [] },
      "runtime+control_plane",
      now,
    ),
  });
}

beforeEach(() => {
  seedSession();
});

describe("DashboardPage cockpit", () => {
  it("shows a loading state before the overview arrives", () => {
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />);
    expect(screen.getByText("Loading control-plane overview…")).toBeInTheDocument();
  });

  it("renders global scope, lifetime totals, counts, and prioritized alerts", async () => {
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });
    expect(screen.getByRole("heading", { name: "Operations overview" })).toBeInTheDocument();
    expect(screen.getByText("All tenants")).toBeInTheDocument();
    expect(screen.getByText("Fresh")).toBeInTheDocument();
    // Lifetime is the default period, labelled explicitly (never a "latest report").
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument();
    expect(within(traffic).getAllByText("All-time totals across the scope").length).toBeGreaterThan(0);
    expect(within(traffic).getByText("$4,210.50")).toBeInTheDocument();
    expect(within(traffic).getByText("3 / 4")).toBeInTheDocument(); // providers enabled/total
    expect(within(traffic).getByText("4 / 5")).toBeInTheDocument(); // mcp connected/total
    // Workers: healthy is DERIVED from the labels the gateway really writes
    // (`online` 8 + `registered` 1), not from a non-existent `active` bucket.
    expect(within(traffic).getByText("9 / 12")).toBeInTheDocument();

    // Core counts link to their filtered management views.
    expect(
      within(traffic).getByRole("link", { name: "View MCP servers" }),
    ).toHaveAttribute("href", "/app/mcp-servers");
    expect(within(traffic).getByRole("link", { name: "View Static assets" })).toHaveAttribute(
      "href",
      "/app/assets",
    );
    expect(within(traffic).getByRole("link", { name: "View Agent runs" })).toHaveAttribute(
      "href",
      "/app/agent-runs",
    );
    expect(
      within(traffic).getByRole("link", { name: "View Self-hosted workers" }),
    ).toHaveAttribute("href", "/app/workers/self-hosted");

    // Alerts region: critical first, with evidence and a link to the source page.
    const alerts = screen.getByRole("region", { name: "Alerts" });
    expect(within(alerts).getByText("Providers unhealthy")).toBeInTheDocument();
    expect(within(alerts).getByText("Agent runs failing")).toBeInTheDocument();
    expect(within(alerts).getByText("Workers under pressure")).toBeInTheDocument();
    expect(within(alerts).getByText("anthropic")).toBeInTheDocument();
    const investigateHrefs = within(alerts)
      .getAllByRole("link", { name: "Investigate" })
      .map((link) => link.getAttribute("href"));
    expect(investigateHrefs).toContain("/app/ops/provider-health");
    expect(investigateHrefs).toContain("/app/agent-runs?status=failed");

    // The #458 alert kinds the live gateway raises are titled and pivotable —
    // not an untitled "Alert" with no link.
    expect(within(alerts).getByText("Quota pressure")).toBeInTheDocument();
    expect(within(alerts).getByText("Tool approvals pending")).toBeInTheDocument();
    expect(investigateHrefs).toContain("/app/quota-policies");
    expect(investigateHrefs).toContain("/app/tool-approvals");
    expect(within(alerts).queryByText("Alert")).not.toBeInTheDocument();

    // The governance signals report the payload's real counts, not "not yet
    // reported": 4 pending approvals and 1 scope under quota pressure.
    expect(within(alerts).getByText("Pending tool approvals")).toBeInTheDocument();
    expect(within(alerts).getByText("Scopes under quota pressure")).toBeInTheDocument();
    expect(within(alerts).queryByText("N/A")).not.toBeInTheDocument();
  });

  it("derives healthy workers from the gateway's own status labels", async () => {
    // `by_status` carries a label this console cannot classify, so the healthy
    // count is genuinely unknown: N/A, never the `0 / 12` a `?? 0` would print
    // for a fleet whose twelve workers are all reporting in.
    mockOverview(
      adminOverview({
        control_plane: overviewSectionOk(
          overviewControlPlaneData({
            self_hosted_workers: { total: 12, by_status: { warming_up: 12 } },
          }),
        ),
      }),
    );
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });
    // The N/A sits in its own (hint-carrying) element, so match on the tile text.
    expect(
      within(traffic).getAllByText((_content, element) => element?.textContent === "N/A / 12")
        .length,
    ).toBeGreaterThan(0);
    expect(within(traffic).queryByText("0 / 12")).not.toBeInTheDocument();
  });

  it("renders an unreadable field as N/A instead of NaN", async () => {
    // The pre-#458 wire shape: `virtual_keys` as a bare number. The parser
    // rejects it, so the cell reads N/A — `format.number({total,enabled})`
    // would have printed "NaN" on screen.
    mockOverview(
      adminOverview({
        control_plane: overviewSectionOk({
          ...overviewControlPlaneData(),
          virtual_keys: 15,
        }),
      }),
    );
    renderWithProviders(<DashboardPage />);

    await screen.findByRole("region", { name: "Traffic and cost" });
    const row = screen.getByRole("row", { name: /Virtual keys/ });
    expect(within(row).getByText("N/A")).toBeInTheDocument();
    expect(screen.queryByText("NaN")).not.toBeInTheDocument();
    // Sibling rows of the same section stay populated.
    expect(within(screen.getByRole("row", { name: /Tenants/ })).getByText("24")).toBeInTheDocument();
  });

  it("shows the #458 breakdowns the backend reports", async () => {
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />);

    await screen.findByRole("region", { name: "Traffic and cost" });
    // Virtual keys enabled/disabled split and asset reference counts. The row
    // total is the object's `total`, never the object itself — passing the
    // `{total,enabled}` payload to a number formatter prints "NaN" on screen.
    expect(within(screen.getByRole("row", { name: /Virtual keys/ })).getByText("15"))
      .toBeInTheDocument();
    expect(screen.queryByText("NaN")).not.toBeInTheDocument();
    expect(screen.getByText("11 enabled / 15 total")).toBeInTheDocument();
    expect(
      screen.getByText("96 channel-referenced / 32 unreferenced"),
    ).toBeInTheDocument();
    // Global-scope policy governance counts are real numbers, and pending
    // approvals appear in the inventory with a link to their page.
    expect(
      within(screen.getByRole("row", { name: /Guardrail policy revisions/ })).getByText("7"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("row", { name: /Pending tool approvals/ })).getByRole("link"),
    ).toHaveAttribute("href", "/app/tool-approvals");
  });

  it("marks tenant-scope policy governance not-applicable, not zero", async () => {
    mockOverview(
      adminOverview({
        scope: { kind: "tenant", tenant_id: "tenant-alpha" },
        control_plane: overviewSectionOk(
          overviewControlPlaneData({
            policy_governance: null,
            assets: {
              count: 128,
              storage_bytes: 5_368_709_120,
              referenced: 96,
              unreferenced: 32,
              storage_quota_bytes: 10_737_418_240,
            },
          }),
        ),
      }),
    );
    renderWithProviders(<DashboardPage />);

    await screen.findByRole("region", { name: "Traffic and cost" });
    const row = screen.getByRole("row", { name: /Quota policies/ });
    expect(within(row).getByText("N/A")).toBeInTheDocument();
    expect(within(row).queryByText("0")).not.toBeInTheDocument();
    // A per-scope asset-storage quota is shown when the scope actually has one.
    expect(screen.getByText(/of a 10 GB scope quota/)).toBeInTheDocument();
  });

  it("never reads an unavailable alerts section as all-clear", async () => {
    mockOverview(
      adminOverview({
        alerts: overviewSectionUnavailable("alert summary unreachable", "runtime+control_plane"),
      }),
    );
    renderWithProviders(<DashboardPage />);

    const alerts = await screen.findByRole("region", { name: "Alerts" });
    expect(alerts.textContent).not.toContain("No active control-plane alerts.");
    expect(within(alerts).getByText("Overview section unavailable")).toBeInTheDocument();
    expect(within(alerts).getByText(/Alert summary is unavailable/)).toBeInTheDocument();
  });

  it("keeps the last payload when a background refresh fails", async () => {
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument();

    // The next refresh fails; the cockpit must degrade to "stale", not blank.
    mockOverviewError();
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("visibilitychange"));

    expect(await screen.findByText(/The last refresh failed/)).toBeInTheDocument();
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument();
    expect(within(traffic).getByText("9 / 12")).toBeInTheDocument();
    expect(screen.getByText("Stale")).toBeInTheDocument();
    expect(
      screen.queryByText(/The control-plane overview could not be loaded/),
    ).not.toBeInTheDocument();
  });

  it("switches the token/cost period and preserves the selection in the control", async () => {
    const user = userEvent.setup();
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });

    const lifetimeBtn = screen.getByRole("button", { name: "Lifetime" });
    const monthBtn = screen.getByRole("button", { name: "This month" });
    expect(lifetimeBtn).toHaveAttribute("aria-pressed", "true");
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument();

    await user.click(monthBtn);
    expect(monthBtn).toHaveAttribute("aria-pressed", "true");
    expect(lifetimeBtn).toHaveAttribute("aria-pressed", "false");
    expect(within(traffic).getByText("1,500,000")).toBeInTheDocument();
    expect(within(traffic).getAllByText("Calendar month 2026-07").length).toBeGreaterThan(0);
  });

  it("keeps healthy sections visible when one section is unavailable (not zero)", async () => {
    mockOverview(
      adminOverview({ control_plane: overviewSectionUnavailable("control-plane store unreachable") }),
    );
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });

    // Healthy sections stay populated.
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument(); // usage ok
    expect(within(traffic).getByText("3 / 4")).toBeInTheDocument(); // runtime ok

    // The failed section is Unavailable — distinct from a zero.
    expect(within(traffic).getAllByText("Unavailable").length).toBeGreaterThan(0);
    expect(within(traffic).queryByText("0 / 0")).not.toBeInTheDocument();

    // The partial failure is surfaced as a visible alert + inventory notice.
    expect(screen.getByText("Overview section unavailable")).toBeInTheDocument();
    expect(
      screen.getAllByText(/control-plane store unreachable/).length,
    ).toBeGreaterThan(0);
  });

  // GATE (#343 box 4/5): the usage section is the ONE section whose failure was
  // untested. Mutating the token tile to `format.tokens(tokens?.total_tokens ?? 0)`
  // left the whole 546-test suite green while the headline global total silently
  // read "0" for an unreachable usage aggregate — the exact fabrication #343
  // exists to forbid. This case fails on that mutation.
  it("renders an unavailable usage section as Unavailable, never as zero totals", async () => {
    mockOverview(
      adminOverview({
        usage: overviewSectionUnavailable("usage aggregate unreachable", "control_plane_store"),
      }),
    );
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });

    // Tokens, requests, and cost are all Unavailable — not 0 / 0 / $0.00.
    const tokenTile = within(traffic).getByText("Total tokens").closest("div");
    expect(tokenTile).not.toBeNull();
    expect(within(tokenTile as HTMLElement).getByText("Unavailable")).toBeInTheDocument();
    expect(within(traffic).getAllByText("Unavailable").length).toBeGreaterThanOrEqual(3);
    expect(within(traffic).queryByText("0")).not.toBeInTheDocument();
    expect(within(traffic).queryByText("$0.00")).not.toBeInTheDocument();
    expect(within(traffic).queryByText("12,000,000")).not.toBeInTheDocument();

    // Healthy sections keep their real values (box 5).
    expect(within(traffic).getByText("3 / 4")).toBeInTheDocument(); // runtime ok
    expect(within(traffic).getByText("9 / 12")).toBeInTheDocument(); // control-plane ok

    // The failure is surfaced, not swallowed.
    expect(screen.getByText("Overview section unavailable")).toBeInTheDocument();
    expect(screen.getAllByText(/usage aggregate unreachable/).length).toBeGreaterThan(0);
  });

  // GATE (#343 box 2): provenance. The global token total must come from the
  // overview's durable lifetime aggregate, NOT from the latest usage report.
  // This asserts both halves: the console never fetches the usage-report list,
  // and the number on screen is the aggregate even when a latest report with a
  // different total is available from the gateway.
  it("takes the global token total from the overview aggregate, not the latest usage report", async () => {
    const usageReportRequests: string[] = [];
    mockOverview(adminOverview());
    // A latest usage report whose token total is deliberately different. If the
    // cockpit ever regressed to a period-report value it would show 987,654.
    server.use(
      http.get(gatewayUrl("/admin/v1/usage-reports"), ({ request }) => {
        usageReportRequests.push(request.url);
        return HttpResponse.json({
          object: "list",
          data: [
            {
              id: "usage-report-latest",
              period_month: "2026-07",
              total_tokens: 987_654,
              cost_usd: 12.34,
            },
          ],
        });
      }),
    );

    renderWithProviders(<DashboardPage />);
    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });

    // The lifetime aggregate, explicitly scoped — never the report's total.
    expect(within(traffic).getByText("12,000,000")).toBeInTheDocument();
    expect(within(traffic).getAllByText("All-time totals across the scope").length).toBeGreaterThan(
      0,
    );
    expect(screen.queryByText("987,654")).not.toBeInTheDocument();
    expect(screen.queryByText("$12.34")).not.toBeInTheDocument();

    // Provenance, not just labelling: the report endpoint is never consulted.
    expect(usageReportRequests).toEqual([]);
  });

  it("renders a brand-new install as real zeros, distinct from unavailable", async () => {
    mockOverview(emptyOverview());
    renderWithProviders(<DashboardPage />);

    const traffic = await screen.findByRole("region", { name: "Traffic and cost" });

    expect(within(traffic).getAllByText("0 / 0").length).toBeGreaterThan(0); // providers/mcp/workers
    expect(within(traffic).getAllByText("0").length).toBeGreaterThan(0); // token/count zeros
    // Nothing is Unavailable: an empty install is zeros, not a failed section.
    expect(screen.queryByText("Unavailable")).not.toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Alerts" }).textContent,
    ).toContain("No active control-plane alerts.");
  });

  it("flags a stale overview", async () => {
    mockOverview(adminOverview({ generated_at_unix: 1_000_000 }));
    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText("Stale")).toBeInTheDocument();
    expect(screen.queryByText("Fresh")).not.toBeInTheDocument();
  });

  it("surfaces a hard load failure without blanking the page chrome", async () => {
    mockOverviewError();
    renderWithProviders(<DashboardPage />);

    expect(
      await screen.findByText(/The control-plane overview could not be loaded/),
    ).toBeInTheDocument();
  });

  it("renders the cockpit in Simplified Chinese", async () => {
    mockOverview(adminOverview());
    renderWithProviders(<DashboardPage />, { locale: "zh-CN" });

    const traffic = await screen.findByRole("region", {
      name: translate("zh-CN", "dashboard.band.traffic.title"),
    });
    expect(
      screen.getByRole("heading", { name: translate("zh-CN", "dashboard.title") }),
    ).toBeInTheDocument();
    expect(screen.getByText(translate("zh-CN", "dashboard.scope.global"))).toBeInTheDocument();
    expect(
      screen.getByText(translate("zh-CN", "dashboard.alert.kind.provider_unhealthy")),
    ).toBeInTheDocument();
    expect(within(traffic).getByText(formatNumber("zh-CN", 12_000_000))).toBeInTheDocument();
    // Identifiers stay byte-for-byte across locales.
    expect(screen.getByText("anthropic")).toBeInTheDocument();
  });
});
