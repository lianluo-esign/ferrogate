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
        virtual_keys: 0,
        assets: { count: 0, storage_bytes: 0 },
        agent_runs: { total: 0, by_status: {} },
        self_hosted_workers: { total: 0, by_status: {} },
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
    expect(within(traffic).getByText("9 / 12")).toBeInTheDocument(); // workers active/total

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

    // Deferred #458 signals render as explicit N/A, never a fabricated zero.
    expect(within(alerts).getByText("Pending approvals")).toBeInTheDocument();
    expect(within(alerts).getAllByText("N/A").length).toBeGreaterThanOrEqual(2);
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
