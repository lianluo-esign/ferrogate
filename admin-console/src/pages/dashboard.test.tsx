import { screen, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import DashboardPage from "@/pages/dashboard";
import { translate } from "@/i18n";
import { formatCurrency, formatNumber } from "@/i18n/format";
import { adminStatus, providerHealth } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import type { AdminSchema } from "@/lib/gateway-client";

type ToolApproval = AdminSchema<"ToolApprovalRecord">;
type RequestLog = AdminSchema<"RequestLog">;
type UsageReport = AdminSchema<"AdminUsageReportRow">;

const pendingApproval: ToolApproval = {
  id: "approval-1",
  request_id: "req-approval-1",
  trace_id: "trace-approval-1",
  tenant: { project_id: "project-1", api_key_id: "key-1" },
  actor_api_key_id: "key-1",
  tool_name: "deploy_production",
  server_name: "release-tools",
  route: "/v1/tools/call",
  approval_policy: "always",
  approval_timeout_secs: 300,
  fingerprint: "sha256:invocation",
  arguments_summary: "environment=production",
  risk_reason: "production mutation",
  status: "pending",
  reviewer_api_key_id: null,
  reviewer_authority: null,
  terminal_reason: null,
  requested_at_unix: 1_752_000_000,
  expires_at_unix: 1_752_000_300,
  decided_at_unix: null,
};

const requests: RequestLog[] = [
  {
    request_id: "req-success-123456",
    provider: "openai",
    logical_model: "gpt-4.1-mini",
    status_code: 200,
    started_at_unix: 1_752_000_100,
  },
  {
    request_id: "req-failed-654321",
    provider: "anthropic",
    logical_model: "claude-sonnet-4",
    status_code: 503,
    error_code: "provider_unavailable",
    started_at_unix: 1_752_000_200,
  },
];

const usage: UsageReport = {
  period_month: "2026-07",
  scope_type: "tenant",
  scope_id: "tenant-1",
  prompt_tokens: 90_000,
  completion_tokens: 60_000,
  total_tokens: 150_000,
  cost_usd: 12.3456,
  request_count: 860,
  error_count: 4,
};

function installDashboardMocks({
  providerFailure = false,
  empty = false,
}: { providerFailure?: boolean; empty?: boolean } = {}) {
  server.use(
    http.get(gatewayUrl("/admin/v1/status"), () => HttpResponse.json(adminStatus())),
    http.get(gatewayUrl("/admin/v1/provider-health"), () =>
      providerFailure
        ? HttpResponse.json(
            { error: { code: "probe_failed", message: "provider probe failed" } },
            { status: 503 },
          )
        : HttpResponse.json({
            object: "list",
            data: empty
              ? []
              : [
                  providerHealth(),
                  providerHealth({
                    name: "anthropic",
                    kind: "anthropic",
                    status: "error",
                    reachable: false,
                    circuit_open: true,
                    consecutive_failures: 3,
                    error: "connect timeout",
                  }),
                ],
          }),
    ),
    http.get(gatewayUrl("/admin/v1/tool-approvals"), () =>
      HttpResponse.json({ object: "list", data: empty ? [] : [pendingApproval] }),
    ),
    http.get(gatewayUrl("/admin/v1/request-logs"), () =>
      HttpResponse.json({
        object: "list",
        data: empty ? [] : requests,
        total: empty ? 0 : requests.length,
        offset: 0,
        limit: 50,
      }),
    ),
    http.get(gatewayUrl("/admin/v1/usage-reports"), () =>
      HttpResponse.json({ object: "list", data: empty ? [] : [usage] }),
    ),
  );
}

beforeEach(() => {
  seedSession();
});

describe("DashboardPage", () => {
  it("renders a live operator summary with actionable links", async () => {
    installDashboardMocks();
    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText("Operations overview")).toBeInTheDocument();
    const posture = screen.getByRole("region", { name: "Gateway posture" });
    expect(await within(posture).findByText("Ready")).toBeInTheDocument();
    expect(within(posture).getByText("1 / 2")).toBeInTheDocument();
    expect(within(posture).getByText("2")).toBeInTheDocument();
    expect(screen.getByText("1 provider needs attention.")).toBeInTheDocument();
    expect(
      screen.getByText("1 tool approval is waiting for review."),
    ).toBeInTheDocument();
    expect(screen.getByText("req-failed-654321")).toBeInTheDocument();
    expect(screen.getAllByText("$12.3456")).toHaveLength(2);
    expect(screen.getByText("150,000")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View logs" })).toHaveAttribute(
      "href",
      "/app/request-logs",
    );
    expect(screen.getByRole("link", { name: "View reports" })).toHaveAttribute(
      "href",
      "/app/usage-reports",
    );
    expect(screen.getAllByText(/^Updated /).length).toBeGreaterThan(0);
  });

  it("keeps the remaining dashboard useful when provider health fails", async () => {
    installDashboardMocks({ providerFailure: true });
    renderWithProviders(<DashboardPage />);

    expect(
      await screen.findByText("Provider health is unavailable: provider probe failed."),
    ).toBeInTheDocument();
    expect(screen.getByText("Ready")).toBeInTheDocument();
    expect(screen.getByText("req-success-123456")).toBeInTheDocument();
    expect(screen.getAllByText("$12.3456")).toHaveLength(2);
  });

  it("shows explicit empty states without inventing activity", async () => {
    installDashboardMocks({ empty: true });
    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText("No retained requests yet.")).toBeInTheDocument();
    expect(screen.getByText("No usage report is available yet.")).toBeInTheDocument();
    expect(screen.getByText("No active gateway, provider, or approval alerts.")).toBeInTheDocument();
  });

  it("renders the overview in Simplified Chinese with locale-formatted values", async () => {
    installDashboardMocks();
    renderWithProviders(<DashboardPage />, { locale: "zh-CN" });

    // Chrome + section copy resolve from the zh-CN catalog.
    expect(
      await screen.findByText(translate("zh-CN", "dashboard.title")),
    ).toBeInTheDocument();
    const posture = screen.getByRole("region", {
      name: translate("zh-CN", "dashboard.posture.title"),
    });
    expect(
      await within(posture).findByText(translate("zh-CN", "dashboard.state.ready")),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        translate("zh-CN", "dashboard.alert.providersUnhealthy.one", { count: 1 }),
      ),
    ).toBeInTheDocument();

    // Numbers/currency route through the shared Intl formatters for zh-CN.
    expect(
      screen.getAllByText(formatCurrency("zh-CN", 12.3456, "USD", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 4,
      })),
    ).toHaveLength(2);
    expect(screen.getByText(formatNumber("zh-CN", 150_000))).toBeInTheDocument();

    // Identifiers stay byte-for-byte unchanged across locales.
    expect(screen.getByText("req-failed-654321")).toBeInTheDocument();
  });
});
