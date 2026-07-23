// Bilingual smoke coverage for the #348 bespoke-page slice: virtual-keys,
// site-domains, and ops-status must render their page-local copy from the typed
// catalog in BOTH `en` and `zh-CN`. This proves the migration actually routes
// through `t()` (no residual hard-coded English) — the runtime companion to the
// `ferrogate/no-untranslated-literal` lint gate now enforced on these files.
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import VirtualKeysPage from "@/pages/virtual-keys";
import SiteDomainsPage from "@/pages/site-domains";
import OpsStatusPage from "@/pages/ops-status";
import AgentRunsPage from "@/pages/agent-runs";
import AgentSchedulesPage from "@/pages/agent-schedules";
import GuardrailPoliciesPage from "@/pages/guardrail-policies";
import GuardrailEvaluationsPage from "@/pages/guardrail-evaluations";
import GuardrailPolicyDetailPage from "@/pages/guardrail-policy-detail";
import BillingWalletsPage from "@/pages/billing-wallets";
import BillingPaymentMethodsPage from "@/pages/billing-payment-methods";
import BillingMeteringPage from "@/pages/billing-metering";
import BillingDeadLettersPage from "@/pages/billing-dead-letters";
import ToolsCatalogPage from "@/pages/tools-catalog";
import ToolSessionsPage from "@/pages/tool-sessions";
import ToolApprovalsPage from "@/pages/tool-approvals";
import TenantRolesPage from "@/pages/tenant-roles";
import McpIdentitiesPage from "@/pages/mcp-identities";
import InvestigationsPage from "@/pages/investigations";
import AssetsPage from "@/pages/assets";
import ManagedWorkerSessionsPage from "@/pages/managed-worker-sessions";
import PluginToolsPage from "@/pages/plugin-tools";
import SelfHostedRunsPage from "@/pages/self-hosted-runs";
import SelfHostedWorkerDetailPage from "@/pages/self-hosted-worker-detail";
import { policyRevision } from "@/test/fixtures/guardrails";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import {
  createTestQueryClient,
  renderWithProviders,
  seedSession,
} from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

describe("virtual-keys page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/virtual-keys", []);
  });

  it("renders English title, description, and empty state", async () => {
    renderWithProviders(<VirtualKeysPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.virtualKeys.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.virtualKeys.description"])).toBeInTheDocument();
    expect(await screen.findByText(en["page.virtualKeys.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, description, and empty state", async () => {
    renderWithProviders(<VirtualKeysPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.virtualKeys.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.virtualKeys.description"])).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.virtualKeys.empty"])).toBeInTheDocument();
  });
});

describe("site-domains page copy is localized", () => {
  beforeEach(() => {
    server.use(
      http.get(gatewayUrl("/admin/v1/site-domains"), () =>
        HttpResponse.json({ object: "list", data: [] }),
      ),
    );
  });

  it("renders English title and bind-form copy", async () => {
    renderWithProviders(<SiteDomainsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.siteDomains.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.siteDomains.bind.title"])).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.siteDomains.bind.submit"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(en["page.siteDomains.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title and bind-form copy", async () => {
    renderWithProviders(<SiteDomainsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.siteDomains.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.siteDomains.bind.title"])).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.siteDomains.bind.submit"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.siteDomains.empty"])).toBeInTheDocument();
  });
});

// A minimal AdminStatus fixture: only the fields ops-status reads. Cast through
// unknown because the generated schema is wide and this test only asserts copy.
function statusFixture() {
  return {
    object: "status",
    service: "ferrogate",
    version: "1.2.3",
    runtime: "tokio",
    snapshot: "snap-1",
    auth_required: true,
    providers: 2,
    enabled_providers: 1,
    models: 4,
    enabled_models: 3,
    upstreams: 1,
    enabled_upstreams: 1,
    routes: 5,
    enabled_routes: 5,
    api_keys: 7,
    plugins: 2,
    active_plugins: 1,
    extensions: 0,
    active_extensions: 0,
    tools: 9,
    acme: { enabled: false, reload_required: false },
    cluster: {
      enabled: true,
      ready: true,
      draining: false,
      accepting_new_requests: true,
      readiness_reason: "ok",
      node_id: "node-1",
      cluster_id: "cluster-1",
      active_revision: "rev-1",
      state_backend: "memory",
      counter_backend: "memory",
      last_sync_at_unix: 1000,
      stale: false,
    },
    storage: {
      provider: "postgres",
      health: "ok",
      durable: true,
      required: true,
      migration_mode: "auto",
    },
    analytics: {
      provider: "clickhouse",
      health: "ok",
      mode: "batch",
      active: true,
      last_success_at_unix: 1000,
    },
  } as unknown as Parameters<typeof HttpResponse.json>[0];
}

describe("ops-status page copy is localized", () => {
  beforeEach(() => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () => HttpResponse.json(statusFixture())),
    );
  });

  it("renders English board copy and reuses common.yes for boolean cells", async () => {
    renderWithProviders(<OpsStatusPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.opsStatus.title"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(en["page.opsStatus.acme.title"])).toBeInTheDocument();
    expect(screen.getByText(en["page.opsStatus.cluster.title"])).toBeInTheDocument();
    // Boolean posture chips reuse the #385 common.yes key (cluster is enabled).
    const cluster = screen.getByText(en["page.opsStatus.cluster.enabled"]).closest("div")!;
    expect(within(cluster).getByText(en["common.yes"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese board copy and reuses common.yes for boolean cells", async () => {
    renderWithProviders(<OpsStatusPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.opsStatus.title"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.opsStatus.acme.title"])).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.opsStatus.cluster.title"])).toBeInTheDocument();
    const cluster = screen.getByText(zhCN["page.opsStatus.cluster.enabled"]).closest("div")!;
    expect(within(cluster).getByText(zhCN["common.yes"])).toBeInTheDocument();
  });
});

describe("agent-runs page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/agent-runs", []);
  });

  it("renders English title, description, and empty state", async () => {
    renderWithProviders(<AgentRunsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.agentRuns.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.agentRuns.description"])).toBeInTheDocument();
    expect(await screen.findByText(en["page.agentRuns.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, description, and empty state", async () => {
    renderWithProviders(<AgentRunsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.agentRuns.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.agentRuns.description"])).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.agentRuns.empty"])).toBeInTheDocument();
  });
});

describe("agent-schedules page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/agent-schedules", []);
  });

  it("renders English title, new-schedule action, and empty state", async () => {
    renderWithProviders(<AgentSchedulesPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.agentSchedules.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.agentSchedules.new"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(en["page.agentSchedules.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, new-schedule action, and empty state", async () => {
    renderWithProviders(<AgentSchedulesPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.agentSchedules.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.agentSchedules.new"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.agentSchedules.empty"])).toBeInTheDocument();
  });
});

describe("guardrail-policies page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/guardrail-policies", []);
  });

  it("renders English title, description, and empty state", async () => {
    renderWithProviders(<GuardrailPoliciesPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.guardrailPolicies.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.guardrailPolicies.description"])).toBeInTheDocument();
    expect(await screen.findByText(en["page.guardrailPolicies.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, description, and empty state", async () => {
    renderWithProviders(<GuardrailPoliciesPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.guardrailPolicies.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.guardrailPolicies.description"])).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.guardrailPolicies.empty"])).toBeInTheDocument();
  });
});

describe("guardrail-evaluations page copy is localized", () => {
  beforeEach(() => {
    server.use(
      http.get(gatewayUrl("/admin/v1/guardrail-evaluations"), () =>
        HttpResponse.json({ object: "list", data: [], total: 0, offset: 0, limit: 100 }),
      ),
    );
  });

  it("renders English title, filter action, and empty state", async () => {
    renderWithProviders(<GuardrailEvaluationsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.guardrailEvaluations.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.guardrailEvaluations.filter.apply"] }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(en["page.guardrailEvaluations.empty"]),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, filter action, and empty state", async () => {
    renderWithProviders(<GuardrailEvaluationsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.guardrailEvaluations.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.guardrailEvaluations.filter.apply"] }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(zhCN["page.guardrailEvaluations.empty"]),
    ).toBeInTheDocument();
  });
});

// The detail page reads its policyId from the route, so it needs a real router
// entry (renderWithProviders' bare MemoryRouter has no param). This mirrors the
// guardrail-policy-detail.test.tsx harness with a forced locale.
function renderDetail(locale: Locale, policyId = "pol-pii") {
  return render(
    <MemoryRouter initialEntries={[`/app/guardrail-policies/${policyId}`]}>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route
                path="/app/guardrail-policies/:policyId"
                element={<GuardrailPolicyDetailPage />}
              />
            </Routes>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

describe("guardrail-policy-detail page copy is localized", () => {
  beforeEach(() => {
    server.use(
      http.get(gatewayUrl("/admin/v1/guardrail-policies/pol-pii/revisions"), () =>
        HttpResponse.json({
          object: "list",
          data: [policyRevision({ revision: 1, status: "active" })],
        }),
      ),
    );
  });

  it("renders English active-revision, history, and dry-run copy", async () => {
    renderDetail("en");
    expect(
      await screen.findByText(en["page.guardrailPolicyDetail.active.title"]),
    ).toBeInTheDocument();
    expect(
      screen.getByText(en["page.guardrailPolicyDetail.history.title"]),
    ).toBeInTheDocument();
    expect(
      screen.getByText(en["page.guardrailPolicyDetail.dryRun.title"]),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese active-revision, history, and dry-run copy", async () => {
    renderDetail("zh-CN");
    expect(
      await screen.findByText(zhCN["page.guardrailPolicyDetail.active.title"]),
    ).toBeInTheDocument();
    expect(
      screen.getByText(zhCN["page.guardrailPolicyDetail.history.title"]),
    ).toBeInTheDocument();
    expect(
      screen.getByText(zhCN["page.guardrailPolicyDetail.dryRun.title"]),
    ).toBeInTheDocument();
  });
});

// --- Billing bespoke-page group (#348 billing slice) -------------------------
// These prove the four billing pages render page-local copy from the typed
// catalog in BOTH locales AND that money/usage values go through the locale
// formatter (`format.currency` / `format.number`), never a hand-rolled string.

/** The locale currency/number formatters the pages bind through `useI18n()`. */
function localeUsd(locale: Locale, amount: number): string {
  return new Intl.NumberFormat(locale, { style: "currency", currency: "USD" }).format(
    amount,
  );
}
function localeNumber(locale: Locale, value: number): string {
  return new Intl.NumberFormat(locale).format(value);
}

describe("billing-wallets page copy is localized", () => {
  function seedWallet() {
    server.use(
      http.get(gatewayUrl("/admin/v1/wallets"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              tenant_id: "org-acme",
              balance_credits: 250_000,
              auto_recharge_threshold_credits: null,
              auto_recharge_amount_credits: null,
              dunning: false,
              created_at_unix: 1_700_000_000,
              updated_at_unix: 1_700_000_500,
            },
          ],
        }),
      ),
    );
  }

  it("renders English title, balance header, and locale-formatted balance", async () => {
    seedWallet();
    renderWithProviders(<BillingWalletsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.billingWallets.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.billingWallets.col.balance"])).toBeInTheDocument();
    // Balance is the API's exact value rendered via the locale number formatter.
    expect(await screen.findByText(localeNumber("en", 250_000))).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, balance header, and locale-formatted balance", async () => {
    seedWallet();
    renderWithProviders(<BillingWalletsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.billingWallets.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(zhCN["page.billingWallets.col.balance"]),
    ).toBeInTheDocument();
    expect(await screen.findByText(localeNumber("zh-CN", 250_000))).toBeInTheDocument();
  });
});

describe("billing-payment-methods page copy is localized", () => {
  it("renders English title and tenant prompt", async () => {
    renderWithProviders(<BillingPaymentMethodsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", {
        name: en["page.billingPaymentMethods.title"],
      }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(en["page.billingPaymentMethods.prompt"]),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.billingPaymentMethods.list"] }),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese title and tenant prompt", async () => {
    renderWithProviders(<BillingPaymentMethodsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", {
        name: zhCN["page.billingPaymentMethods.title"],
      }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(zhCN["page.billingPaymentMethods.prompt"]),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.billingPaymentMethods.list"] }),
    ).toBeInTheDocument();
  });
});

describe("billing-metering page copy is localized", () => {
  function seedEvents() {
    server.use(
      http.get(gatewayUrl("/admin/v1/metering-events"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              request_id: "req-me-1",
              tenant: { organization_id: "org-acme" },
              logical_model: "gpt-4o",
              provider: "openai",
              provider_model: "gpt-4o-2024",
              usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 1500 },
              usage_source: "provider_usage",
              status_code: 200,
              occurred_at_unix: 1_700_000_000,
            },
          ],
          total: 1,
          offset: 0,
          limit: 50,
        }),
      ),
    );
  }

  it("renders English title, tabs, pagination range, and token totals", async () => {
    seedEvents();
    renderWithProviders(<BillingMeteringPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.billingMetering.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: en["page.billingMetering.tab.export"] }),
    ).toBeInTheDocument();
    // Token totals go through the locale number formatter.
    expect(await screen.findByText(localeNumber("en", 1500))).toBeInTheDocument();
    expect(
      screen.getByText(
        en["page.billingMetering.events.range"]
          .replace("{start}", "1")
          .replace("{end}", "1")
          .replace("{total}", "1"),
      ),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, tabs, and pagination range", async () => {
    seedEvents();
    renderWithProviders(<BillingMeteringPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.billingMetering.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: zhCN["page.billingMetering.tab.aggregates"] }),
    ).toBeInTheDocument();
    // Wait for the query so the pagination range reflects the loaded total.
    expect(await screen.findByText(localeNumber("zh-CN", 1500))).toBeInTheDocument();
    expect(
      screen.getByText(
        zhCN["page.billingMetering.events.range"]
          .replace("{start}", "1")
          .replace("{end}", "1")
          .replace("{total}", "1"),
      ),
    ).toBeInTheDocument();
  });
});

describe("billing-dead-letters page copy is localized", () => {
  function seedDeadLetter() {
    server.use(
      http.get(gatewayUrl("/admin/v1/billing-outbox-dead-letters"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              id: "led-dead-1",
              event: {
                request_id: "req-dead-1",
                trace_id: "trace-dead-1",
                tenant: { organization_id: "org-acme" },
                logical_model: "gpt-4o",
                provider: "openai",
                provider_model: "gpt-4o-2024",
                status_code: 200,
                cost_usd: 0.42,
                occurred_at_unix: 1_700_000_000,
              },
              attempts: 7,
              next_attempt_unix: 1_700_000_100,
              dead_lettered_at_unix: 1_700_000_500,
            },
          ],
        }),
      ),
    );
  }

  it("renders English title and formats the cost through the USD formatter", async () => {
    const user = userEvent.setup();
    seedDeadLetter();
    renderWithProviders(<BillingDeadLettersPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.billingDeadLetters.title"] }),
    ).toBeInTheDocument();

    await user.click(
      await screen.findByRole("button", { name: en["page.billingDeadLetters.details"] }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(en["page.billingDeadLetters.detail.cost"]),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(localeUsd("en", 0.42))).toBeInTheDocument();
  });

  it("renders Simplified Chinese title and formats the cost through the USD formatter", async () => {
    const user = userEvent.setup();
    seedDeadLetter();
    renderWithProviders(<BillingDeadLettersPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", {
        name: zhCN["page.billingDeadLetters.title"],
      }),
    ).toBeInTheDocument();

    await user.click(
      await screen.findByRole("button", {
        name: zhCN["page.billingDeadLetters.details"],
      }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(zhCN["page.billingDeadLetters.detail.cost"]),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(localeUsd("zh-CN", 0.42))).toBeInTheDocument();
  });
});

// --- Tool / tenant-roles bespoke-page group (#348 slice) ---------------------
// Proves the six pages render their page-local copy from the typed catalog in
// BOTH `en` and `zh-CN`, the runtime companion to the de-allowlisted lint gate.

describe("tools-catalog page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/tools", []);
  });

  it("renders English title and description", async () => {
    renderWithProviders(<ToolsCatalogPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.toolsCatalog.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.toolsCatalog.description"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title and description", async () => {
    renderWithProviders(<ToolsCatalogPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.toolsCatalog.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.toolsCatalog.description"])).toBeInTheDocument();
  });
});

describe("tool-sessions page copy is localized", () => {
  it("renders English title, lookup form, and prompt", async () => {
    renderWithProviders(<ToolSessionsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.toolSessions.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.toolSessions.inspect"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.toolSessions.prompt"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, lookup form, and prompt", async () => {
    renderWithProviders(<ToolSessionsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.toolSessions.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.toolSessions.inspect"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.toolSessions.prompt"])).toBeInTheDocument();
  });
});

describe("tool-approvals page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/tool-approvals", []);
  });

  it("renders English title, tabs, and empty state", async () => {
    renderWithProviders(<ToolApprovalsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.toolApprovals.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: en["page.toolApprovals.tab.history"] }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(en["page.toolApprovals.pending.empty"]),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, tabs, and empty state", async () => {
    renderWithProviders(<ToolApprovalsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.toolApprovals.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: zhCN["page.toolApprovals.tab.history"] }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(zhCN["page.toolApprovals.pending.empty"]),
    ).toBeInTheDocument();
  });
});

describe("tenant-roles page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/tenant-roles/tenant-1", []);
  });

  it("renders English title, assign action, and empty state", async () => {
    renderWithProviders(<TenantRolesPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.tenantRoles.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.tenantRoles.assign"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(en["page.tenantRoles.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, assign action, and empty state", async () => {
    renderWithProviders(<TenantRolesPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.tenantRoles.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.tenantRoles.assign"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.tenantRoles.empty"])).toBeInTheDocument();
  });
});

describe("mcp-identities page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/mcp-servers", []);
  });

  it("renders English title, server selector, and prompt", async () => {
    renderWithProviders(<McpIdentitiesPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.mcpIdentities.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.mcpIdentities.loadStatus"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.mcpIdentities.prompt"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, server selector, and prompt", async () => {
    renderWithProviders(<McpIdentitiesPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.mcpIdentities.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.mcpIdentities.loadStatus"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.mcpIdentities.prompt"])).toBeInTheDocument();
  });
});

describe("investigations page copy is localized", () => {
  it("renders English title, lookup action, and prompt", async () => {
    renderWithProviders(<InvestigationsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.investigations.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.investigations.investigate"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.investigations.prompt"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, lookup action, and prompt", async () => {
    renderWithProviders(<InvestigationsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.investigations.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.investigations.investigate"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.investigations.prompt"])).toBeInTheDocument();
  });
});

// --- Assets / worker / plugin bespoke-page group (#348 slice) ----------------
// Proves the five pages render their page-local copy from the typed catalog in
// BOTH `en` and `zh-CN`, the runtime companion to the de-allowlisted lint gate.

describe("assets page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/v1/assets", []);
    server.use(
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json({ used_bytes: 2048, quota_bytes: null }),
      ),
    );
  });

  it("renders English title, push form, and empty state", async () => {
    renderWithProviders(<AssetsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.assets.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.assets.push.title"])).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.assets.push.submit"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(en["page.assets.empty"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, push form, and empty state", async () => {
    renderWithProviders(<AssetsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.assets.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.assets.push.title"])).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.assets.push.submit"] }),
    ).toBeInTheDocument();
    expect(await screen.findByText(zhCN["page.assets.empty"])).toBeInTheDocument();
  });
});

describe("managed-worker-sessions page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/managed-worker-sessions", []);
  });

  it("renders English title, description, and empty state", async () => {
    renderWithProviders(<ManagedWorkerSessionsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", {
        name: en["page.managedWorkerSessions.title"],
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(en["page.managedWorkerSessions.description"]),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(en["page.managedWorkerSessions.empty"]),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, description, and empty state", async () => {
    renderWithProviders(<ManagedWorkerSessionsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", {
        name: zhCN["page.managedWorkerSessions.title"],
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(zhCN["page.managedWorkerSessions.description"]),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(zhCN["page.managedWorkerSessions.empty"]),
    ).toBeInTheDocument();
  });
});

// plugin-tools reads pluginId from the route, so it needs a real router entry.
function renderPluginTools(locale: Locale, pluginId = "plg-1") {
  return render(
    <MemoryRouter initialEntries={[`/app/plugins/${pluginId}/tools`]}>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route
                path="/app/plugins/:pluginId/tools"
                element={<PluginToolsPage />}
              />
            </Routes>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

describe("plugin-tools page copy is localized", () => {
  beforeEach(() => {
    mockAdminList("/admin/v1/plugins/plg-1/tools", []);
  });

  it("renders English back link, interpolated title, and description", async () => {
    renderPluginTools("en");
    expect(
      await screen.findByRole("heading", {
        name: en["page.pluginTools.title"].replace("{pluginId}", "plg-1"),
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.pluginTools.back"])).toBeInTheDocument();
    expect(screen.getByText(en["page.pluginTools.description"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese back link, interpolated title, and description", async () => {
    renderPluginTools("zh-CN");
    expect(
      await screen.findByRole("heading", {
        name: zhCN["page.pluginTools.title"].replace("{pluginId}", "plg-1"),
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.pluginTools.back"])).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.pluginTools.description"])).toBeInTheDocument();
  });
});

describe("self-hosted-runs page copy is localized", () => {
  it("renders English title, inspect action, and prompt", async () => {
    renderWithProviders(<SelfHostedRunsPage />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["page.selfHostedRuns.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.selfHostedRuns.inspect"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["page.selfHostedRuns.prompt"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese title, inspect action, and prompt", async () => {
    renderWithProviders(<SelfHostedRunsPage />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["page.selfHostedRuns.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.selfHostedRuns.inspect"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["page.selfHostedRuns.prompt"])).toBeInTheDocument();
  });
});

// A minimal self-hosted worker projection: only the fields the detail page reads.
function workerFixture() {
  return {
    id: "shw-1",
    worker_name: "edge-worker",
    workspace_id: "ws-1",
    tenant: { organization_id: "org-acme" },
    status: "active",
    stale: false,
    trust_level: "reported_by_self_hosted_worker",
    orchestration_enabled: true,
    identity_fingerprint: "sha256:abc",
    identity_expires_at_unix: null,
    registered_at_unix: 1_700_000_000,
    last_seen_at_unix: 1_700_000_500,
    stale_after_unix: 1_700_001_000,
    latest_heartbeat: null,
    telemetry_event_count: 3,
    latest_event_at_unix: 1_700_000_400,
    checkpoint_count: 1,
    latest_checkpoint_at_unix: 1_700_000_300,
    artifact_count: 0,
    latest_artifact_at_unix: null,
  } as unknown as Parameters<typeof HttpResponse.json>[0];
}

function renderWorkerDetail(locale: Locale, workerId = "shw-1") {
  return render(
    <MemoryRouter initialEntries={[`/app/workers/self-hosted/${workerId}`]}>
      <I18nProvider initialLocale={locale}>
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

describe("self-hosted-worker-detail page copy is localized", () => {
  beforeEach(() => {
    server.use(
      http.get(gatewayUrl("/admin/v1/self-hosted-workers/shw-1"), () =>
        HttpResponse.json(workerFixture()),
      ),
    );
    mockAdminList("/admin/v1/self-hosted-workers/shw-1/events", []);
  });

  it("renders English rotate action, count cards, and overview tab", async () => {
    renderWorkerDetail("en");
    expect(
      await screen.findByRole("button", { name: en["page.selfHostedWorkerDetail.rotate"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(en["page.selfHostedWorkerDetail.count.telemetry"]),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: en["page.selfHostedWorkerDetail.tab.overview"] }),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese rotate action, count cards, and overview tab", async () => {
    renderWorkerDetail("zh-CN");
    expect(
      await screen.findByRole("button", {
        name: zhCN["page.selfHostedWorkerDetail.rotate"],
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(zhCN["page.selfHostedWorkerDetail.count.telemetry"]),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: zhCN["page.selfHostedWorkerDetail.tab.overview"] }),
    ).toBeInTheDocument();
  });
});
