// Bilingual smoke coverage for the #348 bespoke-page slice: virtual-keys,
// site-domains, and ops-status must render their page-local copy from the typed
// catalog in BOTH `en` and `zh-CN`. This proves the migration actually routes
// through `t()` (no residual hard-coded English) — the runtime companion to the
// `ferrogate/no-untranslated-literal` lint gate now enforced on these files.
import { screen, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import VirtualKeysPage from "@/pages/virtual-keys";
import SiteDomainsPage from "@/pages/site-domains";
import OpsStatusPage from "@/pages/ops-status";
import AgentRunsPage from "@/pages/agent-runs";
import AgentSchedulesPage from "@/pages/agent-schedules";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

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
