// Dual-locale coverage for localized boolean/derived cell renders (#385).
//
// Before this, the resource framework's column `render` callbacks received no
// translator, so boolean cells emitted hard-coded English "Yes"/"No" (and
// "Enabled"/"Disabled") even after a resource's copy migrated to i18n. #385
// threads the active `t` into `render` and adds the declarative `booleanColumn`
// helper. These tests prove a migrated boolean/derived cell resolves from the
// catalog in BOTH `en` and `zh-CN`, across each already-i18n'd resource group:
//   * routing/policy/quota  -> quota-policies `enabled`
//   * tenancy/IAM/billing   -> plans `mcp_enabled`, virtual-keys `enabled`
//   * gateway/agent/MCP/worker -> self-hosted-workers `orchestration_enabled`
//     (Enabled/Disabled) + `stale`, and agent-workflows `enabled` (read from
//     the unwrapped nested workflow via `booleanColumn`'s `value` accessor).
import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceTable } from "@/components/resource/resource-table";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { translate } from "@/i18n";
import { booleanColumn, type ColumnConfig } from "@/lib/resource-config";
import { agentWorkflowsConfig } from "@/resources/agent-workflows";
import { plansConfig } from "@/resources/plans";
import { quotaPoliciesConfig } from "@/resources/quota-policies";
import { selfHostedWorkersConfig } from "@/resources/self-hosted-workers";
import { virtualKeysConfig } from "@/resources/virtual-keys";
import { renderWithProviders } from "@/test/test-utils";

function setDesktopViewport(matches: boolean) {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockImplementation(() => ({
      matches,
      media: "(min-width: 1024px)",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

beforeEach(() => setDesktopViewport(true));

// The real configs carry precisely-typed row shapes (generated OpenAPI schemas,
// discriminated unions). These integration cases only exercise the boolean
// cells, so the columns are relaxed to a plain record and fed minimal rows.
type AnyColumns = ColumnConfig<Record<string, unknown>>[];
const asColumns = (columns: unknown): AnyColumns => columns as AnyColumns;

interface Row extends Record<string, unknown> {
  flag: boolean;
}

describe("booleanColumn helper", () => {
  it("preserves the typed header key and layout hints, and drops no `header`", () => {
    const col = booleanColumn<Row>({
      key: "flag",
      headerKey: "resource.plans.col.mcp",
      priority: "secondary",
      minWidth: 90,
      mobileVisibility: "always",
    });
    expect(col.key).toBe("flag");
    expect(col.headerKey).toBe("resource.plans.col.mcp");
    expect(col.header).toBeUndefined();
    expect(col.priority).toBe("secondary");
    expect(col.minWidth).toBe(90);
    expect(col.mobileVisibility).toBe("always");
    expect(typeof col.render).toBe("function");
  });

  it("resolves default Yes/No via the active translator in both locales", () => {
    const col = booleanColumn<Row>({ key: "flag", headerKey: "resource.plans.col.mcp" });
    const tEn = (k: Parameters<typeof translate>[1]) => translate("en", k);
    const tZh = (k: Parameters<typeof translate>[1]) => translate("zh-CN", k);
    expect(col.render!({ flag: true }, tEn)).toBe(en["common.yes"]);
    expect(col.render!({ flag: false }, tEn)).toBe(en["common.no"]);
    expect(col.render!({ flag: true }, tZh)).toBe(zhCN["common.yes"]);
    expect(col.render!({ flag: false }, tZh)).toBe(zhCN["common.no"]);
  });

  it("honors custom true/false keys (Enabled/Disabled) and a `value` accessor", () => {
    const col = booleanColumn<Row>({
      key: "ignored",
      headerKey: "resource.selfHostedWorkers.col.orchestration",
      value: (row) => row.flag,
      trueKey: "common.enabled",
      falseKey: "common.disabled",
    });
    const tZh = (k: Parameters<typeof translate>[1]) => translate("zh-CN", k);
    expect(col.render!({ flag: true }, tZh)).toBe(zhCN["common.enabled"]);
    expect(col.render!({ flag: false }, tZh)).toBe(zhCN["common.disabled"]);
  });
});

const quotaRow = {
  id: "q1",
  scope_type: "tenant",
  scope_id: "tenant-1",
  model_allowlist: [],
  rpm_limit: 60,
  tpm_limit: null,
  monthly_budget_usd: null,
  asset_storage_quota_bytes: null,
  enabled: true,
  created_at_unix: 0,
  updated_at_unix: 0,
};

describe("routing/policy/quota: quota-policies `enabled` cell localizes", () => {
  it("renders English Yes", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(quotaPoliciesConfig.columns)} rows={[quotaRow]} isLoading={false} readOnly />,
      { locale: "en" },
    );
    expect(screen.getByRole("cell", { name: en["common.yes"] })).toBeInTheDocument();
  });

  it("renders Simplified Chinese 是", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(quotaPoliciesConfig.columns)} rows={[quotaRow]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(screen.getByRole("cell", { name: zhCN["common.yes"] })).toBeInTheDocument();
  });
});

const planRow = {
  id: "p1",
  name: "Pro",
  slug: "pro",
  mcp_enabled: true,
  extension_tools_enabled: false,
  self_hosted_workers_enabled: false,
  asset_hosting_enabled: false,
  default_monthly_budget_usd: 100,
};

describe("tenancy/IAM/billing: plans + virtual-keys boolean cells localize", () => {
  it("renders English Yes/No across the plan boolean columns", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(plansConfig.columns)} rows={[planRow]} isLoading={false} readOnly />,
      { locale: "en" },
    );
    const cells = screen.getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toContain(en["common.yes"]);
    expect(cells).toContain(en["common.no"]);
  });

  it("renders Simplified Chinese 是/否 across the plan boolean columns", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(plansConfig.columns)} rows={[planRow]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    const cells = screen.getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toContain(zhCN["common.yes"]);
    expect(cells).toContain(zhCN["common.no"]);
  });

  it("renders virtual-keys `enabled` in Simplified Chinese", () => {
    const vkRow = {
      id: "vk1",
      name: "svc",
      key_prefix: "fg",
      last4: "1234",
      workspace_id: "ws1",
      enabled: false,
      scopes: ["admin.read"],
    };
    renderWithProviders(
      <ResourceTable columns={asColumns(virtualKeysConfig.columns)} rows={[vkRow]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(screen.getByRole("cell", { name: zhCN["common.no"] })).toBeInTheDocument();
  });
});

const workerRow = {
  id: "w1",
  worker_name: "edge-1",
  status: "online",
  trust_level: "trusted",
  stale: false,
  orchestration_enabled: true,
  registered_at_unix: 0,
  last_seen_at_unix: 0,
  telemetry_event_count: 3,
};

describe("gateway/agent/MCP/worker: self-hosted-workers + agent-workflows cells localize", () => {
  it("renders English Enabled + No", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(selfHostedWorkersConfig.columns)} rows={[workerRow]} isLoading={false} readOnly />,
      { locale: "en" },
    );
    expect(screen.getByRole("cell", { name: en["common.enabled"] })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: en["common.no"] })).toBeInTheDocument();
  });

  it("renders Simplified Chinese 已启用 + 否", () => {
    renderWithProviders(
      <ResourceTable columns={asColumns(selfHostedWorkersConfig.columns)} rows={[workerRow]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(screen.getByRole("cell", { name: zhCN["common.enabled"] })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: zhCN["common.no"] })).toBeInTheDocument();
  });

  it("localizes agent-workflows `enabled` read from the nested workflow record", () => {
    const wfRow = {
      workflow: { id: "wf1", name: "triage", version: 1, enabled: true, nodes: [], edges: [] },
      counters: {
        request_count: 5,
        error_count: 0,
        billing_event_count: 0,
        audit_event_count: 0,
        estimated_tokens: 0,
      },
    };
    renderWithProviders(
      <ResourceTable columns={asColumns(agentWorkflowsConfig.columns)} rows={[wfRow]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(screen.getByRole("cell", { name: zhCN["common.yes"] })).toBeInTheDocument();
  });
});
