// Dual-locale coverage for the gateway-setup / agent / MCP / worker per-resource
// copy + read-only logs (#348).
//
// Slice 4 threaded typed catalog keys into the resource-config layer; slices 4
// and 5 migrated the routing/policy/quota and tenancy/IAM/billing groups. This
// slice migrates the gateway-setup / agent / MCP / worker group (providers,
// models, agent-upstreams, agent-workflows, skill-packages, prompt-templates,
// mcp-servers, self-hosted-workers, managed-workers) plus the read-only logs
// (request-logs, audit-events) so their title, column headers, field labels/
// descriptions, and select-option labels resolve from the typed catalog via the
// `titleKey` / `headerKey` / `labelKey` / `descriptionKey` indirections. These
// tests prove a migrated config renders that copy in BOTH `en` and `zh-CN`, that
// data-driven values (column `key`s, boolean cell renders) are untouched, and
// that catalog parity holds for the new namespaces.
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { ResourcePage } from "@/components/resource/resource-page";
import { ResourceTable } from "@/components/resource/resource-table";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { defaultFieldValues } from "@/lib/resource-config";
import { agentUpstreamsConfig } from "@/resources/agent-upstreams";
import { auditEventsConfig } from "@/resources/audit-events";
import { promptTemplatesConfig } from "@/resources/prompt-templates";
import { providersConfig } from "@/resources/providers";
import { requestLogsConfig } from "@/resources/request-logs";
import { skillPackagesConfig } from "@/resources/skill-packages";
import { mockAdminList } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

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

const MIGRATED_NAMESPACES = [
  "resource.providers.",
  "resource.models.",
  "resource.agentUpstreams.",
  "resource.agentWorkflows.",
  "resource.skillPackages.",
  "resource.promptTemplates.",
  "resource.mcpServers.",
  "resource.selfHostedWorkers.",
  "resource.managedWorkers.",
  "resource.requestLogs.",
  "resource.auditEvents.",
] as const;

describe("gateway/agent/MCP/worker + logs per-resource catalog parity", () => {
  it("defines every migrated per-resource key in both locales", () => {
    const keys = Object.keys(en).filter((key) =>
      MIGRATED_NAMESPACES.some((namespace) => key.startsWith(namespace)),
    );
    expect(keys.length).toBeGreaterThan(100);
    for (const key of keys) {
      expect(zhCN[key as keyof typeof en], `zh-CN missing ${key}`).toBeTruthy();
    }
  });

  it("keeps typed key references, not inline literals, on migrated configs", () => {
    // Read-only configs: title/description keyed, every column header keyed.
    expect(providersConfig.title).toBeUndefined();
    expect(providersConfig.titleKey).toBe("resource.providers.title");
    expect(providersConfig.columns.every((c) => c.headerKey && !c.header)).toBe(true);
    expect(requestLogsConfig.columns.every((c) => c.headerKey && !c.header)).toBe(true);
    expect(auditEventsConfig.titleKey).toBe("resource.auditEvents.title");
    // CRUD configs: every field label keyed, including select-option labels.
    expect(agentUpstreamsConfig.fields.every((f) => f.labelKey && !f.label)).toBe(true);
    const statusOptions = promptTemplatesConfig.fields.find((f) => f.name === "status");
    expect(statusOptions?.options?.every((o) => o.labelKey && !o.label)).toBe(true);
    // Data-driven identifiers stay untouched.
    expect(providersConfig.key).toBe("providers");
    expect(providersConfig.columns.map((c) => c.key)).toContain("has_api_key");
    expect(agentUpstreamsConfig.fields.map((f) => f.name)).toContain("tenant_ids");
  });
});

describe("providers columns localize per locale", () => {
  const row = {
    name: "openai",
    kind: "openai",
    compatibility: "openai",
    base_url: "https://api.openai.com",
    has_api_key: true,
    enabled: true,
  };

  it("renders English headers and leaves data-driven cell values untouched", () => {
    renderWithProviders(
      <ResourceTable columns={providersConfig.columns} rows={[row]} isLoading={false} readOnly />,
      { locale: "en" },
    );
    expect(
      screen.getByRole("columnheader", { name: en["resource.providers.col.baseUrl"] }),
    ).toBeInTheDocument();
    // Identifier cell value is byte-for-byte unchanged by the header migration.
    expect(screen.getByRole("cell", { name: "https://api.openai.com" })).toBeInTheDocument();
  });

  it("renders Simplified Chinese headers", () => {
    renderWithProviders(
      <ResourceTable columns={providersConfig.columns} rows={[]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.providers.col.baseUrl"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.providers.col.hasApiKey"] }),
    ).toBeInTheDocument();
  });
});

describe("skill-packages form localizes field labels per locale", () => {
  it("renders English field labels", () => {
    renderWithProviders(
      <ResourceForm
        fields={skillPackagesConfig.fields}
        initialValues={defaultFieldValues(skillPackagesConfig.fields)}
        submitLabel="Create"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "en" },
    );
    // Required text fields append the " *" marker to the localized label.
    expect(
      screen.getByLabelText(`${en["resource.skillPackages.field.name"]} *`),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(en["resource.skillPackages.field.apiKeyIds"]),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese field labels", () => {
    renderWithProviders(
      <ResourceForm
        fields={skillPackagesConfig.fields}
        initialValues={defaultFieldValues(skillPackagesConfig.fields)}
        submitLabel="创建"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );
    expect(
      screen.getByLabelText(`${zhCN["resource.skillPackages.field.name"]} *`),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(zhCN["resource.skillPackages.field.apiKeyIds"]),
    ).toBeInTheDocument();
  });
});

describe("prompt-templates select options localize per locale", () => {
  // The `model` field is an entity picker; stub its (empty) options list so the
  // form's picker never issues an unhandled request under MSW.
  beforeEach(() => {
    seedSession();
    mockAdminList("/admin/v1/models", []);
  });

  it("renders English field labels and select-option labels", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <ResourceForm
        fields={promptTemplatesConfig.fields}
        initialValues={defaultFieldValues(promptTemplatesConfig.fields)}
        submitLabel="Create"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "en" },
    );
    expect(screen.getByText(en["resource.promptTemplates.field.target"])).toBeInTheDocument();
    // Open the `status` select and assert its options resolve from the catalog.
    await user.click(
      screen.getByRole("combobox", { name: en["resource.promptTemplates.field.status"] }),
    );
    const listbox = await screen.findByRole("listbox");
    expect(
      within(listbox).getByRole("option", {
        name: en["resource.promptTemplates.option.status.draft"],
      }),
    ).toBeInTheDocument();
    expect(
      within(listbox).getByRole("option", {
        name: en["resource.promptTemplates.option.status.archived"],
      }),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese field labels and select-option labels", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <ResourceForm
        fields={promptTemplatesConfig.fields}
        initialValues={defaultFieldValues(promptTemplatesConfig.fields)}
        submitLabel="创建"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );
    expect(screen.getByText(zhCN["resource.promptTemplates.field.target"])).toBeInTheDocument();
    await user.click(
      screen.getByRole("combobox", { name: zhCN["resource.promptTemplates.field.status"] }),
    );
    const listbox = await screen.findByRole("listbox");
    expect(
      within(listbox).getByRole("option", {
        name: zhCN["resource.promptTemplates.option.status.archived"],
      }),
    ).toBeInTheDocument();
  });
});

describe("request-logs page title localizes per locale", () => {
  beforeEach(() => seedSession());

  it("renders the English resource title and description heading", async () => {
    mockAdminList("/admin/v1/request-logs", []);
    renderWithProviders(<ResourcePage config={requestLogsConfig} />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["resource.requestLogs.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["resource.requestLogs.description"])).toBeInTheDocument();
  });

  it("renders the Simplified Chinese resource title and description heading", async () => {
    mockAdminList("/admin/v1/request-logs", []);
    renderWithProviders(<ResourcePage config={requestLogsConfig} />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["resource.requestLogs.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["resource.requestLogs.description"])).toBeInTheDocument();
  });
});
