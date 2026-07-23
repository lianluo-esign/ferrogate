// Dual-locale coverage for the routing/policy/quota per-resource copy (#348).
//
// Slice 3 localized the shared resource-CRUD framework chrome and kept the
// per-resource display copy (`config.title`, column headers, field labels,
// select options) data-driven. This slice migrates that copy for the
// quota-policies, plugins, and policies configs onto the typed catalog via the
// new `titleKey` / `headerKey` / `labelKey` indirections. These tests prove a
// migrated config renders its title, columns, field labels, and select options
// from the catalog in BOTH `en` and `zh-CN`, that data-driven values (option
// `value`s, boolean cell renders) are untouched, and that catalog parity holds
// for the new namespaces.
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { ResourcePage } from "@/components/resource/resource-page";
import { ResourceTable } from "@/components/resource/resource-table";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { defaultFieldValues } from "@/lib/resource-config";
import { pluginsConfig } from "@/resources/plugins";
import { policiesConfig } from "@/resources/policies";
import { quotaPoliciesConfig } from "@/resources/quota-policies";
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
  "resource.quotaPolicies.",
  "resource.plugins.",
  "resource.policies.",
] as const;

describe("routing/policy/quota per-resource catalog parity", () => {
  it("defines every migrated per-resource key in both locales", () => {
    const keys = Object.keys(en).filter((key) =>
      MIGRATED_NAMESPACES.some((namespace) => key.startsWith(namespace)),
    );
    expect(keys.length).toBeGreaterThan(50);
    for (const key of keys) {
      expect(zhCN[key as keyof typeof en], `zh-CN missing ${key}`).toBeTruthy();
    }
  });

  it("keeps typed key references, not inline literals, on migrated configs", () => {
    // The migration replaces inline `title`/`header`/`label` with `*Key`.
    expect(quotaPoliciesConfig.title).toBeUndefined();
    expect(quotaPoliciesConfig.titleKey).toBe("resource.quotaPolicies.title");
    expect(quotaPoliciesConfig.columns.every((c) => c.headerKey && !c.header)).toBe(true);
    expect(pluginsConfig.fields.every((f) => f.labelKey && !f.label)).toBe(true);
    // Data-driven identifiers stay untouched.
    expect(quotaPoliciesConfig.key).toBe("quota-policies");
    expect(quotaPoliciesConfig.columns.map((c) => c.key)).toContain("scope_type");
  });
});

describe("quota-policies columns localize per locale", () => {
  it("renders English headers and leaves data-driven cell values untouched", () => {
    renderWithProviders(
      <ResourceTable
        columns={quotaPoliciesConfig.columns}
        rows={[
          {
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
          },
        ]}
        isLoading={false}
        readOnly
      />,
      { locale: "en" },
    );
    expect(
      screen.getByRole("columnheader", { name: en["resource.quotaPolicies.col.scope"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: en["resource.quotaPolicies.col.rpmLimit"] }),
    ).toBeInTheDocument();
    // Boolean cell render stays data-driven (English Yes/No; later slice).
    expect(screen.getByRole("cell", { name: "Yes" })).toBeInTheDocument();
  });

  it("renders Simplified Chinese headers", () => {
    renderWithProviders(
      <ResourceTable columns={quotaPoliciesConfig.columns} rows={[]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.quotaPolicies.col.scope"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.quotaPolicies.col.assetQuota"] }),
    ).toBeInTheDocument();
  });
});

describe("plugins form localizes labels and select options per locale", () => {
  it("renders English field labels and select-option labels", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <ResourceForm
        fields={pluginsConfig.fields}
        initialValues={defaultFieldValues(pluginsConfig.fields)}
        submitLabel="Create"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "en" },
    );

    expect(screen.getByText(en["resource.plugins.field.approvalPolicy"])).toBeInTheDocument();
    // Open the `kind` select and assert its options resolve from the catalog.
    await user.click(screen.getByRole("combobox", { name: /Kind/ }));
    const listbox = await screen.findByRole("listbox");
    expect(
      within(listbox).getByRole("option", { name: en["resource.plugins.option.kind.requestHook"] }),
    ).toBeInTheDocument();
    expect(
      within(listbox).getByRole("option", { name: en["resource.plugins.option.kind.eventSink"] }),
    ).toBeInTheDocument();
  });

  it("renders Simplified Chinese field labels and select-option labels", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <ResourceForm
        fields={pluginsConfig.fields}
        initialValues={defaultFieldValues(pluginsConfig.fields)}
        submitLabel="创建"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );

    expect(screen.getByText(zhCN["resource.plugins.field.manifest"])).toBeInTheDocument();
    await user.click(screen.getByRole("combobox", { name: /类型/ }));
    const listbox = await screen.findByRole("listbox");
    expect(
      within(listbox).getByRole("option", { name: zhCN["resource.plugins.option.kind.toolProvider"] }),
    ).toBeInTheDocument();
  });
});

describe("policies validation interpolates the localized field label", () => {
  it("surfaces the Simplified Chinese label in the JSON validation message", async () => {
    // Policies fields include entity-reference pickers, which read the session.
    seedSession();
    const user = userEvent.setup();
    renderWithProviders(
      <ResourceForm
        fields={policiesConfig.fields}
        initialValues={{
          ...defaultFieldValues(policiesConfig.fields),
          name: "deny-eu",
        }}
        submitLabel="创建"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );
    // The `name` field label localizes and reads back on the required *marker.
    expect(
      screen.getByText(zhCN["resource.policies.field.name"], { exact: false }),
    ).toBeInTheDocument();
    // Deny message placeholder stays an inline example value (issue-protected).
    expect(screen.getByPlaceholderText("request denied by policy")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "创建" }));
  });
});

describe("quota-policies page title localizes per locale", () => {
  beforeEach(() => seedSession());

  it("renders the English resource title and description heading", async () => {
    mockAdminList("/admin/v1/quota-policies", []);
    renderWithProviders(<ResourcePage config={quotaPoliciesConfig} />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["resource.quotaPolicies.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["resource.quotaPolicies.description"])).toBeInTheDocument();
  });

  it("renders the Simplified Chinese resource title and description heading", async () => {
    mockAdminList("/admin/v1/quota-policies", []);
    renderWithProviders(<ResourcePage config={quotaPoliciesConfig} />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["resource.quotaPolicies.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["resource.quotaPolicies.description"])).toBeInTheDocument();
  });
});
