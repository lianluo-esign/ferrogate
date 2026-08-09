import { ResourceForm } from "@/components/resource/resource-form";
import { ResourcePage } from "@/components/resource/resource-page";
import { ResourceTable } from "@/components/resource/resource-table";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { defaultFieldValues } from "@/lib/resource-config";
import { permissionsConfig } from "@/resources/permissions";
import { plansConfig } from "@/resources/plans";
import { tenantAccountsConfig } from "@/resources/tenant-accounts";
import { virtualKeysConfig } from "@/resources/virtual-keys";
import { mockAdminList } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
// Dual-locale coverage for the tenancy / IAM / billing per-resource copy (#348).
//
// Slice 4 threaded typed catalog keys into the resource-config layer and
// migrated the routing/policy/quota group. This slice migrates the tenancy /
// IAM / billing group (tenant-accounts, projects, workspaces, plans, api-keys,
// virtual-keys, roles, permissions, billing-events, usage-reports) so their
// title, column headers, and field labels resolve from the typed catalog via
// the `titleKey` / `headerKey` / `labelKey` / `descriptionKey` indirections.
// These tests prove a migrated config renders that copy in BOTH `en` and
// `zh-CN`, that data-driven values (column `key`s, boolean cell renders) are
// untouched, and that catalog parity holds for the new namespaces.
import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
  "resource.tenantAccounts.",
  "resource.projects.",
  "resource.workspaces.",
  "resource.plans.",
  "resource.apiKeys.",
  "resource.virtualKeys.",
  "resource.roles.",
  "resource.permissions.",
  "resource.billingEvents.",
  "resource.usageReports.",
] as const;

describe("tenancy/IAM/billing per-resource catalog parity", () => {
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
    // Fully migrated configs carry only keys.
    expect(tenantAccountsConfig.title).toBeUndefined();
    expect(tenantAccountsConfig.titleKey).toBe("resource.tenantAccounts.title");
    expect(tenantAccountsConfig.columns.every((c) => c.headerKey && !c.header)).toBe(true);
    expect(plansConfig.fields.every((f) => f.labelKey && !f.label)).toBe(true);
    // Data-driven identifiers stay untouched.
    expect(tenantAccountsConfig.key).toBe("tenant-accounts");
    expect(tenantAccountsConfig.columns.map((c) => c.key)).toContain("plan_id");
    // Virtual keys is a partial migration: its bespoke page reads title/
    // description page-locally, so those stay inline while columns/fields (which
    // flow through the shared framework components) are key-driven.
    expect(virtualKeysConfig.title).toBe("API / virtual keys");
    expect(virtualKeysConfig.columns.every((c) => c.headerKey && !c.header)).toBe(true);
    expect(virtualKeysConfig.fields.every((f) => f.labelKey && !f.label)).toBe(true);
  });
});

describe("tenant-accounts columns localize per locale", () => {
  const row = {
    id: "tenant-1",
    name: "Acme",
    slug: "acme",
    status: "active",
    plan_id: "plan-pro",
    created_at_unix: 0,
    updated_at_unix: 0,
  };

  it("renders English headers and leaves data-driven cell values untouched", () => {
    renderWithProviders(
      <ResourceTable
        columns={tenantAccountsConfig.columns}
        rows={[row]}
        isLoading={false}
        readOnly
      />,
      { locale: "en" },
    );
    expect(
      screen.getByRole("columnheader", { name: en["resource.tenantAccounts.col.plan"] }),
    ).toBeInTheDocument();
    // Data-driven cell value is untouched by the header migration.
    expect(screen.getByRole("cell", { name: "plan-pro" })).toBeInTheDocument();
  });

  it("renders Simplified Chinese headers", () => {
    renderWithProviders(
      <ResourceTable columns={tenantAccountsConfig.columns} rows={[]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.tenantAccounts.col.plan"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.tenantAccounts.col.status"] }),
    ).toBeInTheDocument();
  });
});

describe("permissions form localizes field labels per locale", () => {
  it("renders English field labels", () => {
    renderWithProviders(
      <ResourceForm
        fields={permissionsConfig.fields}
        initialValues={defaultFieldValues(permissionsConfig.fields)}
        submitLabel="Create"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "en" },
    );
    // Required text fields append the " *" marker to the localized label.
    expect(screen.getByLabelText(`${en["resource.permissions.field.key"]} *`)).toBeInTheDocument();
    expect(screen.getByLabelText(en["resource.permissions.field.description"])).toBeInTheDocument();
  });

  it("renders Simplified Chinese field labels", () => {
    renderWithProviders(
      <ResourceForm
        fields={permissionsConfig.fields}
        initialValues={defaultFieldValues(permissionsConfig.fields)}
        submitLabel="创建"
        onSubmit={vi.fn().mockResolvedValue(undefined)}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );
    expect(
      screen.getByLabelText(`${zhCN["resource.permissions.field.key"]} *`),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(zhCN["resource.permissions.field.description"]),
    ).toBeInTheDocument();
  });
});

describe("plans page title localizes per locale", () => {
  beforeEach(() => seedSession());

  it("renders the English resource title and description heading", async () => {
    mockAdminList("/admin/v1/plans", []);
    renderWithProviders(<ResourcePage config={plansConfig} />, { locale: "en" });
    expect(
      await screen.findByRole("heading", { name: en["resource.plans.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(en["resource.plans.description"])).toBeInTheDocument();
  });

  it("renders the Simplified Chinese resource title and description heading", async () => {
    mockAdminList("/admin/v1/plans", []);
    renderWithProviders(<ResourcePage config={plansConfig} />, { locale: "zh-CN" });
    expect(
      await screen.findByRole("heading", { name: zhCN["resource.plans.title"] }),
    ).toBeInTheDocument();
    expect(screen.getByText(zhCN["resource.plans.description"])).toBeInTheDocument();
  });
});
