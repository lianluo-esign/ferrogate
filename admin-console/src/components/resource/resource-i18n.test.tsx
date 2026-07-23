// Dual-locale coverage for the shared resource-CRUD framework chrome (#348).
//
// The framework renders every resource page, so proving its chrome resolves
// from the typed catalog in BOTH `en` and `zh-CN` (and that catalog parity
// holds) localizes many operator surfaces at once. Resource-specific display
// names (column headers, the `New {name}` title, field labels) stay
// data-driven and are asserted to pass through unchanged.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { ResourcePage } from "@/components/resource/resource-page";
import { ResourceTable } from "@/components/resource/resource-table";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { defaultFieldValues, type ColumnConfig, type FieldConfig, type ResourceConfig } from "@/lib/resource-config";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

interface WidgetRow extends Record<string, unknown> {
  id: string;
  name: string;
}

const columns: ColumnConfig<WidgetRow>[] = [{ key: "name", header: "Name" }];
const fields: FieldConfig[] = [
  { name: "name", label: "Name", type: "text", required: true },
  { name: "settings", label: "Settings", type: "json" },
];

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

describe("resource framework catalog parity", () => {
  it("defines every resource.* key in both locales", () => {
    const resourceKeys = Object.keys(en).filter((key) => key.startsWith("resource."));
    expect(resourceKeys.length).toBeGreaterThan(0);
    for (const key of resourceKeys) {
      expect(zhCN[key as keyof typeof en], `zh-CN missing ${key}`).toBeTruthy();
    }
  });
});

describe("ResourceTable chrome renders per locale", () => {
  it("uses English loading/empty chrome and keeps data-driven headers", () => {
    renderWithProviders(
      <ResourceTable columns={columns} rows={[]} isLoading readOnly />,
      { locale: "en" },
    );
    expect(screen.getByText(en["resource.table.loading"])).toBeInTheDocument();
  });

  it("uses Simplified Chinese empty-state chrome", () => {
    renderWithProviders(
      <ResourceTable columns={columns} rows={[]} isLoading={false} readOnly />,
      { locale: "zh-CN" },
    );
    expect(screen.getByText(zhCN["resource.table.empty"])).toBeInTheDocument();
    // Data-driven column header is not translated by the framework.
    expect(screen.getByText("Name")).toBeInTheDocument();
  });

  it("localizes the row-action menu labels in Simplified Chinese", async () => {
    const user = userEvent.setup();
    const rows: WidgetRow[] = [{ id: "w1", name: "Sprocket" }];
    renderWithProviders(
      <ResourceTable
        columns={columns}
        rows={rows}
        isLoading={false}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
      />,
      { locale: "zh-CN" },
    );
    const dataRow = screen.getAllByRole("row").slice(1)[0];
    await user.click(within(dataRow).getByRole("button"));
    expect(await screen.findByRole("menuitem", { name: zhCN["resource.action.edit"] })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: zhCN["resource.action.delete"] })).toBeInTheDocument();
  });
});

describe("ResourceForm chrome renders per locale", () => {
  it("shows Simplified Chinese Cancel chrome and localized validation copy", async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    renderWithProviders(
      <ResourceForm
        fields={fields}
        initialValues={defaultFieldValues(fields)}
        submitLabel="创建"
        onSubmit={onSubmit}
        onCancel={vi.fn()}
      />,
      { locale: "zh-CN" },
    );

    expect(screen.getByRole("button", { name: zhCN["resource.action.cancel"] })).toBeInTheDocument();

    // Invalid JSON exercises the framework's JS-level validation, surfacing the
    // localized copy with the data-driven field label interpolated.
    await user.type(screen.getByLabelText("Name *"), "Sprocket");
    await user.type(screen.getByLabelText("Settings"), "not-json");
    await user.click(screen.getByRole("button", { name: "创建" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Settings必须是有效的 JSON");
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

describe("ResourcePage chrome renders per locale", () => {
  const widgetsConfig: ResourceConfig<WidgetRow> = {
    key: "widgets",
    title: "Widgets",
    basePath: "/admin/v1/widgets",
    idField: "id",
    columns,
    fields,
  };

  beforeEach(() => seedSession());

  it("renders English pagination + create chrome, data-driven title untouched", async () => {
    mockAdminList("/admin/v1/widgets", [{ id: "w1", name: "Sprocket" }]);
    renderWithProviders(<ResourcePage config={widgetsConfig} />, { locale: "en" });

    expect(await screen.findByText("Sprocket")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en["resource.action.new"] })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en["resource.pagination.previous"] })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en["resource.pagination.next"] })).toBeInTheDocument();
    // Data-driven resource title is rendered verbatim (later slices translate it).
    expect(screen.getByRole("heading", { name: "Widgets" })).toBeInTheDocument();
  });

  it("renders Simplified Chinese create dialog + delete confirmation chrome", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(gatewayUrl("/admin/v1/widgets"), () =>
        HttpResponse.json({ object: "list", data: [{ id: "w1", name: "Sprocket" }] }),
      ),
    );
    renderWithProviders(<ResourcePage config={widgetsConfig} />, { locale: "zh-CN" });
    await screen.findByText("Sprocket");

    // Create sheet title localizes chrome around the data-driven resource name.
    await user.click(screen.getByRole("button", { name: zhCN["resource.action.new"] }));
    expect(await screen.findByText("新建Widgets")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: zhCN["resource.action.cancel"] }));

    // Row action -> delete confirmation dialog uses the localized chrome.
    const dataRow = screen.getAllByRole("row").slice(1)[0];
    await user.click(within(dataRow).getByRole("button"));
    await user.click(await screen.findByRole("menuitem", { name: zhCN["resource.action.delete"] }));
    await waitFor(() =>
      expect(screen.getByText(zhCN["resource.dialog.deleteDescription"])).toBeInTheDocument(),
    );
    expect(screen.getByRole("alertdialog")).toHaveTextContent("删除widgets？");
  });
});
