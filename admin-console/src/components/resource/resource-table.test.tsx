import { ResourceTable } from "@/components/resource/resource-table";
import type { ColumnConfig } from "@/lib/resource-config";
import { renderWithProviders } from "@/test/test-utils";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

interface WidgetRow extends Record<string, unknown> {
  id: string;
  name: string;
  size: number;
}

const columns: ColumnConfig<WidgetRow>[] = [
  { key: "name", header: "Name" },
  { key: "size", header: "Size", render: (row) => `${row.size} mm` },
];

const rows: WidgetRow[] = [
  { id: "w1", name: "Sprocket", size: 12 },
  { id: "w2", name: "Flange", size: 30 },
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

describe("ResourceTable", () => {
  it("renders column headers and one row per record (custom render applied)", () => {
    renderWithProviders(<ResourceTable columns={columns} rows={rows} isLoading={false} readOnly />);

    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Size")).toBeInTheDocument();
    expect(screen.getByText("Sprocket")).toBeInTheDocument();
    expect(screen.getByText("12 mm")).toBeInTheDocument();
    expect(screen.getByText("30 mm")).toBeInTheDocument();
    // header row + 2 data rows
    expect(screen.getAllByRole("row")).toHaveLength(3);
  });

  it("shows the loading state", () => {
    renderWithProviders(<ResourceTable columns={columns} rows={[]} isLoading readOnly />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows the empty state when there are no rows", () => {
    renderWithProviders(<ResourceTable columns={columns} rows={[]} isLoading={false} readOnly />);
    expect(screen.getByText("No records yet.")).toBeInTheDocument();
  });

  it("uses a prioritized record layout below the desktop breakpoint", () => {
    setDesktopViewport(false);
    renderWithProviders(<ResourceTable columns={columns} rows={rows} isLoading={false} readOnly />);

    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(screen.getByText("Sprocket")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("invokes onEdit/onDelete with the row from the actions menu", async () => {
    const user = userEvent.setup();
    const onEdit = vi.fn();
    const onDelete = vi.fn();
    renderWithProviders(
      <ResourceTable
        columns={columns}
        rows={rows}
        isLoading={false}
        onEdit={onEdit}
        onDelete={onDelete}
      />,
    );

    const dataRows = screen.getAllByRole("row").slice(1);
    await user.click(within(dataRows[1]).getByRole("button"));
    await user.click(await screen.findByRole("menuitem", { name: "Edit" }));
    expect(onEdit).toHaveBeenCalledWith(rows[1], expect.any(HTMLElement));

    await user.click(within(dataRows[0]).getByRole("button"));
    await user.click(await screen.findByRole("menuitem", { name: "Delete" }));
    expect(onDelete).toHaveBeenCalledWith(rows[0], expect.any(HTMLElement));
  });
});
