import type { AdminSchema } from "@/lib/gateway-client";
import ToolsCatalogPage from "@/pages/tools-catalog";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

type AdminTool = AdminSchema<"AdminTool">;

function tool(overrides: Partial<AdminTool> = {}): AdminTool {
  return {
    name: "search_repo",
    description: "Search a repository",
    input_schema: {},
    extension_id: "github-plugin",
    approval_policy: "never",
    tenant_allowlist: [],
    api_key_allowlist: [],
    route_allowlist: [],
    ...overrides,
  };
}

function renderPage() {
  return renderWithProviders(<ToolsCatalogPage />);
}

beforeEach(() => {
  seedSession();
});

describe("ToolsCatalogPage", () => {
  it("lists tools with approval policy and links the owning plugin", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/tools"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            tool(),
            tool({ name: "delete_repo", approval_policy: "always", extension_id: "github-plugin" }),
          ],
        }),
      ),
    );
    renderPage();

    const searchRow = await screen.findByTestId("tool-search_repo");
    expect(within(searchRow).getByText("Search a repository")).toBeInTheDocument();
    expect(within(searchRow).getByRole("link", { name: "github-plugin" })).toHaveAttribute(
      "href",
      "/app/plugins/github-plugin/tools",
    );

    const deleteRow = screen.getByTestId("tool-delete_repo");
    expect(within(deleteRow).getByText("always")).toBeInTheDocument();
  });

  it("shows an empty state when no tools are registered", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/tools"), () =>
        HttpResponse.json({ object: "list", data: [] }),
      ),
    );
    renderPage();

    expect(await screen.findByText("No registered tools.")).toBeInTheDocument();
  });
});
