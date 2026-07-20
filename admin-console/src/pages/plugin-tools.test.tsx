import { render, screen, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import PluginToolsPage from "@/pages/plugin-tools";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type AdminTool = AdminSchema<"AdminTool">;

function tool(overrides: Partial<AdminTool> = {}): AdminTool {
  return {
    name: "search_repo",
    description: "Search a repository",
    input_schema: {},
    extension_id: "github-plugin",
    approval_policy: "never",
    tenant_allowlist: ["org-acme"],
    api_key_allowlist: [],
    route_allowlist: [],
    ...overrides,
  };
}

function renderPage(pluginId: string) {
  return render(
    <MemoryRouter initialEntries={[`/app/plugins/${pluginId}/tools`]}>
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <Routes>
            <Route path="/app/plugins/:pluginId/tools" element={<PluginToolsPage />} />
          </Routes>
        </QueryClientProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("PluginToolsPage", () => {
  it("lists the tools registered by one plugin", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/plugins/github-plugin/tools"), () =>
        HttpResponse.json({ object: "list", data: [tool()] }),
      ),
    );
    renderPage("github-plugin");

    expect(
      await screen.findByRole("heading", { name: "Tools for github-plugin" }),
    ).toBeInTheDocument();
    const row = await screen.findByTestId("tool-search_repo");
    // tenant allowlist rendered (not the "any" fallback)
    expect(within(row).getByText("org-acme")).toBeInTheDocument();
  });
});
