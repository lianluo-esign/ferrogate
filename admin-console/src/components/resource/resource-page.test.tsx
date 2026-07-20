import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { ResourcePage } from "@/components/resource/resource-page";
import type { ResourceConfig } from "@/lib/resource-config";
import { plansConfig, type AdminPlan } from "@/resources/plans";
import {
  gatewayUrl,
  mockAdminError,
  mockAdminList,
  server,
} from "@/test/msw";
import { renderWithProviders, seedSession, TEST_GATEWAY_API_KEY } from "@/test/test-utils";

interface WidgetRow extends Record<string, unknown> {
  id: string;
  name: string;
}

const widgetsConfig: ResourceConfig<WidgetRow> = {
  key: "widgets",
  title: "Widgets",
  basePath: "/admin/v1/widgets",
  idField: "id",
  columns: [{ key: "name", header: "Name" }],
  fields: [{ name: "name", label: "Name", type: "text", required: true }],
};

function plan(overrides: Partial<AdminPlan> = {}): AdminPlan {
  return {
    id: "plan-free",
    name: "Free",
    slug: "free",
    mcp_enabled: true,
    self_hosted_workers_enabled: false,
    default_model_allowlist: [],
    asset_hosting_enabled: false,
    extension_tools_enabled: false,
    created_at_unix: 1,
    updated_at_unix: 1,
    ...overrides,
  };
}

beforeEach(() => {
  seedSession();
});

describe("ResourcePage", () => {
  it("lists rows fetched with the session's gateway API key", async () => {
    let authorization: string | null = null;
    server.use(
      http.get(gatewayUrl("/admin/v1/widgets"), ({ request }) => {
        authorization = request.headers.get("authorization");
        return HttpResponse.json({
          object: "list",
          data: [
            { id: "w1", name: "Sprocket" },
            { id: "w2", name: "Flange" },
          ],
        });
      }),
    );

    renderWithProviders(<ResourcePage config={widgetsConfig} />);

    expect(await screen.findByText("Sprocket")).toBeInTheDocument();
    expect(screen.getByText("Flange")).toBeInTheDocument();
    expect(authorization).toBe(`Bearer ${TEST_GATEWAY_API_KEY}`);
  });

  it("lists rows via the typed OpenAPI fetchList exemplar (plans)", async () => {
    mockAdminList("/admin/v1/plans", [plan({ name: "Free" }), plan({ id: "p2", name: "Pro", slug: "pro" })]);

    renderWithProviders(<ResourcePage config={plansConfig} />);

    expect(await screen.findByText("Free")).toBeInTheDocument();
    expect(screen.getByText("Pro")).toBeInTheDocument();
  });

  it("creates a record from the New form and refreshes the list", async () => {
    const user = userEvent.setup();
    const rows: WidgetRow[] = [{ id: "w1", name: "Sprocket" }];
    let createdBody: unknown = null;
    server.use(
      http.get(gatewayUrl("/admin/v1/widgets"), () =>
        HttpResponse.json({ object: "list", data: rows }),
      ),
      http.post(gatewayUrl("/admin/v1/widgets"), async ({ request }) => {
        createdBody = await request.json();
        rows.push({ id: "w2", name: "Flange" });
        return HttpResponse.json({ id: "w2", name: "Flange" }, { status: 201 });
      }),
    );

    renderWithProviders(<ResourcePage config={widgetsConfig} />);
    await screen.findByText("Sprocket");

    await user.click(screen.getByRole("button", { name: "New" }));
    await user.type(await screen.findByLabelText("Name *"), "Flange");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(createdBody).toEqual({ name: "Flange" }));
    // list invalidated -> refetched with the created row
    expect(await screen.findByText("Flange")).toBeInTheDocument();
  });

  it("shows the API error message when the list request fails", async () => {
    mockAdminError("get", "/admin/v1/widgets", 403, "forbidden", "missing admin scope");

    renderWithProviders(<ResourcePage config={widgetsConfig} />);

    expect(
      await screen.findByText(/Failed to load widgets: missing admin scope/),
    ).toBeInTheDocument();
  });
});
