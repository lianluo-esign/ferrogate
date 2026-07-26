import { HttpResponse, http } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

const cascadingFields: FieldConfig[] = [
  {
    name: "tenant_id",
    label: "Tenant",
    type: "entity",
    required: true,
    reference: {
      target: "tenant-accounts",
      valueKey: "id",
      primaryLabelKey: "name",
      secondaryLabelKeys: ["slug"],
    },
  },
  {
    name: "project_id",
    label: "Project",
    type: "entity",
    required: true,
    reference: {
      target: "projects",
      valueKey: "id",
      primaryLabelKey: "name",
      secondaryLabelKeys: ["slug"],
      dependencies: [{ field: "tenant_id", queryKey: "tenant_id" }],
    },
  },
  {
    name: "workspace_ids",
    label: "Workspaces",
    type: "entities",
    reference: {
      target: "workspaces",
      valueKey: "id",
      primaryLabelKey: "name",
      dependencies: [{ field: "project_id", queryKey: "project_id" }],
    },
  },
];

const tenants = [
  { id: "tenant-1", name: "Acme", slug: "acme" },
  { id: "tenant-2", name: "Globex", slug: "globex" },
];
const projects = [
  { id: "project-1", tenant_id: "tenant-1", name: "Production", slug: "prod" },
  { id: "project-2", tenant_id: "tenant-2", name: "Staging", slug: "staging" },
];
const workspaces = [
  { id: "workspace-1", project_id: "project-1", name: "US East" },
  { id: "workspace-2", project_id: "project-1", name: "EU West" },
];

function installCascadingHandlers() {
  server.use(
    http.get(gatewayUrl("/admin/v1/tenant-accounts"), ({ request }) => {
      const url = new URL(request.url);
      const search = (url.searchParams.get("search") ?? "").toLowerCase();
      const data = tenants.filter((tenant) =>
        `${tenant.name} ${tenant.slug} ${tenant.id}`.toLowerCase().includes(search),
      );
      return HttpResponse.json({ object: "list", data, total: data.length, offset: 0, limit: 20 });
    }),
    http.get(gatewayUrl("/admin/v1/tenant-accounts/:tenantId"), ({ params }) => {
      const tenant = tenants.find((item) => item.id === params.tenantId);
      return tenant
        ? HttpResponse.json({ object: "tenant", tenant })
        : HttpResponse.json({ error: { code: "not_found", message: "not found" } }, { status: 404 });
    }),
    http.get(gatewayUrl("/admin/v1/projects"), ({ request }) => {
      const url = new URL(request.url);
      const tenantId = url.searchParams.get("tenant_id");
      const data = projects.filter((project) => !tenantId || project.tenant_id === tenantId);
      return HttpResponse.json({ object: "list", data, total: data.length, offset: 0, limit: 20 });
    }),
    http.get(gatewayUrl("/admin/v1/projects/:projectId"), ({ params }) => {
      const project = projects.find((item) => item.id === params.projectId);
      return project
        ? HttpResponse.json({ object: "project", project })
        : HttpResponse.json({ error: { code: "not_found", message: "not found" } }, { status: 404 });
    }),
    http.get(gatewayUrl("/admin/v1/workspaces"), ({ request }) => {
      const url = new URL(request.url);
      const projectId = url.searchParams.get("project_id");
      const data = workspaces.filter(
        (workspace) => !projectId || workspace.project_id === projectId,
      );
      return HttpResponse.json({ object: "list", data, total: data.length, offset: 0, limit: 20 });
    }),
    http.get(gatewayUrl("/admin/v1/workspaces/:workspaceId"), ({ params }) => {
      const workspace = workspaces.find((item) => item.id === params.workspaceId);
      return workspace
        ? HttpResponse.json({ object: "workspace", workspace })
        : HttpResponse.json({ error: { code: "not_found", message: "not found" } }, { status: 404 });
    }),
  );
}

function renderReferenceForm(
  fields: FieldConfig[],
  initialValues = defaultFieldValues(fields),
) {
  seedSession();
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  renderWithProviders(
    <ResourceForm
      fields={fields}
      initialValues={initialValues}
      submitLabel="Create"
      onSubmit={onSubmit}
      onCancel={vi.fn()}
    />,
  );
  return onSubmit;
}

describe("EntityReferencePicker", () => {
  it("scopes cascading lookups and recursively clears invalid descendants", async () => {
    installCascadingHandlers();
    const user = userEvent.setup();
    renderReferenceForm(cascadingFields);

    expect(screen.getByRole("combobox", { name: "Project *" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Workspaces" })).toBeDisabled();

    await user.click(screen.getByRole("combobox", { name: "Tenant *" }));
    await user.click(await screen.findByRole("option", { name: /Acme/ }));
    await user.click(screen.getByRole("combobox", { name: "Project *" }));
    expect(await screen.findByRole("option", { name: /Production/ })).toBeVisible();
    expect(screen.queryByRole("option", { name: /Staging/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: /Production/ }));

    await user.click(screen.getByRole("combobox", { name: "Workspaces" }));
    await user.click(await screen.findByRole("option", { name: /US East/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.getByRole("list", { name: "Selected Workspaces" })).toHaveTextContent("US East");

    await user.click(screen.getByRole("combobox", { name: "Tenant *" }));
    await user.click(await screen.findByRole("option", { name: /Acme/ }));
    expect(screen.getByRole("list", { name: "Selected Project" })).toHaveTextContent(
      "Production",
    );
    expect(screen.getByRole("list", { name: "Selected Workspaces" })).toHaveTextContent(
      "US East",
    );

    await user.click(screen.getByRole("combobox", { name: "Tenant *" }));
    await user.click(await screen.findByRole("option", { name: /Globex/ }));

    expect(screen.queryByRole("list", { name: "Selected Project" })).not.toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Selected Workspaces" })).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Workspaces" })).toBeDisabled();
  });

  it("serializes multi-reference values as canonical IDs", async () => {
    const permissions = [
      { id: "permission-1", key: "admin.read", name: "Read administration", description: "Read" },
      { id: "permission-2", key: "admin.write", name: "Write administration", description: "Write" },
    ];
    server.use(
      http.get(gatewayUrl("/admin/v1/permissions"), ({ request }) => {
        const search = new URL(request.url).searchParams.get("search")?.toLowerCase() ?? "";
        const data = permissions.filter((permission) =>
          `${permission.key} ${permission.name}`.toLowerCase().includes(search),
        );
        return HttpResponse.json({ object: "list", data, total: data.length, offset: 0, limit: 20 });
      }),
    );
    const fields: FieldConfig[] = [
      {
        name: "permission_keys",
        label: "Permissions",
        type: "entities",
        reference: {
          target: "permissions",
          valueKey: "key",
          primaryLabelKey: "name",
          secondaryLabelKeys: ["key"],
        },
      },
    ];
    const user = userEvent.setup();
    const onSubmit = renderReferenceForm(fields);

    await user.click(screen.getByRole("combobox", { name: "Permissions" }));
    await user.click(await screen.findByRole("option", { name: /Read administration/ }));
    await user.click(screen.getByRole("option", { name: /Write administration/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        permission_keys: ["admin.read", "admin.write"],
      }),
    );
  });

  it("keeps a deleted existing value visible as an unresolved reference", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/projects/missing-project"), () =>
        HttpResponse.json(
          { error: { code: "project_not_found", message: "not found" } },
          { status: 404 },
        ),
      ),
    );
    const fields: FieldConfig[] = [
      {
        name: "project_id",
        label: "Project",
        type: "entity",
        reference: {
          target: "projects",
          valueKey: "id",
          primaryLabelKey: "name",
        },
      },
    ];
    renderReferenceForm(fields, { project_id: "missing-project" });

    expect(await screen.findByText("Unresolved reference")).toBeVisible();
    expect(screen.getAllByText("missing-project").length).toBeGreaterThan(0);
  });

  // #340 acceptance box 5. Before this, a model with `enabled: false` rendered
  // as an ordinary selectable option with no badge — only the *deleted* half of
  // "disabled/deleted targets are visibly marked and cannot be newly selected"
  // was implemented.
  it("marks a disabled target and refuses to newly select it", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/models"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            { name: "gpt-live", provider: "openai", enabled: true },
            { name: "gpt-retired", provider: "openai", enabled: false },
          ],
          total: 2,
          offset: 0,
          limit: 20,
        }),
      ),
    );
    const fields: FieldConfig[] = [
      {
        name: "allowed_models",
        label: "Allowed models",
        type: "entities",
        reference: {
          target: "models",
          valueKey: "name",
          primaryLabelKey: "name",
          disabledWhen: { key: "enabled", activeValues: ["true"] },
        },
      },
    ];
    const user = userEvent.setup();
    const onSubmit = renderReferenceForm(fields);

    await user.click(screen.getByRole("combobox", { name: "Allowed models" }));
    const retired = await screen.findByRole("option", { name: /gpt-retired/ });
    expect(retired).toBeDisabled();
    expect(retired).toHaveTextContent("Disabled");
    await user.click(retired);
    expect(screen.queryByRole("list", { name: "Selected Allowed models" })).not.toBeInTheDocument();

    // The live model in the same catalog is unaffected.
    await user.click(screen.getByRole("option", { name: /gpt-live/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({ allowed_models: ["gpt-live"] }),
    );
  });

  it("keeps an already-stored disabled value inspectable and repairable", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/models"), () =>
        HttpResponse.json({
          object: "list",
          data: [{ name: "gpt-retired", provider: "openai", enabled: false }],
          total: 1,
          offset: 0,
          limit: 20,
        }),
      ),
    );
    const fields: FieldConfig[] = [
      {
        name: "allowed_models",
        label: "Allowed models",
        type: "entities",
        reference: {
          target: "models",
          valueKey: "name",
          primaryLabelKey: "name",
          disabledWhen: { key: "enabled", activeValues: ["true"] },
        },
      },
    ];
    const user = userEvent.setup();
    const onSubmit = renderReferenceForm(fields, { allowed_models: ["gpt-retired"] });

    // Hydration resolves the stored value against the catalog, so the badge
    // appears once the lookup lands.
    expect(await screen.findByText("Disabled")).toBeVisible();
    expect(screen.getByRole("list", { name: "Selected Allowed models" })).toHaveTextContent(
      "gpt-retired",
    );

    // Repairable: the stored value can still be removed.
    await user.click(screen.getByRole("button", { name: "Remove gpt-retired" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ allowed_models: [] }));
  });

  it("surfaces lookup failures and retries without losing the form", async () => {
    let attempts = 0;
    server.use(
      http.get(gatewayUrl("/admin/v1/tenant-accounts"), () => {
        attempts += 1;
        if (attempts === 1) {
          return HttpResponse.json(
            { error: { code: "storage_unavailable", message: "lookup unavailable" } },
            { status: 503 },
          );
        }
        return HttpResponse.json({
          object: "list",
          data: [tenants[0]],
          total: 1,
          offset: 0,
          limit: 20,
        });
      }),
    );
    const user = userEvent.setup();
    renderReferenceForm([cascadingFields[0]]);

    await user.click(screen.getByRole("combobox", { name: "Tenant *" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("lookup unavailable");
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("option", { name: /Acme/ })).toBeVisible();
    expect(attempts).toBe(2);
  });
});
