import { HttpResponse, http } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";
import { apiKeysConfig } from "@/resources/api-keys";
import { plansConfig } from "@/resources/plans";
import { tenantAccountsConfig } from "@/resources/tenant-accounts";
import { virtualKeysConfig } from "@/resources/virtual-keys";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

// #340: tenancy/IAM/key forms adopt the shared #337 entity-reference pickers
// for their relationship fields. These tests prove a converted form renders the
// picker, resolves a human display name for an existing value, and submits the
// underlying canonical ID unchanged (no API/contract change).

const models = [
  { name: "gpt-4o", provider: "openai", provider_model: "gpt-4o" },
  { name: "claude-sonnet", provider: "anthropic", provider_model: "claude-3-5-sonnet" },
];
const providers = [
  { name: "openai", kind: "openai", base_url: "https://api.openai.com" },
  { name: "anthropic", kind: "anthropic", base_url: "https://api.anthropic.com" },
];
const tenants = [
  { id: "tenant-1", name: "Acme", slug: "acme", status: "active" },
];
const projects = [
  { id: "project-1", tenant_id: "tenant-1", name: "Production", slug: "prod" },
];
const workspaces = [
  { id: "workspace-1", project_id: "project-1", tenant_id: "tenant-1", name: "Staging", slug: "staging" },
];
const plans = [
  { id: "plan-pro", name: "Pro", slug: "pro" },
  { id: "plan-free", name: "Free", slug: "free" },
];

function installCatalogHandlers() {
  server.use(
    http.get(gatewayUrl("/admin/v1/models"), () =>
      HttpResponse.json({ object: "list", data: models }),
    ),
    http.get(gatewayUrl("/admin/v1/providers"), () =>
      HttpResponse.json({ object: "list", data: providers }),
    ),
    http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
      HttpResponse.json({ object: "list", data: tenants, total: tenants.length, offset: 0, limit: 20 }),
    ),
    http.get(gatewayUrl("/admin/v1/tenant-accounts/:id"), ({ params }) => {
      const tenant = tenants.find((item) => item.id === params.id);
      return tenant
        ? HttpResponse.json({ object: "tenant", tenant })
        : HttpResponse.json({ error: { code: "not_found", message: "x" } }, { status: 404 });
    }),
    http.get(gatewayUrl("/admin/v1/projects"), () =>
      HttpResponse.json({ object: "list", data: projects, total: projects.length, offset: 0, limit: 20 }),
    ),
    http.get(gatewayUrl("/admin/v1/workspaces"), () =>
      HttpResponse.json({ object: "list", data: workspaces, total: workspaces.length, offset: 0, limit: 20 }),
    ),
    http.get(gatewayUrl("/admin/v1/plans"), () =>
      HttpResponse.json({ object: "list", data: plans }),
    ),
    http.get(gatewayUrl("/admin/v1/plans/:id"), ({ params }) => {
      const plan = plans.find((item) => item.id === params.id);
      return plan
        ? HttpResponse.json({ object: "plan", plan })
        : HttpResponse.json({ error: { code: "not_found", message: "x" } }, { status: 404 });
    }),
    http.get(gatewayUrl("/admin/v1/projects/:id"), ({ params }) => {
      const project = projects.find((item) => item.id === params.id);
      return project
        ? HttpResponse.json({ object: "project", project })
        : HttpResponse.json({ error: { code: "not_found", message: "x" } }, { status: 404 });
    }),
    http.get(gatewayUrl("/admin/v1/workspaces/:id"), ({ params }) => {
      const workspace = workspaces.find((item) => item.id === params.id);
      return workspace
        ? HttpResponse.json({ object: "workspace", workspace })
        : HttpResponse.json({ error: { code: "not_found", message: "x" } }, { status: 404 });
    }),
  );
}

function renderForm(
  fields: FieldConfig[],
  initialValues: Record<string, unknown> = defaultFieldValues(fields),
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

describe("tenancy/IAM/key entity-reference conversions", () => {
  it("tenant-account plan field hydrates an existing plan_id to its human label", async () => {
    installCatalogHandlers();
    renderForm(tenantAccountsConfig.fields, {
      ...defaultFieldValues(tenantAccountsConfig.fields),
      name: "Acme",
      slug: "acme",
      plan_id: "plan-pro",
    });

    // The relationship field renders a picker, not a raw text input.
    expect(screen.getByRole("combobox", { name: "Plan" })).toBeInTheDocument();

    // Existing value hydrates to its display name while keeping the canonical ID.
    const selected = await screen.findByRole("list", { name: "Selected Plan" });
    await waitFor(() => expect(selected).toHaveTextContent("Pro"));
    expect(selected).toHaveTextContent("plan-pro");
  });

  it("tenant-account plan field submits the selected plan's canonical id", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(tenantAccountsConfig.fields, {
      ...defaultFieldValues(tenantAccountsConfig.fields),
      name: "Acme",
      slug: "acme",
    });

    await user.click(screen.getByRole("combobox", { name: "Plan" }));
    await user.click(await screen.findByRole("option", { name: /Free/ }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ name: "Acme", slug: "acme", plan_id: "plan-free" }),
      ),
    );
  });

  it("virtual-key form selects workspace + allowed providers and submits canonical IDs", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(virtualKeysConfig.fields, {
      ...defaultFieldValues(virtualKeysConfig.fields),
      name: "gateway-key",
    });

    // Formerly raw text/CSV fields are now searchable pickers. workspace_id is
    // required, so its accessible name carries the " *" required marker.
    const workspacePicker = screen.getByRole("combobox", { name: "Workspace *" });
    expect(workspacePicker).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Allowed models" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Allowed providers" })).toBeInTheDocument();

    // Single-select closes on choose.
    await user.click(workspacePicker!);
    await user.click(await screen.findByRole("option", { name: /Staging/ }));

    await user.click(screen.getByRole("combobox", { name: "Allowed providers" }));
    await user.click(await screen.findByRole("option", { name: /openai/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "gateway-key",
          workspace_id: "workspace-1",
          allowed_providers: ["openai"],
        }),
      ),
    );
  });

  it("native api-key form uses tenant/project/workspace/model pickers and keeps opaque IDs raw", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(apiKeysConfig.fields, {
      ...defaultFieldValues(apiKeysConfig.fields),
      name: "native-key",
    });

    expect(screen.getByRole("combobox", { name: "Project" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Workspace" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Allowed models" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Denied providers" })).toBeInTheDocument();

    // #340 box 1: organization_id is a tenant-accounts reference (the gateway
    // compares it against `project.tenant_id`), so it is a picker, NOT the free
    // text this assertion previously locked in.
    expect(screen.getByRole("combobox", { name: "Tenant" })).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Tenant" })).not.toBeInTheDocument();

    // user_id has no catalog to bind to (the Admin API exposes no users
    // endpoint), so it stays a text input -- an explicit box-7 exclusion.
    expect(screen.getByRole("textbox", { name: "User ID" })).toBeInTheDocument();

    await user.click(screen.getByRole("combobox", { name: "Project" }));
    await user.click(await screen.findByRole("option", { name: /Production/ }));

    await user.click(screen.getByRole("combobox", { name: "Tenant" }));
    await user.click(await screen.findByRole("option", { name: /Acme/ }));

    await user.click(screen.getByRole("combobox", { name: "Allowed models" }));
    await user.click(await screen.findByRole("option", { name: /gpt-4o/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "native-key",
          // The picker submits the canonical tenant id, unchanged in shape from
          // the free-text field it replaced.
          organization_id: "tenant-1",
          project_id: "project-1",
          allowed_models: ["gpt-4o"],
        }),
      ),
    );
  });

  it("an api-key organization_id that is not a tenant row stays inspectable and repairable", async () => {
    // #340 acceptance: "Existing invalid or deleted references must remain
    // inspectable and repairable." A value stored before the picker landed (or
    // whose tenant was since deleted) must not vanish from the form.
    installCatalogHandlers();
    renderForm(apiKeysConfig.fields, {
      ...defaultFieldValues(apiKeysConfig.fields),
      name: "legacy-key",
      organization_id: "org-not-a-tenant-row",
    });

    const selected = await screen.findByRole("list", { name: "Selected Tenant" });
    // The raw id is still shown...
    await waitFor(() => expect(selected).toHaveTextContent("org-not-a-tenant-row"));
    // ...and is visibly marked as not resolving to a live tenant.
    expect(selected).toHaveTextContent(/Unresolved reference/i);
  });

  it("plan default model allowlist is a model picker submitting canonical names", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(plansConfig.fields, {
      ...defaultFieldValues(plansConfig.fields),
      id: "plan-x",
      name: "Pro",
      slug: "pro",
    });

    // Formerly a raw comma-separated field; now a multi-select model picker.
    const picker = screen.getByRole("combobox", { name: "Default model allowlist" });
    expect(picker).toBeInTheDocument();

    await user.click(picker);
    await user.click(await screen.findByRole("option", { name: /gpt-4o/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Pro",
          slug: "pro",
          default_model_allowlist: ["gpt-4o"],
        }),
      ),
    );
  });

  it("native api-key workspace picker cascades from (and is filtered by) the selected project", async () => {
    const user = userEvent.setup();
    let workspaceProjectFilter: string | null = "unset";
    server.use(
      http.get(gatewayUrl("/admin/v1/projects"), () =>
        HttpResponse.json({ object: "list", data: projects, total: projects.length, offset: 0, limit: 20 }),
      ),
      http.get(gatewayUrl("/admin/v1/workspaces"), ({ request }) => {
        workspaceProjectFilter = new URL(request.url).searchParams.get("project_id");
        return HttpResponse.json({ object: "list", data: workspaces, total: workspaces.length, offset: 0, limit: 20 });
      }),
    );

    renderForm(apiKeysConfig.fields, {
      ...defaultFieldValues(apiKeysConfig.fields),
      name: "native-key",
    });

    // The workspace picker is disabled until a project scopes it — no
    // cross-project (hence cross-tenant) combo is selectable.
    expect(screen.getByRole("combobox", { name: "Workspace" })).toBeDisabled();

    await user.click(screen.getByRole("combobox", { name: "Project" }));
    await user.click(await screen.findByRole("option", { name: /Production/ }));

    await waitFor(() =>
      expect(screen.getByRole("combobox", { name: "Workspace" })).toBeEnabled(),
    );
    await user.click(screen.getByRole("combobox", { name: "Workspace" }));
    await screen.findByRole("option", { name: /Staging/ });

    // The workspace list is scoped to the selected project.
    await waitFor(() => expect(workspaceProjectFilter).toBe("project-1"));
  });

  // #340 acceptance box 5, against the SHIPPED config rather than a synthetic
  // one: the disabled marking has to be declared on the real api-keys fields,
  // not merely supported by the picker.
  it("native api-key form marks disabled catalog targets and keeps them unselectable", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(gatewayUrl("/admin/v1/projects"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            { ...projects[0], status: "active" },
            {
              id: "project-retired",
              tenant_id: "tenant-1",
              name: "Retired sandbox",
              slug: "retired",
              status: "suspended",
            },
          ],
          total: 2,
          offset: 0,
          limit: 20,
        }),
      ),
      http.get(gatewayUrl("/admin/v1/projects/:id"), ({ params }) =>
        params.id === "project-1"
          ? HttpResponse.json({ object: "project", project: { ...projects[0], status: "active" } })
          : HttpResponse.json({ error: { code: "not_found", message: "x" } }, { status: 404 }),
      ),
      http.get(gatewayUrl("/admin/v1/models"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            { ...models[0], enabled: true },
            { name: "gpt-retired", provider: "openai", provider_model: "gpt-retired", enabled: false },
          ],
        }),
      ),
    );

    const onSubmit = renderForm(apiKeysConfig.fields, {
      ...defaultFieldValues(apiKeysConfig.fields),
      name: "native-key",
    });

    await user.click(screen.getByRole("combobox", { name: "Allowed models" }));
    expect(await screen.findByRole("option", { name: /gpt-retired/ })).toBeDisabled();
    await user.click(screen.getByRole("option", { name: /gpt-retired/ }));
    await user.click(screen.getByRole("option", { name: /gpt-4o/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("combobox", { name: "Project" }));
    expect(await screen.findByRole("option", { name: /Retired sandbox/ })).toBeDisabled();
    await user.click(screen.getByRole("option", { name: /Retired sandbox/ }));
    await user.click(screen.getByRole("option", { name: /Production/ }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    // Only the live targets made it into the payload.
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ allowed_models: ["gpt-4o"], project_id: "project-1" }),
      ),
    );
  });

  // #340 acceptance box 5, for the NEW organization_id -> tenant-accounts
  // picker specifically. Added by the test gate: the box-5 case above covers
  // only the models and projects pickers, so deleting
  // `disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE` from the tenant reference
  // in api-keys.ts left the whole suite green.
  it("native api-key tenant picker lists a suspended tenant but keeps it unselectable", async () => {
    const user = userEvent.setup();
    installCatalogHandlers();
    server.use(
      http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            { ...tenants[0], status: "active" },
            { id: "tenant-suspended", name: "Dormant Co", slug: "dormant", status: "suspended" },
          ],
          total: 2,
          offset: 0,
          limit: 20,
        }),
      ),
    );

    const onSubmit = renderForm(apiKeysConfig.fields, {
      ...defaultFieldValues(apiKeysConfig.fields),
      name: "native-key",
    });

    await user.click(screen.getByRole("combobox", { name: "Tenant" }));
    // Listed (inspectable) …
    const suspended = await screen.findByRole("option", { name: /Dormant Co/ });
    // … but marked and not newly selectable.
    expect(suspended).toBeDisabled();
    await user.click(suspended);
    await user.click(screen.getByRole("option", { name: /Acme/ }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ organization_id: "tenant-1" }),
      ),
    );
  });
});
