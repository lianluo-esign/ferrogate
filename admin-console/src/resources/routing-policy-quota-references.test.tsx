import { HttpResponse, http } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";
import { agentUpstreamsConfig } from "@/resources/agent-upstreams";
import { policiesConfig } from "@/resources/policies";
import { promptTemplatesConfig } from "@/resources/prompt-templates";
import { quotaPoliciesConfig } from "@/resources/quota-policies";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

// #341: routing/policy/quota forms adopt the shared #337 entity-reference
// pickers for their relationship fields. These tests prove a converted form
// renders the picker, resolves a human display name for an existing value, and
// submits the underlying canonical ID unchanged.

const models = [
  { name: "gpt-4o", provider: "openai", provider_model: "gpt-4o" },
  { name: "claude-sonnet", provider: "anthropic", provider_model: "claude-3-5-sonnet" },
];
const providers = [
  { name: "openai", kind: "openai", base_url: "https://api.openai.com" },
  { name: "anthropic", kind: "anthropic", base_url: "https://api.anthropic.com" },
];
const projects = [
  { id: "project-1", tenant_id: "tenant-1", name: "Production", slug: "prod" },
];
const tenants = [{ id: "tenant-1", name: "Acme", slug: "acme" }];

function installCatalogHandlers() {
  server.use(
    http.get(gatewayUrl("/admin/v1/models"), () =>
      HttpResponse.json({ object: "list", data: models }),
    ),
    http.get(gatewayUrl("/admin/v1/providers"), () =>
      HttpResponse.json({ object: "list", data: providers }),
    ),
    http.get(gatewayUrl("/admin/v1/projects"), () =>
      HttpResponse.json({ object: "list", data: projects, total: projects.length, offset: 0, limit: 20 }),
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

describe("routing/policy/quota entity-reference conversions", () => {
  it("policies form selects models/providers from the catalog and submits canonical IDs", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(policiesConfig.fields, {
      ...defaultFieldValues(policiesConfig.fields),
      name: "deny-eu",
    });

    // The relationship fields render pickers, not raw text inputs.
    expect(screen.getByRole("combobox", { name: "Models" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Providers" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Projects" })).toBeInTheDocument();

    await user.click(screen.getByRole("combobox", { name: "Models" }));
    // Resolved human label is shown for the catalog entry.
    await user.click(await screen.findByRole("option", { name: /gpt-4o/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("combobox", { name: "Providers" }));
    await user.click(await screen.findByRole("option", { name: /openai/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "deny-eu",
          models: ["gpt-4o"],
          providers: ["openai"],
        }),
      ),
    );
  });

  it("quota policy model allowlist submits canonical model names", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(quotaPoliciesConfig.fields, {
      ...defaultFieldValues(quotaPoliciesConfig.fields),
      scope_type: "tenant",
      scope_id: "tenant-1",
    });

    expect(screen.getByRole("combobox", { name: "Model allowlist" })).toBeInTheDocument();
    await user.click(screen.getByRole("combobox", { name: "Model allowlist" }));
    await user.click(await screen.findByRole("option", { name: /claude-sonnet/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ model_allowlist: ["claude-sonnet"] }),
      ),
    );
  });

  it("prompt template model field renders a single-select model picker", async () => {
    installCatalogHandlers();
    const user = userEvent.setup();
    renderForm(promptTemplatesConfig.fields);

    const picker = screen.getByRole("combobox", { name: "Model" });
    expect(picker).toBeInTheDocument();
    await user.click(picker);
    expect(await screen.findByRole("option", { name: /gpt-4o/ })).toBeVisible();
  });

  it("agent upstream tenants hydrate an existing ID to its human label", async () => {
    installCatalogHandlers();
    renderForm(agentUpstreamsConfig.fields, {
      ...defaultFieldValues(agentUpstreamsConfig.fields),
      tenant_ids: ["tenant-1"],
    });

    // Resolved display name (Acme) plus the canonical ID stay visible.
    const selected = await screen.findByRole("list", { name: "Selected Tenants" });
    await waitFor(() => expect(selected).toHaveTextContent("Acme"));
    expect(selected).toHaveTextContent("tenant-1");
  });
});
