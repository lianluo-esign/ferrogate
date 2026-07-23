import { HttpResponse, http } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";
import { agentWorkflowsConfig } from "@/resources/agent-workflows";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

// #342: agent/MCP/worker surfaces adopt the shared #337 entity-reference
// pickers for their relationship fields. These tests prove a converted form
// renders the picker, resolves a human display name for an existing value, and
// submits the underlying canonical ID unchanged.

const projects = [
  { id: "project-1", tenant_id: "tenant-1", name: "Production", slug: "prod" },
  { id: "project-2", tenant_id: "tenant-1", name: "Staging", slug: "stg" },
];

function installProjectHandlers() {
  server.use(
    http.get(gatewayUrl("/admin/v1/projects"), () =>
      HttpResponse.json({
        object: "list",
        data: projects,
        total: projects.length,
        offset: 0,
        limit: 20,
      }),
    ),
    http.get(gatewayUrl("/admin/v1/projects/:id"), ({ params }) => {
      const project = projects.find((item) => item.id === params.id);
      return project
        ? HttpResponse.json({ object: "project", project })
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

describe("agent/MCP/worker entity-reference conversions", () => {
  it("agent workflow project scope selects from the catalog and submits canonical IDs", async () => {
    installProjectHandlers();
    const user = userEvent.setup();
    const onSubmit = renderForm(agentWorkflowsConfig.fields, {
      ...defaultFieldValues(agentWorkflowsConfig.fields),
      id: "wf-1",
      name: "Nightly enrichment",
    });

    // The relationship field renders a picker, not a raw CSV text input.
    const picker = screen.getByRole("combobox", { name: "Projects" });
    expect(picker).toBeInTheDocument();

    await user.click(picker);
    // Resolved human label is shown for the catalog entry.
    await user.click(await screen.findByRole("option", { name: /Production/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "wf-1",
          name: "Nightly enrichment",
          project_ids: ["project-1"],
        }),
      ),
    );
  });

  it("agent workflow hydrates an existing project ID to its human label", async () => {
    installProjectHandlers();
    renderForm(agentWorkflowsConfig.fields, {
      ...defaultFieldValues(agentWorkflowsConfig.fields),
      id: "wf-2",
      name: "Backfill",
      project_ids: ["project-2"],
    });

    // Resolved display name (Staging) plus the canonical ID stay visible.
    const selected = await screen.findByRole("list", { name: "Selected Projects" });
    await waitFor(() => expect(selected).toHaveTextContent("Staging"));
    expect(selected).toHaveTextContent("project-2");
  });
});
