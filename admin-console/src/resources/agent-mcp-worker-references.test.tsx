import { HttpResponse, http } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";
import { agentWorkflowsConfig } from "@/resources/agent-workflows";
import { skillPackagesConfig } from "@/resources/skill-packages";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
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

// #342: skill-package `capabilities` is a structured reference array embedded in
// the package document. These tests prove the structured editor resolves human
// labels for each kind, keeps per-row non-reference fields (the note) and
// neighbouring JSON fields (metadata) round-tripping unchanged, clears a stale
// id when the kind changes, falls back to a raw-id input for the kind with no
// list endpoint, and flags an unresolved reference.

function installCapabilityCatalogs() {
  mockAdminList("/admin/v1/plugins", [
    { id: "plugin-a", kind: "tool_provider", version: "1.0.0" },
  ]);
  mockAdminList("/admin/v1/tools", [
    { name: "search", extension_id: "plugin-a", description: null },
  ]);
  mockAdminList("/admin/v1/mcp-servers", [
    { name: "weather", transport: "stdio", enabled: true },
  ]);
  mockAdminList("/admin/v1/prompt-templates", [
    { id: "pt-1", name: "Welcome", model: "gpt-4o", status: "active" },
  ]);
  // agent-workflows envelopes each row as { workflow, counters } — the adapter's
  // unwrapListItem must lift `workflow` for the label to resolve.
  server.use(
    http.get(gatewayUrl("/admin/v1/agent-workflows"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          {
            workflow: { id: "wf-1", name: "Nightly", version: 2, nodes: [], edges: [] },
            counters: { request_count: 0 },
          },
        ],
      }),
    ),
  );
}

function renderSkillForm(initialValues: Record<string, unknown>) {
  seedSession();
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  renderWithProviders(
    <ResourceForm
      fields={skillPackagesConfig.fields}
      initialValues={{ ...defaultFieldValues(skillPackagesConfig.fields), ...initialValues }}
      submitLabel="Create"
      onSubmit={onSubmit}
      onCancel={vi.fn()}
    />,
  );
  return onSubmit;
}

describe("skill-package structured capability editor", () => {
  it("resolves labels, preserves the per-row note, and round-trips neighbouring JSON", async () => {
    installCapabilityCatalogs();
    const user = userEvent.setup();
    const onSubmit = renderSkillForm({
      id: "sp-1",
      name: "Support kit",
      capabilities: [{ kind: "prompt_template", id: "pt-1", description: "seed note" }],
      metadata: { team: "growth" },
    });

    // The reference id resolves to the prompt template's human name (shown in
    // both the picker trigger and the selected-value list).
    expect(await screen.findAllByText("Welcome")).not.toHaveLength(0);
    const note = screen.getByLabelText("Note (optional)");
    expect(note).toHaveValue("seed note");

    await user.clear(note);
    await user.type(note, "updated note");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "sp-1",
          name: "Support kit",
          capabilities: [{ kind: "prompt_template", id: "pt-1", description: "updated note" }],
          // The unrelated free-form JSON document field round-trips unchanged.
          metadata: { team: "growth" },
        }),
      ),
    );
  });

  it("resolves a nested (enveloped) agent-workflow reference via unwrapListItem", async () => {
    installCapabilityCatalogs();
    renderSkillForm({
      id: "sp-2",
      name: "Ops kit",
      capabilities: [{ kind: "agent_workflow", id: "wf-1" }],
    });

    expect(await screen.findAllByText("Nightly")).not.toHaveLength(0);
    expect(screen.getByText("wf-1")).toBeInTheDocument();
  });

  it("clears the stale id when the capability kind changes", async () => {
    installCapabilityCatalogs();
    const user = userEvent.setup();
    const onSubmit = renderSkillForm({
      id: "sp-3",
      name: "Switch kit",
      capabilities: [{ kind: "prompt_template", id: "pt-1" }],
    });

    expect(await screen.findAllByText("Welcome")).not.toHaveLength(0);

    // Switch the kind: the previously-selected prompt-template id is now stale.
    await user.click(screen.getByRole("combobox", { name: "Kind" }));
    await user.click(await screen.findByRole("option", { name: "MCP server" }));

    await user.click(screen.getByRole("button", { name: "Create" }));

    // The stale id was dropped, so the incomplete row is not submitted.
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ id: "sp-3", capabilities: [] }),
      ),
    );
  });

  it("accepts a raw id for the mcp_tool kind that has no list endpoint", async () => {
    installCapabilityCatalogs();
    const user = userEvent.setup();
    const onSubmit = renderSkillForm({ id: "sp-4", name: "Raw kit", capabilities: [] });

    await user.click(screen.getByRole("button", { name: /Add capabilities entry/i }));
    await user.click(screen.getByRole("combobox", { name: "Kind" }));
    await user.click(await screen.findByRole("option", { name: "MCP tool" }));

    // No entity picker for this kind — a plain id input is offered instead.
    const rawId = screen.getByRole("textbox", { name: "Reference" });
    await user.type(rawId, "weather.today");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          capabilities: [{ kind: "mcp_tool", id: "weather.today" }],
        }),
      ),
    );
  });

  it("flags an unresolved reference the catalog cannot resolve", async () => {
    installCapabilityCatalogs();
    renderSkillForm({
      id: "sp-5",
      name: "Ghost kit",
      capabilities: [{ kind: "plugin", id: "ghost" }],
    });

    expect(await screen.findByText("Unresolved reference")).toBeInTheDocument();
  });
});
