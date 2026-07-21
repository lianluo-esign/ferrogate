import { describe, expect, it } from "vitest";
import {
  clearDependentReferenceValues,
  defaultFieldValues,
  type FieldConfig,
} from "@/lib/resource-config";

const cascadingFields: FieldConfig[] = [
  {
    name: "tenant_id",
    label: "Tenant",
    type: "entity",
    reference: {
      target: "tenant-accounts",
      valueKey: "id",
      primaryLabelKey: "name",
    },
  },
  {
    name: "project_id",
    label: "Project",
    type: "entity",
    reference: {
      target: "projects",
      valueKey: "id",
      primaryLabelKey: "name",
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
  { name: "name", label: "Name", type: "text" },
];

describe("entity reference field state", () => {
  it("initializes single and multi references with their canonical payload shapes", () => {
    expect(defaultFieldValues(cascadingFields)).toEqual({
      tenant_id: "",
      project_id: "",
      workspace_ids: [],
      name: "",
    });
  });

  it("recursively clears descendants without changing unrelated values", () => {
    expect(
      clearDependentReferenceValues(
        cascadingFields,
        {
          tenant_id: "tenant-2",
          project_id: "project-1",
          workspace_ids: ["workspace-1"],
          name: "Operator workflow",
        },
        "tenant_id",
      ),
    ).toEqual({
      tenant_id: "tenant-2",
      project_id: "",
      workspace_ids: [],
      name: "Operator workflow",
    });
  });
});
