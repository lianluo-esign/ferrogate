import { adminGet } from "@/lib/gateway-client";
import { DISABLED_WHEN_STATUS_NOT_ACTIVE, type ResourceConfig } from "@/lib/resource-config";

export interface AdminWorkspace extends Record<string, unknown> {
  id: string;
  project_id: string;
  tenant_id: string;
  name: string;
  slug: string;
  environment: string;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey` resolve
// under the active locale. Resource IDs, field `name`s, and the example
// environment/status placeholders (`default`, `active`) stay data-driven.
export const workspacesConfig: ResourceConfig<AdminWorkspace> = {
  key: "workspaces",
  titleKey: "resource.workspaces.title",
  descriptionKey: "resource.workspaces.description",
  basePath: "/admin/v1/workspaces",
  idField: "id",
  pagination: "offset",
  fetchList: (apiKey, request) => adminGet(apiKey, "/admin/v1/workspaces", { query: request }),
  columns: [
    { key: "name", headerKey: "resource.workspaces.col.name" },
    { key: "slug", headerKey: "resource.workspaces.col.slug" },
    { key: "project_id", headerKey: "resource.workspaces.col.project" },
    { key: "environment", headerKey: "resource.workspaces.col.environment" },
    { key: "status", headerKey: "resource.workspaces.col.status" },
  ],
  fields: [
    {
      name: "project_id",
      labelKey: "resource.workspaces.field.project",
      type: "entity",
      required: true,
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
        // #340: a suspended project is listed but marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
      },
      // Immutable after create (#326: the backend rejects project re-attribution
      // with 400 to avoid stranding child rows), so it is hidden on edit.
      createOnly: true,
    },
    { name: "name", labelKey: "resource.workspaces.field.name", type: "text", required: true },
    { name: "slug", labelKey: "resource.workspaces.field.slug", type: "text", required: true },
    {
      name: "environment",
      labelKey: "resource.workspaces.field.environment",
      type: "text",
      placeholder: "default",
    },
    {
      name: "status",
      labelKey: "resource.workspaces.field.status",
      type: "text",
      placeholder: "active",
    },
  ],
};
