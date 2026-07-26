import { adminGet } from "@/lib/gateway-client";
import {
  DISABLED_WHEN_STATUS_NOT_ACTIVE,
  type ResourceConfig,
} from "@/lib/resource-config";

export interface AdminProject extends Record<string, unknown> {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey` resolve
// under the active locale. Resource IDs, field `name`s, and the example status
// placeholder (`active`) stay data-driven.
export const projectsConfig: ResourceConfig<AdminProject> = {
  key: "projects",
  titleKey: "resource.projects.title",
  descriptionKey: "resource.projects.description",
  basePath: "/admin/v1/projects",
  idField: "id",
  pagination: "offset",
  fetchList: (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/projects", { query: request }),
  rowLabel: (row) => row.name,
  columns: [
    { key: "name", headerKey: "resource.projects.col.name", priority: "primary", minWidth: 220, mobileVisibility: "always" },
    { key: "slug", headerKey: "resource.projects.col.slug", priority: "secondary", minWidth: 180, mobileVisibility: "always" },
    { key: "tenant_id", headerKey: "resource.projects.col.tenant", priority: "detail", minWidth: 220, copyable: true, mobileVisibility: "details" },
    { key: "status", headerKey: "resource.projects.col.status", priority: "secondary", minWidth: 100, mobileVisibility: "always" },
  ],
  fields: [
    {
      name: "tenant_id",
      labelKey: "resource.projects.field.tenant",
      type: "entity",
      required: true,
      reference: {
        target: "tenant-accounts",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug"],
        // #340: a suspended tenant is listed but marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
      },
      // Immutable after create (#326: the backend rejects tenant re-attribution
      // with 400 to avoid stranding child rows), so it is hidden on edit.
      createOnly: true,
    },
    { name: "name", labelKey: "resource.projects.field.name", type: "text", required: true },
    { name: "slug", labelKey: "resource.projects.field.slug", type: "text", required: true },
    { name: "status", labelKey: "resource.projects.field.status", type: "text", placeholder: "active" },
  ],
};
