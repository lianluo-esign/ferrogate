import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * RBAC permissions (#321) over `/admin/v1/permissions`. GET/POST plus DELETE
 * `/admin/v1/permissions/{permission_id}` with no update endpoint, so this
 * resource is create + delete only (`noUpdate`).
 *
 * Row shape derived from the OpenAPI contract (#314): regenerate via
 * `npm run generate:api` if the contract changes.
 */
export type AdminPermission = AdminSchema<"AdminPermission"> &
  Record<string, unknown>;

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey` resolve
// under the active locale. Resource IDs, field `name`s, and the example key
// placeholder (`admin.read`, an issue-protected example value) stay data-driven.
export const permissionsConfig: ResourceConfig<AdminPermission> = {
  key: "permissions",
  titleKey: "resource.permissions.title",
  descriptionKey: "resource.permissions.description",
  basePath: "/admin/v1/permissions",
  idField: "id",
  noUpdate: true,
  pagination: "offset",
  fetchList: (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/permissions", { query: request }),
  columns: [
    { key: "key", headerKey: "resource.permissions.col.key" },
    { key: "name", headerKey: "resource.permissions.col.name" },
    { key: "description", headerKey: "resource.permissions.col.description" },
  ],
  fields: [
    {
      name: "key",
      labelKey: "resource.permissions.field.key",
      type: "text",
      required: true,
      placeholder: "admin.read",
    },
    { name: "name", labelKey: "resource.permissions.field.name", type: "text", required: true },
    { name: "description", labelKey: "resource.permissions.field.description", type: "textarea" },
  ],
};
