import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * RBAC roles (#321) over `/admin/v1/roles`. The contract exposes GET/POST plus
 * DELETE `/admin/v1/roles/{role_id}` but no PUT/PATCH, so this resource is
 * create + delete only (`noUpdate`). Tenant-scoped callers (#232) manage only
 * their own tenant's roles; a 403 from the gateway surfaces in the list/delete
 * error paths rather than being hidden here.
 *
 * Row shape derived from the OpenAPI contract (#314): regenerate via
 * `npm run generate:api` if docs/openapi/admin-api.openapi.json changes.
 */
export type AdminRole = AdminSchema<"AdminRole"> & Record<string, unknown>;

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey` resolve
// under the active locale. Resource IDs and field `name`s stay data-driven.
export const rolesConfig: ResourceConfig<AdminRole> = {
  key: "roles",
  titleKey: "resource.roles.title",
  descriptionKey: "resource.roles.description",
  basePath: "/admin/v1/roles",
  idField: "id",
  noUpdate: true,
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/roles"),
  columns: [
    { key: "name", headerKey: "resource.roles.col.name" },
    { key: "slug", headerKey: "resource.roles.col.slug" },
    { key: "description", headerKey: "resource.roles.col.description" },
    {
      key: "permission_keys",
      headerKey: "resource.roles.col.permissions",
      render: (row) => (row.permission_keys ?? []).join(", ") || "-",
    },
  ],
  fields: [
    { name: "name", labelKey: "resource.roles.field.name", type: "text", required: true },
    { name: "slug", labelKey: "resource.roles.field.slug", type: "text", required: true },
    { name: "description", labelKey: "resource.roles.field.description", type: "textarea" },
    {
      name: "permission_keys",
      labelKey: "resource.roles.field.permissions",
      type: "entities",
      reference: {
        target: "permissions",
        valueKey: "key",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["key", "description"],
      },
    },
  ],
};
