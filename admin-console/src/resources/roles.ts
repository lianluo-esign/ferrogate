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

export const rolesConfig: ResourceConfig<AdminRole> = {
  key: "roles",
  title: "Roles",
  description:
    "Named permission bundles assigned to tenants via tenant-role bindings.",
  basePath: "/admin/v1/roles",
  idField: "id",
  noUpdate: true,
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/roles"),
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "description", header: "Description" },
    {
      key: "permission_keys",
      header: "Permissions",
      render: (row) => (row.permission_keys ?? []).join(", ") || "-",
    },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "description", label: "Description", type: "textarea" },
    {
      name: "permission_keys",
      label: "Permissions",
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
