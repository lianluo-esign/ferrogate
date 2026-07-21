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

export const permissionsConfig: ResourceConfig<AdminPermission> = {
  key: "permissions",
  title: "Permissions",
  description: "Atomic capability keys referenced by roles.",
  basePath: "/admin/v1/permissions",
  idField: "id",
  noUpdate: true,
  pagination: "offset",
  fetchList: (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/permissions", { query: request }),
  columns: [
    { key: "key", header: "Key" },
    { key: "name", header: "Name" },
    { key: "description", header: "Description" },
  ],
  fields: [
    {
      name: "key",
      label: "Key",
      type: "text",
      required: true,
      placeholder: "admin.read",
    },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "description", label: "Description", type: "textarea" },
  ],
};
