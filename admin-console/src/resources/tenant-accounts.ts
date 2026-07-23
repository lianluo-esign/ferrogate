import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminTenantAccount = AdminSchema<"AdminTenantAccount"> &
  Record<string, unknown>;

export const tenantAccountsConfig: ResourceConfig<AdminTenantAccount> = {
  key: "tenant-accounts",
  title: "Tenant accounts",
  description: "Top-level organizations in the control plane.",
  basePath: "/admin/v1/tenant-accounts",
  idField: "id",
  pagination: "offset",
  fetchList: (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/tenant-accounts", { query: request }),
  // Deleting a tenant is a large, cascading, destructive operation this
  // console deliberately never offers -- the backend has no DELETE
  // handler for /admin/v1/tenant-accounts/{id} either (GET/PUT/PATCH
  // only). Edit IS supported: PUT is accepted with the same
  // field-optional merge semantics as PATCH specifically so this
  // generic edit form (which always sends PUT) can reassign plan_id.
  noDelete: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "status", header: "Status" },
    { key: "plan_id", header: "Plan" },
    { key: "id", header: "ID" },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
    {
      // #340: plan_id was a raw text field asking operators to paste a plan
      // id/slug. It is a first-class entity (the Plans catalog), so it now uses
      // the shared single-entity picker. The submitted value is unchanged: the
      // plan's canonical `id`.
      name: "plan_id",
      label: "Plan",
      type: "entity",
      description: "The subscription plan this tenant inherits quota/features from.",
      reference: {
        target: "plans",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug"],
      },
    },
  ],
};
