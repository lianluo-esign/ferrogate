import { type AdminSchema, adminGet } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminTenantAccount = AdminSchema<"AdminTenantAccount"> & Record<string, unknown>;

// Per-resource operator copy is migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, and field `labelKey`/
// `descriptionKey` resolve under the active locale in the shared resource-CRUD
// framework. Resource IDs, field `name`s, and the example status placeholder
// (`active`, an issue-protected example value) stay data-driven.
export const tenantAccountsConfig: ResourceConfig<AdminTenantAccount> = {
  key: "tenant-accounts",
  titleKey: "resource.tenantAccounts.title",
  descriptionKey: "resource.tenantAccounts.description",
  basePath: "/admin/v1/tenant-accounts",
  idField: "id",
  pagination: "offset",
  fetchList: (apiKey, request) => adminGet(apiKey, "/admin/v1/tenant-accounts", { query: request }),
  // Deleting a tenant is a large, cascading, destructive operation this
  // console deliberately never offers -- the backend has no DELETE
  // handler for /admin/v1/tenant-accounts/{id} either (GET/PUT/PATCH
  // only). Edit IS supported: PUT is accepted with the same
  // field-optional merge semantics as PATCH specifically so this
  // generic edit form (which always sends PUT) can reassign plan_id.
  noDelete: true,
  columns: [
    { key: "name", headerKey: "resource.tenantAccounts.col.name" },
    { key: "slug", headerKey: "resource.tenantAccounts.col.slug" },
    { key: "status", headerKey: "resource.tenantAccounts.col.status" },
    { key: "plan_id", headerKey: "resource.tenantAccounts.col.plan" },
    { key: "id", headerKey: "resource.tenantAccounts.col.id" },
  ],
  fields: [
    { name: "name", labelKey: "resource.tenantAccounts.field.name", type: "text", required: true },
    { name: "slug", labelKey: "resource.tenantAccounts.field.slug", type: "text", required: true },
    {
      name: "status",
      labelKey: "resource.tenantAccounts.field.status",
      type: "text",
      placeholder: "active",
    },
    {
      // #340: plan_id was a raw text field asking operators to paste a plan
      // id/slug. It is a first-class entity (the Plans catalog), so it now uses
      // the shared single-entity picker. The submitted value is unchanged: the
      // plan's canonical `id`.
      name: "plan_id",
      labelKey: "resource.tenantAccounts.field.plan",
      type: "entity",
      descriptionKey: "resource.tenantAccounts.field.plan.desc",
      reference: {
        target: "plans",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug"],
      },
    },
  ],
};
