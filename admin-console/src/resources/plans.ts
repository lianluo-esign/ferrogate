import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminPlan = AdminSchema<"AdminPlan"> & Record<string, unknown>;

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey`/
// `placeholderKey`/`descriptionKey` resolve under the active locale. Resource
// IDs, field `name`s, and the boolean Yes/No cell renders (data-driven, deferred
// per the framework follow-up) stay untouched.
export const plansConfig: ResourceConfig<AdminPlan> = {
  key: "plans",
  titleKey: "resource.plans.title",
  descriptionKey: "resource.plans.description",
  basePath: "/admin/v1/plans",
  idField: "id",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/plans"),
  columns: [
    { key: "name", headerKey: "resource.plans.col.name" },
    { key: "slug", headerKey: "resource.plans.col.slug" },
    { key: "mcp_enabled", headerKey: "resource.plans.col.mcp", render: (row) => (row.mcp_enabled ? "Yes" : "No") },
    {
      key: "extension_tools_enabled",
      headerKey: "resource.plans.col.extensions",
      render: (row) => (row.extension_tools_enabled ? "Yes" : "No"),
    },
    {
      key: "self_hosted_workers_enabled",
      headerKey: "resource.plans.col.selfHostedWorkers",
      render: (row) => (row.self_hosted_workers_enabled ? "Yes" : "No"),
    },
    {
      key: "asset_hosting_enabled",
      headerKey: "resource.plans.col.assetHosting",
      render: (row) => (row.asset_hosting_enabled ? "Yes" : "No"),
    },
    { key: "default_monthly_budget_usd", headerKey: "resource.plans.col.defaultMonthlyBudget" },
  ],
  fields: [
    {
      name: "id",
      labelKey: "resource.plans.field.id",
      type: "text",
      createOnly: true,
      placeholderKey: "resource.plans.field.id.placeholder",
      descriptionKey: "resource.plans.field.id.desc",
    },
    { name: "name", labelKey: "resource.plans.field.name", type: "text", required: true },
    { name: "slug", labelKey: "resource.plans.field.slug", type: "text", required: true },
    { name: "mcp_enabled", labelKey: "resource.plans.field.mcpEnabled", type: "boolean" },
    { name: "extension_tools_enabled", labelKey: "resource.plans.field.extensionToolsEnabled", type: "boolean" },
    {
      name: "self_hosted_workers_enabled",
      labelKey: "resource.plans.field.selfHostedWorkersEnabled",
      type: "boolean",
    },
    { name: "asset_hosting_enabled", labelKey: "resource.plans.field.assetHostingEnabled", type: "boolean" },
    { name: "admin_console_seats", labelKey: "resource.plans.field.adminConsoleSeats", type: "number" },
    {
      name: "default_model_allowlist",
      labelKey: "resource.plans.field.defaultModelAllowlist",
      type: "csv",
    },
    { name: "default_rpm_limit", labelKey: "resource.plans.field.defaultRpmLimit", type: "number" },
    { name: "default_tpm_limit", labelKey: "resource.plans.field.defaultTpmLimit", type: "number" },
    { name: "default_monthly_budget_usd", labelKey: "resource.plans.field.defaultMonthlyBudget", type: "number" },
    {
      name: "default_asset_storage_quota_bytes",
      labelKey: "resource.plans.field.defaultAssetStorageQuota",
      type: "number",
    },
  ],
};
