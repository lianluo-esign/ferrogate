import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminPlan = AdminSchema<"AdminPlan"> & Record<string, unknown>;

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey`/
// `placeholderKey`/`descriptionKey` resolve under the active locale. Resource
// IDs and field `name`s stay untouched; the boolean Yes/No cell renders now
// localize via `booleanColumn` (#385).
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
    booleanColumn<AdminPlan>({ key: "mcp_enabled", headerKey: "resource.plans.col.mcp" }),
    booleanColumn<AdminPlan>({ key: "extension_tools_enabled", headerKey: "resource.plans.col.extensions" }),
    booleanColumn<AdminPlan>({
      key: "self_hosted_workers_enabled",
      headerKey: "resource.plans.col.selfHostedWorkers",
    }),
    booleanColumn<AdminPlan>({ key: "asset_hosting_enabled", headerKey: "resource.plans.col.assetHosting" }),
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
      // #340: the plan's default model allowlist was a raw CSV of model names.
      // Models are a first-class catalog, so it now uses the shared multi-entity
      // picker targeting the model catalog by canonical `name` (same shape as the
      // key allowlists). The submitted value is unchanged: an array of model
      // names. An existing name no longer in the catalog stays inspectable as an
      // unresolved chip rather than silently disappearing.
      name: "default_model_allowlist",
      labelKey: "resource.plans.field.defaultModelAllowlist",
      type: "entities",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
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
