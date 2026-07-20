import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminPlan = AdminSchema<"AdminPlan"> & Record<string, unknown>;

export const plansConfig: ResourceConfig<AdminPlan> = {
  key: "plans",
  title: "Plans",
  description:
    "Sellable subscription tiers: the feature flags and default quota/budget a tenant inherits via tenant-accounts.plan_id.",
  basePath: "/admin/v1/plans",
  idField: "id",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/plans"),
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "mcp_enabled", header: "MCP", render: (row) => (row.mcp_enabled ? "Yes" : "No") },
    {
      key: "extension_tools_enabled",
      header: "Extensions",
      render: (row) => (row.extension_tools_enabled ? "Yes" : "No"),
    },
    {
      key: "self_hosted_workers_enabled",
      header: "Self-hosted workers",
      render: (row) => (row.self_hosted_workers_enabled ? "Yes" : "No"),
    },
    {
      key: "asset_hosting_enabled",
      header: "Asset hosting",
      render: (row) => (row.asset_hosting_enabled ? "Yes" : "No"),
    },
    { key: "default_monthly_budget_usd", header: "Default monthly budget (USD)" },
  ],
  fields: [
    {
      name: "id",
      label: "ID",
      type: "text",
      createOnly: true,
      placeholder: "defaults to slug when left blank",
      description: "Referenced by tenant-accounts.plan_id. Immutable after creation.",
    },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "mcp_enabled", label: "MCP tool execution enabled", type: "boolean" },
    { name: "extension_tools_enabled", label: "Extension tool execution enabled", type: "boolean" },
    {
      name: "self_hosted_workers_enabled",
      label: "Self-hosted workers enabled",
      type: "boolean",
    },
    { name: "asset_hosting_enabled", label: "Asset hosting enabled", type: "boolean" },
    { name: "admin_console_seats", label: "Admin console seats", type: "number" },
    {
      name: "default_model_allowlist",
      label: "Default model allowlist (comma-separated)",
      type: "csv",
    },
    { name: "default_rpm_limit", label: "Default RPM limit", type: "number" },
    { name: "default_tpm_limit", label: "Default TPM limit", type: "number" },
    { name: "default_monthly_budget_usd", label: "Default monthly budget (USD)", type: "number" },
    {
      name: "default_asset_storage_quota_bytes",
      label: "Default asset storage quota (bytes)",
      type: "number",
    },
  ],
};
