import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminVirtualApiKey = AdminSchema<"AdminVirtualApiKey"> &
  Record<string, unknown>;

export const virtualKeysConfig: ResourceConfig<AdminVirtualApiKey> = {
  key: "virtual-keys",
  title: "API / virtual keys",
  description: "Keys used to call the gateway and its Admin API.",
  basePath: "/admin/v1/virtual-keys",
  idField: "id",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/virtual-keys"),
  secretResponseKey: "secret",
  rowLabel: (row) => row.name,
  columns: [
    { key: "name", header: "Name", priority: "primary", minWidth: 190, mobileVisibility: "always" },
    { key: "key_prefix", header: "Prefix", priority: "secondary", minWidth: 150, mobileVisibility: "always", render: (row) => `${row.key_prefix}...${row.last4}` },
    { key: "workspace_id", header: "Workspace", priority: "detail", minWidth: 190, copyable: true, mobileVisibility: "details" },
    { key: "enabled", header: "Enabled", priority: "secondary", minWidth: 100, mobileVisibility: "always", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "scopes", header: "Scopes", priority: "detail", minWidth: 220, mobileVisibility: "details", render: (row) => row.scopes.join(", ") },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true, createOnly: true },
    {
      // #340: workspace_id was a raw text field. A virtual key is issued against
      // a workspace row, so it now uses the shared single-entity picker.
      // Immutable after create (the key's workspace scope is fixed at issue
      // time), so it stays `createOnly`. Submitted value is the workspace `id`.
      name: "workspace_id",
      label: "Workspace",
      type: "entity",
      required: true,
      createOnly: true,
      reference: {
        target: "workspaces",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "project_id"],
      },
    },
    {
      // Scopes are an enumerated set of Admin API permission strings
      // (admin.read, admin.write, …), not entity rows backed by a list/get API,
      // so they stay free text per the #337 escape-hatch guidance (#340).
      name: "scopes",
      label: "Scopes (comma-separated)",
      type: "csv",
      placeholder: "admin.read,admin.write",
    },
    {
      // #340: allowed_models targets the model catalog by canonical `name`.
      name: "allowed_models",
      label: "Allowed models",
      type: "entities",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    {
      // #340: allowed_providers targets the provider catalog by canonical `name`.
      name: "allowed_providers",
      label: "Allowed providers",
      type: "entities",
      reference: {
        target: "providers",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["kind", "base_url"],
      },
    },
    { name: "monthly_token_budget", label: "Monthly token budget", type: "number" },
    { name: "request_limit_per_minute", label: "Requests per minute", type: "number" },
  ],
};
