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
  columns: [
    { key: "name", header: "Name" },
    { key: "key_prefix", header: "Prefix", render: (row) => `${row.key_prefix}...${row.last4}` },
    { key: "workspace_id", header: "Workspace" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "scopes", header: "Scopes", render: (row) => row.scopes.join(", ") },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true, createOnly: true },
    { name: "workspace_id", label: "Workspace ID", type: "text", required: true, createOnly: true },
    {
      name: "scopes",
      label: "Scopes (comma-separated)",
      type: "csv",
      placeholder: "admin.read,admin.write",
    },
    { name: "allowed_models", label: "Allowed models (comma-separated)", type: "csv" },
    { name: "allowed_providers", label: "Allowed providers (comma-separated)", type: "csv" },
    { name: "monthly_token_budget", label: "Monthly token budget", type: "number" },
    { name: "request_limit_per_minute", label: "Requests per minute", type: "number" },
  ],
};
