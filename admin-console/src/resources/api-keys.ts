import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Native gateway API keys (#321) over `/admin/v1/api-keys` — distinct from the
 * durable virtual keys at `/admin/v1/virtual-keys`. These are the caller-supplied
 * keys (env-var reference or plaintext) the gateway authenticates directly. Full
 * CRUD: GET/POST on the collection and GET/PUT/PATCH/DELETE on
 * `/admin/v1/api-keys/{id}`. The secret material (`key`/`key_env`) is set only at
 * creation, so those fields are `createOnly`.
 *
 * Row shape derived from the OpenAPI contract (#314): regenerate via
 * `npm run generate:api` if the contract changes.
 */
export type AdminApiKey = AdminSchema<"AdminApiKey"> & Record<string, unknown>;

export const apiKeysConfig: ResourceConfig<AdminApiKey> = {
  key: "api-keys-native",
  title: "API keys",
  description:
    "Native gateway API keys the caller presents directly (distinct from virtual keys).",
  basePath: "/admin/v1/api-keys",
  idField: "id",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/api-keys"),
  rowLabel: (row) => row.name,
  columns: [
    { key: "name", header: "Name", priority: "primary", minWidth: 220, mobileVisibility: "always" },
    { key: "key_source", header: "Source", priority: "secondary", minWidth: 140, mobileVisibility: "always" },
    { key: "enabled", header: "Enabled", priority: "secondary", minWidth: 100, mobileVisibility: "always", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "scopes", header: "Scopes", priority: "detail", minWidth: 240, mobileVisibility: "details", render: (row) => (row.scopes ?? []).join(", ") || "-" },
  ],
  fields: [
    {
      name: "id",
      label: "ID",
      type: "text",
      createOnly: true,
      placeholder: "auto-generated when blank",
    },
    { name: "name", label: "Name", type: "text", required: true },
    {
      name: "key_env",
      label: "Key environment variable",
      type: "text",
      createOnly: true,
      placeholder: "FERRO_API_KEY_ACME",
      description: "Reference an env var holding the secret (preferred over inline key).",
    },
    {
      name: "key",
      label: "Key (plaintext)",
      type: "text",
      createOnly: true,
      description: "Inline secret; stored hashed. Set once at creation.",
    },
    { name: "enabled", label: "Enabled", type: "boolean" },
    { name: "scopes", label: "Scopes (comma-separated)", type: "csv" },
    { name: "allowed_models", label: "Allowed models (comma-separated)", type: "csv" },
    { name: "denied_models", label: "Denied models (comma-separated)", type: "csv" },
    { name: "allowed_providers", label: "Allowed providers (comma-separated)", type: "csv" },
    { name: "denied_providers", label: "Denied providers (comma-separated)", type: "csv" },
    { name: "organization_id", label: "Organization ID", type: "text" },
    { name: "project_id", label: "Project ID", type: "text" },
    { name: "workspace_id", label: "Workspace ID", type: "text" },
    { name: "user_id", label: "User ID", type: "text" },
    { name: "monthly_token_budget", label: "Monthly token budget", type: "number" },
    { name: "request_limit_per_minute", label: "Requests per minute", type: "number" },
    { name: "expires_at_unix", label: "Expires at (unix seconds)", type: "number" },
    { name: "log_bodies", label: "Log request/response bodies", type: "boolean" },
    { name: "cache_enabled", label: "Cache enabled", type: "boolean" },
  ],
};
