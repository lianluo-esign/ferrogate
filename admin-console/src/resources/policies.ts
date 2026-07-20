import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

/**
 * Access-control policy rules (#321) over `/admin/v1/policies`. Full CRUD:
 * GET/POST on the collection and GET/PUT/PATCH/DELETE on
 * `/admin/v1/policies/{name}` — the rule `name` is the identifier, so it is
 * `createOnly` (editing a rule keeps its name; the PUT path carries it).
 *
 * Row shape derived from the OpenAPI contract (#314): regenerate via
 * `npm run generate:api` if the contract changes.
 */
export type PolicyRule = AdminSchema<"PolicyRule"> & Record<string, unknown>;

export const policiesConfig: ResourceConfig<PolicyRule> = {
  key: "policies",
  title: "Policies",
  description:
    "Allow/deny rules evaluated against callers, models and providers.",
  basePath: "/admin/v1/policies",
  idField: "name",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/policies"),
  columns: [
    { key: "name", header: "Name" },
    { key: "effect", header: "Effect" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "code", header: "Deny code" },
  ],
  fields: [
    {
      name: "name",
      label: "Name",
      type: "text",
      required: true,
      createOnly: true,
      description: "Immutable identifier for the rule.",
    },
    {
      name: "effect",
      label: "Effect",
      type: "select",
      options: [
        { label: "Deny", value: "deny" },
        { label: "Allow", value: "allow" },
      ],
    },
    { name: "organization_ids", label: "Organization IDs (comma-separated)", type: "csv" },
    { name: "project_ids", label: "Project IDs (comma-separated)", type: "csv" },
    { name: "api_key_ids", label: "API key IDs (comma-separated)", type: "csv" },
    { name: "models", label: "Models (comma-separated)", type: "csv" },
    { name: "providers", label: "Providers (comma-separated)", type: "csv" },
    { name: "code", label: "Deny code", type: "text", placeholder: "policy_denied" },
    {
      name: "message",
      label: "Deny message",
      type: "text",
      placeholder: "request denied by policy",
    },
    { name: "enabled", label: "Enabled", type: "boolean" },
  ],
};
