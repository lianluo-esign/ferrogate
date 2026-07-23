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
    // organization_ids and api_key_ids match on the raw identifier the caller
    // presents at request time (see ferrogate-cli policy evaluation), which is
    // not guaranteed to be an admin-console tenant/key row, so they stay
    // free-text rather than being force-mapped to an entity source (#341).
    { name: "organization_ids", label: "Organization IDs (comma-separated)", type: "csv" },
    {
      name: "project_ids",
      label: "Projects",
      type: "entities",
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
    },
    { name: "api_key_ids", label: "API key IDs (comma-separated)", type: "csv" },
    {
      name: "models",
      label: "Models",
      type: "entities",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    {
      name: "providers",
      label: "Providers",
      type: "entities",
      reference: {
        target: "providers",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["kind", "base_url"],
      },
    },
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
