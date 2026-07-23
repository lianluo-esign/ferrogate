import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

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

// Per-resource operator copy migrated onto the typed i18n catalog (#348).
// Rule `name`, field `name`s, and option `value`s stay data-driven; the two
// example placeholders (`policy_denied`, `request denied by policy`) stay inline
// literals because they are illustrative code/config values the issue protects
// from translation. The boolean Yes/No cell now localizes via `booleanColumn`
// (#385).
export const policiesConfig: ResourceConfig<PolicyRule> = {
  key: "policies",
  titleKey: "resource.policies.title",
  descriptionKey: "resource.policies.description",
  basePath: "/admin/v1/policies",
  idField: "name",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/policies"),
  columns: [
    { key: "name", headerKey: "resource.policies.col.name" },
    { key: "effect", headerKey: "resource.policies.col.effect" },
    booleanColumn<PolicyRule>({ key: "enabled", headerKey: "resource.policies.col.enabled" }),
    { key: "code", headerKey: "resource.policies.col.code" },
  ],
  fields: [
    {
      name: "name",
      labelKey: "resource.policies.field.name",
      type: "text",
      required: true,
      createOnly: true,
      descriptionKey: "resource.policies.field.name.desc",
    },
    {
      name: "effect",
      labelKey: "resource.policies.field.effect",
      type: "select",
      options: [
        { labelKey: "resource.policies.option.effect.deny", value: "deny" },
        { labelKey: "resource.policies.option.effect.allow", value: "allow" },
      ],
    },
    // organization_ids and api_key_ids match on the raw identifier the caller
    // presents at request time (see ferrogate-cli policy evaluation), which is
    // not guaranteed to be an admin-console tenant/key row, so they stay
    // free-text rather than being force-mapped to an entity source (#341).
    { name: "organization_ids", labelKey: "resource.policies.field.organizationIds", type: "csv" },
    {
      name: "project_ids",
      labelKey: "resource.policies.field.projectIds",
      type: "entities",
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
    },
    { name: "api_key_ids", labelKey: "resource.policies.field.apiKeyIds", type: "csv" },
    {
      name: "models",
      labelKey: "resource.policies.field.models",
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
      labelKey: "resource.policies.field.providers",
      type: "entities",
      reference: {
        target: "providers",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["kind", "base_url"],
      },
    },
    { name: "code", labelKey: "resource.policies.field.code", type: "text", placeholder: "policy_denied" },
    {
      name: "message",
      labelKey: "resource.policies.field.message",
      type: "text",
      placeholder: "request denied by policy",
    },
    { name: "enabled", labelKey: "resource.policies.field.enabled", type: "boolean" },
  ],
};
