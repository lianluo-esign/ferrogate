import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

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

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey`/
// `placeholderKey`/`descriptionKey` resolve under the active locale. Resource
// IDs, field `name`s, and the example env-var placeholder (`FERRO_API_KEY_ACME`,
// an issue-protected example value) stay data-driven; the boolean Yes/No cell
// now localizes via `booleanColumn` (#385).
export const apiKeysConfig: ResourceConfig<AdminApiKey> = {
  key: "api-keys-native",
  titleKey: "resource.apiKeys.title",
  descriptionKey: "resource.apiKeys.description",
  basePath: "/admin/v1/api-keys",
  idField: "id",
  fetchList: async (apiKey) => adminGet(apiKey, "/admin/v1/api-keys"),
  rowLabel: (row) => row.name,
  columns: [
    { key: "name", headerKey: "resource.apiKeys.col.name", priority: "primary", minWidth: 220, mobileVisibility: "always" },
    { key: "key_source", headerKey: "resource.apiKeys.col.source", priority: "secondary", minWidth: 140, mobileVisibility: "always" },
    booleanColumn<AdminApiKey>({ key: "enabled", headerKey: "resource.apiKeys.col.enabled", priority: "secondary", minWidth: 100, mobileVisibility: "always" }),
    { key: "scopes", headerKey: "resource.apiKeys.col.scopes", priority: "detail", minWidth: 240, mobileVisibility: "details", render: (row) => (row.scopes ?? []).join(", ") || "-" },
  ],
  fields: [
    {
      name: "id",
      labelKey: "resource.apiKeys.field.id",
      type: "text",
      createOnly: true,
      placeholderKey: "resource.apiKeys.field.id.placeholder",
    },
    { name: "name", labelKey: "resource.apiKeys.field.name", type: "text", required: true },
    {
      name: "key_env",
      labelKey: "resource.apiKeys.field.keyEnv",
      type: "text",
      createOnly: true,
      placeholder: "FERRO_API_KEY_ACME",
      descriptionKey: "resource.apiKeys.field.keyEnv.desc",
    },
    {
      name: "key",
      labelKey: "resource.apiKeys.field.key",
      type: "text",
      createOnly: true,
      descriptionKey: "resource.apiKeys.field.key.desc",
    },
    { name: "enabled", labelKey: "resource.apiKeys.field.enabled", type: "boolean" },
    {
      // Scopes are an enumerated set of Admin API permission strings, not entity
      // rows with a list/get API, so they stay free text (#337 escape hatch, #340).
      name: "scopes",
      labelKey: "resource.apiKeys.field.scopes",
      type: "csv",
    },
    {
      // #340: allow/deny model + provider lists target the model/provider
      // catalogs by canonical `name` (same shape as policies.ts from #341).
      name: "allowed_models",
      labelKey: "resource.apiKeys.field.allowedModels",
      type: "entities",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    {
      name: "denied_models",
      labelKey: "resource.apiKeys.field.deniedModels",
      type: "entities",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    {
      name: "allowed_providers",
      labelKey: "resource.apiKeys.field.allowedProviders",
      type: "entities",
      reference: {
        target: "providers",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["kind", "base_url"],
      },
    },
    {
      name: "denied_providers",
      labelKey: "resource.apiKeys.field.deniedProviders",
      type: "entities",
      reference: {
        target: "providers",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["kind", "base_url"],
      },
    },
    // organization_id and user_id match the raw identifier the caller presents
    // at request time (see the native api-key auth path in ferrogate-cli); they
    // are not guaranteed to be admin-console tenant/user rows and the console
    // exposes no organizations/users list endpoint, so they stay free text
    // rather than being force-mapped to an entity source (mirrors the
    // policies.ts organization_ids decision from #341; #340).
    { name: "organization_id", labelKey: "resource.apiKeys.field.organizationId", type: "text" },
    {
      // #340: project_id / workspace_id are first-class rows the key is scoped
      // to, so they now use the shared single-entity pickers. Submitted values
      // are unchanged (the canonical `id`).
      name: "project_id",
      labelKey: "resource.apiKeys.field.project",
      type: "entity",
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
    },
    {
      name: "workspace_id",
      labelKey: "resource.apiKeys.field.workspace",
      type: "entity",
      reference: {
        target: "workspaces",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "project_id"],
      },
    },
    { name: "user_id", labelKey: "resource.apiKeys.field.userId", type: "text" },
    { name: "monthly_token_budget", labelKey: "resource.apiKeys.field.monthlyTokenBudget", type: "number" },
    { name: "request_limit_per_minute", labelKey: "resource.apiKeys.field.requestLimitPerMinute", type: "number" },
    { name: "expires_at_unix", labelKey: "resource.apiKeys.field.expiresAt", type: "number" },
    { name: "log_bodies", labelKey: "resource.apiKeys.field.logBodies", type: "boolean" },
    { name: "cache_enabled", labelKey: "resource.apiKeys.field.cacheEnabled", type: "boolean" },
  ],
};
