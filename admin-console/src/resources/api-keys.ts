import { type AdminSchema, adminGet } from "@/lib/gateway-client";
import {
  DISABLED_WHEN_NOT_ENABLED,
  DISABLED_WHEN_STATUS_NOT_ACTIVE,
  type ResourceConfig,
  booleanColumn,
} from "@/lib/resource-config";

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
    {
      key: "name",
      headerKey: "resource.apiKeys.col.name",
      priority: "primary",
      minWidth: 220,
      mobileVisibility: "always",
    },
    {
      key: "key_source",
      headerKey: "resource.apiKeys.col.source",
      priority: "secondary",
      minWidth: 140,
      mobileVisibility: "always",
    },
    booleanColumn<AdminApiKey>({
      key: "enabled",
      headerKey: "resource.apiKeys.col.enabled",
      priority: "secondary",
      minWidth: 100,
      mobileVisibility: "always",
    }),
    {
      key: "scopes",
      headerKey: "resource.apiKeys.col.scopes",
      priority: "detail",
      minWidth: 240,
      mobileVisibility: "details",
      render: (row) => (row.scopes ?? []).join(", ") || "-",
    },
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
      // Scopes stay free text (#337 escape hatch, #340). The justification is
      // NOT "no list/get API exists" -- `/admin/v1/permissions` exists and backs
      // roles.permission_keys. It is that these are a different vocabulary from
      // a different subsystem: `scopes` are the auth-time capability strings
      // matched in ferrogate-cli/src/auth.rs (plus `*`, and provider-facing
      // entries like `chat.completions` that are not RBAC rows at all), whereas
      // the permissions catalog is the #182 RBAC entitlement table
      // (ferrogate-cli/src/gateway/rbac.rs). Binding this field to that catalog
      // would silently forbid legal scopes and imply a coupling that does not
      // exist.
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
        // #340 box 5: a model the operator disabled in the catalog is listed,
        // marked, and unselectable; an already-stored one stays inspectable.
        disabledWhen: DISABLED_WHEN_NOT_ENABLED,
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
        // #340 box 5: a model the operator disabled in the catalog is listed,
        // marked, and unselectable; an already-stored one stays inspectable.
        disabledWhen: DISABLED_WHEN_NOT_ENABLED,
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
        // #340 box 5: same marking for a disabled provider.
        disabledWhen: DISABLED_WHEN_NOT_ENABLED,
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
        // #340 box 5: same marking for a disabled provider.
        disabledWhen: DISABLED_WHEN_NOT_ENABLED,
      },
    },
    {
      // #340 box 1: `organization_id` IS a tenant reference, so it is a picker
      // over the same `tenant-accounts` catalog projects.ts uses for its
      // `tenant_id`. It previously shipped as free text on the premise that it
      // "is not guaranteed to be an admin-console tenant row and the console
      // exposes no organizations list endpoint" -- both halves are false:
      //   * the gateway compares this value DIRECTLY against a tenant-accounts
      //     row id (`project.tenant_id != organization_id` in
      //     crates/ferrogate-cli/src/gateway/api_key_tenancy.rs), and the same
      //     equivalence holds across the tree (local.rs resolves the request
      //     tenant as `auth.organization_id`, wallets are 1:1 with it);
      //   * `/admin/v1/tenant-accounts` is exactly the list endpoint the
      //     premise claimed was missing -- projects.ts:39 already targets it.
      // The submitted payload is unchanged (the canonical tenant `id`). A
      // stored value that is not a tenant row still renders, badged as an
      // unresolved reference with its raw id shown, so pre-existing and deleted
      // references stay inspectable and repairable.
      name: "organization_id",
      labelKey: "resource.apiKeys.field.organization",
      descriptionKey: "resource.apiKeys.field.organization.desc",
      type: "entity",
      reference: {
        target: "tenant-accounts",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug"],
        // #340 box 5: a suspended tenant is listed but marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
      },
    },
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
        // #340 box 5: a suspended project is marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
      },
    },
    {
      // #340: the workspace picker is scoped to the selected project via a
      // dependent selector (the workspaces list honours a `project_id` filter),
      // so an operator cannot pair project A's id with a workspace that lives in
      // project B — a cross-project (and therefore cross-tenant) combo the API
      // would reject. Choosing/clearing the project clears a stale workspace
      // (clearDependentReferenceValues); the picker stays disabled until a
      // project is picked.
      name: "workspace_id",
      labelKey: "resource.apiKeys.field.workspace",
      type: "entity",
      reference: {
        target: "workspaces",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "project_id"],
        // #340 box 5: a suspended workspace is marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
        // No inline `label`: the picker humanizes the field name ("project id")
        // for its "select … first" prompt, so no untranslated literal is baked
        // into the shared config data.
        dependencies: [{ field: "project_id", queryKey: "project_id" }],
      },
    },
    {
      // #340 box 7 (explicit exclusion, not a silent one): `user_id` stays free
      // text. Box 1 does not list "user" among the entity kinds it forbids, and
      // unlike `organization_id` there is genuinely no catalog to bind to --
      // the Admin API exposes no users list/get endpoint, so there is nothing
      // for the shared #337 picker to read. Revisit if a users endpoint lands.
      name: "user_id",
      labelKey: "resource.apiKeys.field.userId",
      type: "text",
    },
    {
      name: "monthly_token_budget",
      labelKey: "resource.apiKeys.field.monthlyTokenBudget",
      type: "number",
    },
    {
      name: "request_limit_per_minute",
      labelKey: "resource.apiKeys.field.requestLimitPerMinute",
      type: "number",
    },
    { name: "expires_at_unix", labelKey: "resource.apiKeys.field.expiresAt", type: "number" },
    { name: "log_bodies", labelKey: "resource.apiKeys.field.logBodies", type: "boolean" },
    { name: "cache_enabled", labelKey: "resource.apiKeys.field.cacheEnabled", type: "boolean" },
  ],
};
