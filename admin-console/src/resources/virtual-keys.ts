import { type AdminSchema, adminGet } from "@/lib/gateway-client";
import {
  DISABLED_WHEN_NOT_ENABLED,
  DISABLED_WHEN_STATUS_NOT_ACTIVE,
  type ResourceConfig,
  booleanColumn,
} from "@/lib/resource-config";

/**
 * Row shape derived from the OpenAPI contract (#314): if
 * docs/openapi/admin-api.openapi.json changes this resource, the columns/
 * fetcher below stop type-checking. Regenerate via `npm run generate:api`.
 */
export type AdminVirtualApiKey = AdminSchema<"AdminVirtualApiKey"> & Record<string, unknown>;

// Per-resource operator copy partially migrated onto the typed i18n catalog
// (#348): column `headerKey` and field `labelKey`/`placeholderKey` resolve under
// the active locale via the shared ResourceTable/ResourceForm the bespoke page
// (src/pages/virtual-keys.tsx) renders. `title`/`description` stay inline
// literals because that bespoke page reads them page-locally (not through the
// framework); localizing them belongs to the bespoke-page slice — noted as
// remaining. Resource IDs, field `name`s, and the example scopes placeholder
// (`admin.read,admin.write`) stay data-driven; the boolean Yes/No cell now
// localizes via `booleanColumn` (#385).
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
    {
      key: "name",
      headerKey: "resource.virtualKeys.col.name",
      priority: "primary",
      minWidth: 190,
      mobileVisibility: "always",
    },
    {
      key: "key_prefix",
      headerKey: "resource.virtualKeys.col.prefix",
      priority: "secondary",
      minWidth: 150,
      mobileVisibility: "always",
      render: (row) => `${row.key_prefix}...${row.last4}`,
    },
    {
      key: "workspace_id",
      headerKey: "resource.virtualKeys.col.workspace",
      priority: "detail",
      minWidth: 190,
      copyable: true,
      mobileVisibility: "details",
    },
    booleanColumn<AdminVirtualApiKey>({
      key: "enabled",
      headerKey: "resource.virtualKeys.col.enabled",
      priority: "secondary",
      minWidth: 100,
      mobileVisibility: "always",
    }),
    {
      key: "scopes",
      headerKey: "resource.virtualKeys.col.scopes",
      priority: "detail",
      minWidth: 220,
      mobileVisibility: "details",
      render: (row) => row.scopes.join(", "),
    },
  ],
  fields: [
    {
      name: "name",
      labelKey: "resource.virtualKeys.field.name",
      type: "text",
      required: true,
      createOnly: true,
    },
    {
      // #340: workspace_id was a raw text field. A virtual key is issued against
      // a workspace row, so it now uses the shared single-entity picker.
      // Immutable after create (the key's workspace scope is fixed at issue
      // time), so it stays `createOnly`. Submitted value is the workspace `id`.
      name: "workspace_id",
      labelKey: "resource.virtualKeys.field.workspace",
      type: "entity",
      required: true,
      createOnly: true,
      reference: {
        target: "workspaces",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "project_id"],
        // #340 box 5: a suspended workspace is marked and unselectable.
        disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
      },
    },
    {
      // Scopes stay free text per the #337 escape hatch (#340). Not because no
      // list/get API exists -- `/admin/v1/permissions` does, and backs
      // roles.permission_keys -- but because it is a different vocabulary from a
      // different subsystem: these are the auth-time capability strings matched
      // in ferrogate-cli/src/auth.rs (a virtual key's are data-plane scopes such
      // as `chat.completions`, and privileged `admin.*`/`*` values are rejected
      // outright by the API), whereas the permissions catalog is the #182 RBAC
      // entitlement table (ferrogate-cli/src/gateway/rbac.rs).
      name: "scopes",
      labelKey: "resource.virtualKeys.field.scopes",
      type: "csv",
      placeholder: "admin.read,admin.write",
    },
    {
      // #340: allowed_models targets the model catalog by canonical `name`.
      name: "allowed_models",
      labelKey: "resource.virtualKeys.field.allowedModels",
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
      // #340: allowed_providers targets the provider catalog by canonical `name`.
      name: "allowed_providers",
      labelKey: "resource.virtualKeys.field.allowedProviders",
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
      name: "monthly_token_budget",
      labelKey: "resource.virtualKeys.field.monthlyTokenBudget",
      type: "number",
    },
    {
      name: "request_limit_per_minute",
      labelKey: "resource.virtualKeys.field.requestLimitPerMinute",
      type: "number",
    },
  ],
};
