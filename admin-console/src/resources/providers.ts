import { adminGet } from "@/lib/gateway-client";
import { type ResourceConfig, booleanColumn } from "@/lib/resource-config";

/**
 * Provider list-row shape. The list projection matches the contract
 * `AdminProvider`, plus the `id` the mutation endpoints key on: the backend
 * mints one on create and returns it on every row (the OpenAPI schema carries
 * an open index signature over the enumerated fields). Contract drift on the
 * enumerated fields is still caught at the `adminGet` call in `fetchList`.
 */
export interface AdminProvider extends Record<string, unknown> {
  id?: string;
  name: string;
  kind: string;
  compatibility: string;
  base_url: string;
  has_api_key: boolean;
  enabled: boolean;
}

// Provider channels became FULL CRUD in #912 (previously a read-only view):
// create/edit/delete are enabled, and the resource is `platformScopable` so a
// superadmin can toggle between the tenant catalog and the platform default
// catalog. `idField` is `id` — the backend mints an id on create and the
// detail (edit/delete) path is `/admin/v1/providers/{id}`; the create form must
// NOT force an id. Per-resource copy resolves through the typed i18n catalog
// (#348); the boolean cells localize via `booleanColumn` (#385).
export const providersConfig: ResourceConfig<AdminProvider> = {
  key: "providers",
  titleKey: "resource.providers.title",
  descriptionKey: "resource.providers.description",
  basePath: "/admin/v1/providers",
  idField: "id",
  platformScopable: true,
  fetchList: async (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/providers", {
      query: { offset: request.offset, limit: request.limit },
    }),
  columns: [
    { key: "name", headerKey: "resource.providers.col.name" },
    { key: "kind", headerKey: "resource.providers.col.kind" },
    { key: "compatibility", headerKey: "resource.providers.col.compatibility" },
    { key: "base_url", headerKey: "resource.providers.col.baseUrl" },
    booleanColumn<AdminProvider>({
      key: "has_api_key",
      headerKey: "resource.providers.col.hasApiKey",
    }),
    booleanColumn<AdminProvider>({ key: "enabled", headerKey: "resource.providers.col.enabled" }),
  ],
  fields: [
    { name: "name", labelKey: "resource.providers.field.name", type: "text", required: true },
    { name: "kind", labelKey: "resource.providers.field.kind", type: "text", required: true },
    {
      name: "base_url",
      labelKey: "resource.providers.field.baseUrl",
      type: "text",
      required: true,
      inputMode: "url",
      autoComplete: "off",
    },
    { name: "api_key_var", labelKey: "resource.providers.field.apiKeyVar", type: "text" },
    { name: "byok_alias", labelKey: "resource.providers.field.byokAlias", type: "text" },
    {
      name: "auth_scheme",
      labelKey: "resource.providers.field.authScheme",
      type: "select",
      options: [
        { labelKey: "resource.providers.option.authScheme.bearer", value: "bearer" },
        { labelKey: "resource.providers.option.authScheme.xApiKey", value: "x-api-key" },
      ],
    },
    { name: "region", labelKey: "resource.providers.field.region", type: "text" },
    {
      name: "zero_data_retention",
      labelKey: "resource.providers.field.zeroDataRetention",
      type: "boolean",
    },
    { name: "enabled", labelKey: "resource.providers.field.enabled", type: "boolean" },
  ],
};
