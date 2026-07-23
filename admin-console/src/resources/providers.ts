import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminProvider extends Record<string, unknown> {
  name: string;
  kind: string;
  compatibility: string;
  base_url: string;
  has_api_key: boolean;
  enabled: boolean;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale in the shared resource-CRUD framework. Column `key`s and the boolean
// Yes/No cell renders (a cross-cutting `render` callback with no `t` access,
// deferred to #385) stay data-driven; this is a read-only resource with no
// fields.
export const providersConfig: ResourceConfig<AdminProvider> = {
  key: "providers",
  titleKey: "resource.providers.title",
  descriptionKey: "resource.providers.description",
  basePath: "/admin/v1/providers",
  idField: "name",
  readOnly: true,
  columns: [
    { key: "name", headerKey: "resource.providers.col.name" },
    { key: "kind", headerKey: "resource.providers.col.kind" },
    { key: "compatibility", headerKey: "resource.providers.col.compatibility" },
    { key: "base_url", headerKey: "resource.providers.col.baseUrl" },
    { key: "has_api_key", headerKey: "resource.providers.col.hasApiKey", render: (row) => (row.has_api_key ? "Yes" : "No") },
    { key: "enabled", headerKey: "resource.providers.col.enabled", render: (row) => (row.enabled ? "Yes" : "No") },
  ],
  fields: [],
};
