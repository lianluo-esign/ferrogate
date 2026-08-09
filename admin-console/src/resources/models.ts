import { adminGet } from "@/lib/gateway-client";
import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

export type ModelCapability =
  | "chat"
  | "streaming"
  | "vision"
  | "images"
  | "embeddings"
  | "tools"
  | "structured_output";

/**
 * Model list-row shape. The list projection matches the contract `Model`, plus
 * the `id` the mutation endpoints key on: the backend mints one on create and
 * returns it on every row (the OpenAPI schema carries an open index signature
 * over the enumerated fields). Contract drift on the enumerated fields is still
 * caught at the `adminGet` call in `fetchList`.
 */
export interface AdminModel extends Record<string, unknown> {
  id?: string;
  name: string;
  provider: string | null;
  provider_model: string | null;
  routing_strategy: string;
  capabilities?: ModelCapability[];
  context_window?: number | null;
  enabled: boolean;
}

// Catalog models became FULL CRUD in #912 (previously a read-only view):
// create/edit/delete are enabled, and the resource is `platformScopable` so a
// superadmin can toggle between the tenant catalog and the platform default
// catalog. `idField` is `id` — the backend mints an id on create and the
// detail (edit/delete) path is `/admin/v1/models/{id}`; the create form must
// NOT force an id. Per-resource copy resolves through the typed i18n catalog
// (#348); the boolean cell localizes via `booleanColumn` (#385).
export const modelsConfig: ResourceConfig<AdminModel> = {
  key: "models",
  titleKey: "resource.models.title",
  descriptionKey: "resource.models.description",
  basePath: "/admin/v1/models",
  idField: "id",
  platformScopable: true,
  fetchList: async (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/models", {
      query: { offset: request.offset, limit: request.limit },
    }),
  columns: [
    { key: "name", headerKey: "resource.models.col.name" },
    { key: "provider", headerKey: "resource.models.col.provider" },
    { key: "provider_model", headerKey: "resource.models.col.providerModel" },
    { key: "routing_strategy", headerKey: "resource.models.col.routingStrategy" },
    { key: "context_window", headerKey: "resource.models.col.contextWindow" },
    booleanColumn<AdminModel>({ key: "enabled", headerKey: "resource.models.col.enabled" }),
  ],
  fields: [
    { name: "name", labelKey: "resource.models.field.name", type: "text", required: true },
    { name: "family", labelKey: "resource.models.field.family", type: "text" },
    { name: "owned_by", labelKey: "resource.models.field.ownedBy", type: "text" },
    {
      name: "capabilities",
      labelKey: "resource.models.field.capabilities",
      type: "csv",
      placeholderKey: "resource.models.field.capabilities.placeholder",
    },
    {
      name: "context_window",
      labelKey: "resource.models.field.contextWindow",
      type: "number",
    },
    {
      name: "routing_strategy",
      labelKey: "resource.models.field.routingStrategy",
      type: "select",
      options: [
        { labelKey: "resource.models.option.routingStrategy.priority", value: "priority" },
        { labelKey: "resource.models.option.routingStrategy.lowestCost", value: "lowest_cost" },
        { labelKey: "resource.models.option.routingStrategy.lowestLatency", value: "lowest_latency" },
        { labelKey: "resource.models.option.routingStrategy.balanced", value: "balanced" },
      ],
    },
    { name: "enabled", labelKey: "resource.models.field.enabled", type: "boolean" },
  ],
};
