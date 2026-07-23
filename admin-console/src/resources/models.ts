import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

export interface AdminModel extends Record<string, unknown> {
  name: string;
  provider: string;
  provider_model: string;
  routing_strategy: string;
  capabilities: string[];
  context_window: number | null;
  input_price_per_1m: number | null;
  output_price_per_1m: number | null;
  enabled: boolean;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s stay data-driven; the boolean Yes/No cell now localizes
// via `booleanColumn` (#385). This is a read-only resource with no fields.
export const modelsConfig: ResourceConfig<AdminModel> = {
  key: "models",
  titleKey: "resource.models.title",
  descriptionKey: "resource.models.description",
  basePath: "/admin/v1/models",
  idField: "name",
  readOnly: true,
  columns: [
    { key: "name", headerKey: "resource.models.col.name" },
    { key: "provider", headerKey: "resource.models.col.provider" },
    { key: "provider_model", headerKey: "resource.models.col.providerModel" },
    { key: "routing_strategy", headerKey: "resource.models.col.routingStrategy" },
    { key: "context_window", headerKey: "resource.models.col.contextWindow" },
    booleanColumn<AdminModel>({ key: "enabled", headerKey: "resource.models.col.enabled" }),
  ],
  fields: [],
};
