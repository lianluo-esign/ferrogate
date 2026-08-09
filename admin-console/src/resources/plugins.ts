import { type ResourceConfig, booleanColumn } from "@/lib/resource-config";

export interface AdminPlugin extends Record<string, unknown> {
  id: string;
  kind: "request_hook" | "tool_provider" | "event_sink";
  version: string;
  enabled: boolean;
  source: string;
  order: number;
  active: boolean;
  lifecycle: string;
  health: string;
  last_error: string | null;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348).
// Resource ID, field `name`s, and option `value`s stay data-driven; the
// boolean Yes/No cell now localizes via `booleanColumn` (#385).
export const pluginsConfig: ResourceConfig<AdminPlugin> = {
  key: "plugins",
  titleKey: "resource.plugins.title",
  descriptionKey: "resource.plugins.description",
  basePath: "/admin/v1/plugins",
  idField: "id",
  columns: [
    { key: "id", headerKey: "resource.plugins.col.id" },
    { key: "kind", headerKey: "resource.plugins.col.kind" },
    { key: "version", headerKey: "resource.plugins.col.version" },
    booleanColumn<AdminPlugin>({ key: "enabled", headerKey: "resource.plugins.col.enabled" }),
    { key: "health", headerKey: "resource.plugins.col.health" },
    { key: "last_error", headerKey: "resource.plugins.col.lastError" },
  ],
  fields: [
    {
      name: "id",
      labelKey: "resource.plugins.field.id",
      type: "text",
      required: true,
      createOnly: true,
    },
    {
      name: "kind",
      labelKey: "resource.plugins.field.kind",
      type: "select",
      required: true,
      options: [
        { labelKey: "resource.plugins.option.kind.requestHook", value: "request_hook" },
        { labelKey: "resource.plugins.option.kind.toolProvider", value: "tool_provider" },
        { labelKey: "resource.plugins.option.kind.eventSink", value: "event_sink" },
      ],
    },
    { name: "version", labelKey: "resource.plugins.field.version", type: "text" },
    { name: "source", labelKey: "resource.plugins.field.source", type: "text" },
    { name: "order", labelKey: "resource.plugins.field.order", type: "number" },
    { name: "enabled", labelKey: "resource.plugins.field.enabled", type: "boolean" },
    {
      name: "approval_policy",
      labelKey: "resource.plugins.field.approvalPolicy",
      type: "select",
      options: [
        { labelKey: "resource.plugins.option.approvalPolicy.never", value: "never" },
        { labelKey: "resource.plugins.option.approvalPolicy.always", value: "always" },
      ],
    },
    { name: "manifest", labelKey: "resource.plugins.field.manifest", type: "json" },
    { name: "compatibility", labelKey: "resource.plugins.field.compatibility", type: "json" },
    { name: "permissions", labelKey: "resource.plugins.field.permissions", type: "json" },
    { name: "config", labelKey: "resource.plugins.field.config", type: "json" },
  ],
};
