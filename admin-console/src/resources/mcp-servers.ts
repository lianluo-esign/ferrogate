import { type ResourceConfig, booleanColumn } from "@/lib/resource-config";

// The exact McpServerConfig/McpServerStatus shape lives in ferrogate-mcp and
// wasn't traced field-by-field; this resource is intentionally generic
// (raw JSON in, whatever the gateway returns rendered defensively) until a
// follow-up pass types it precisely.
export interface AdminMcpServer extends Record<string, unknown> {
  name?: string;
  id?: string;
  enabled?: boolean;
  transport?: string;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, and field `labelKey`/
// `descriptionKey` resolve under the active locale. Resource IDs, field
// `name`s, and the defensive name/transport fallback renders stay data-driven;
// the boolean Yes/No cell now localizes via `booleanColumn` (#385).
export const mcpServersConfig: ResourceConfig<AdminMcpServer> = {
  key: "mcp-servers",
  titleKey: "resource.mcpServers.title",
  descriptionKey: "resource.mcpServers.description",
  basePath: "/admin/v1/mcp-servers",
  idField: "name",
  resolveDetailPath: (row) => String(row.name ?? row.id ?? ""),
  columns: [
    {
      key: "name",
      headerKey: "resource.mcpServers.col.name",
      render: (row) => String(row.name ?? row.id ?? ""),
    },
    {
      key: "transport",
      headerKey: "resource.mcpServers.col.transport",
      render: (row) => String(row.transport ?? ""),
    },
    booleanColumn<AdminMcpServer>({ key: "enabled", headerKey: "resource.mcpServers.col.enabled" }),
  ],
  fields: [
    {
      name: "name",
      labelKey: "resource.mcpServers.field.name",
      type: "text",
      required: true,
      createOnly: true,
    },
    { name: "enabled", labelKey: "resource.mcpServers.field.enabled", type: "boolean" },
    {
      name: "config",
      labelKey: "resource.mcpServers.field.config",
      type: "json",
      descriptionKey: "resource.mcpServers.field.config.desc",
    },
  ],
};
