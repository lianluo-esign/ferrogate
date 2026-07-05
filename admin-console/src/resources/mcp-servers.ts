import type { ResourceConfig } from "@/lib/resource-config";

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

export const mcpServersConfig: ResourceConfig<AdminMcpServer> = {
  key: "mcp-servers",
  title: "MCP servers",
  description: "Model Context Protocol servers the gateway can dispatch tool calls to.",
  basePath: "/admin/v1/mcp-servers",
  idField: "name",
  resolveDetailPath: (row) => String(row.name ?? row.id ?? ""),
  columns: [
    { key: "name", header: "Name", render: (row) => String(row.name ?? row.id ?? "") },
    { key: "transport", header: "Transport", render: (row) => String(row.transport ?? "") },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true, createOnly: true },
    { name: "enabled", label: "Enabled", type: "boolean" },
    {
      name: "config",
      label: "Full server config (JSON)",
      type: "json",
      description: "Transport, auth, TLS, and endpoint fields per ferrogate-mcp::McpServerConfig.",
    },
  ],
};
