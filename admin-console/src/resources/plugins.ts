import type { ResourceConfig } from "@/lib/resource-config";

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

export const pluginsConfig: ResourceConfig<AdminPlugin> = {
  key: "plugins",
  title: "Plugins",
  description: "Request hooks, tool providers, and event sinks loaded into the gateway.",
  basePath: "/admin/v1/plugins",
  idField: "id",
  columns: [
    { key: "id", header: "ID" },
    { key: "kind", header: "Kind" },
    { key: "version", header: "Version" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "health", header: "Health" },
    { key: "last_error", header: "Last error" },
  ],
  fields: [
    { name: "id", label: "ID", type: "text", required: true, createOnly: true },
    {
      name: "kind",
      label: "Kind",
      type: "select",
      required: true,
      options: [
        { label: "Request hook", value: "request_hook" },
        { label: "Tool provider", value: "tool_provider" },
        { label: "Event sink", value: "event_sink" },
      ],
    },
    { name: "version", label: "Version", type: "text" },
    { name: "source", label: "Source", type: "text" },
    { name: "order", label: "Order", type: "number" },
    { name: "enabled", label: "Enabled", type: "boolean" },
    {
      name: "approval_policy",
      label: "Approval policy",
      type: "select",
      options: [
        { label: "Never", value: "never" },
        { label: "Always", value: "always" },
      ],
    },
    { name: "manifest", label: "Manifest (JSON)", type: "json" },
    { name: "compatibility", label: "Compatibility (JSON)", type: "json" },
    { name: "permissions", label: "Permissions (JSON)", type: "json" },
    { name: "config", label: "Config (JSON)", type: "json" },
  ],
};
