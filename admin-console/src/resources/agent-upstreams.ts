import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminAgentUpstream extends Record<string, unknown> {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  protocol: "a2a";
  endpoint: string;
  tenant_ids: string[];
  capabilities: string[];
}

export const agentUpstreamsConfig: ResourceConfig<AdminAgentUpstream> = {
  key: "agent-upstreams",
  title: "Agent upstreams",
  description: "A2A-protocol agent upstreams the gateway can dispatch to.",
  basePath: "/admin/v1/agent-upstreams",
  idField: "id",
  columns: [
    { key: "name", header: "Name" },
    { key: "endpoint", header: "Endpoint" },
    { key: "protocol", header: "Protocol" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "capabilities", header: "Capabilities", render: (row) => row.capabilities.join(", ") },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true, createOnly: true },
    { name: "description", label: "Description", type: "textarea" },
    { name: "endpoint", label: "Endpoint URL", type: "text", required: true },
    { name: "enabled", label: "Enabled", type: "boolean" },
    {
      name: "capabilities",
      label: "Capabilities (comma-separated: invoke,read,stream,discover)",
      type: "csv",
    },
    { name: "tenant_ids", label: "Tenant IDs (comma-separated)", type: "csv" },
    {
      name: "auth",
      label: "Auth (JSON, e.g. \"none\" or {\"bearer\":{\"token\":\"...\"}})",
      type: "json",
    },
  ],
};
