import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminSkillPackage extends Record<string, unknown> {
  id: string;
  name: string;
  version: string;
  description: string | null;
  enabled: boolean;
  capabilities: { kind: string; id: string; description?: string }[];
  api_key_ids: string[];
}

export const skillPackagesConfig: ResourceConfig<AdminSkillPackage> = {
  key: "skill-packages",
  title: "Skill packages",
  description: "Bundles of plugins, tools, prompts, and workflows shipped as one unit.",
  basePath: "/admin/v1/skill-packages",
  idField: "id",
  columns: [
    { key: "name", header: "Name" },
    { key: "version", header: "Version" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "capabilities", header: "Capabilities", render: (row) => String(row.capabilities?.length ?? 0) },
  ],
  fields: [
    { name: "id", label: "ID", type: "text", required: true, createOnly: true },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "version", label: "Version", type: "text", placeholder: "0.1.0" },
    { name: "description", label: "Description", type: "textarea" },
    { name: "enabled", label: "Enabled", type: "boolean" },
    { name: "api_key_ids", label: "API key IDs (comma-separated)", type: "csv" },
    {
      name: "compatibility",
      label: "Compatibility (JSON)",
      type: "json",
      placeholder: '{"min_gateway_version":"0.1.0","agent_runtimes":["claude-code"]}',
    },
    {
      name: "permissions",
      label: "Permissions (JSON)",
      type: "json",
      placeholder:
        '{"tools":[],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false}',
    },
    {
      name: "capabilities",
      label: "Capabilities (JSON array)",
      type: "json",
      placeholder: '[{"kind":"plugin","id":"my-plugin"}]',
    },
    {
      name: "resources",
      label: "Resources (JSON: plugins/mcp_servers/prompt_templates/agent_workflows)",
      type: "json",
    },
    { name: "metadata", label: "Metadata (JSON)", type: "json" },
  ],
};
