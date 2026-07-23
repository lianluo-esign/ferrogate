import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

export interface AdminSkillPackage extends Record<string, unknown> {
  id: string;
  name: string;
  version: string;
  description: string | null;
  enabled: boolean;
  capabilities: { kind: string; id: string; description?: string }[];
  api_key_ids: string[];
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, and field `labelKey` resolve
// under the active locale. The boolean Yes/No cell now localizes via
// `booleanColumn` (#385). Resource IDs, field `name`s, the remaining
// data-driven column render (capabilities count), and the JSON/example
// placeholders (`0.1.0`, JSON shapes — protected code/config values) stay
// data-driven.
export const skillPackagesConfig: ResourceConfig<AdminSkillPackage> = {
  key: "skill-packages",
  titleKey: "resource.skillPackages.title",
  descriptionKey: "resource.skillPackages.description",
  basePath: "/admin/v1/skill-packages",
  idField: "id",
  columns: [
    { key: "name", headerKey: "resource.skillPackages.col.name" },
    { key: "version", headerKey: "resource.skillPackages.col.version" },
    booleanColumn<AdminSkillPackage>({ key: "enabled", headerKey: "resource.skillPackages.col.enabled" }),
    { key: "capabilities", headerKey: "resource.skillPackages.col.capabilities", render: (row) => String(row.capabilities?.length ?? 0) },
  ],
  fields: [
    { name: "id", labelKey: "resource.skillPackages.field.id", type: "text", required: true, createOnly: true },
    { name: "name", labelKey: "resource.skillPackages.field.name", type: "text", required: true },
    { name: "version", labelKey: "resource.skillPackages.field.version", type: "text", placeholder: "0.1.0" },
    { name: "description", labelKey: "resource.skillPackages.field.description", type: "textarea" },
    { name: "enabled", labelKey: "resource.skillPackages.field.enabled", type: "boolean" },
    { name: "api_key_ids", labelKey: "resource.skillPackages.field.apiKeyIds", type: "csv" },
    {
      name: "compatibility",
      labelKey: "resource.skillPackages.field.compatibility",
      type: "json",
      placeholder: '{"min_gateway_version":"0.1.0","agent_runtimes":["claude-code"]}',
    },
    {
      name: "permissions",
      labelKey: "resource.skillPackages.field.permissions",
      type: "json",
      placeholder:
        '{"tools":[],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false}',
    },
    // #342: capabilities is an array of typed references embedded in the skill
    // package document. It becomes a structured reference editor (kind + entity
    // picker + optional description) so operators pick known plugins/tools/MCP
    // servers/prompts/workflows by name instead of hand-writing ids, while the
    // per-row `description` and the surrounding JSON fields (compatibility/
    // permissions/resources/metadata) round-trip unchanged. `mcp_tool` has no
    // flat list endpoint, so it stays a validated raw-id input (no silent
    // exclusion).
    {
      name: "capabilities",
      labelKey: "resource.skillPackages.field.capabilities",
      descriptionKey: "resource.skillPackages.field.capabilities.desc",
      type: "reference-list",
      discriminantKey: "kind",
      valueKey: "id",
      kinds: [
        {
          value: "plugin",
          labelKey: "resource.skillPackages.capabilityKind.plugin",
          reference: {
            target: "plugins",
            valueKey: "id",
            primaryLabelKey: "id",
            secondaryLabelKeys: ["kind", "version"],
          },
        },
        {
          value: "tool",
          labelKey: "resource.skillPackages.capabilityKind.tool",
          reference: {
            target: "tools",
            valueKey: "name",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["extension_id"],
          },
        },
        {
          value: "mcp_server",
          labelKey: "resource.skillPackages.capabilityKind.mcpServer",
          reference: {
            target: "mcp-servers",
            valueKey: "name",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["transport"],
          },
        },
        {
          value: "mcp_tool",
          labelKey: "resource.skillPackages.capabilityKind.mcpTool",
        },
        {
          value: "prompt_template",
          labelKey: "resource.skillPackages.capabilityKind.promptTemplate",
          reference: {
            target: "prompt-templates",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["model", "status"],
          },
        },
        {
          value: "agent_workflow",
          labelKey: "resource.skillPackages.capabilityKind.agentWorkflow",
          reference: {
            target: "agent-workflows",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["version"],
          },
        },
      ],
      extraFields: [
        {
          key: "description",
          labelKey: "resource.skillPackages.field.capability.description",
          type: "text",
        },
      ],
    },
    {
      name: "resources",
      labelKey: "resource.skillPackages.field.resources",
      type: "json",
    },
    { name: "metadata", labelKey: "resource.skillPackages.field.metadata", type: "json" },
  ],
};
