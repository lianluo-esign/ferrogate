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
    {
      name: "capabilities",
      labelKey: "resource.skillPackages.field.capabilities",
      type: "json",
      placeholder: '[{"kind":"plugin","id":"my-plugin"}]',
    },
    {
      name: "resources",
      labelKey: "resource.skillPackages.field.resources",
      type: "json",
    },
    { name: "metadata", labelKey: "resource.skillPackages.field.metadata", type: "json" },
  ],
};
