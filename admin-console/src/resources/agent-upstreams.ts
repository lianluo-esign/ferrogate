import { type ResourceConfig, booleanColumn } from "@/lib/resource-config";

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

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, and field `labelKey`/
// `descriptionKey` resolve under the active locale. Resource IDs, field
// `name`s and the comma-joined capabilities cell stay data-driven; the boolean
// Yes/No cell now localizes via `booleanColumn` (#385). The
// capabilities/auth labels keep their inline code/config example values
// (`invoke,read,stream,discover`, JSON shapes) inside the translated copy.
export const agentUpstreamsConfig: ResourceConfig<AdminAgentUpstream> = {
  key: "agent-upstreams",
  titleKey: "resource.agentUpstreams.title",
  descriptionKey: "resource.agentUpstreams.description",
  basePath: "/admin/v1/agent-upstreams",
  idField: "id",
  columns: [
    { key: "name", headerKey: "resource.agentUpstreams.col.name" },
    { key: "endpoint", headerKey: "resource.agentUpstreams.col.endpoint" },
    { key: "protocol", headerKey: "resource.agentUpstreams.col.protocol" },
    booleanColumn<AdminAgentUpstream>({
      key: "enabled",
      headerKey: "resource.agentUpstreams.col.enabled",
    }),
    {
      key: "capabilities",
      headerKey: "resource.agentUpstreams.col.capabilities",
      render: (row) => row.capabilities.join(", "),
    },
  ],
  fields: [
    {
      name: "name",
      labelKey: "resource.agentUpstreams.field.name",
      type: "text",
      required: true,
      createOnly: true,
    },
    {
      name: "description",
      labelKey: "resource.agentUpstreams.field.description",
      type: "textarea",
    },
    {
      name: "endpoint",
      labelKey: "resource.agentUpstreams.field.endpoint",
      type: "text",
      required: true,
    },
    { name: "enabled", labelKey: "resource.agentUpstreams.field.enabled", type: "boolean" },
    {
      name: "capabilities",
      labelKey: "resource.agentUpstreams.field.capabilities",
      type: "csv",
    },
    {
      name: "tenant_ids",
      labelKey: "resource.agentUpstreams.field.tenants",
      type: "entities",
      descriptionKey: "resource.agentUpstreams.field.tenants.desc",
      reference: {
        target: "tenant-accounts",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug"],
      },
    },
    {
      name: "auth",
      labelKey: "resource.agentUpstreams.field.auth",
      type: "json",
    },
  ],
};
