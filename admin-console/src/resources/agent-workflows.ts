import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

interface AgentWorkflowPolicy {
  id: string;
  name: string;
  version: number;
  enabled: boolean;
  nodes: unknown[];
  edges: unknown[];
}

interface AgentWorkflowCounters {
  request_count: number;
  error_count: number;
  billing_event_count: number;
  audit_event_count: number;
  estimated_tokens: number;
}

export interface AdminAgentWorkflowRow extends Record<string, unknown> {
  workflow: AgentWorkflowPolicy;
  counters: AgentWorkflowCounters;
}

function workflowOf(row: AdminAgentWorkflowRow): AgentWorkflowPolicy | undefined {
  return row.workflow ?? (row as unknown as AgentWorkflowPolicy);
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, and field `labelKey` resolve
// under the active locale. The boolean Yes/No cell now localizes via
// `booleanColumn` reading the unwrapped workflow flag (#385). Resource IDs,
// field `name`s, the remaining data-driven column `render` callbacks (workflow
// field unwrapping, request-count formatting), and the JSON/example
// placeholders (`1`, node/edge shapes — protected code/config values) stay
// data-driven.
export const agentWorkflowsConfig: ResourceConfig<AdminAgentWorkflowRow> = {
  key: "agent-workflows",
  titleKey: "resource.agentWorkflows.title",
  descriptionKey: "resource.agentWorkflows.description",
  basePath: "/admin/v1/agent-workflows",
  idField: "workflow",
  resolveDetailPath: (row) => workflowOf(row)?.id ?? "",
  unwrapRow: (row) => (workflowOf(row) as unknown as Record<string, unknown>) ?? {},
  columns: [
    { key: "name", headerKey: "resource.agentWorkflows.col.name", render: (row) => workflowOf(row)?.name ?? "" },
    { key: "id", headerKey: "resource.agentWorkflows.col.id", render: (row) => workflowOf(row)?.id ?? "" },
    { key: "version", headerKey: "resource.agentWorkflows.col.version", render: (row) => String(workflowOf(row)?.version ?? "") },
    booleanColumn<AdminAgentWorkflowRow>({
      key: "enabled",
      headerKey: "resource.agentWorkflows.col.enabled",
      value: (row) => workflowOf(row)?.enabled,
    }),
    {
      key: "requests",
      headerKey: "resource.agentWorkflows.col.requests",
      render: (row) => String(row.counters?.request_count ?? 0),
    },
  ],
  fields: [
    { name: "id", labelKey: "resource.agentWorkflows.field.id", type: "text", required: true, createOnly: true },
    { name: "name", labelKey: "resource.agentWorkflows.field.name", type: "text", required: true },
    { name: "version", labelKey: "resource.agentWorkflows.field.version", type: "number", placeholder: "1" },
    { name: "enabled", labelKey: "resource.agentWorkflows.field.enabled", type: "boolean" },
    // organization_ids and api_key_ids scope a workflow to the raw identifiers a
    // caller presents at request time (ferrogate-cli agent-workflow evaluation),
    // which are not guaranteed to be admin-console tenant/key rows, so they stay
    // free-text rather than being force-mapped to an entity source (mirrors the
    // policies.ts decision from #341).
    { name: "organization_ids", labelKey: "resource.agentWorkflows.field.organizationIds", type: "csv" },
    {
      name: "project_ids",
      labelKey: "resource.agentWorkflows.field.projects",
      type: "entities",
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
    },
    { name: "api_key_ids", labelKey: "resource.agentWorkflows.field.apiKeyIds", type: "csv" },
    // nodes/edges are a structured workflow document whose model/provider/MCP/
    // tool/prompt references live inside per-node JSON. Converting those to inline
    // pickers needs a structured reference panel (issue #342 acceptance) and is
    // explicitly a non-goal for this slice ("not a full visual DAG editor"); they
    // stay raw JSON so non-reference document fields round-trip unchanged.
    {
      name: "nodes",
      labelKey: "resource.agentWorkflows.field.nodes",
      type: "json",
      placeholder: '[{"id":"n1","kind":"model","model":"gpt-4o","providers":["openai"]}]',
    },
    {
      name: "edges",
      labelKey: "resource.agentWorkflows.field.edges",
      type: "json",
      placeholder: '[{"from":"n1","to":"n2"}]',
    },
    { name: "max_model_calls", labelKey: "resource.agentWorkflows.field.maxModelCalls", type: "number" },
    { name: "max_tool_calls", labelKey: "resource.agentWorkflows.field.maxToolCalls", type: "number" },
    { name: "max_parallelism", labelKey: "resource.agentWorkflows.field.maxParallelism", type: "number" },
    { name: "max_iterations", labelKey: "resource.agentWorkflows.field.maxIterations", type: "number" },
    { name: "timeout_millis", labelKey: "resource.agentWorkflows.field.timeout", type: "number" },
    { name: "token_budget", labelKey: "resource.agentWorkflows.field.tokenBudget", type: "number" },
  ],
};
