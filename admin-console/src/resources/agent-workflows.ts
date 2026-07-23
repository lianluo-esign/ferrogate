import type { ResourceConfig } from "@/lib/resource-config";

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

export const agentWorkflowsConfig: ResourceConfig<AdminAgentWorkflowRow> = {
  key: "agent-workflows",
  title: "Agent workflows",
  description: "Multi-step orchestration graphs (model/tool/router/human/checkpoint nodes).",
  basePath: "/admin/v1/agent-workflows",
  idField: "workflow",
  resolveDetailPath: (row) => workflowOf(row)?.id ?? "",
  unwrapRow: (row) => (workflowOf(row) as unknown as Record<string, unknown>) ?? {},
  columns: [
    { key: "name", header: "Name", render: (row) => workflowOf(row)?.name ?? "" },
    { key: "id", header: "ID", render: (row) => workflowOf(row)?.id ?? "" },
    { key: "version", header: "Version", render: (row) => String(workflowOf(row)?.version ?? "") },
    {
      key: "enabled",
      header: "Enabled",
      render: (row) => (workflowOf(row)?.enabled ? "Yes" : "No"),
    },
    {
      key: "requests",
      header: "Requests",
      render: (row) => String(row.counters?.request_count ?? 0),
    },
  ],
  fields: [
    { name: "id", label: "ID", type: "text", required: true, createOnly: true },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "version", label: "Version", type: "number", placeholder: "1" },
    { name: "enabled", label: "Enabled", type: "boolean" },
    // organization_ids and api_key_ids scope a workflow to the raw identifiers a
    // caller presents at request time (ferrogate-cli agent-workflow evaluation),
    // which are not guaranteed to be admin-console tenant/key rows, so they stay
    // free-text rather than being force-mapped to an entity source (mirrors the
    // policies.ts decision from #341).
    { name: "organization_ids", label: "Organization IDs (comma-separated)", type: "csv" },
    {
      name: "project_ids",
      label: "Projects",
      type: "entities",
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
    },
    { name: "api_key_ids", label: "API key IDs (comma-separated)", type: "csv" },
    // nodes/edges are a structured workflow document whose model/provider/MCP/
    // tool/prompt references live inside per-node JSON. Converting those to inline
    // pickers needs a structured reference panel (issue #342 acceptance) and is
    // explicitly a non-goal for this slice ("not a full visual DAG editor"); they
    // stay raw JSON so non-reference document fields round-trip unchanged.
    {
      name: "nodes",
      label: "Nodes (JSON array)",
      type: "json",
      placeholder: '[{"id":"n1","kind":"model","model":"gpt-4o","providers":["openai"]}]',
    },
    {
      name: "edges",
      label: "Edges (JSON array)",
      type: "json",
      placeholder: '[{"from":"n1","to":"n2"}]',
    },
    { name: "max_model_calls", label: "Max model calls", type: "number" },
    { name: "max_tool_calls", label: "Max tool calls", type: "number" },
    { name: "max_parallelism", label: "Max parallelism", type: "number" },
    { name: "max_iterations", label: "Max iterations", type: "number" },
    { name: "timeout_millis", label: "Timeout (ms)", type: "number" },
    { name: "token_budget", label: "Token budget", type: "number" },
  ],
};
