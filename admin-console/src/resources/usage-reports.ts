import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminUsageReportRow extends Record<string, unknown> {
  period_month?: string;
  scope_type?: string;
  scope_id?: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  request_count: number;
  error_count: number;
}

export const usageReportsConfig: ResourceConfig<AdminUsageReportRow> = {
  key: "usage-reports",
  title: "Usage reports",
  description: "Monthly token usage and cost rollups, grouped by scope or period.",
  basePath: "/admin/v1/usage-reports",
  idField: "scope_id",
  readOnly: true,
  columns: [
    { key: "period_month", header: "Month", render: (row) => row.period_month ?? "" },
    { key: "scope_type", header: "Scope", render: (row) => row.scope_type ?? "" },
    { key: "scope_id", header: "Scope ID", render: (row) => row.scope_id ?? "" },
    { key: "total_tokens", header: "Total tokens" },
    { key: "cost_usd", header: "Cost (USD)" },
    { key: "request_count", header: "Requests" },
    { key: "error_count", header: "Errors" },
  ],
  fields: [],
};
