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

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s and the data-driven cell renders stay untouched; this is
// a read-only resource with no fields.
export const usageReportsConfig: ResourceConfig<AdminUsageReportRow> = {
  key: "usage-reports",
  titleKey: "resource.usageReports.title",
  descriptionKey: "resource.usageReports.description",
  basePath: "/admin/v1/usage-reports",
  idField: "scope_id",
  readOnly: true,
  columns: [
    { key: "period_month", headerKey: "resource.usageReports.col.month", render: (row) => row.period_month ?? "" },
    { key: "scope_type", headerKey: "resource.usageReports.col.scope", render: (row) => row.scope_type ?? "" },
    { key: "scope_id", headerKey: "resource.usageReports.col.scopeId", render: (row) => row.scope_id ?? "" },
    { key: "total_tokens", headerKey: "resource.usageReports.col.totalTokens" },
    { key: "cost_usd", headerKey: "resource.usageReports.col.cost" },
    { key: "request_count", headerKey: "resource.usageReports.col.requests" },
    { key: "error_count", headerKey: "resource.usageReports.col.errors" },
  ],
  fields: [],
};
