import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminRequestLog extends Record<string, unknown> {
  request_id: string;
  trace_id: string | null;
  route: string;
  provider: string;
  logical_model: string;
  provider_model: string;
  status_code: number;
  error_code: string | null;
  started_at_unix: number;
  completed_at_unix: number;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s and layout hints stay untouched; this is a read-only
// resource with no fields.
export const requestLogsConfig: ResourceConfig<AdminRequestLog> = {
  key: "request-logs",
  titleKey: "resource.requestLogs.title",
  descriptionKey: "resource.requestLogs.description",
  basePath: "/admin/v1/request-logs",
  idField: "request_id",
  readOnly: true,
  rowLabel: (row) => row.request_id,
  columns: [
    { key: "request_id", headerKey: "resource.requestLogs.col.requestId", priority: "primary", minWidth: 210, copyable: true, mobileVisibility: "always" },
    { key: "route", headerKey: "resource.requestLogs.col.route", priority: "detail", minWidth: 160, mobileVisibility: "details" },
    { key: "provider", headerKey: "resource.requestLogs.col.provider", priority: "secondary", minWidth: 120, mobileVisibility: "always" },
    { key: "logical_model", headerKey: "resource.requestLogs.col.model", priority: "secondary", minWidth: 180, mobileVisibility: "always" },
    { key: "status_code", headerKey: "resource.requestLogs.col.status", priority: "secondary", minWidth: 90, mobileVisibility: "always" },
    { key: "error_code", headerKey: "resource.requestLogs.col.error", priority: "detail", minWidth: 160, mobileVisibility: "details" },
  ],
  fields: [],
};
