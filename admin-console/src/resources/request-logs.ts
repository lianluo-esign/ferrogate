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

export const requestLogsConfig: ResourceConfig<AdminRequestLog> = {
  key: "request-logs",
  title: "Request logs",
  description: "Recent proxied requests handled by the gateway.",
  basePath: "/admin/v1/request-logs",
  idField: "request_id",
  readOnly: true,
  rowLabel: (row) => row.request_id,
  columns: [
    { key: "request_id", header: "Request ID", priority: "primary", minWidth: 210, copyable: true, mobileVisibility: "always" },
    { key: "route", header: "Route", priority: "detail", minWidth: 160, mobileVisibility: "details" },
    { key: "provider", header: "Provider", priority: "secondary", minWidth: 120, mobileVisibility: "always" },
    { key: "logical_model", header: "Model", priority: "secondary", minWidth: 180, mobileVisibility: "always" },
    { key: "status_code", header: "Status", priority: "secondary", minWidth: 90, mobileVisibility: "always" },
    { key: "error_code", header: "Error", priority: "detail", minWidth: 160, mobileVisibility: "details" },
  ],
  fields: [],
};
