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
  columns: [
    { key: "request_id", header: "Request ID" },
    { key: "route", header: "Route" },
    { key: "provider", header: "Provider" },
    { key: "logical_model", header: "Model" },
    { key: "status_code", header: "Status" },
    { key: "error_code", header: "Error" },
  ],
  fields: [],
};
