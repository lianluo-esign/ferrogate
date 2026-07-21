import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

export type AdminBillingEvent = AdminSchema<"TokenMeteringEvent"> &
  Record<string, unknown>;

export const billingEventsConfig: ResourceConfig<AdminBillingEvent> = {
  key: "billing-events",
  title: "Billing events",
  description: "Per-request usage/cost events fed into billing.",
  basePath: "/admin/v1/billing-events",
  idField: "request_id",
  readOnly: true,
  pagination: "offset",
  fetchList: async (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/billing-events", { query: request }),
  rowLabel: (row) => row.request_id,
  columns: [
    { key: "logical_model", header: "Model", priority: "primary", minWidth: 190, mobileVisibility: "always" },
    { key: "provider", header: "Provider", priority: "secondary", minWidth: 120, mobileVisibility: "always" },
    {
      key: "total_tokens",
      header: "Total tokens",
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      render: (row) => String(row.usage?.total_tokens ?? 0),
    },
    { key: "usage_source", header: "Usage source", priority: "detail", minWidth: 150, mobileVisibility: "details" },
    { key: "status_code", header: "Status", priority: "detail", minWidth: 90, mobileVisibility: "details" },
    { key: "request_id", header: "Request ID", priority: "detail", minWidth: 210, copyable: true, mobileVisibility: "details" },
  ],
  fields: [],
};
