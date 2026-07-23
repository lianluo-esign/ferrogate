import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

export type AdminBillingEvent = AdminSchema<"TokenMeteringEvent"> &
  Record<string, unknown>;

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s and the numeric cell render stay data-driven; this is a
// read-only resource with no fields.
export const billingEventsConfig: ResourceConfig<AdminBillingEvent> = {
  key: "billing-events",
  titleKey: "resource.billingEvents.title",
  descriptionKey: "resource.billingEvents.description",
  basePath: "/admin/v1/billing-events",
  idField: "request_id",
  readOnly: true,
  pagination: "offset",
  fetchList: async (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/billing-events", { query: request }),
  rowLabel: (row) => row.request_id,
  columns: [
    { key: "logical_model", headerKey: "resource.billingEvents.col.model", priority: "primary", minWidth: 190, mobileVisibility: "always" },
    { key: "provider", headerKey: "resource.billingEvents.col.provider", priority: "secondary", minWidth: 120, mobileVisibility: "always" },
    {
      key: "total_tokens",
      headerKey: "resource.billingEvents.col.totalTokens",
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      render: (row) => String(row.usage?.total_tokens ?? 0),
    },
    { key: "usage_source", headerKey: "resource.billingEvents.col.usageSource", priority: "detail", minWidth: 150, mobileVisibility: "details" },
    { key: "status_code", headerKey: "resource.billingEvents.col.status", priority: "detail", minWidth: 90, mobileVisibility: "details" },
    { key: "request_id", headerKey: "resource.billingEvents.col.requestId", priority: "detail", minWidth: 210, copyable: true, mobileVisibility: "details" },
  ],
  fields: [],
};
