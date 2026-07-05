import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminBillingEvent extends Record<string, unknown> {
  request_id: string;
  logical_model: string;
  provider: string;
  provider_model: string;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  status_code: number;
  cost_usd: number | null;
  occurred_at_unix: number | null;
}

export const billingEventsConfig: ResourceConfig<AdminBillingEvent> = {
  key: "billing-events",
  title: "Billing events",
  description: "Per-request usage/cost events fed into billing.",
  basePath: "/admin/v1/billing-events",
  idField: "request_id",
  readOnly: true,
  columns: [
    { key: "logical_model", header: "Model" },
    { key: "provider", header: "Provider" },
    {
      key: "total_tokens",
      header: "Total tokens",
      render: (row) => String(row.usage?.total_tokens ?? 0),
    },
    { key: "cost_usd", header: "Cost (USD)", render: (row) => String(row.cost_usd ?? "") },
    { key: "status_code", header: "Status" },
  ],
  fields: [],
};
