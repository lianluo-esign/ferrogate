import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminModel extends Record<string, unknown> {
  name: string;
  provider: string;
  provider_model: string;
  routing_strategy: string;
  capabilities: string[];
  context_window: number | null;
  input_price_per_1m: number | null;
  output_price_per_1m: number | null;
  enabled: boolean;
}

export const modelsConfig: ResourceConfig<AdminModel> = {
  key: "models",
  title: "Models",
  description: "Logical model routes exposed by the gateway (read-only).",
  basePath: "/admin/v1/models",
  idField: "name",
  readOnly: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "provider", header: "Provider" },
    { key: "provider_model", header: "Provider model" },
    { key: "routing_strategy", header: "Routing strategy" },
    { key: "context_window", header: "Context window" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
  ],
  fields: [],
};
