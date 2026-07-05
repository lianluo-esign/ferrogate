import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminProvider extends Record<string, unknown> {
  name: string;
  kind: string;
  compatibility: string;
  base_url: string;
  has_api_key: boolean;
  enabled: boolean;
}

export const providersConfig: ResourceConfig<AdminProvider> = {
  key: "providers",
  title: "Providers",
  description: "Upstream model providers configured for this gateway (read-only).",
  basePath: "/admin/v1/providers",
  idField: "name",
  readOnly: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "kind", header: "Kind" },
    { key: "compatibility", header: "Compatibility" },
    { key: "base_url", header: "Base URL" },
    { key: "has_api_key", header: "Has API key", render: (row) => (row.has_api_key ? "Yes" : "No") },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
  ],
  fields: [],
};
