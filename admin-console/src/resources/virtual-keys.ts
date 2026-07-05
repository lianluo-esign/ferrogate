import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminVirtualApiKey extends Record<string, unknown> {
  id: string;
  workspace_id: string;
  tenant_id: string;
  project_id: string;
  name: string;
  key_prefix: string;
  last4: string;
  enabled: boolean;
  scopes: string[];
  allowed_models: string[];
  allowed_providers: string[];
  monthly_token_budget: number | null;
  request_limit_per_minute: number | null;
  created_at_unix: number;
  updated_at_unix: number;
  rotated_at_unix: number | null;
  expires_at_unix: number | null;
  revoked_at_unix: number | null;
}

export const virtualKeysConfig: ResourceConfig<AdminVirtualApiKey> = {
  key: "virtual-keys",
  title: "API / virtual keys",
  description: "Keys used to call the gateway and its Admin API.",
  basePath: "/admin/v1/virtual-keys",
  idField: "id",
  secretResponseKey: "secret",
  columns: [
    { key: "name", header: "Name" },
    { key: "key_prefix", header: "Prefix", render: (row) => `${row.key_prefix}...${row.last4}` },
    { key: "workspace_id", header: "Workspace" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
    { key: "scopes", header: "Scopes", render: (row) => row.scopes.join(", ") },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true, createOnly: true },
    { name: "workspace_id", label: "Workspace ID", type: "text", required: true, createOnly: true },
    {
      name: "scopes",
      label: "Scopes (comma-separated)",
      type: "csv",
      placeholder: "admin.read,admin.write",
    },
    { name: "allowed_models", label: "Allowed models (comma-separated)", type: "csv" },
    { name: "allowed_providers", label: "Allowed providers (comma-separated)", type: "csv" },
    { name: "monthly_token_budget", label: "Monthly token budget", type: "number" },
    { name: "request_limit_per_minute", label: "Requests per minute", type: "number" },
  ],
};
