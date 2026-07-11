import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminQuotaPolicy extends Record<string, unknown> {
  id: string;
  scope_type: "tenant" | "project" | "workspace" | "key";
  scope_id: string;
  model_allowlist: string[];
  rpm_limit: number | null;
  tpm_limit: number | null;
  monthly_budget_usd: number | null;
  asset_storage_quota_bytes: number | null;
  enabled: boolean;
  created_at_unix: number;
  updated_at_unix: number;
}

export const quotaPoliciesConfig: ResourceConfig<AdminQuotaPolicy> = {
  key: "quota-policies",
  title: "Quota policies",
  description: "Rate and budget limits applied to a tenant, project, workspace, or key.",
  basePath: "/admin/v1/quota-policies",
  idField: "id",
  resolveDetailPath: (row) => `${row.scope_type}/${row.scope_id}`,
  columns: [
    { key: "scope_type", header: "Scope" },
    { key: "scope_id", header: "Scope ID" },
    { key: "rpm_limit", header: "RPM limit" },
    { key: "tpm_limit", header: "TPM limit" },
    { key: "monthly_budget_usd", header: "Monthly budget (USD)" },
    { key: "asset_storage_quota_bytes", header: "Tenant asset quota (bytes)" },
    { key: "enabled", header: "Enabled", render: (row) => (row.enabled ? "Yes" : "No") },
  ],
  fields: [
    {
      name: "scope_type",
      label: "Scope type",
      type: "select",
      required: true,
      createOnly: true,
      options: [
        { label: "Tenant", value: "tenant" },
        { label: "Project", value: "project" },
        { label: "Workspace", value: "workspace" },
        { label: "Key", value: "key" },
      ],
    },
    { name: "scope_id", label: "Scope ID", type: "text", required: true, createOnly: true },
    { name: "model_allowlist", label: "Model allowlist (comma-separated)", type: "csv" },
    { name: "rpm_limit", label: "Requests per minute", type: "number" },
    { name: "tpm_limit", label: "Tokens per minute", type: "number" },
    { name: "monthly_budget_usd", label: "Monthly budget (USD)", type: "number" },
    {
      name: "asset_storage_quota_bytes",
      label: "Tenant-only asset storage quota (bytes)",
      type: "number",
      description: "Valid only when scope type is tenant.",
    },
    { name: "enabled", label: "Enabled", type: "boolean" },
  ],
};
