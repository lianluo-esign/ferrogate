import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminTenantAccount extends Record<string, unknown> {
  id: string;
  name: string;
  slug: string;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

export const tenantAccountsConfig: ResourceConfig<AdminTenantAccount> = {
  key: "tenant-accounts",
  title: "Tenant accounts",
  description: "Top-level organizations in the control plane.",
  basePath: "/admin/v1/tenant-accounts",
  idField: "id",
  noEditDelete: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "status", header: "Status" },
    { key: "id", header: "ID" },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
  ],
};
