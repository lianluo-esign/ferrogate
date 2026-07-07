import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminTenantAccount extends Record<string, unknown> {
  id: string;
  name: string;
  slug: string;
  status: string;
  plan_id: string | null;
  created_at_unix: number;
  updated_at_unix: number;
}

export const tenantAccountsConfig: ResourceConfig<AdminTenantAccount> = {
  key: "tenant-accounts",
  title: "Tenant accounts",
  description: "Top-level organizations in the control plane.",
  basePath: "/admin/v1/tenant-accounts",
  idField: "id",
  // The create form only supports POST (creates fine without a plan_id,
  // which the backend then defaults to "free"). Reassigning a tenant's
  // plan after creation is a PATCH-only backend operation
  // (GET/PATCH /admin/v1/tenant-accounts/{id}) that this generic
  // create/PUT/delete resource form doesn't model -- see the Plans page
  // (/app/plans) for viewing plan definitions themselves. Tracked as
  // follow-up UI work on issue #168.
  noEditDelete: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "status", header: "Status" },
    { key: "plan_id", header: "Plan" },
    { key: "id", header: "ID" },
  ],
  fields: [
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
  ],
};
