import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminProject extends Record<string, unknown> {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

export const projectsConfig: ResourceConfig<AdminProject> = {
  key: "projects",
  title: "Projects",
  description: "Projects group workspaces under a tenant.",
  basePath: "/admin/v1/projects",
  idField: "id",
  rowLabel: (row) => row.name,
  columns: [
    { key: "name", header: "Name", priority: "primary", minWidth: 220, mobileVisibility: "always" },
    { key: "slug", header: "Slug", priority: "secondary", minWidth: 180, mobileVisibility: "always" },
    { key: "tenant_id", header: "Tenant", priority: "detail", minWidth: 220, copyable: true, mobileVisibility: "details" },
    { key: "status", header: "Status", priority: "secondary", minWidth: 100, mobileVisibility: "always" },
  ],
  fields: [
    {
      name: "tenant_id",
      label: "Tenant ID",
      type: "text",
      required: true,
      // Immutable after create (#326: the backend rejects tenant re-attribution
      // with 400 to avoid stranding child rows), so it is hidden on edit.
      createOnly: true,
    },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
  ],
};
