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
  noEditDelete: true,
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "tenant_id", header: "Tenant" },
    { key: "status", header: "Status" },
  ],
  fields: [
    { name: "tenant_id", label: "Tenant ID", type: "text", required: true },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
  ],
};
