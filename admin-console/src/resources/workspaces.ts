import { adminGet } from "@/lib/gateway-client";
import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminWorkspace extends Record<string, unknown> {
  id: string;
  project_id: string;
  tenant_id: string;
  name: string;
  slug: string;
  environment: string;
  status: string;
  created_at_unix: number;
  updated_at_unix: number;
}

export const workspacesConfig: ResourceConfig<AdminWorkspace> = {
  key: "workspaces",
  title: "Workspaces",
  description: "Workspaces are the scope virtual API keys are issued against.",
  basePath: "/admin/v1/workspaces",
  idField: "id",
  pagination: "offset",
  fetchList: (apiKey, request) =>
    adminGet(apiKey, "/admin/v1/workspaces", { query: request }),
  columns: [
    { key: "name", header: "Name" },
    { key: "slug", header: "Slug" },
    { key: "project_id", header: "Project" },
    { key: "environment", header: "Environment" },
    { key: "status", header: "Status" },
  ],
  fields: [
    {
      name: "project_id",
      label: "Project",
      type: "entity",
      required: true,
      reference: {
        target: "projects",
        valueKey: "id",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["slug", "tenant_id"],
      },
      // Immutable after create (#326: the backend rejects project re-attribution
      // with 400 to avoid stranding child rows), so it is hidden on edit.
      createOnly: true,
    },
    { name: "name", label: "Name", type: "text", required: true },
    { name: "slug", label: "Slug", type: "text", required: true },
    { name: "environment", label: "Environment", type: "text", placeholder: "default" },
    { name: "status", label: "Status", type: "text", placeholder: "active" },
  ],
};
