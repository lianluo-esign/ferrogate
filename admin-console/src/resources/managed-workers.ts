import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminManagedWorkerRuntime extends Record<string, unknown> {
  id: string;
  status: string;
  process_name: string;
  gateway_role: string;
  agent_worker_role: string;
  lifecycle_actions: string[];
  capability_boundary: string;
}

export const managedWorkersConfig: ResourceConfig<AdminManagedWorkerRuntime> = {
  key: "managed-workers",
  title: "Managed workers",
  description: "The gateway-managed agent worker capability contract (read-only descriptor).",
  basePath: "/admin/v1/managed-workers",
  idField: "id",
  readOnly: true,
  columns: [
    { key: "id", header: "ID" },
    { key: "status", header: "Status" },
    { key: "process_name", header: "Process" },
    { key: "gateway_role", header: "Gateway role" },
    { key: "agent_worker_role", header: "Worker role" },
    {
      key: "lifecycle_actions",
      header: "Lifecycle actions",
      render: (row) => row.lifecycle_actions.join(", "),
    },
  ],
  fields: [],
};
