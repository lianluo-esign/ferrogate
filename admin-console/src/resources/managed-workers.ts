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

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s and the comma-joined lifecycle-actions cell (a
// data-driven `render` callback) stay untouched; this is a read-only resource
// with no fields.
export const managedWorkersConfig: ResourceConfig<AdminManagedWorkerRuntime> = {
  key: "managed-workers",
  titleKey: "resource.managedWorkers.title",
  descriptionKey: "resource.managedWorkers.description",
  basePath: "/admin/v1/managed-workers",
  idField: "id",
  readOnly: true,
  columns: [
    { key: "id", headerKey: "resource.managedWorkers.col.id" },
    { key: "status", headerKey: "resource.managedWorkers.col.status" },
    { key: "process_name", headerKey: "resource.managedWorkers.col.process" },
    { key: "gateway_role", headerKey: "resource.managedWorkers.col.gatewayRole" },
    { key: "agent_worker_role", headerKey: "resource.managedWorkers.col.workerRole" },
    {
      key: "lifecycle_actions",
      headerKey: "resource.managedWorkers.col.lifecycleActions",
      render: (row) => row.lifecycle_actions.join(", "),
    },
  ],
  fields: [],
};
