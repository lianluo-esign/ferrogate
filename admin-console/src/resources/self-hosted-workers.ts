import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminSelfHostedWorkerRecord extends Record<string, unknown> {
  id: string;
  worker_name: string;
  status: string;
  trust_level: string;
  stale: boolean;
  orchestration_enabled: boolean;
  registered_at_unix: number | null;
  last_seen_at_unix: number | null;
  telemetry_event_count: number;
}

export const selfHostedWorkersConfig: ResourceConfig<AdminSelfHostedWorkerRecord> = {
  key: "self-hosted-workers",
  title: "Self-hosted workers",
  description:
    "Agent workers registered from customer infrastructure (read-only; registration happens via the worker's own bootstrap flow).",
  basePath: "/admin/v1/self-hosted-worker-records",
  idField: "id",
  readOnly: true,
  rowLabel: (row) => row.worker_name,
  columns: [
    { key: "worker_name", header: "Name", priority: "primary", minWidth: 200, mobileVisibility: "always" },
    { key: "status", header: "Status", priority: "secondary", minWidth: 110, mobileVisibility: "always" },
    { key: "trust_level", header: "Trust level", priority: "detail", minWidth: 230, mobileVisibility: "details" },
    { key: "stale", header: "Stale", priority: "secondary", minWidth: 90, mobileVisibility: "always", render: (row) => (row.stale ? "Yes" : "No") },
    {
      key: "orchestration_enabled",
      header: "Orchestration",
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      render: (row) => (row.orchestration_enabled ? "Enabled" : "Disabled"),
    },
    { key: "telemetry_event_count", header: "Telemetry events", priority: "detail", minWidth: 140, mobileVisibility: "details" },
  ],
  fields: [],
};
