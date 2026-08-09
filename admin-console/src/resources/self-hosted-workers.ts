import { type ResourceConfig, booleanColumn } from "@/lib/resource-config";

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

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s and layout hints stay untouched; the boolean Yes/No
// (`stale`) and Enabled/Disabled (`orchestration_enabled`) cells now localize
// via `booleanColumn` (#385). This is a read-only resource with no fields.
export const selfHostedWorkersConfig: ResourceConfig<AdminSelfHostedWorkerRecord> = {
  key: "self-hosted-workers",
  titleKey: "resource.selfHostedWorkers.title",
  descriptionKey: "resource.selfHostedWorkers.description",
  basePath: "/admin/v1/self-hosted-worker-records",
  idField: "id",
  readOnly: true,
  rowLabel: (row) => row.worker_name,
  columns: [
    {
      key: "worker_name",
      headerKey: "resource.selfHostedWorkers.col.name",
      priority: "primary",
      minWidth: 200,
      mobileVisibility: "always",
    },
    {
      key: "status",
      headerKey: "resource.selfHostedWorkers.col.status",
      priority: "secondary",
      minWidth: 110,
      mobileVisibility: "always",
    },
    {
      key: "trust_level",
      headerKey: "resource.selfHostedWorkers.col.trustLevel",
      priority: "detail",
      minWidth: 230,
      mobileVisibility: "details",
    },
    booleanColumn<AdminSelfHostedWorkerRecord>({
      key: "stale",
      headerKey: "resource.selfHostedWorkers.col.stale",
      priority: "secondary",
      minWidth: 90,
      mobileVisibility: "always",
    }),
    booleanColumn<AdminSelfHostedWorkerRecord>({
      key: "orchestration_enabled",
      headerKey: "resource.selfHostedWorkers.col.orchestration",
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      trueKey: "common.enabled",
      falseKey: "common.disabled",
    }),
    {
      key: "telemetry_event_count",
      headerKey: "resource.selfHostedWorkers.col.telemetryEvents",
      priority: "detail",
      minWidth: 140,
      mobileVisibility: "details",
    },
  ],
  fields: [],
};
