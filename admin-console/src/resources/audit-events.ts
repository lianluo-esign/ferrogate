import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminAuditEvent extends Record<string, unknown> {
  id: string;
  action: string;
  target: string;
  outcome: string;
  message: string;
  actor_api_key_id: string | null;
  occurred_at_unix: number | null;
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey` and column `headerKey` resolve under the active
// locale. Column `key`s stay untouched; this is a read-only resource with no
// fields.
export const auditEventsConfig: ResourceConfig<AdminAuditEvent> = {
  key: "audit-events",
  titleKey: "resource.auditEvents.title",
  descriptionKey: "resource.auditEvents.description",
  basePath: "/admin/v1/audit-events",
  idField: "id",
  readOnly: true,
  columns: [
    { key: "action", headerKey: "resource.auditEvents.col.action" },
    { key: "target", headerKey: "resource.auditEvents.col.target" },
    { key: "outcome", headerKey: "resource.auditEvents.col.outcome" },
    { key: "message", headerKey: "resource.auditEvents.col.message" },
    { key: "actor_api_key_id", headerKey: "resource.auditEvents.col.actorKey" },
  ],
  fields: [],
};
