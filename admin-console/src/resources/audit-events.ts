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

export const auditEventsConfig: ResourceConfig<AdminAuditEvent> = {
  key: "audit-events",
  title: "Audit events",
  description: "Administrative and security-relevant actions recorded by the gateway.",
  basePath: "/admin/v1/audit-events",
  idField: "id",
  readOnly: true,
  columns: [
    { key: "action", header: "Action" },
    { key: "target", header: "Target" },
    { key: "outcome", header: "Outcome" },
    { key: "message", header: "Message" },
    { key: "actor_api_key_id", header: "Actor key" },
  ],
  fields: [],
};
