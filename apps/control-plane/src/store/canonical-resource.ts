import type { StoreRecord } from "../ports.js";

/** During the rolling migration, native tables still use the old writer. */
export async function writeCanonicalResourceIfView(
  db: D1Database,
  table: "api_keys" | "plans" | "payment_methods",
  kind: "virtual-keys" | "plans" | "payment-methods",
  record: StoreRecord,
  nowUnix: number,
): Promise<boolean> {
  const schema = await db
    .prepare("SELECT type FROM sqlite_master WHERE name = ?")
    .bind(table)
    .first<{ type: string }>();
  if (schema?.type !== "view") return false;
  const resources = kind === "plans" ? "control_plane_resources" : "tenant_resources";
  await db
    .prepare(`INSERT INTO ${resources}
    (resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
    VALUES (?,?,?,1,?,?) ON CONFLICT(resource_kind,resource_id) DO UPDATE SET
      document_json=excluded.document_json,revision=${resources}.revision+1,
      updated_at_unix=excluded.updated_at_unix
    WHERE ${resources}.document_json <> excluded.document_json`)
    .bind(kind, record.id, JSON.stringify(record), nowUnix, nowUnix)
    .run();
  return true;
}
