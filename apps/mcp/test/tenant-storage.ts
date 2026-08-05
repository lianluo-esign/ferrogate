import { DurableObjectD1Database } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";

export interface TenantDataBindings {
  readonly TENANT_DATA: TenantDataNamespace;
}

export function tenantDataNamespace(env: unknown): TenantDataNamespace {
  const namespace = (env as TenantDataBindings).TENANT_DATA;
  if (namespace === undefined) throw new Error("MCP tests require the TENANT_DATA binding");
  return namespace;
}

export function tenantDatabase(
  namespace: TenantDataNamespace,
  tenantId: string,
): D1Database {
  return new DurableObjectD1Database(
    tenantId,
    namespace.get(namespace.idFromName(tenantId)),
  ).asD1Database();
}

export async function clearMcpIdentityTables(
  namespace: TenantDataNamespace,
  tenantId: string,
): Promise<void> {
  const db = tenantDatabase(namespace, tenantId);
  await db.batch([
    db.prepare("DELETE FROM mcp_oauth_credentials"),
    db.prepare("DELETE FROM mcp_identity_generations"),
    db.prepare("DELETE FROM mcp_servers"),
  ]);
}
