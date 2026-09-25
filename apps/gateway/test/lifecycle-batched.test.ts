import { env } from "cloudflare:test";
import { DurableObjectD1Database } from "@ferrogate/storage";
import { describe, expect, it, vi } from "vitest";
import { lifecycleRowSourceFactoryFromEnv, resolveLifecycleChain } from "../src/adapters.js";
import { tenantObjectDb } from "./tenant-object.js";

describe("workspace lifecycle reads its parent in the same tenant RPC", () => {
  it("checks actual AND declared ancestors while avoiding a second parent lookup", async () => {
    const tenant = "speed-lifecycle";
    const db = tenantObjectDb(tenant);
    await db.batch([
      db
        .prepare(
          "INSERT OR REPLACE INTO projects (id,tenant_id,name,slug,status) VALUES ('actual',?,'actual','actual','suspended')",
        )
        .bind(tenant),
      db
        .prepare(
          "INSERT OR REPLACE INTO projects (id,tenant_id,name,slug,status) VALUES ('declared',?,'declared','declared','active')",
        )
        .bind(tenant),
      db
        .prepare(
          "INSERT OR REPLACE INTO workspaces (id,tenant_id,project_id,name,slug,status) VALUES ('workspace',?,'actual','workspace','workspace','active')",
        )
        .bind(tenant),
    ]);
    const factory = lifecycleRowSourceFactoryFromEnv(env as unknown as Record<string, unknown>);
    expect(factory).not.toBeNull();
    const spy = vi.spyOn(DurableObjectD1Database.prototype, "runStatement");
    try {
      const source = factory?.(tenant);
      if (!source) throw new Error("missing lifecycle source");
      const chain = await resolveLifecycleChain(source, {
        tenantId: tenant,
        projectId: "declared",
        workspaceId: "workspace",
      });
      expect(chain).toContainEqual({ kind: "project", id: "actual", status: "suspended" });
      expect(chain).toContainEqual({ kind: "project", id: "declared", status: "active" });
      const queries = spy.mock.calls.map(([statement]) => statement.sql);
      expect(queries.filter((sql) => sql.includes("FROM workspaces"))).toHaveLength(1);
      expect(queries.filter((sql) => sql.includes("FROM projects"))).toHaveLength(1);
      spy.mockClear();
      await resolveLifecycleChain(factory?.(tenant) as NonNullable<typeof source>, {
        tenantId: tenant,
        projectId: "actual",
        workspaceId: "workspace",
      });
      expect(
        spy.mock.calls
          .map(([statement]) => statement.sql)
          .filter((sql) => sql.includes("FROM projects")),
      ).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });
});
