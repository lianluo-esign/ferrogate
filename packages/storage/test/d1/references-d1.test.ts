/**
 * Reference-guarded deletes against a REAL D1 database (inventory §1.5.7,
 * issue #328 finding 4).
 *
 * The interesting claim is not "a referenced project is refused" — the
 * in-memory backend shows that, and shows it for a reason (a single JS thread)
 * that does not exist in SQLite. The claim that needs real D1 is that the
 * check and the delete are ONE statement, so a reference that appears after a
 * caller would have "checked" still blocks the delete. The last describe below
 * interleaves exactly that write and is the reason this file exists.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1ReferenceGuardedDeletes,
  MemoryReferenceGuardedDeletes,
  type TenantDatabaseHandle,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, setupDatabases } from "./harness.js";

const NOW = 1_700_000_000;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

async function clear(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM api_keys"),
    db.prepare("DELETE FROM workspaces"),
    db.prepare("DELETE FROM projects"),
  ]);
}

beforeEach(async () => {
  await clear(env.TENANT_DB_A);
  await clear(env.TENANT_DB_B);
});

async function seedProject(db: D1Database, id: string, tenantId = TENANT_A): Promise<void> {
  await db
    .prepare(
      "INSERT INTO projects (id, tenant_id, name, slug, status, created_at_unix, " +
        "updated_at_unix) VALUES (?, ?, ?, ?, 'active', ?, ?)",
    )
    .bind(id, tenantId, id, id, NOW, NOW)
    .run();
}

async function seedWorkspace(
  db: D1Database,
  id: string,
  projectId: string,
  tenantId = TENANT_A,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO workspaces (id, project_id, tenant_id, name, slug, environment, status, " +
        "created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?, 'default', 'active', ?, ?)",
    )
    .bind(id, projectId, tenantId, id, id, NOW, NOW)
    .run();
}

async function seedApiKey(
  db: D1Database,
  id: string,
  projectId: string,
  workspaceId: string,
  tenantId = TENANT_A,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO api_keys (id, workspace_id, tenant_id, project_id, name, key_prefix, " +
        "key_hash, last4, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, 'fg_', ?, 'abcd', ?, ?)",
    )
    .bind(id, workspaceId, tenantId, projectId, id, `hash-${id}`, NOW, NOW)
    .run();
}

async function projectExists(db: D1Database, id: string): Promise<boolean> {
  const row = await db.prepare("SELECT 1 AS present FROM projects WHERE id = ?").bind(id).first();
  return row !== null;
}

describe("D1ReferenceGuardedDeletes — projects", () => {
  test("an unreferenced project is deleted, and the row is really gone", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    const deletes = new D1ReferenceGuardedDeletes(handleA);
    expect(await deletes.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "deleted" });
    expect(await projectExists(env.TENANT_DB_A, "proj_1")).toBe(false);
  });

  test("a workspace reference refuses AND the project survives", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    await seedWorkspace(env.TENANT_DB_A, "ws_1", "proj_1");
    const deletes = new D1ReferenceGuardedDeletes(handleA);
    expect(await deletes.deleteProjectIfUnreferenced("proj_1")).toEqual({
      kind: "referenced",
      workspaces: 1,
      virtualKeys: 0,
    });
    // A refusal that still removed the row would orphan the workspace, whose
    // api-keys would keep authenticating against a project that no longer is.
    expect(await projectExists(env.TENANT_DB_A, "proj_1")).toBe(true);
  });

  test("a virtual key alone refuses, with both counts reported separately", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    await seedWorkspace(env.TENANT_DB_A, "ws_1", "proj_1");
    await seedApiKey(env.TENANT_DB_A, "key_1", "proj_1", "ws_1");
    await seedApiKey(env.TENANT_DB_A, "key_2", "proj_1", "ws_1");
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteProjectIfUnreferenced("proj_1"),
    ).toEqual({ kind: "referenced", workspaces: 1, virtualKeys: 2 });
  });

  test("an unknown id is not_found, not a silent success", async () => {
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteProjectIfUnreferenced("nope"),
    ).toEqual({ kind: "not_found" });
  });

  test("the delete is scoped to the tenant's OWN database", async () => {
    // Same project id in two tenant databases. Deleting through tenant A's
    // handle must not reach into B — the isolation the DB-per-tenant split buys.
    await seedProject(env.TENANT_DB_A, "proj_shared");
    await seedProject(env.TENANT_DB_B, "proj_shared", TENANT_B);
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteProjectIfUnreferenced("proj_shared"),
    ).toEqual({ kind: "deleted" });
    expect(await projectExists(env.TENANT_DB_B, "proj_shared")).toBe(true);
  });

  test("a reference in ANOTHER tenant's database does not block", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    await seedWorkspace(env.TENANT_DB_B, "ws_1", "proj_1", TENANT_B);
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteProjectIfUnreferenced("proj_1"),
    ).toEqual({ kind: "deleted" });
  });
});

describe("D1ReferenceGuardedDeletes — workspaces", () => {
  test("an unreferenced workspace is deleted", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    await seedWorkspace(env.TENANT_DB_A, "ws_1", "proj_1");
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteWorkspaceIfUnreferenced("ws_1"),
    ).toEqual({ kind: "deleted" });
  });

  test("a key in the workspace refuses; a key in a SIBLING workspace does not", async () => {
    await seedProject(env.TENANT_DB_A, "proj_1");
    await seedWorkspace(env.TENANT_DB_A, "ws_1", "proj_1");
    await seedWorkspace(env.TENANT_DB_A, "ws_2", "proj_1");
    await seedApiKey(env.TENANT_DB_A, "key_1", "proj_1", "ws_2");
    const deletes = new D1ReferenceGuardedDeletes(handleA);
    expect(await deletes.deleteWorkspaceIfUnreferenced("ws_2")).toEqual({
      kind: "referenced",
      virtualKeys: 1,
    });
    expect(await deletes.deleteWorkspaceIfUnreferenced("ws_1")).toEqual({ kind: "deleted" });
  });

  test("an unknown workspace is not_found", async () => {
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteWorkspaceIfUnreferenced("nope"),
    ).toEqual({ kind: "not_found" });
  });
});

/**
 * THE TOCTOU PROOF.
 *
 * Postgres closed the check/use window with `SELECT ... FOR UPDATE`; D1 has no
 * row lock, so the port's answer is that there is no window because there is no
 * second statement — the `NOT EXISTS` guard is evaluated by SQLite as part of
 * the DELETE, against committed state, at execution time.
 *
 * This test makes that falsifiable by inserting the blocking reference LATE:
 * after the operation has begun and immediately before the guarded DELETE is
 * dispatched. A check-then-delete implementation would have already counted
 * zero and would delete a project that is referenced by the time the delete
 * lands. The guarded single statement sees the row and refuses.
 */
describe("the check/use window the guard closes", () => {
  test("a reference committed just before the DELETE still blocks it", async () => {
    await seedProject(env.TENANT_DB_A, "proj_race");

    let injected = false;
    // A handle whose `prepare` slips a committed workspace INSERT in front of
    // the guarded DELETE — the interleaving a concurrent request produces.
    const racing: TenantDatabaseHandle = {
      ...handleA,
      db: {
        ...handleA.db,
        prepare(sql: string) {
          const statement = handleA.db.prepare(sql);
          if (!sql.startsWith("DELETE FROM projects")) return statement;
          return {
            ...statement,
            bind(...values: unknown[]) {
              const bound = statement.bind(...values);
              return {
                ...bound,
                async run() {
                  if (!injected) {
                    injected = true;
                    await seedWorkspace(env.TENANT_DB_A, "ws_late", "proj_race");
                  }
                  return bound.run();
                },
                first: bound.first.bind(bound),
                all: bound.all.bind(bound),
                raw: bound.raw.bind(bound),
              } as unknown as D1PreparedStatement;
            },
          } as unknown as D1PreparedStatement;
        },
      } as unknown as D1Database,
    };

    const outcome = await new D1ReferenceGuardedDeletes(racing).deleteProjectIfUnreferenced(
      "proj_race",
    );
    expect(injected).toBe(true);
    // Check-then-delete would report `deleted` here and orphan `ws_late`.
    expect(outcome).toEqual({ kind: "referenced", workspaces: 1, virtualKeys: 0 });
    expect(await projectExists(env.TENANT_DB_A, "proj_race")).toBe(true);
  });

  test("the durable backend and the in-memory baseline agree on every outcome", async () => {
    const memory = new MemoryReferenceGuardedDeletes();
    const durable = new D1ReferenceGuardedDeletes(handleA);

    memory.addProject({ id: "p_free" });
    memory.addProject({ id: "p_held" });
    memory.addWorkspace({ id: "w_held", projectId: "p_held" });
    await seedProject(env.TENANT_DB_A, "p_free");
    await seedProject(env.TENANT_DB_A, "p_held");
    await seedWorkspace(env.TENANT_DB_A, "w_held", "p_held");

    for (const id of ["p_free", "p_held", "p_missing"]) {
      expect(await durable.deleteProjectIfUnreferenced(id)).toEqual(
        memory.deleteProjectIfUnreferenced(id),
      );
    }
  });
});
