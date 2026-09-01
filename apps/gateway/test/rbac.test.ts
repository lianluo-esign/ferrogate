/**
 * `D1RbacAuthorizer` — the durable Permission → Role → TenantRoleBinding walk.
 *
 * The port of `crates/ferrogate-gateway/src/state_rbac.rs::
 * tenant_has_permission_result`, run against the REAL `CONTROL_DB` binding
 * `wrangler.toml` declares and the REAL `permissions` / `roles` /
 * `tenant_role_bindings` DDL from `sql/d1-ts/control/0001_init_control.sql`
 * (applied by `test/setup-d1.ts`). Nothing here doubles the database — the
 * outage tests substitute a THROWING database, which is the one thing a live
 * binding cannot be asked to do.
 *
 * The file has two halves and they prove different things:
 *
 *  - the decision table, driven directly against the adapter;
 *  - the MOUNT, driven through `SELF.fetch` — i.e. through `depsFromEnv` on the
 *    app `src/index.ts` exports. A `D1RbacAuthorizer` that is written, tested
 *    and never reached by `depsFromEnv` is the defect class this repo has
 *    already shipped twice, so the mount gets its own failing-when-unmounted
 *    assertion rather than being assumed.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  ConfiguredRbacAuthorizer,
  D1RbacAuthorizer,
  RBAC_PERMISSION_EXISTS_SQL,
  type RbacDatabase,
  depsFromEnv,
} from "../src/adapters.js";
import { CONTROL_DATA_ADDRESS } from "@ferrogate/storage";
import { CONTROL_STORAGE_MISCONFIGURED, controlDatabaseFrom } from "../src/control-data.js";
import type { AuthContext, RbacDecision } from "../src/ports.js";
import {
  seedTenantRosterRows,
  tenantObjectPrivilegedBatch,
  tenantObjectRouter,
} from "./tenant-object.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    // Loud, never a silent skip: `wrangler.toml` declares it, so an absent
    // binding means the declaration was removed and this suite is about to
    // prove something other than what it claims.
    throw new Error(
      "rbac tests expect the `CONTROL_DB` D1 binding (apps/gateway/wrangler.toml). " +
        "See src/adapters.ts for why RBAC reads the CONTROL database.",
    );
  }
  return binding;
}

/** A tenant credential, the shape `contractAuth` puts on the context. */
function tenantAuth(tenantId: string): AuthContext {
  return {
    subject: "key_x",
    tenancy: { tenantId, projectId: null, workspaceId: null, userId: null },
    scopes: ["admin.read"],
    platformOperator: false,
    source: "durable_native",
  };
}

const OPERATOR: AuthContext = {
  subject: "key_root",
  tenancy: { tenantId: null, projectId: null, workspaceId: null, userId: null },
  scopes: ["*"],
  platformOperator: true,
  source: "static_config",
};

/** Seed a permission row (step 1 of the Rust walk: the action must be declared). */
async function declarePermission(key: string): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO permissions (id, key, name, description) VALUES (?1, ?2, ?3, '')",
    )
    .bind(`perm_${key}`, key, key)
    .run();
}

/** Seed a role holding `permissionKeys`, and bind it to `tenantId`. */
async function grantRole(
  roleId: string,
  permissionKeys: readonly string[],
  tenantId?: string,
): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(roleId, roleId, roleId, JSON.stringify(permissionKeys))
    .run();
  if (tenantId !== undefined) {
    await bindRole(tenantId, roleId);
  }
}

/**
 * Bind a role id to a tenant — the id may name a role row that does not exist.
 *
 * Post-#863 (`sql/d1-ts/control/0016_tenant_configuration_policy_legacy.sql`)
 * the binding lives in the TENANT OBJECT, not the control database, and the
 * object refuses ordinary tenant SQL against it — so the seed goes through the
 * privileged operator RPC, the same path the production backfill uses.
 */
async function bindRole(tenantId: string, roleId: string): Promise<void> {
  await tenantObjectPrivilegedBatch(tenantId, [
    {
      sql: "INSERT OR REPLACE INTO tenant_role_bindings (id, tenant_id, role_id) VALUES (?, ?, ?)",
      params: [`${tenantId}:${roleId}`, tenantId, roleId],
    },
  ]);
}

/** Every tenant a test in this file writes a durable role binding for. */
const BOUND_TENANTS = ["tenant_a", "tenant_c"] as const;

async function resetRbacTables(): Promise<void> {
  const db = controlDb();
  // The shared catalog stays in CONTROL; the bindings are tenant-object rows.
  await db.batch([db.prepare("DELETE FROM roles"), db.prepare("DELETE FROM permissions")]);
  for (const tenantId of BOUND_TENANTS) {
    await tenantObjectPrivilegedBatch(tenantId, [
      { sql: "DELETE FROM tenant_role_bindings" },
      { sql: "DELETE FROM tenant_role_catalog" },
    ]);
  }
}

/** A database that fails every statement, as an outage would. */
const failingDb: RbacDatabase = {
  prepare(): never {
    throw new Error("D1_ERROR: control database is unreachable");
  },
};

/** A database that records whether it was consulted at all. */
function recordingDb(): { db: RbacDatabase; readonly statements: string[] } {
  const statements: string[] = [];
  const inner = controlDb() as unknown as RbacDatabase;
  return {
    statements,
    db: {
      prepare(sql: string) {
        statements.push(sql);
        return inner.prepare(sql);
      },
    },
  };
}

const ACTION = "guardrails.policy.read";

beforeEach(async () => {
  await resetRbacTables();
});

// ---------------------------------------------------------------------------
// The decision table
// ---------------------------------------------------------------------------

describe("D1RbacAuthorizer — tenant_has_permission_result", () => {
  it("grants when a bound role holds the declared permission", async () => {
    await declarePermission(ACTION);
    await grantRole("role_guardrail_reader", [ACTION], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toEqual({ allowed: true });
  });

  it("denies a permission that no `permissions` row declares, even when a role names it", async () => {
    // Step 1 of the Rust walk, and it is not a formality: without it a typo in
    // a role's `permission_keys` would mint an entitlement nobody declared.
    await grantRole("role_guardrail_reader", [ACTION], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toMatchObject({
      allowed: false,
      code: "guardrail_rbac_denied",
    });
  });

  it("denies when the tenant's roles do not hold the permission", async () => {
    await declarePermission(ACTION);
    await grantRole("role_other", ["guardrails.policy.archive"], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toEqual({
      allowed: false,
      code: "guardrail_rbac_denied",
      message: "tenant roles do not grant required action guardrails.policy.read",
    });
  });

  it("scopes grants to the BOUND tenant — another tenant's role is not a grant", async () => {
    await declarePermission(ACTION);
    await grantRole("role_guardrail_reader", [ACTION], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_b"), ACTION)).toMatchObject({ allowed: false });
  });

  it("skips a binding whose role row is missing rather than treating it as a grant", async () => {
    // Rust: `let Some(role) = get_role(..) else { continue }`.
    await declarePermission(ACTION);
    await bindRole("tenant_a", "role_that_was_deleted");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toMatchObject({ allowed: false });
  });

  it("has NO wildcard: a role holding `*` grants only the permission named `*`", async () => {
    // The Rust compares `key == permission_key`. The var table's `"*"` is a
    // bootstrap convenience and copying it here would be a silent privilege
    // escalation for every role somebody wrote `*` into.
    await declarePermission(ACTION);
    await grantRole("role_star", ["*"], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toMatchObject({ allowed: false });
  });

  it("names the denial after the action's domain", async () => {
    await declarePermission("workers.self_hosted");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), "workers.self_hosted")).toMatchObject({
      allowed: false,
      code: "rbac_denied",
    });
  });

  it("ignores a corrupt role document without revoking the tenant's other roles", async () => {
    await declarePermission(ACTION);
    await controlDb()
      .prepare(
        "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) VALUES (?1, ?1, ?1, ?2)",
      )
      .bind("role_corrupt", "{not json")
      .run();
    await bindRole("tenant_a", "role_corrupt");
    await grantRole("role_good", [ACTION], "tenant_a");

    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toEqual({ allowed: true });
  });

  it("waves a platform operator through WITHOUT querying the database", async () => {
    const recording = recordingDb();
    const rbac = new D1RbacAuthorizer(recording.db);
    expect(await rbac.authorize(OPERATOR, ACTION)).toEqual({ allowed: true });
    // Not just "allowed": the Rust guards the whole block with
    // `if let CallerScope::Tenant(..)`, so root access must not depend on the
    // control database being up.
    expect(recording.statements).toEqual([]);
  });

  it("issues exactly the two ported statements, in order", async () => {
    // The native-binding compatibility leg (no `tenantDatabases` router): the
    // statement TEXT and ORDER are the ported Rust walk, and both are pinned —
    // `test/fleet-control-matrix.test.ts` scans these very literals to see the
    // gateway reading the RBAC authority. Post-#863 the deployed posture routes
    // the second read through the tenant object instead (the tests above), but
    // the compat leg must keep issuing the permission-existence check FIRST.
    await declarePermission(ACTION);
    const recording = recordingDb();
    await new D1RbacAuthorizer(recording.db).authorize(tenantAuth("tenant_a"), ACTION);
    expect(recording.statements[0]).toBe(RBAC_PERMISSION_EXISTS_SQL);
    expect(recording.statements).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Outage vs decision, and the config fallback
// ---------------------------------------------------------------------------

describe("D1RbacAuthorizer — an outage is not a decision", () => {
  it("answers `unavailable` (→ 503) when the control database fails", async () => {
    const rbac = new D1RbacAuthorizer(failingDb);
    const decision = await rbac.authorize(tenantAuth("tenant_a"), ACTION);
    expect(decision.allowed).toBe("unavailable");
    expect((decision as { detail: string }).detail).toContain("unreachable");
  });

  it("does NOT fall through to the config table on an outage", async () => {
    // The `D1ApiKeyResolver` rule, and the Rust one: papering an outage over
    // with config would make a control-plane failure grant whatever the
    // bootstrap var happens to say, which is the opposite of fail-closed.
    const generous = new ConfiguredRbacAuthorizer({ tenant_a: ["*"] });
    const rbac = new D1RbacAuthorizer(failingDb, { fallback: generous });
    expect((await rbac.authorize(tenantAuth("tenant_a"), ACTION)).allowed).toBe("unavailable");
  });

  it("DOES fall through to the config table on a durable not-granted", async () => {
    await declarePermission(ACTION);
    const generous = new ConfiguredRbacAuthorizer({ tenant_a: [ACTION] });
    const rbac = new D1RbacAuthorizer(controlDb() as unknown as RbacDatabase, {
      fallback: generous,
      tenantDatabases: tenantObjectRouter(),
    });
    expect(await rbac.authorize(tenantAuth("tenant_a"), ACTION)).toEqual({ allowed: true });
    // …and the fallback is not a blanket yes: a tenant it does not name is
    // still denied.
    expect(await rbac.authorize(tenantAuth("tenant_z"), ACTION)).toMatchObject({ allowed: false });
  });
});

// ---------------------------------------------------------------------------
// The mount
// ---------------------------------------------------------------------------

describe("depsFromEnv wires the durable authorizer", () => {
  it("builds a D1RbacAuthorizer when CONTROL_DATA is bound, and not otherwise", () => {
    expect(depsFromEnv(bindings as never).rbac).toBeInstanceOf(D1RbacAuthorizer);
    // Removing the `[[durable_objects.bindings]] CONTROL_DATA` stanza from
    // wrangler.toml, or the `D1RbacAuthorizer.fromEnv(...) ??` from
    // `depsFromEnv`, turns the first assertion red while leaving the whole
    // decision table above green.
    const withoutBinding = { ...bindings, CONTROL_DATA: undefined };
    expect(depsFromEnv(withoutBinding as never).rbac).toBeInstanceOf(ConfiguredRbacAuthorizer);
  });
});

describe("CONTROL storage seam", () => {
  it("resolves the CONTROL_DATA facade, and rejects d1_compat and other illegal modes", async () => {
    // Zero-D1 S5 (#881): `durable_object` is the ONLY posture. There is no
    // `d1_compat` leg and no `CONTROL_DB`/`BILLING_DB` fallback — `d1_compat` is
    // now an illegal value like any other, not a rollback path.
    let addressedName: string | undefined;
    const namespace = {
      idFromName(name: string) {
        addressedName = name;
        return "control-id";
      },
      get() {
        return {
          query: async () => ({ results: [] }),
          batch: async () => [],
        };
      },
    };

    const facade = controlDatabaseFrom({ CONTROL_DATA: namespace });
    expect(facade).toBeDefined();
    // The facade addresses the singleton "control" object when first used.
    await (facade as D1Database).prepare("SELECT 1").all();
    expect(addressedName).toBe(CONTROL_DATA_ADDRESS);

    // No CONTROL_DATA bound ⇒ undefined (the optional reads' config path),
    // never a fall-through to a legacy binding.
    expect(controlDatabaseFrom({})).toBeUndefined();

    for (const mode of ["d1_compat", "invalid"]) {
      let error: unknown;
      try {
        controlDatabaseFrom({ GATEWAY_CONTROL_STORAGE: mode, CONTROL_DATA: namespace });
      } catch (caught) {
        error = caught;
      }
      expect(error, `mode ${mode} must be refused`).toMatchObject({
        status: 503,
        code: CONTROL_STORAGE_MISCONFIGURED,
      });
    }
  });
});

/**
 * The behavioural half — through `SELF.fetch`, i.e. the deployed app.
 *
 * `/admin/v1/guardrail-policies` is owned by `apps/control-plane`, so this
 * Worker mounts no route for it. That is exactly what makes it a clean probe:
 * `contractAuth` is an `app.use("*")` guard, so it runs and decides BEFORE the
 * 404. A caller that clears the guard sees 404 (nothing here serves it); a
 * caller the RBAC walk denies sees 403 with the Rust's own code. The two are
 * unambiguous.
 *
 * `tenant_c` is used deliberately: `vitest.config.ts` grants
 * `guardrails.policy.read` to `tenant_a` through `TENANT_RBAC_ACTIONS`, so a
 * test on `tenant_a` could pass on the config fallback alone and prove nothing
 * about the durable leg.
 */
describe("composition root — the durable RBAC walk decides a real request", () => {
  const ADMIN_KEY = "fg_tenant_c_admin";

  beforeAll(async () => {
    // A native key for `tenant_c` carrying the operation's `admin.read` scope,
    // so the request reaches the RBAC step instead of stopping at `scope_denied`.
    bindings.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
      { key: ADMIN_KEY, id: "key_tenant_c", tenant_id: "tenant_c", scopes: ["admin.read"] },
    ]);
    // `tenant_c` is not a vitest.config fixture tenant, so `test/setup-d1.ts`
    // seeds no roster row for it — and an ADMITTED request then 503s downstream
    // when the backend-dispatching router cannot place the tenant.
    await seedTenantRosterRows(["tenant_c"]);
  });

  afterEach(async () => {
    await resetRbacTables();
  });

  function listPolicies(): Promise<Response> {
    return SELF.fetch("https://gw.test/admin/v1/guardrail-policies", {
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
  }

  it("403 `guardrail_rbac_denied` with no durable grant and no config grant", async () => {
    const res = await listPolicies();
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "guardrail_rbac_denied",
    );
  });

  it("clears the guard once a role in the CONTROL database grants the action", async () => {
    await declarePermission(ACTION);
    await grantRole("role_guardrail_reader", [ACTION], "tenant_c");

    const res = await listPolicies();
    // 404, not 403: the guard admitted the request and `apps/control-plane`
    // owns the route. Nothing but the D1 rows above changed between the two
    // tests, so this is the durable walk deciding, not the var table.
    expect(res.status).toBe(404);
  });

  it("503 `rbac_unavailable` is what an unmigrated control database answers", async () => {
    // Proven by dropping the table the walk reads first, then restoring it —
    // the same failure an operator gets by deploying before
    // `wrangler d1 migrations apply ferrogate-control`.
    await controlDb().prepare("DROP TABLE permissions").run();
    try {
      const res = await listPolicies();
      expect(res.status).toBe(503);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
        "rbac_unavailable",
      );
    } finally {
      await controlDb()
        .prepare(
          "CREATE TABLE IF NOT EXISTS permissions (id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, " +
            "name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', " +
            "created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()), " +
            "updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()))",
        )
        .run();
    }
  });
});

/** Compile-time proof that a live `D1Database` satisfies the narrow port. */
const _bindingSatisfiesThePort: (db: D1Database) => RbacDatabase = (db) => db;
void _bindingSatisfiesThePort;
void (undefined as unknown as RbacDecision);
