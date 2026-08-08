/**
 * The DURABLE {@link AuthPort} (`src/auth.ts`), driven through the REAL Worker.
 *
 * Before this suite `portsBound` was `FG_DEV_IN_MEMORY_PORTS === "1"` and
 * nothing else, so a production `ferrogate-mcp` — one that correctly refuses to
 * set the dev flag — answered `503 mcp_auth_unavailable` on every authenticated
 * surface, forever. The credential tables were already in the database this
 * Worker binds; only the reader was missing.
 *
 * ## Why almost every test goes through `SELF.fetch`
 *
 * A test that constructs its own `D1McpAuth` proves the CLASS works and proves
 * nothing about the Worker that ships — the "implemented, fully tested, never
 * mounted" defect this project has been bitten by five times. So the rows are
 * seeded into the REAL `env.DB` / `env.TENANT_DB_A` that
 * `@cloudflare/vitest-pool-workers` boots in workerd, and the credential is
 * then presented to the REAL exported app over HTTP. Deleting the
 * `auth: durableAuth(env)` line in `resolvePorts` turns this file red.
 *
 * The three unit-level tests at the bottom are the ones a live binding cannot
 * express: a D1 OUTAGE (the binding is healthy for the whole run) and the
 * clock-dependent expiry boundary.
 *
 * ## The taxonomy under test
 *
 * Every refusal short of "authenticated but under-scoped" is the SAME
 * `401 invalid_api_key` an unknown key gets — disabled, revoked, expired, a
 * directory row whose tenant row is gone, a tenant with no registry entry. Key
 * state is NEVER disclosed. `403` is reserved for a caller who IS
 * authenticated; `503` for a dependency this deployment cannot reach.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { controlNamespace } from "./support/control-namespace.js";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  API_KEY_DIRECTORY_TABLE,
  D1McpAuth,
  STATIC_API_KEY_TABLE,
  forgetControlTableProbe,
  hashApiKeySecret,
  parseStaticScopes,
  parseVirtualKeyScopes,
} from "../src/auth.js";
import { mcpRouter } from "../src/index.js";
import { durableAuthBound, portsBound, resolvePorts } from "../src/ports.js";
import { EXEC_KEY, type Fixture, rpcRequest, seedFixture } from "./fixtures.js";
import {
  registerDurableObjectTenant,
  resetTenantObjectState,
  seedTenantRoleProjection,
  tenantObjectDb,
} from "./tenant-object.js";

interface D1AuthBindings {
  readonly DB: D1Database;
  readonly TENANT_DB_A: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

function bindings(): D1AuthBindings {
  return env as unknown as D1AuthBindings;
}

const control = (): D1Database => bindings().DB;
const tenantDb = (): D1Database => tenantObjectDb(ROUTED_TENANT);

/** The tenant whose database really is bound in `vitest.config.ts`. */
const ROUTED_TENANT = "tenant-routed";
/** Registered naming a binding this Worker does NOT have. */
const UNROUTABLE_TENANT = "tenant-not-deployed";
/** This file must not reset the shared `fixtures.ts` tenant object. */
const STATIC_TENANT = "tenant-mcp-d1-auth";

const STATIC_KEY = "fg_static_operator_key";
const VIRTUAL_KEY = "fg_virtual_tenant_key";

let fixture: Fixture;

beforeAll(async () => {
  const b = bindings();
  // Zero-D1 S5 (#881): the ControlDataObject self-applies its schema on first
  // wake; there is no control D1 to migrate here.
  await applyD1Migrations(b.TENANT_DB_A, b.TEST_TENANT_D1_SCHEMA);
  // The table probe in `src/auth.ts` is cached per D1 handle for the life of
  // the isolate, and another test file may already have driven a request that
  // cached "these tables do not exist". Forgetting it here is the same thing an
  // isolate recycle does after a migration lands.
  forgetControlTableProbe(b.DB);
});

beforeEach(async () => {
  // The pool does not roll D1 writes back and the databases persist under
  // `.wrangler/state`, so a passing assertion could otherwise be a previous
  // run's leftover row.
  await control().batch([
    control().prepare(`DELETE FROM ${STATIC_API_KEY_TABLE}`),
    control().prepare(`DELETE FROM ${API_KEY_DIRECTORY_TABLE}`),
    control().prepare("DELETE FROM tenant_databases"),
    control().prepare("DELETE FROM roles"),
  ]);
  await resetTenantObjectState([ROUTED_TENANT]);
  await resetTenantObjectState([STATIC_TENANT]);
  await registerDurableObjectTenant(STATIC_TENANT);
  fixture = seedFixture({ tenantId: STATIC_TENANT });
});

// ---------------------------------------------------------------------------
// Seeding — raw SQL, never through the code under test
// ---------------------------------------------------------------------------

interface StaticSeed {
  readonly tenantId?: string | null;
  readonly platformOperator?: 0 | 1;
  readonly scopesJson?: string | null;
  readonly enabled?: 0 | 1;
  readonly expiresAtUnix?: number | null;
}

async function seedStaticKey(secret: string, seed: StaticSeed = {}): Promise<void> {
  await control()
    .prepare(
      `INSERT INTO ${STATIC_API_KEY_TABLE}
         (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      await hashApiKeySecret(secret),
      "static-key-1",
      seed.tenantId === undefined ? STATIC_TENANT : seed.tenantId,
      seed.platformOperator ?? 0,
      seed.scopesJson === undefined ? JSON.stringify(["tools.read"]) : seed.scopesJson,
      seed.enabled ?? 1,
      seed.expiresAtUnix ?? null,
    )
    .run();
}

async function registerTenantDatabase(tenantId: string, bindingName: string | null): Promise<void> {
  const durableObject = bindingName === null;
  await control()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, provisioned_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, 'ready', 1, 1)`,
    )
    .bind(
      tenantId,
      durableObject ? null : bindingName,
      durableObject ? 15 : 1,
      durableObject ? "durable_object" : "native_binding",
    )
    .run();
}

interface DirectorySeed {
  readonly tenantId?: string;
  readonly enabled?: 0 | 1;
  readonly expiresAtUnix?: number | null;
  readonly revokedAtUnix?: number | null;
}

async function seedDirectoryRow(secret: string, seed: DirectorySeed = {}): Promise<void> {
  await control()
    .prepare(
      `INSERT INTO ${API_KEY_DIRECTORY_TABLE}
         (key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
          enabled, expires_at_unix, revoked_at_unix)
       VALUES (?, ?, ?, ?, ?, 'fg_', 'key1', ?, ?, ?)`,
    )
    .bind(
      await hashApiKeySecret(secret),
      "virtual-key-1",
      seed.tenantId ?? ROUTED_TENANT,
      "proj-1",
      "ws-1",
      seed.enabled ?? 1,
      seed.expiresAtUnix ?? null,
      seed.revokedAtUnix ?? null,
    )
    .run();
}

interface TenantKeySeed {
  readonly scopesJson?: string;
  readonly enabled?: 0 | 1;
  readonly revokedAtUnix?: number | null;
}

async function seedTenantKeyRow(secret: string, seed: TenantKeySeed = {}): Promise<void> {
  await tenantDb()
    .prepare(
      `INSERT INTO api_keys
         (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4,
          enabled, scopes_json, revoked_at_unix)
       VALUES (?, 'ws-1', ?, 'proj-1', 'mcp', 'fg_', ?, 'key1', ?, ?, ?)`,
    )
    .bind(
      "virtual-key-1",
      ROUTED_TENANT,
      await hashApiKeySecret(secret),
      seed.enabled ?? 1,
      seed.scopesJson ?? JSON.stringify(["tools.read", "tools.execute"]),
      seed.revokedAtUnix ?? null,
    )
    .run();
}

/** Bind an RBAC role to a tenant. */
async function seedRole(tenantId: string, permissionKeys: string[]): Promise<void> {
  await control().batch([
    control()
      .prepare(
        `INSERT INTO roles (id, name, slug, description, permission_keys_json)
         VALUES ('role-1', 'MCP', 'mcp', '', ?)`,
      )
      .bind(JSON.stringify(permissionKeys)),
  ]);
  await seedTenantRoleProjection(tenantId, "role-1", permissionKeys);
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

async function toolsList(key: string): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(
    rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, { key }),
  );
  return { status: res.status, body: (await res.json()) as JsonBody };
}

async function toolsCall(key: string): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(
    rpcRequest(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "srv-echo", arguments: {} } },
      { key },
    ),
  );
  return { status: res.status, body: (await res.json()) as JsonBody };
}

interface JsonBody {
  readonly error?: { code: string; message: string };
  readonly result?: unknown;
}

// ---------------------------------------------------------------------------

describe("this suite exercises the DEPLOYED surfaces, not a harness", () => {
  it("drives operations the production registry actually mounted", () => {
    const registered = new Set(mcpRouter.registeredOperationIds());
    expect(registered.has("mcpJsonRpc")).toBe(true);
  });
});

describe("the durable AuthPort is MOUNTED on the app the Worker exports", () => {
  it("authenticates a STATIC key that exists only as a row in env.DB", async () => {
    // Control: the same secret is rejected before the row exists, so a pass
    // below cannot be "any bearer works".
    const before = await toolsList(STATIC_KEY);
    expect(before.body.error?.code).toBe("invalid_api_key");

    await seedStaticKey(STATIC_KEY);
    const after = await toolsList(STATIC_KEY);
    expect(after.status).toBe(200);
    expect(after.body.error).toBeUndefined();
    expect(after.body.result).toBeDefined();
  });

  it("authenticates a VIRTUAL key through the directory + the routed tenant database", async () => {
    await registerTenantDatabase(ROUTED_TENANT, null);
    await seedDirectoryRow(VIRTUAL_KEY);
    await seedTenantKeyRow(VIRTUAL_KEY);
    await seedRole(ROUTED_TENANT, ["mcp.execute"]);

    const called = await toolsCall(VIRTUAL_KEY);
    expect(called.body.error).toBeUndefined();

    // The identity the app ACTED ON came from the two D1 rows, not a default.
    expect(fixture.calls).toHaveLength(1);
    const auth = fixture.calls[0]?.context.auth;
    expect(auth?.organizationId).toBe(ROUTED_TENANT);
    expect(auth?.projectId).toBe("proj-1");
    expect(auth?.workspaceId).toBe("ws-1");
    expect(auth?.apiKeyId).toBe("virtual-key-1");
    // The tenant database supplied the scopes; the control RBAC tables supplied
    // the permission keys.
    expect(auth?.scopes).toEqual(["tools.read", "tools.execute"]);
    expect(auth?.permissions).toEqual(["mcp.execute"]);
  });

  it("never lets a virtual key become platform root", async () => {
    await registerTenantDatabase(ROUTED_TENANT, null);
    await seedDirectoryRow(VIRTUAL_KEY);
    // A hostile tenant row cannot declare it: the column does not exist, and
    // `virtualKeyContext` writes the literal `false`.
    await seedTenantKeyRow(VIRTUAL_KEY, { scopesJson: JSON.stringify(["*"]) });

    await toolsCall(VIRTUAL_KEY);
    expect(fixture.calls[0]?.context.auth.platformOperator).toBe(false);
  });

  it("honours platform_operator on an OPERATOR-authored static key", async () => {
    await seedStaticKey(STATIC_KEY, {
      platformOperator: 1,
      tenantId: null,
      scopesJson: null, // NULL ⇒ the wildcard, for a static key only
    });
    await toolsCall(STATIC_KEY);
    const auth = fixture.calls[0]?.context.auth;
    expect(auth?.platformOperator).toBe(true);
    expect(auth?.organizationId).toBeUndefined();
  });
});

describe("the 401-vs-403 taxonomy, over the real Worker", () => {
  it("a DISABLED static key is 401 invalid_api_key — never 403", async () => {
    await seedStaticKey(STATIC_KEY, { enabled: 0 });
    const res = await toolsList(STATIC_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("an EXPIRED static key is 401 invalid_api_key", async () => {
    await seedStaticKey(STATIC_KEY, { expiresAtUnix: 1 });
    const res = await toolsList(STATIC_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("a REVOKED directory row is 401 even though the tenant row is still live", async () => {
    await registerTenantDatabase(ROUTED_TENANT, null);
    await seedDirectoryRow(VIRTUAL_KEY, { revokedAtUnix: 10 });
    await seedTenantKeyRow(VIRTUAL_KEY);
    const res = await toolsList(VIRTUAL_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("a DISABLED tenant row is 401 even though the directory still says enabled", async () => {
    await registerTenantDatabase(ROUTED_TENANT, null);
    await seedDirectoryRow(VIRTUAL_KEY);
    await seedTenantKeyRow(VIRTUAL_KEY, { enabled: 0 });
    const res = await toolsList(VIRTUAL_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("a directory row whose tenant row is GONE is 401, not 500", async () => {
    await registerTenantDatabase(ROUTED_TENANT, null);
    await seedDirectoryRow(VIRTUAL_KEY); // no tenant `api_keys` row at all
    const res = await toolsList(VIRTUAL_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("an UNPROVISIONED tenant is 401 — no registry row, no invented scopes", async () => {
    await seedDirectoryRow(VIRTUAL_KEY); // no `tenant_databases` row
    await seedTenantKeyRow(VIRTUAL_KEY);
    const res = await toolsList(VIRTUAL_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("an UNROUTABLE tenant is 503 — a deployment fault an operator must see", async () => {
    await registerTenantDatabase(UNROUTABLE_TENANT, "TENANT_DB_NOT_DEPLOYED");
    await seedDirectoryRow(VIRTUAL_KEY, { tenantId: UNROUTABLE_TENANT });
    const res = await toolsList(VIRTUAL_KEY);
    expect(res.status).toBe(503);
    expect(res.body.error?.code).toBe("mcp_auth_unavailable");
    // ...and the 503 discloses the DEPENDENCY, never the credential.
    expect(res.body.error?.message).not.toContain(VIRTUAL_KEY);
  });

  it("a resolved key missing the operation's scope is 403 insufficient_scope", async () => {
    await seedStaticKey(STATIC_KEY, { scopesJson: JSON.stringify(["tools.read"]) });
    // tools/list is granted...
    expect((await toolsList(STATIC_KEY)).status).toBe(200);
    // ...tools/call is not, and that is the ONE case that may be a 403.
    const res = await toolsCall(STATIC_KEY);
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("insufficient_scope");
  });

  it("no Bearer header is 401 unauthenticated", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    );
    expect(res.status).toBe(401);
    expect(((await res.json()) as JsonBody).error?.code).toBe("unauthenticated");
  });
});

describe("the durable row DECIDES — a dev key can never overrule it", () => {
  it("a disabled durable row beats an enabled in-memory key of the same secret", async () => {
    // The in-memory dev table would happily authenticate this secret with a
    // wildcard scope. If the fallback ran FIRST, this would be a 200 — which is
    // exactly how a stale dev/config key re-enables a credential the database
    // revoked.
    fixture.ports.auth.register(STATIC_KEY, {
      apiKeyId: "dev",
      organizationId: STATIC_TENANT,
      scopes: ["*"],
      permissions: [],
      platformOperator: false,
    });
    await seedStaticKey(STATIC_KEY, { enabled: 0 });

    const res = await toolsList(STATIC_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("still reaches the dev table for a credential no durable row knows", async () => {
    // The fallback is not dead: the whole rest of this suite depends on it.
    const res = await toolsList(EXEC_KEY);
    expect(res.status).toBe(200);
    expect(res.body.error).toBeUndefined();
  });
});

describe("readiness now tracks the binding, not the dev flag", () => {
  it("a Worker with only the control database bound is READY", () => {
    expect(durableAuthBound({ DB: control(), CONTROL_DATA: controlNamespace() })).toBe(true);
    expect(portsBound({ DB: control(), CONTROL_DATA: controlNamespace() })).toBe(true);
    // ...and the port it reports on really is the durable one.
    expect(resolvePorts({ DB: control(), CONTROL_DATA: controlNamespace() }).auth).toBeInstanceOf(D1McpAuth);
  });

  it("a Worker with NO database and no dev flag is still not ready", () => {
    expect(durableAuthBound({})).toBe(false);
    expect(portsBound({})).toBe(false);
    expect(resolvePorts({}).auth).not.toBeInstanceOf(D1McpAuth);
  });
});

// ---------------------------------------------------------------------------
// The arms a live, healthy binding cannot express
// ---------------------------------------------------------------------------

/** A D1 stub whose table probe succeeds and whose row read always throws. */
function brokenDb(tables: readonly string[]): D1Database {
  return {
    prepare(sql: string) {
      const statement = {
        bind: () => statement,
        all: async () => {
          if (sql.includes("sqlite_master")) return { results: tables.map((name) => ({ name })) };
          throw new Error("D1_ERROR: network");
        },
        first: async () => {
          throw new Error("D1_ERROR: network");
        },
      };
      return statement;
    },
  } as unknown as D1Database;
}

describe("a D1 OUTAGE is 503, never 401", () => {
  it("does not let an unreachable database look like a revoked credential", async () => {
    const auth = new D1McpAuth(brokenDb([STATIC_API_KEY_TABLE]));
    const outcome = await auth.authenticate(
      new Headers({ authorization: `Bearer ${STATIC_KEY}` }),
      "tools.read",
    );
    expect(outcome).toMatchObject({ status: 503, code: "mcp_auth_unavailable" });
  });

  it("does not fall through to the dev table when the store is unreachable", async () => {
    // Falling through here is the dangerous behaviour: the dev/config table may
    // still list a key the database revoked.
    const auth = new D1McpAuth(brokenDb([STATIC_API_KEY_TABLE]), {
      fallback: {
        authenticate: async () => ({
          apiKeyId: "dev",
          scopes: ["*"],
          permissions: [],
          platformOperator: false,
        }),
      },
    });
    const outcome = await auth.authenticate(
      new Headers({ authorization: `Bearer ${STATIC_KEY}` }),
      "tools.read",
    );
    expect(outcome).toMatchObject({ status: 503 });
  });

  it("treats an ABSENT table as 'this leg is not provisioned', not as an outage", async () => {
    // The probe returns no tables, so no query is ever attempted and the
    // fallback is consulted — which is what keeps a deployment that has not
    // applied the control migration working exactly as it did before.
    const auth = new D1McpAuth(brokenDb([]), {
      fallback: {
        authenticate: async () => ({
          apiKeyId: "dev",
          scopes: ["tools.read"],
          permissions: [],
          platformOperator: false,
        }),
      },
    });
    const outcome = await auth.authenticate(
      new Headers({ authorization: `Bearer ${STATIC_KEY}` }),
      "tools.read",
    );
    expect(outcome).toMatchObject({ apiKeyId: "dev" });
  });
});

describe("expiry is evaluated against an injected clock", () => {
  it("an expiry exactly equal to now is EXPIRED (Rust parity)", async () => {
    await seedStaticKey(STATIC_KEY, { expiresAtUnix: 1_000 });
    const headers = new Headers({ authorization: `Bearer ${STATIC_KEY}` });

    const atExpiry = new D1McpAuth(control(), { now: () => 1_000 });
    expect(await atExpiry.authenticate(headers, "tools.read")).toMatchObject({
      status: 401,
      code: "invalid_api_key",
    });

    const beforeExpiry = new D1McpAuth(control(), { now: () => 999 });
    expect(await beforeExpiry.authenticate(headers, "tools.read")).toMatchObject({
      apiKeyId: "static-key-1",
    });
  });
});

describe("scope parsing keeps the static/virtual asymmetry", () => {
  it("NULL means the wildcard for a STATIC key and the EMPTY set for a VIRTUAL one", () => {
    // Different values that mean opposite things; normalizing them together
    // would silently promote a deliberately powerless tenant key.
    expect(parseStaticScopes(null)).toEqual(["*"]);
    expect(parseVirtualKeyScopes(null)).toEqual([]);
    // '[]' is the empty set for BOTH, and is not the wildcard.
    expect(parseStaticScopes("[]")).toEqual([]);
    // Unreadable JSON is the empty set, never the wildcard.
    expect(parseStaticScopes("{not json")).toEqual([]);
    expect(parseStaticScopes('"a string"')).toEqual([]);
  });
});

describe("the hash is the verification", () => {
  it("probes with a sha256-tagged digest, so a PLAINTEXT row can never match", async () => {
    const hash = await hashApiKeySecret(STATIC_KEY);
    expect(hash.startsWith("sha256:")).toBe(true);
    expect(hash).toHaveLength("sha256:".length + 64);
    expect(hash).not.toContain(STATIC_KEY);
    // Whitespace around the presented secret is normalized the same way the
    // minting side normalizes it.
    expect(await hashApiKeySecret(`  ${STATIC_KEY}  `)).toBe(hash);
  });
});
