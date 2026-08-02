/**
 * The DURABLE NATIVE (virtual) key leg — two hops through the tenant router.
 *
 * `src/store/api_keys.ts` used to carry a `PORT-TODO` declaring this a platform
 * limit: a virtual key's `scopes_json` lives in the PER-TENANT database and "a
 * Worker cannot open a D1 database by uuid at runtime". The premise was true and
 * the conclusion was not — a Worker selects a database by BINDING NAME, and
 * `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter` is exactly the registry
 * that turns a tenant id into one. It just had no importers.
 *
 * So these tests are simultaneously the marker's close and a second mount gate
 * for the router: every one of them fails if `resolveApiKeys` stops routing.
 *
 * The invariant under the most pressure here is `ROUTE-MAP.md` #6 — **a
 * suspended native key is 401, NOT 403** — because this path now has four
 * distinct ways to refuse (directory disabled, directory revoked, tenant row
 * disabled, tenant row missing) and every one of them must be indistinguishable
 * from a typo'd secret. A 403 anywhere would confirm the presented string is a
 * real credential.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { hashApiKeySecret } from "../src/store/api_keys.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer } from "./harness.js";
import {
  TENANT_A,
  TENANT_B,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
  tenantDbB,
} from "./tenant-db.js";

const SECRET = "fg_live_virtualkeysecret";
const KEY_ID = "vk_1";

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
  // No declarative keys at all: everything below is resolved from rows, so a
  // passing assertion cannot be a var speaking for the database.
  arm({ store: "d1" });
});

interface KeyState {
  readonly tenantId?: string;
  readonly tenantDb?: D1Database;
  readonly scopes?: readonly string[];
  readonly directoryEnabled?: number;
  readonly directoryRevokedAt?: number | null;
  readonly tenantEnabled?: number;
  readonly tenantRevokedAt?: number | null;
  readonly monthlyTokenBudget?: number | null;
  readonly skipTenantRow?: boolean;
}

/** Provision a virtual key: the CONTROL directory row plus the TENANT row. */
async function provisionVirtualKey(state: KeyState = {}): Promise<void> {
  const hash = await hashApiKeySecret(SECRET);
  const tenantId = state.tenantId ?? TENANT_A;
  await db()
    .prepare(
      `INSERT INTO api_key_directory
         (key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
          enabled, expires_at_unix, revoked_at_unix)
       VALUES (?, ?, ?, 'proj_1', 'ws_1', 'fg_live_', 'cret', ?, NULL, ?)`,
    )
    .bind(hash, KEY_ID, tenantId, state.directoryEnabled ?? 1, state.directoryRevokedAt ?? null)
    .run();

  if (state.skipTenantRow === true) return;
  const handle = state.tenantDb ?? tenantDbA();
  await handle
    .prepare(
      `INSERT INTO api_keys
         (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4,
          enabled, scopes_json, monthly_token_budget, revoked_at_unix)
       VALUES (?, 'ws_1', ?, 'proj_1', 'virtual', 'fg_live_', ?, 'cret', ?, ?, ?, ?)`,
    )
    .bind(
      KEY_ID,
      tenantId,
      hash,
      state.tenantEnabled ?? 1,
      JSON.stringify(state.scopes ?? ["admin.read", "admin.write"]),
      state.monthlyTokenBudget ?? null,
      state.tenantRevokedAt ?? null,
    )
    .run();
}

const listProjects = (): Promise<Response> =>
  SELF.fetch(`${BASE}/admin/v1/projects`, { headers: bearer(SECRET) });

describe("durable virtual key resolved through the tenant router", () => {
  it("authenticates a key whose SCOPES live in the tenant database", async () => {
    // THE MOUNT GATE. `scopes_json` exists only in `TENANT_DB_A`; there is no
    // declarative var and the control database's directory row deliberately has
    // no scopes column. A 200 here is only possible if the router resolved the
    // tenant's database and read it.
    await provisionVirtualKey();
    const response = await listProjects();
    expect(response.status).toBe(200);
  });

  it("confines the key to its own tenant's rows", async () => {
    await provisionVirtualKey();
    // Seeded as tenant B, through the store's own stamping path.
    await db()
      .prepare(
        `INSERT INTO control_plane_resources
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES ('projects', 'proj_b', ?, 1, 1, 1)`,
      )
      .bind(JSON.stringify({ id: "proj_b", tenant_id: TENANT_B }))
      .run();

    const body = (await (await listProjects()).json()) as { data: { id: string }[] };
    expect(body.data.map((project) => project.id)).toEqual([]);
  });

  it("refuses a key with NO scopes — 403, not a silent admin grant", async () => {
    // `hasScope`: the empty set grants data-plane scopes and never an `admin.*`
    // one, and every operation on this Worker is `admin.*`. A virtual key must
    // never acquire the wildcard the way an operator-authored static key does.
    await provisionVirtualKey({ scopes: [] });
    const response = await listProjects();
    // Authenticated but not authorized — the 403 half of the taxonomy.
    expect(response.status).toBe(403);
  });

  it("refuses an UNPARSEABLE scopes_json rather than widening it", async () => {
    await provisionVirtualKey();
    await tenantDbA().prepare("UPDATE api_keys SET scopes_json = 'not json'").run();
    expect((await listProjects()).status).toBe(403);
  });

  it("reads the TENANT row, not the directory mirror, for lifecycle", async () => {
    // The directory says enabled; the authority says disabled. The authority
    // wins, or the physically-isolated row an operator actually edits would not
    // be the one that decides.
    await provisionVirtualKey({ directoryEnabled: 1, tenantEnabled: 0 });
    expect((await listProjects()).status).toBe(401);
  });
});

describe("suspension is 401, never 403 (ROUTE-MAP invariant 6)", () => {
  const unknownKeyBody = async (response: Response): Promise<string> => {
    const body = (await response.json()) as { error: { code: string } };
    return body.error.code;
  };

  it("answers 401 invalid_api_key for a directory-DISABLED key", async () => {
    await provisionVirtualKey({ directoryEnabled: 0 });
    const response = await listProjects();
    expect(response.status).toBe(401);
    expect(await unknownKeyBody(response)).toBe("invalid_api_key");
  });

  it("answers 401 invalid_api_key for a directory-REVOKED key", async () => {
    // Revoke writes the DIRECTORY first (the dual-write ordering in
    // `packages/storage/README.md` §1), so a revoke that crashed before its
    // second leg must already deny here.
    await provisionVirtualKey({ directoryRevokedAt: 1_700_000_000 });
    expect((await listProjects()).status).toBe(401);
  });

  it("answers 401 for a directory entry whose TENANT ROW is gone", async () => {
    await provisionVirtualKey({ skipTenantRow: true });
    const response = await listProjects();
    expect(response.status).toBe(401);
    expect(await unknownKeyBody(response)).toBe("invalid_api_key");
  });

  it("answers exactly the same 401 for a secret that was never provisioned", async () => {
    // The point of the invariant: every refusal above is INDISTINGUISHABLE from
    // this one. If any of them were a 403, a caller could probe which strings
    // are real credentials.
    const response = await SELF.fetch(`${BASE}/admin/v1/projects`, {
      headers: bearer("fg_live_neverexisted"),
    });
    expect(response.status).toBe(401);
    expect(await unknownKeyBody(response)).toBe("invalid_api_key");
  });

  it("answers 429 for an exhausted monthly token budget", async () => {
    // `monthly_token_budget == 0` is a property of the ACCOUNT, not of the
    // credential, so it is its own outcome rather than a suspension.
    await provisionVirtualKey({ monthlyTokenBudget: 0 });
    expect((await listProjects()).status).toBe(429);
  });
});

describe("tenant database resolution on the credential path", () => {
  it("answers 401 — never an invented scope — when the tenant has NO database", async () => {
    await provisionVirtualKey();
    await db().prepare("DELETE FROM tenant_databases").run();
    const response = await listProjects();
    expect(response.status).toBe(401);
  });

  it("answers 503 when the tenant IS registered but its binding is not deployed", async () => {
    await provisionVirtualKey();
    await db()
      .prepare(
        "UPDATE tenant_databases SET binding_name = 'TENANT_DB_NOT_DEPLOYED' WHERE tenant_id = ?",
      )
      .bind(TENANT_A)
      .run();
    const response = await listProjects();
    // A deployment fault an operator must see. It discloses nothing about the
    // key: the same 503 comes back for an unknown secret against the same
    // broken tenant... which is not observable, precisely because resolution
    // never reaches the tenant for an unknown secret.
    expect(response.status).toBe(503);
  });

  it("does not resolve a key against ANOTHER tenant's database", async () => {
    // The directory routes to tenant A; the `api_keys` row was written into
    // tenant B's database. A router that ignored its argument, or a shared
    // database, would authenticate this. The correct answer is that A's
    // database has no such row → 401.
    await provisionVirtualKey({ tenantId: TENANT_A, tenantDb: tenantDbB() });
    expect((await listProjects()).status).toBe(401);
  });
});
