/**
 * The DURABLE tenancy lifecycle gate (`src/store/lifecycle.ts`), driven through
 * the EXPORTED Worker against a REAL D1 binding.
 *
 * Every request goes through `SELF` — i.e. through the object `src/worker.ts`
 * re-exports — with `CONTROL_PLANE_STORE` unset, which is the production
 * default. That is deliberate and it is the whole point of this file: the gate
 * is a composition-root wire (`resolveLifecycle` inside `resolveDeps`), and a
 * fully implemented, fully unit-tested port that nothing MOUNTS is dead in
 * production while every suite stays green. This repo has shipped that twice.
 * So the assertions below are made through the real pipeline, and
 * `TENANCY_LIFECYCLE` is left EMPTY throughout the durable cases — a 403 here
 * can only have come from a row in `control_plane_resources`.
 *
 * Coverage mirrors the Rust gate's own claims:
 *  - the status the admin API writes decides the very next request (#514's
 *    "decorative status column");
 *  - the chain is WALKED, not declared: a credential naming only a project (or
 *    only a workspace) is still stopped by the suspended tenant above it, and
 *    the rejection names the ROOT cause;
 *  - `disabled` is admitted on the lifecycle-reversal routes and only there;
 *  - absence is not suspension;
 *  - a lookup that FAILS is 503, never an implicit allow.
 */
import { SELF, env as testEnv } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { JsonTenancyLifecycleGate, resolveLifecycle } from "../src/adapters.js";
import type { ApiOperation } from "../src/contract.js";
import type { AuthContext, ControlPlaneBindings, ControlPlaneStore } from "../src/ports.js";
import { StoreTenancyLifecycleGate } from "../src/store/lifecycle.js";
import { MemoryControlPlaneStore } from "../src/store/memory.js";
import { applySchema, db, resetD1, seedD1 } from "./d1.js";
import { registerObjectTenants } from "./tenant-object.js";
import { BASE, type NativeKey, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const OPERATOR = operatorKey.secret;
const TENANT_KEY = "tenant-a-secret";

/** A native key with an explicit, possibly partial, tenancy chain. */
function chainKey(secret: string, chain: Partial<NativeKey>): NativeKey {
  return { secret, id: `key_${secret}`, scopes: ["admin.read", "admin.write"], ...chain };
}

interface ErrorEnvelope {
  error: { message: string; code: string };
}

async function envelope(response: Response): Promise<ErrorEnvelope> {
  return (await response.json()) as ErrorEnvelope;
}

/** Any ordinary guarded read; `listWorkspaces` declares no `rbac_action`. */
function probe(secret: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/workspaces`, { headers: bearer(secret) });
}

beforeAll(async () => {
  await applySchema();
});

// ---------------------------------------------------------------------------
// The status the admin API writes is the status the gate reads
// ---------------------------------------------------------------------------

describe("the exported Worker gates on the DURABLE tenancy status", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      // EMPTY on purpose: nothing below may be explained by the declarative map.
      lifecycle: {},
    });
  });

  it("suspends a tenant through PATCH and refuses its next request (no redeploy)", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts`,
      jsonRequest(OPERATOR, "POST", { id: "tenant_a", tenant_id: "tenant_a", name: "A" }),
    );
    expect(created.status).toBe(201);
    // Active: the credential works.
    expect((await probe(TENANT_KEY)).status).toBe(200);

    const suspended = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_a`,
      jsonRequest(OPERATOR, "PATCH", { status: "suspended" }),
    );
    expect(suspended.status).toBe(200);

    // THE assertion: the very next request, same isolate, no binding change.
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    const body = await envelope(denied);
    expect(body.error.code).toBe("tenancy_suspended");
    // Rust `LifecycleRejection::message`, naming the row that denied.
    expect(body.error.message).toBe(
      "tenant tenant_a is suspended; requests authenticated against this tenancy chain are refused",
    );
  });

  it("answers 403 tenancy_deleted for a soft-deleted tenant row", async () => {
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", status: "deleted" }]);
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_deleted");
  });

  it("is a 403, not a 401 — the credential authenticated, the tenancy is forbidden", async () => {
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "suspended" },
    ]);
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    // The suspended-KEY invariant is the opposite one and must not be confused
    // with this: a suspended native key is 401 `invalid_api_key`.
    expect((await envelope(denied)).error.code).not.toBe("invalid_api_key");
  });

  it("reads an unrecognized status as active — absence and legacy rows keep working", async () => {
    // Rust `LifecycleStatus::parse`: rows predating #514 carry arbitrary values.
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", status: "suspend" }]);
    expect((await probe(TENANT_KEY)).status).toBe(200);
  });

  it("folds case and whitespace in the stored status", async () => {
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "  SUSPENDED " },
    ]);
    expect((await probe(TENANT_KEY)).status).toBe(403);
  });

  it("admits a tenant whose row names no status at all", async () => {
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", name: "A" }]);
    expect((await probe(TENANT_KEY)).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// The chain is WALKED, not declared  (Rust `resolve_lifecycle_chain`)
// ---------------------------------------------------------------------------

describe("the gate walks the tenant -> project -> workspace hierarchy", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [
        chainKey("project-only", { project_id: "project_1" }),
        chainKey("workspace-only", { workspace_id: "workspace_1" }),
        chainKey("tenant-only", { tenant_id: "tenant_a" }),
      ],
      lifecycle: {},
    });
  });

  it("stops a PROJECT-only credential on the suspended tenant ABOVE it", async () => {
    // THE headline bypass: the credential names no tenant, so a gate that
    // checked only what the caller declared would see `[project(active)]`.
    await seedD1("projects", [
      { id: "project_1", tenant_id: "tenant_a", status: "active", name: "p" },
    ]);
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "suspended" },
    ]);

    const denied = await probe("project-only");
    expect(denied.status).toBe(403);
    const body = await envelope(denied);
    expect(body.error.code).toBe("tenancy_suspended");
    // Shallowest-first: it names the TENANT, not the (active) project.
    expect(body.error.message).toContain("tenant tenant_a is suspended");
  });

  it("stops a WORKSPACE-only credential on the suspended tenant two levels up", async () => {
    await seedD1("workspaces", [
      { id: "workspace_1", tenant_id: "tenant_a", project_id: "project_1", status: "active" },
    ]);
    await seedD1("projects", [{ id: "project_1", tenant_id: "tenant_a", status: "active" }]);
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "suspended" },
    ]);

    const denied = await probe("workspace-only");
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.message).toContain("tenant tenant_a is suspended");
  });

  it("denies on a suspended PROJECT while its tenant is active", async () => {
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", status: "active" }]);
    await seedD1("projects", [
      { id: "project_1", tenant_id: "tenant_a", status: "suspended", name: "p" },
    ]);

    const denied = await probe("project-only");
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.message).toContain("project project_1 is suspended");
  });

  it("names the ROOT cause when the whole chain is suspended", async () => {
    await seedD1("workspaces", [
      { id: "workspace_1", tenant_id: "tenant_a", project_id: "project_1", status: "suspended" },
    ]);
    await seedD1("projects", [{ id: "project_1", tenant_id: "tenant_a", status: "suspended" }]);
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "suspended" },
    ]);

    const denied = await probe("workspace-only");
    expect((await envelope(denied)).error.message).toContain("tenant tenant_a is suspended");
  });

  it("admits a credential whose whole resolved chain is active", async () => {
    await seedD1("workspaces", [
      { id: "workspace_1", tenant_id: "tenant_a", project_id: "project_1", status: "active" },
    ]);
    await seedD1("projects", [{ id: "project_1", tenant_id: "tenant_a", status: "active" }]);
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", status: "active" }]);
    expect((await probe("workspace-only")).status).toBe(200);
  });

  it("skips ids that name no row — absence is not suspension", async () => {
    // Nothing seeded at all: the chain resolves empty and the request is served.
    expect((await probe("project-only")).status).toBe(200);
    expect((await probe("workspace-only")).status).toBe(200);
    expect((await probe("tenant-only")).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Reads run as PLATFORM OPERATOR (the gate may not be hidden from)
// ---------------------------------------------------------------------------

describe("the gate resolves rows the CALLER cannot see", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      lifecycle: {},
    });
  });

  it("a tenant-scoped STORE read cannot see a row attributed to another tenant", async () => {
    // The premise of the next test, established independently: with the row
    // attributed to `tenant_b`, `GET /admin/v1/tenant-accounts/tenant_a` as
    // tenant A is a 404 — the store's isolation predicate excludes it, so a gate
    // reading with the CALLER's scope would resolve an empty chain here.
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_b", status: "active" }]);
    const invisible = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/tenant_a`, {
      headers: bearer(TENANT_KEY),
    });
    expect(invisible.status).toBe(404);
  });

  it("denies on a suspended tenant row attributed to ANOTHER tenant", async () => {
    // Same invisible row, now suspended. A gate that read with the caller's own
    // scope would resolve an EMPTY chain and serve the suspended tenant.
    // Reading as a platform operator is what closes that, and this is the
    // assertion that holds it.
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_b", status: "suspended" },
    ]);
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_suspended");
  });

  it("still isolates ORDINARY reads across tenants (the store guard is untouched)", async () => {
    await seedD1("workspaces", [
      { id: "ws_a", tenant_id: "tenant_a", status: "active" },
      { id: "ws_b", tenant_id: "tenant_b", status: "active" },
    ]);
    const response = await probe(TENANT_KEY);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id)).toEqual(["ws_a"]);

    // …and by bare id: tenant B's workspace is a 404, not a 200 and not a 403.
    const foreign = await SELF.fetch(`${BASE}/admin/v1/workspaces/ws_b`, {
      headers: bearer(TENANT_KEY),
    });
    expect(foreign.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// The recovery carve-out (#514, finding 5)
// ---------------------------------------------------------------------------

describe("a DISABLED durable row still reaches the reversal routes", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      lifecycle: {},
    });
    await seedD1("tenant-accounts", [
      { id: "tenant_a", tenant_id: "tenant_a", status: "disabled", name: "A" },
    ]);
  });

  it("refuses an ordinary request with 403 tenancy_disabled", async () => {
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_disabled");
  });

  it("admits updateTenantAccount so the switch is not a one-way door", async () => {
    const reversed = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_a`,
      jsonRequest(TENANT_KEY, "PATCH", { status: "active" }),
    );
    expect(reversed.status).toBe(200);
    // And the reversal really took: the ordinary route is served again.
    expect((await probe(TENANT_KEY)).status).toBe(200);
  });

  it("does NOT extend the carve-out to a suspended row", async () => {
    await seedD1("tenant-accounts", [
      { id: "tenant_b", tenant_id: "tenant_b", status: "suspended" },
    ]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [chainKey("suspended-key", { tenant_id: "tenant_b" })],
      lifecycle: {},
    });
    const denied = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_b`,
      jsonRequest("suspended-key", "PATCH", { status: "active" }),
    );
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_suspended");
  });
});

// ---------------------------------------------------------------------------
// Fallback: the declarative map decides only when NO durable row resolves
// ---------------------------------------------------------------------------

describe("the declarative TENANCY_LIFECYCLE map is the fallback", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
  });

  it("decides when the tenant has no durable row", async () => {
    arm({
      store: "d1",
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      lifecycle: { tenant_a: "suspended" },
    });
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_suspended");
  });

  it("is NOT consulted once a durable row exists — the row decides alone", async () => {
    arm({
      store: "d1",
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      lifecycle: { tenant_a: "suspended" },
    });
    await seedD1("tenant-accounts", [{ id: "tenant_a", tenant_id: "tenant_a", status: "active" }]);
    // Provisioning the hierarchy into the database cannot be second-guessed by
    // a stale var, exactly as for `D1RbacAuthorizer` / `D1ApiKeyAuthenticator`.
    expect((await probe(TENANT_KEY)).status).toBe(200);
  });

  it("keeps the memory store on the declarative gate", async () => {
    arm({
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      lifecycle: { tenant_a: "deleted" },
    });
    const denied = await probe(TENANT_KEY);
    expect(denied.status).toBe(403);
    expect((await envelope(denied)).error.code).toBe("tenancy_deleted");
  });
});

// ---------------------------------------------------------------------------
// Fail-closed: a lookup that cannot answer is 503, never "active"
// ---------------------------------------------------------------------------

describe("an unreadable lifecycle row is 503, not an implicit allow", () => {
  beforeEach(async () => {
    await resetD1();
    // Roster rows for the fixture tenants: the gate's platform-operator reads
    // fan out over `tenant_databases`, which onboarding writes in production.
    await registerObjectTenants(["tenant_a", "tenant_b"]);
    arm({
      store: "d1",
      nativeKeys: [chainKey(TENANT_KEY, { tenant_id: "tenant_a" })],
      // A var that WOULD admit, so a fail-open regression cannot hide behind
      // the fallback answering "active" for its own reasons.
      lifecycle: { tenant_a: "active" },
    });
  });

  it("answers 503 lifecycle_status_unavailable when the row cannot be read", async () => {
    // Corrupt document: `D1ControlPlaneStore` refuses loudly rather than
    // returning `null`, because "unreadable" and "absent" are different facts.
    await db()
      .prepare(
        `INSERT INTO control_plane_resources
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES ('tenant-accounts', 'tenant_a', 'not json at all', 1, 1, 1)`,
      )
      .run();

    const response = await probe(TENANT_KEY);
    expect(response.status).toBe(503);
    const body = await envelope(response);
    expect(body.error.code).toBe("lifecycle_status_unavailable");
    expect(body.error.message).toContain("unparseable document_json");
  });
});

// ---------------------------------------------------------------------------
// Composition root: the durable gate is the one `resolveDeps` builds
// ---------------------------------------------------------------------------

describe("resolveLifecycle", () => {
  const store: ControlPlaneStore = new MemoryControlPlaneStore();

  it("builds the durable gate when the control database is in play", () => {
    const env = { CONTROL_DATA: (testEnv as unknown as { CONTROL_DATA: unknown }).CONTROL_DATA } as unknown as ControlPlaneBindings;
    expect(resolveLifecycle(env, store)).toBeInstanceOf(StoreTenancyLifecycleGate);
  });

  it("builds the declarative gate when the memory store is asked for by name", () => {
    const env = { CONTROL_DATA: (testEnv as unknown as { CONTROL_DATA: unknown }).CONTROL_DATA, CONTROL_PLANE_STORE: "memory" } as unknown as ControlPlaneBindings;
    expect(resolveLifecycle(env, store)).toBeInstanceOf(JsonTenancyLifecycleGate);
  });

  it("builds the declarative gate when no database is bound", () => {
    expect(resolveLifecycle({} as unknown as ControlPlaneBindings, store)).toBeInstanceOf(
      JsonTenancyLifecycleGate,
    );
  });
});

// ---------------------------------------------------------------------------
// The fail-closed claim, held directly (Rust: "a test can implement a *failing*
// source to hold the fail-closed claim -- a claim that, as landed, no test
// held; swapping the error mapping for `unwrap_or_default()` changed no
// assertion")
// ---------------------------------------------------------------------------

describe("StoreTenancyLifecycleGate against a failing store", () => {
  const failing: ControlPlaneStore = new Proxy({} as ControlPlaneStore, {
    get() {
      return () => Promise.reject(new Error("d1 is down"));
    },
  });
  const auth = {
    subject: "k",
    tenancy: { tenantId: "tenant_a" },
    scopes: ["admin.read"],
    platformOperator: false,
    source: "durable_native",
  } as AuthContext;
  const operation = { operationId: "listWorkspaces" } as ApiOperation;

  it("reports unavailable rather than deferring to the fallback", async () => {
    // The fallback would ADMIT (empty map ⇒ active). If the gate swallowed the
    // failure it would look identical to a healthy admit, which is the bypass.
    const gate = new StoreTenancyLifecycleGate(failing, new JsonTenancyLifecycleGate({}));
    const decision = await gate.admit(auth, operation);
    expect(decision.admitted).toBe("unavailable");
  });

  it("costs no reads at all for a credential that declares no tenancy chain", async () => {
    const gate = new StoreTenancyLifecycleGate(failing, new JsonTenancyLifecycleGate({}));
    const operatorAuth = { ...auth, tenancy: { tenantId: null } } as AuthContext;
    // A platform-operator key carries no chain, so the failing store is never
    // touched and the request is not turned into a 503 by an outage it does not
    // depend on.
    expect(await gate.admit(operatorAuth, operation)).toEqual({ admitted: true });
  });
});
