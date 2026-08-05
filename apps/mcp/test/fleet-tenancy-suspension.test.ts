/**
 * **ONE SUSPENSION, THREE DOORS** — the fleet effect of suspending a tenant.
 * (`docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-2**.)
 *
 * ## The defect this file exists to fail on
 *
 * An operator suspends a compromised / delinquent / abusive tenant. In the Rust
 * tree that was one `check_usable_tenancy` inside one `authenticate()`, so the
 * refusal covered every spending surface at once. The rewrite split the data
 * plane across five Workers and carried the lifecycle gate onto ONE of them:
 *
 * | Worker | before this slice |
 * |---|---|
 * | `apps/gateway` | `403 tenancy_suspended` off `tenants.status` in the control database |
 * | `apps/mcp` | **no lifecycle check in any posture** — `tools/call` ADMITTED |
 * | `apps/agent-runtime` | could RENDER `tenancy_suspended` and its deployed `d1ApiKeyPort` could never PRODUCE it — only the `FG_DEV_API_KEYS` table could |
 *
 * The exploit is wave 16's, wearing a second control: **call the other
 * endpoint.** The tenant's KEY was never revoked — only its tenancy — so the
 * credential still resolves everywhere. `/v1/chat/completions` says 403; MCP
 * `tools/call` and the A2A dispatch surface admit it and spend against a quota
 * and a wallet nobody zeroed.
 *
 * Every per-Worker suite stayed green throughout, because **every Worker was
 * individually correct**. `apps/agent-runtime` even had a PASSING suspension
 * test — driven through the dev in-memory table, which is the one port that
 * could produce the outcome and the one port production never mounts. That is
 * the `lifecycle-tenancy-scenario-neverrun` failure mode, one Worker over.
 *
 * ## Why the assertion is shaped like this
 *
 * A test that proves THIS Worker refuses is the test that missed the defect
 * three times. So the whole property is written as ONE path: seed one
 * credential, watch all three doors OPEN, apply the operator's ONE control-plane
 * action, watch all three doors SHUT with the SAME status and the SAME code.
 * A regression on any one Worker fails this test, not a different app's suite
 * six minutes later.
 *
 * ## How three separately-bundled Workers are reached from one test file
 *
 * No app may import another's module graph — that coupling is what
 * `wrangler deploy` would reject. This file is a TEST, not a bundle, and the
 * sibling `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`
 * establishes the shape. Each door here is the OTHER Worker's REAL request
 * path, not a reproduction of it:
 *
 *  - **`apps/mcp`** — `SELF.fetch` into the deployed `src/worker.ts` of THIS
 *    Worker, over real HTTP, exactly as `test/d1-auth.test.ts` drives it.
 *  - **`apps/gateway`** — its DEFAULT-EXPORTED Hono app (`src/index.ts`),
 *    invoked with `app.fetch(request, env)` against the same two D1 handles.
 *    Every middleware the deployed Worker runs — correlation, the pre-auth
 *    network gate, `contractAuth` — runs here.
 *  - **`apps/agent-runtime`** — likewise its default-exported app.
 *
 * `app.fetch(req, env)` is how a Workers module entrypoint is invoked in
 * production; handing it an env built from THIS harness's bindings is what lets
 * one isolate hold all three. Nothing is stubbed, and no refusal is
 * reproduced — every status and code below came out of that Worker's own
 * middleware.
 *
 * ## ONE credential, three Workers — and why that is possible at all
 *
 * All three resolve the same `sha256:`-tagged `api_keys` row:
 *
 *  - the gateway reads `api_keys` in its `DB` (the TENANT database) directly;
 *  - `apps/agent-runtime`'s `d1ApiKeyPort` reads the same table in the same
 *    binding;
 *  - `apps/mcp` reaches it in two hops — `api_key_directory` in the CONTROL
 *    database (its `DB`) maps the hash to a tenant, then
 *    `EnvBindingTenantDatabaseRouter` opens that tenant's own database for the
 *    authoritative row.
 *
 * So the credential below is not three credentials that happen to agree. It is
 * ONE row, and the suspension below is ONE `UPDATE` of ONE row in the control
 * database — which is exactly the operator's action, and exactly what makes a
 * divergence here a divergence in production.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import agentRuntimeApp from "../../agent-runtime/src/index.js";
import gatewayApp from "../../gateway/src/index.js";
import { hashApiKeySecret } from "../src/auth.js";
import { rpcRequest, seedFixture } from "./fixtures.js";
import {
  registerDurableObjectTenant,
  resetTenantObjectState,
  seedTenantRoleProjection,
  tenantObjectDb,
  tenantObjectNamespace,
} from "./tenant-object.js";

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

interface FleetBindings {
  /** `apps/mcp`'s `DB` IS the CONTROL database (`wrangler.toml`). */
  readonly DB: D1Database;
  readonly TENANT_DATA: ReturnType<typeof tenantObjectNamespace>;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

function bindings(): FleetBindings {
  const b = env as unknown as Partial<FleetBindings>;
  if (b.DB === undefined || b.TENANT_DATA === undefined) {
    throw new Error(
      "the FC-2 fleet gate needs both the `DB` (control) and `TENANT_DATA` bindings; " +
        "without them it would prove nothing about any Worker.",
    );
  }
  return b as FleetBindings;
}

const control = (): D1Database => bindings().DB;
const tenantDb = (): D1Database => tenantObjectDb(TENANT);

/**
 * The env the other two Workers are invoked with.
 *
 * The binding NAMES are theirs, not this Worker's: both `apps/gateway` and
 * `apps/agent-runtime` bind the TENANT database as `DB` and the control
 * database as `CONTROL_DB` (`apps/gateway/wrangler.toml`;
 * `apps/agent-runtime/wrangler.toml`'s commented deploy stanzas). `apps/mcp`
 * binds the CONTROL database as `DB`, which is why the mapping is not the
 * identity.
 */
const siblingEnv = (): Record<string, unknown> => ({
  DB: tenantDb(),
  CONTROL_DB: control(),
  TENANT_DATA: bindings().TENANT_DATA,
});

// ---------------------------------------------------------------------------
// The one credential
// ---------------------------------------------------------------------------

const TENANT = "tenant-fc2";
const PROJECT = "proj-fc2";
const WORKSPACE = "ws-fc2";

/** `fg_` + 48 hex chars — the shape `virtual_api_key_material` mints. */
const KEY = `fg_${"a1b2c3d4".repeat(6)}`;
const KEY_PREFIX = KEY.slice(0, 16);
const KEY_LAST4 = KEY.slice(-4);

/**
 * Enough scope for one non-spending operation on each Worker. Deliberately NOT
 * the wildcard: a `["*"]` key would make a 403 ambiguous between "scope" and
 * "tenancy", and the whole point is which refusal is produced.
 */
const SCOPES = ["tools.read", "tools.execute", "agents.invoke"];

// ---------------------------------------------------------------------------
// Seeding — raw SQL, never through the code under test
// ---------------------------------------------------------------------------

async function seedCredential(): Promise<void> {
  const hash = await hashApiKeySecret(KEY);

  await control().batch([
    control().prepare("DELETE FROM tenants"),
    control().prepare("DELETE FROM tenant_databases"),
    control().prepare("DELETE FROM api_key_directory"),
    control().prepare("DELETE FROM static_api_keys"),
    control().prepare("DELETE FROM roles"),
    control().prepare("DELETE FROM permissions"),
  ]);
  await resetTenantObjectState([TENANT]);
  await tenantDb().batch([
    tenantDb().prepare("DELETE FROM api_keys"),
    tenantDb().prepare("DELETE FROM workspaces"),
    tenantDb().prepare("DELETE FROM projects"),
  ]);

  await control().batch([
    // THE AUTHORITY the operator mutates. `active` here; the test flips it.
    control()
      .prepare("INSERT INTO tenants (id, name, slug, status) VALUES (?, 'FC2', 'fc2', 'active')")
      .bind(TENANT),
    // `apps/mcp`'s NATIVE leg: hash -> tenant, then route to that tenant's db.
    control()
      .prepare(
        `INSERT INTO api_key_directory (key_hash, id, tenant_id, project_id, workspace_id,
           key_prefix, last4, enabled)
         VALUES (?, 'key-fc2', ?, ?, ?, ?, ?, 1)`,
      )
      .bind(hash, TENANT, PROJECT, WORKSPACE, KEY_PREFIX, KEY_LAST4),
    // `mcp.execute` — the S5/R1 entitlement ladder (`src/entitlements.ts`)
    // walks Permission → Role → TenantRoleBinding for it, so all THREE rows are
    // needed and the DECLARATION is one of them: this tenant's plan is `free`,
    // whose migration default is `mcp_enabled = 0`, so the bound role is what
    // opens the MCP door here. Rust's `tenant_tool_entitlement_denied` checks
    // `list_permissions()` before reading any binding, which is why a role
    // naming an undeclared key grants nothing — see
    // `test/entitlements.test.ts`. Dropping this row makes DOOR 2 answer
    // `mcp_tools_disabled` and the ADMITTED baseline below stops holding.
    control().prepare(
      "INSERT INTO permissions (id, key, name) VALUES ('perm-fc2', 'mcp.execute', 'MCP')",
    ),
    control()
      .prepare(
        `INSERT INTO roles (id, name, slug, description, permission_keys_json)
         VALUES ('role-fc2', 'MCP', 'mcp', '', ?)`,
      )
      .bind(JSON.stringify(["mcp.execute"])),
  ]);

  await registerDurableObjectTenant(TENANT);
  await seedTenantRoleProjection(TENANT, "role-fc2", ["mcp.execute"]);

  await tenantDb().batch([
    tenantDb()
      .prepare(
        `INSERT INTO projects (id, tenant_id, name, slug, status)
         VALUES (?, ?, 'p', 'p', 'active')`,
      )
      .bind(PROJECT, TENANT),
    tenantDb()
      .prepare(
        `INSERT INTO workspaces (id, project_id, tenant_id, name, slug, status)
         VALUES (?, ?, ?, 'w', 'w', 'active')`,
      )
      .bind(WORKSPACE, PROJECT, TENANT),
    // THE authoritative credential row — read by all three Workers.
    tenantDb()
      .prepare(
        `INSERT INTO api_keys (id, workspace_id, tenant_id, project_id, name, key_prefix,
           key_hash, last4, enabled, scopes_json)
         VALUES ('key-fc2', ?, ?, ?, 'fc2', ?, ?, ?, 1, ?)`,
      )
      .bind(WORKSPACE, TENANT, PROJECT, KEY_PREFIX, hash, KEY_LAST4, JSON.stringify(SCOPES)),
  ]);
}

/** THE OPERATOR'S ONE ACTION — `PUT /admin/v1/tenants/{id}` writes this column. */
async function setTenantStatus(status: string): Promise<void> {
  const result = await control()
    .prepare("UPDATE tenants SET status = ?1 WHERE id = ?2")
    .bind(status, TENANT)
    .run();
  // Without this the refusals below could pass against a tenant row that was
  // never there — the vacuous shape this repository keeps finding.
  expect(result.meta.changes, "the suspension updated no row").toBe(1);
}

async function setProjectStatus(status: string): Promise<void> {
  const result = await tenantDb()
    .prepare("UPDATE projects SET status = ?1 WHERE id = ?2")
    .bind(status, PROJECT)
    .run();
  expect(result.meta.changes, "the project update touched no row").toBe(1);
}

// ---------------------------------------------------------------------------
// The three doors
// ---------------------------------------------------------------------------

/** The wire answer, reduced to the two fields a client actually branches on. */
interface Wire {
  readonly status: number;
  readonly code: string | undefined;
}

async function wireOf(response: Response): Promise<Wire> {
  const body = (await response.json().catch(() => ({}))) as { error?: { code?: string } };
  return { status: response.status, code: body.error?.code };
}

/**
 * DOOR 1 — `apps/gateway`. `GET /v1/tools` is bearer `tools.read` and spends
 * nothing; a caller that gets past `contractAuth` reaches the not-yet-ported
 * handler and is told so, which is an unambiguous "ADMITTED" signal that costs
 * no provider call.
 */
async function gatewayDoor(): Promise<Wire> {
  return wireOf(
    await gatewayApp.fetch(
      new Request("https://gw.test/v1/tools", { headers: { authorization: `Bearer ${KEY}` } }),
      siblingEnv() as never,
    ),
  );
}

/**
 * DOOR 2 — `apps/mcp` `tools/call`, the surface that spends real provider money
 * through an upstream MCP server. Driven over `SELF` into the deployed Worker.
 */
async function mcpDoor(): Promise<Wire> {
  return wireOf(
    await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "srv-echo", arguments: {} },
        },
        { key: KEY },
      ),
    ),
  );
}

/**
 * DOOR 3 — `apps/agent-runtime` A2A dispatch (`POST /v1/agents/{name}`, bearer
 * `agents.invoke`). The catalog is empty in this harness, so an ADMITTED caller
 * lands on `404 agent_not_found` from the handler — past the credential and
 * lifecycle gates, and again with no outbound call.
 */
async function agentRuntimeDoor(): Promise<Wire> {
  return wireOf(
    await agentRuntimeApp.fetch(
      new Request("https://ar.test/v1/agents/no-such-agent", {
        method: "POST",
        headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ input: {} }),
      }),
      siblingEnv() as never,
    ),
  );
}

/** The three doors, always in the same order, always all three. */
const DOORS = [
  ["gateway", gatewayDoor],
  ["mcp", mcpDoor],
  ["agent-runtime", agentRuntimeDoor],
] as const;

async function fleet(): Promise<Record<string, Wire>> {
  const out: Record<string, Wire> = {};
  for (const [name, door] of DOORS) out[name] = await door();
  return out;
}

/**
 * What each Worker answers a caller it ADMITTED — its own handler's outcome,
 * pinned exactly.
 *
 * Pinned rather than asserted as "not a 403", because "not a 403" is satisfied
 * by a fleet that refuses everything for an unrelated reason, and then the
 * refusals after the suspension prove nothing at all.
 */
const ADMITTED: Record<string, Wire> = {
  // `GET /v1/tools` is a DROPPED capability on the gateway (owner decision
  // 2026-08-02, cluster S2 — `docs/rewrite/DROPPED-CAPABILITIES.md`), so its
  // admitted-caller answer is the explicit refusal, not the old unported-stub
  // `not_implemented`. The status is unchanged and so is what this file uses it
  // for: proof that the ONE `api_keys` row got all the way past the gateway's
  // tenancy gate to a handler.
  gateway: { status: 501, code: "capability_not_offered" },
  mcp: { status: 200, code: undefined },
  "agent-runtime": { status: 404, code: "agent_not_found" },
};

/** THE fleet contract: one refusal, identical on every Worker that spends. */
const REFUSED: Wire = { status: 403, code: "tenancy_suspended" };

/**
 * What each Worker answers when the lifecycle authority itself cannot be read.
 *
 * **503 on all three** — that is the fleet contract, and it is the field a
 * client branches on. The CODE differs on `apps/agent-runtime` because its
 * `ApiKeyResolution` carries exactly one outage arm (`unavailable`), which
 * `src/middleware/auth.ts` renders as `agent_runtime_unavailable` for every
 * credential-authority failure alike. Narrowing that to
 * `lifecycle_status_unavailable` is an edit to `middleware/auth.ts` — a file
 * this slice does not own — so the divergence is STATED here rather than
 * hidden behind a looser assertion. See the PORT-TODO on
 * `tenancyGatedApiKeyPort` in `apps/agent-runtime/src/ports.ts`.
 */
const UNAVAILABLE: Record<string, Wire> = {
  gateway: { status: 503, code: "lifecycle_status_unavailable" },
  mcp: { status: 503, code: "lifecycle_status_unavailable" },
  "agent-runtime": { status: 503, code: "agent_runtime_unavailable" },
};

// ---------------------------------------------------------------------------

beforeAll(async () => {
  const b = bindings();
  await applyD1Migrations(b.DB, b.TEST_CONTROL_D1_SCHEMA);
});

beforeEach(async () => {
  // The MCP upstream catalog + the recorded-call sink `tools/call` needs.
  seedFixture();
  await seedCredential();
});

describe("FC-2 — one tenant suspension, every Worker that spends", () => {
  it("opens all three doors for the credential before the suspension", async () => {
    // The positive control, and the reason the refusals below mean anything:
    // ONE api_keys row authenticates on all three Workers today.
    expect(await fleet()).toEqual(ADMITTED);
  });

  it("shuts all three doors with the SAME status and code after ONE suspension", async () => {
    expect(await fleet(), "the fleet did not admit before the suspension").toEqual(ADMITTED);

    // THE OPERATOR'S ONE ACTION, on the ONE authority: `tenants.status`.
    await setTenantStatus("suspended");

    // No redeploy, no restart, no cache flush. A failure on ANY line is the
    // defect, and it is the same test either way.
    expect(await fleet()).toEqual({
      gateway: REFUSED,
      mcp: REFUSED,
      "agent-runtime": REFUSED,
    });
  });

  it("computes an EMPTY exploit set — no Worker still admits a suspended tenant", async () => {
    await setTenantStatus("suspended");
    const answers = await fleet();
    const stillAdmitting = Object.entries(answers)
      .filter(([, wire]) => wire.status !== 403 || wire.code !== "tenancy_suspended")
      .map(([name]) => name);
    // FLEET-CONSISTENCY §4 records this set as `["mcp","agent-runtime"]`. The
    // slice is done when it is empty — stated as a computed VALUE so the
    // failure message names the Worker that regressed.
    expect(stillAdmitting).toEqual([]);
  });

  it("refuses on a suspended ANCESTOR too, not just the tenant row", async () => {
    // Rust `check_lifecycle_chain` walks tenant -> project -> workspace, so a
    // suspended PROJECT under an active tenant denies as well. A Worker that
    // only read `tenants.status` would pass the test above and fail this one.
    await setProjectStatus("suspended");
    expect(await fleet()).toEqual({
      gateway: REFUSED,
      mcp: REFUSED,
      "agent-runtime": REFUSED,
    });
  });

  it("re-opens every door when the operator lifts the suspension", async () => {
    await setTenantStatus("suspended");
    expect(await fleet()).toEqual({ gateway: REFUSED, mcp: REFUSED, "agent-runtime": REFUSED });

    // A control that cannot be lifted is a one-way door, and a gate that
    // refuses unconditionally would satisfy every assertion above.
    await setTenantStatus("active");
    expect(await fleet()).toEqual(ADMITTED);
  });
});

describe("the 401-vs-403 taxonomy survives the new gate", () => {
  it("a suspended KEY is still 401 on all three Workers — never 403", async () => {
    // The confusion this repo has actually shipped: revoking a CREDENTIAL must
    // stay indistinguishable from an unknown one (401), while suspending a
    // TENANCY is authenticated-but-forbidden (403). A lifecycle gate that
    // reported 403 for a dead key would leak key existence.
    await tenantDb().prepare("UPDATE api_keys SET enabled = 0 WHERE id = 'key-fc2'").run();
    await control().prepare("UPDATE api_key_directory SET enabled = 0 WHERE id = 'key-fc2'").run();

    const answers = await fleet();
    for (const [name, wire] of Object.entries(answers)) {
      expect(wire.status, `${name} did not answer 401 for a suspended KEY`).toBe(401);
      expect(wire.code, `${name} disclosed key state`).toBe("invalid_api_key");
    }
  });

  it("an under-scoped credential is still 403 scope_denied, not tenancy_suspended", async () => {
    // The other half: a 403 must still name the right cause. Scoped for
    // nothing this fleet serves.
    await tenantDb()
      .prepare("UPDATE api_keys SET scopes_json = ?1 WHERE id = 'key-fc2'")
      .bind(JSON.stringify(["skills.read"]))
      .run();
    const gateway = await gatewayDoor();
    expect(gateway.status).toBe(403);
    expect(gateway.code).not.toBe("tenancy_suspended");
  });
});

describe("FAIL CLOSED — a lifecycle authority that cannot be read admits nobody", () => {
  it("answers 503 rather than admitting when a lifecycle row cannot be read", async () => {
    // "Flap the control plane" must not be a suspension bypass (Rust
    // `LifecycleGateError::Unavailable`). Renaming a table the WALK reads is
    // the cheapest real read failure available to an offline harness: the
    // query raises exactly as it would against an unreachable database.
    //
    // `projects` rather than `tenants` on purpose. `tenants` also carries
    // `plan_id`, so hiding it takes the QUOTA chain down too and every Worker
    // then answers `503 quota_resolution_unavailable` — a fail-closed refusal
    // for the wrong reason, which would let this test pass against a fleet
    // with no lifecycle gate at all. `projects` is read by the lifecycle walk
    // and by nothing else on these three request paths, so the codes below can
    // only come from the gate under test.
    await tenantDb().prepare("ALTER TABLE projects RENAME TO projects_hidden").run();
    try {
      expect(await fleet()).toEqual(UNAVAILABLE);
    } finally {
      await tenantDb().prepare("ALTER TABLE projects_hidden RENAME TO projects").run();
    }
  });
});

describe("the refusal NAMES the tier and the state, exactly as apps/gateway does", () => {
  // Beyond "everyone refuses": a client must be told the same thing by every
  // Worker, or "your account is suspended, pay the bill" and "this project is
  // switched off" become the same opaque 403 depending on which endpoint was
  // called. `apps/mcp` carries the gateway's full vocabulary; `apps/agent-runtime`
  // does not, and that gap is asserted rather than smoothed over.
  it.each([
    ["disabled", "tenancy_disabled"],
    ["deleted", "tenancy_deleted"],
  ])("a %s tenancy is 403 %s on the gateway AND on mcp", async (status, code) => {
    await setTenantStatus(status);
    expect(await gatewayDoor()).toEqual({ status: 403, code });
    expect(await mcpDoor()).toEqual({ status: 403, code });

    // PORT-TODO(P: FLEET-CONSISTENCY §FC-2). `apps/agent-runtime` DENIES — the
    // decision agrees, which is what protects the money — but its
    // `ApiKeyResolution` has a single inactive-tenancy arm, so it reports
    // `tenancy_suspended` for all three states. Closing it is a widened union
    // plus one `switch` arm in that Worker's `src/middleware/auth.ts`, a file
    // the slice that landed this gate does not own. Asserted as the CURRENT
    // truth so the day it is fixed this line goes red and gets updated,
    // rather than the gap living only in a comment.
    expect(await agentRuntimeDoor()).toEqual(REFUSED);
  });

  it("an unrecognised status ADMITS everywhere — absence is not suspension", async () => {
    // The fail-OPEN READ default #514 chose: these columns were decorative
    // before it, so legacy rows carry arbitrary values and denial is opt-in.
    // The three Workers must agree on that too, or a typo revokes a tenant on
    // one endpoint and not another.
    await setTenantStatus("suspend");
    expect(await fleet()).toEqual(ADMITTED);
  });
});

describe("the gate is MOUNTED, not merely written", () => {
  it("resolvePorts binds the durable lifecycle gate in the posture this Worker deploys", async () => {
    // The behavioural tests above already fail if the mount is removed. This
    // one names the reason in one line, because "implemented, fully tested,
    // never mounted" is this repository's dominant defect and the mount is the
    // half that keeps going missing.
    const { D1McpTenancyLifecycleGate } = await import("../src/lifecycle.js");
    const { resolvePorts } = await import("../src/ports.js");
    expect(resolvePorts(env as never).lifecycle).toBeInstanceOf(D1McpTenancyLifecycleGate);
  });
});
