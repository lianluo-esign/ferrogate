/**
 * **S5 / finding R1 — the plan-and-RBAC tool-entitlement ladder.**
 * (`docs/rewrite/CUTOVER-READINESS.md` §2.1 A3, §3 cluster S5.)
 *
 * ## The defect this file exists to fail on
 *
 * `plans.mcp_enabled` is parsed into a `StoredPlan` by four Workers and, before
 * this slice, consumed by none. The gate itself was mounted on both MCP
 * transports and bound to `InMemoryEntitlements`, whose `deniedTenants` set has
 * exactly one writer in the whole repository — a test. So on every DEPLOYED
 * posture `toolExecutionDenial` answered `undefined` for every caller, and an
 * operator who moved a tenant onto a plan with `mcp_enabled = 0` changed
 * nothing: the tenant kept executing tools and kept spending upstream money.
 *
 * That is a REGRESSION, not a gap. Rust enforced it in
 * `crates/ferrogate-gateway/src/server/local.rs:137
 * tool_execution_entitlement_denial` (issues #168/#182/#183), reached from two
 * live request-path call sites (`local.rs:3617`, `mcp_rpc.rs:567`), over the
 * durable walk in `state_rbac.rs:11 tenant_tool_entitlement_denied`.
 *
 * ## What is asserted, and why in this shape
 *
 * Every case below drives the DEPLOYED Worker over `SELF` with a DURABLE
 * credential (`api_key_directory` → the tenant database's `api_keys`), against
 * rows written with raw SQL — never through the code under test. The operator's
 * action is a single column, `plans.mcp_enabled`, exactly as
 * `PUT /admin/v1/plans/{id}` writes it.
 *
 * Both transports are asserted on every case. The Rust doc comment on
 * `tool_execution_entitlement_denial` says in as many words that the failure
 * mode which produced #182 AND #183 AND the later JSON-RPC audit was *a gate
 * added at one HTTP entry point with nothing forcing every other entry point to
 * apply it too*. Asserting one door here would reproduce that bug's conditions.
 *
 * ## This is also the MOUNT gate for the seam
 *
 * Deleting `entitlements` from `resolvePorts` (`src/ports.ts`) puts the
 * always-allow `InMemoryEntitlements` back and turns the denial cases red,
 * because the durable ladder is then never consulted. See
 * `docs/rewrite/MOUNT-SEAMS.md` row `MCP-P15`, whose published recipe
 * (`const entitlements = durableEntitlements(env);` → `inMemoryPorts()
 * .entitlements`) was run and measured at **5 RED of 8**.
 */
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { hashApiKeySecret } from "../src/auth.js";
import { MCP_EXECUTE_PERMISSION, TOOL_ENTITLEMENTS } from "../src/entitlements.js";
import { type Fixture, rpcRequest, seedFixture } from "./fixtures.js";
import {
  registerDurableObjectTenant,
  resetTenantObjectState,
  seedTenantRoleProjection,
  tenantObjectDb,
} from "./tenant-object.js";

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

interface Bindings {
  /** `apps/mcp`'s `DB` IS the CONTROL database (`wrangler.toml`). */
  readonly DB: D1Database;
  readonly TENANT_DATA: unknown;
}

function bindings(): Bindings {
  const b = env as unknown as Partial<Bindings>;
  if (b.DB === undefined || b.TENANT_DATA === undefined) {
    throw new Error(
      "the S5 entitlement gate needs both the `DB` (control) and `TENANT_DATA` bindings; " +
        "without them the ladder has nothing durable to read and this file proves nothing.",
    );
  }
  return b as Bindings;
}

const control = (): D1Database => bindings().DB;
const tenantDb = (): D1Database => tenantObjectDb(TENANT);

// ---------------------------------------------------------------------------
// The one credential + the one plan
// ---------------------------------------------------------------------------

const TENANT = "tenant-s5";
const PROJECT = "proj-s5";
const WORKSPACE = "ws-s5";
const PLAN = "plan-s5";
const ROLE = "role-s5";

const KEY = `fg_${"5a5b5c5d".repeat(6)}`;
const KEY_PREFIX = KEY.slice(0, 16);
const KEY_LAST4 = KEY.slice(-4);

/** Enough API-key SCOPE to execute. The entitlement is a separate authority. */
const SCOPES = ["tools.read", "tools.execute", "assets.read"];

async function seedCredential(): Promise<void> {
  const hash = await hashApiKeySecret(KEY);
  await resetTenantObjectState([TENANT]);

  await control().batch([
    control().prepare("DELETE FROM tenants WHERE id = ?").bind(TENANT),
    control().prepare("DELETE FROM tenant_databases WHERE tenant_id = ?").bind(TENANT),
    control().prepare("DELETE FROM api_key_directory WHERE tenant_id = ?").bind(TENANT),
    control().prepare("DELETE FROM roles WHERE id = ?").bind(ROLE),
    control().prepare("DELETE FROM permissions WHERE key = ?").bind(MCP_EXECUTE_PERMISSION),
    control().prepare("DELETE FROM plans WHERE id = ?").bind(PLAN),
  ]);
  await tenantDb().batch([
    tenantDb().prepare("DELETE FROM api_keys WHERE tenant_id = ?").bind(TENANT),
    tenantDb().prepare("DELETE FROM workspaces WHERE tenant_id = ?").bind(TENANT),
    tenantDb().prepare("DELETE FROM projects WHERE tenant_id = ?").bind(TENANT),
  ]);

  await control().batch([
    control()
      .prepare(
        "INSERT INTO tenants (id, name, slug, status, plan_id) VALUES (?, 'S5', 's5', 'active', ?)",
      )
      .bind(TENANT, PLAN),
    control()
      .prepare(
        `INSERT INTO api_key_directory (key_hash, id, tenant_id, project_id, workspace_id,
           key_prefix, last4, enabled)
         VALUES (?, 'key-s5', ?, ?, ?, ?, ?, 1)`,
      )
      .bind(hash, TENANT, PROJECT, WORKSPACE, KEY_PREFIX, KEY_LAST4),
  ]);
  await registerDurableObjectTenant(TENANT);

  await tenantDb().batch([
    tenantDb()
      .prepare(
        "INSERT INTO projects (id, tenant_id, name, slug, status) VALUES (?, ?, 'p', 'p', 'active')",
      )
      .bind(PROJECT, TENANT),
    tenantDb()
      .prepare(
        `INSERT INTO workspaces (id, project_id, tenant_id, name, slug, status)
         VALUES (?, ?, ?, 'w', 'w', 'active')`,
      )
      .bind(WORKSPACE, PROJECT, TENANT),
    tenantDb()
      .prepare(
        `INSERT INTO api_keys (id, workspace_id, tenant_id, project_id, name, key_prefix,
           key_hash, last4, enabled, scopes_json)
         VALUES ('key-s5', ?, ?, ?, 's5', ?, ?, ?, 1, ?)`,
      )
      .bind(WORKSPACE, TENANT, PROJECT, KEY_PREFIX, hash, KEY_LAST4, JSON.stringify(SCOPES)),
  ]);
}

/** THE OPERATOR'S ONE ACTION — `POST/PUT /admin/v1/plans` writes this column. */
async function setPlanMcpEnabled(enabled: 0 | 1): Promise<void> {
  const result = await control()
    .prepare(
      `INSERT INTO plans (id, name, slug, mcp_enabled) VALUES (?1, 'S5', 's5-plan', ?2)
       ON CONFLICT (id) DO UPDATE SET mcp_enabled = ?2`,
    )
    .bind(PLAN, enabled)
    .run();
  // Without this the refusals below could pass against a plan row that was
  // never written — the vacuous shape this repository keeps finding.
  expect(result.meta.changes, "the plan write touched no row").toBe(1);
}

/** Bind a role holding `mcp.execute`. `declare` controls step 1 of the walk. */
async function bindRole(options: { declare: boolean }): Promise<void> {
  const statements = [
    control()
      .prepare(
        `INSERT INTO roles (id, name, slug, description, permission_keys_json)
         VALUES (?, 'MCP', 'mcp-s5', '', ?)`,
      )
      .bind(ROLE, JSON.stringify([MCP_EXECUTE_PERMISSION])),
  ];
  if (options.declare) {
    statements.unshift(
      control()
        .prepare("INSERT INTO permissions (id, key, name) VALUES ('perm-s5', ?, 'MCP execute')")
        .bind(MCP_EXECUTE_PERMISSION),
    );
  }
  await control().batch(statements);
  await seedTenantRoleProjection(TENANT, ROLE, [MCP_EXECUTE_PERMISSION]);
}

// ---------------------------------------------------------------------------
// The two doors — both transports of the SAME governed chokepoint
// ---------------------------------------------------------------------------

/** The wire answer, reduced to what a client branches on. */
interface Wire {
  readonly status: number;
  readonly code: string | number | undefined;
  readonly message: string | undefined;
}

/** DOOR 1 — `POST /v1/mcp` JSON-RPC `tools/call` (`mcp_rpc.rs:567`). */
async function jsonRpcDoor(name = "srv-echo"): Promise<Wire> {
  const res = await SELF.fetch(
    rpcRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } },
      { key: KEY },
    ),
  );
  const body = (await res.json().catch(() => ({}))) as {
    error?: { code?: number; message?: string };
  };
  return { status: res.status, code: body.error?.code, message: body.error?.message };
}

/** DOOR 2 — `POST /v1/mcp/tool/execute`, the REST transport (`local.rs:3617`). */
async function restDoor(name = "srv-echo"): Promise<Wire> {
  const res = await SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/tool/execute", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${KEY}` },
      body: JSON.stringify({ name, arguments: {} }),
    }),
  );
  const body = (await res.json().catch(() => ({}))) as {
    error?: { code?: string; message?: string };
  };
  return { status: res.status, code: body.error?.code, message: body.error?.message };
}

/**
 * The refusal, pinned EXACTLY as Rust spells it — code, status and message all
 * three, because a client that switches on `mcp_tools_disabled` is the reason
 * the taxonomy is not free to drift.
 */
const DENIED_MESSAGE =
  "the tenant's plan does not enable MCP tool execution and no bound role " +
  "grants the mcp.execute permission";
const DENIED_JSON_RPC: Wire = { status: 200, code: -32000, message: DENIED_MESSAGE };
const DENIED_REST: Wire = { status: 403, code: "mcp_tools_disabled", message: DENIED_MESSAGE };

/** What an ADMITTED caller gets: the tool actually ran. */
const ADMITTED_JSON_RPC: Wire = { status: 200, code: undefined, message: undefined };
const ADMITTED_REST: Wire = { status: 200, code: undefined, message: undefined };

let fixture: Fixture;

beforeEach(async () => {
  fixture = seedFixture({ tenantId: TENANT });
  await seedCredential();
});

describe("S5 / R1 — the plan tool-entitlement gate", () => {
  it("DENIES both transports when the tenant's plan disables MCP tool execution", async () => {
    await setPlanMcpEnabled(0);

    expect(await jsonRpcDoor()).toEqual(DENIED_JSON_RPC);
    expect(await restDoor()).toEqual(DENIED_REST);
    // The refusal is BEFORE the chokepoint: no upstream call was made, which is
    // the whole point of a plan gate that also governs spend.
    expect(fixture.calls, "a denied tenant still reached the upstream").toHaveLength(0);
  });

  it("ADMITS both transports when the SAME plan enables it — one column, no redeploy", async () => {
    await setPlanMcpEnabled(0);
    expect(await jsonRpcDoor()).toEqual(DENIED_JSON_RPC);

    await setPlanMcpEnabled(1);

    expect(await jsonRpcDoor()).toEqual(ADMITTED_JSON_RPC);
    expect(await restDoor()).toEqual(ADMITTED_REST);
    expect(fixture.calls, "the admitted tenant never reached the upstream").toHaveLength(2);
  });

  it("lets a bound ROLE lift a plan denial (issue #182's per-tenant override)", async () => {
    await setPlanMcpEnabled(0);
    expect(await jsonRpcDoor()).toEqual(DENIED_JSON_RPC);

    await bindRole({ declare: true });

    expect(await jsonRpcDoor()).toEqual(ADMITTED_JSON_RPC);
    expect(await restDoor()).toEqual(ADMITTED_REST);
  });

  it("grants nothing for a role naming an UNDECLARED permission", async () => {
    // Step 1 of Rust's `tenant_tool_entitlement_denied` walk: `list_permissions`
    // must contain the key before any role can hold it. A role naming a
    // permission the platform never declared is a typo, not a grant.
    await setPlanMcpEnabled(0);
    await bindRole({ declare: false });

    expect(await jsonRpcDoor()).toEqual(DENIED_JSON_RPC);
    expect(await restDoor()).toEqual(DENIED_REST);
  });

  it("DENIES a registered tenant whose plan_id names no plan row", async () => {
    // Rust reads the tenant account and the plan SEPARATELY, so a dangling
    // `plan_id` is `tenant_account_exists = true` with `plan_grants = false` —
    // DENIED unless a role lifts it. This is the case an INNER join silently
    // converts into "not registered", which ADMITS. Nothing else in this file
    // can tell the two joins apart.
    await control()
      .prepare("UPDATE tenants SET plan_id = 'plan-that-was-deleted' WHERE id = ?")
      .bind(TENANT)
      .run();

    expect(await jsonRpcDoor()).toEqual(DENIED_JSON_RPC);
    expect(await restDoor()).toEqual(DENIED_REST);
  });

  it("does NOT deny a tenant with no registered tenant account", async () => {
    // Rust denies only when a `StoredTenantAccount` exists: pre-#515 keys and
    // `ferrogate.toml`-declared keys carry an `organization_id` that was never
    // registered, and these flags were unchecked before #182, so treating
    // "no tenant record" as an implicit denial is a silent breaking change.
    await setPlanMcpEnabled(0);
    await control().prepare("DELETE FROM tenants WHERE id = ?").bind(TENANT).run();

    expect(await jsonRpcDoor()).toEqual(ADMITTED_JSON_RPC);
    expect(await restDoor()).toEqual(ADMITTED_REST);
  });

  it("pins the per-backend taxonomy transcribed from `local.rs:143-168`", () => {
    // The literals below are the Rust ones, typed out from the deleted-tomorrow
    // source rather than read back off the port — the whole value of a
    // transcription is that it does not agree with the implementation by
    // construction. The `extension` arm is NOT wired (`executeTool` answers 501
    // — cluster S2); it is carried so S2 does not have to re-derive the
    // taxonomy from a file that no longer exists.
    expect(TOOL_ENTITLEMENTS).toEqual({
      mcp: {
        planColumn: "mcp_enabled",
        permissionKey: "mcp.execute",
        errorCode: "mcp_tools_disabled",
        errorMessage:
          "the tenant's plan does not enable MCP tool execution and no bound role " +
          "grants the mcp.execute permission",
      },
      extension: {
        planColumn: "extension_tools_enabled",
        permissionKey: "extensions.execute",
        errorCode: "extension_tools_disabled",
        errorMessage:
          "the tenant's plan does not enable extension tool execution and no bound role " +
          "grants the extensions.execute permission",
      },
    });
  });

  it("does NOT gate the BUILTIN backend, which carries no plan flag", async () => {
    // `ToolExecuteBackend::Builtin => return None`. `builtin.fetch_asset`
    // reuses the asset-read authz enforced inside the tool itself, so a
    // plan-denied tenant must fail on the ASSET, never on `mcp_tools_disabled`.
    await setPlanMcpEnabled(0);

    const rpc = await jsonRpcDoor("builtin.fetch_asset");
    expect(rpc.message).not.toBe(DENIED_MESSAGE);
    const rest = await restDoor("builtin.fetch_asset");
    expect(rest.code).not.toBe("mcp_tools_disabled");
  });
});
