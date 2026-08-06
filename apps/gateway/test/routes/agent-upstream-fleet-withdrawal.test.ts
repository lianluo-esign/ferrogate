/**
 * **ONE WITHDRAWAL, BOTH DOORS** — the fleet effect of
 * `DELETE /admin/v1/agent-upstreams/{id}`.
 * (CUTOVER-READINESS CLASS A, item A3 — the join between leg 1 and leg 2.)
 *
 * ## Why this file exists when two green suites already cover the same rows
 *
 * Wave 20 closed the DISCOVERY door and proved it in
 * `./agent-upstream-withdrawal.test.ts`. Wave 21 closed the DISPATCH door and
 * proved it in `apps/agent-runtime/test/durable/agent-upstream-withdrawal.spec.ts`.
 * Both suites are green, and **neither can fail for the defect the operator
 * actually cares about**, because each looks at one Worker:
 *
 * > A withdrawal that covers one reach path and not the other is the defect.
 *
 * That is precisely the state the fleet shipped in between the two waves — the
 * admin API answered `200 {"deleted": true}`, the endpoint vanished from
 * `GET /.well-known/agent.json`, and `POST /v1/agents/{id}` kept forwarding to
 * the compromised host. Two suites green, one operator wrong. It is shipped
 * defect #2 of `docs/rewrite/FLEET-CONSISTENCY.md` §1, and the lesson recorded
 * there is that **correctness per Worker does not imply correctness of the
 * fleet**.
 *
 * So the assertion below is deliberately written as ONE path: store a row,
 * observe BOTH reach paths hold it, issue ONE delete, observe BOTH reach paths
 * have lost it — inside a single `it()`, so a regression on either side fails
 * the same test rather than a different app's suite six minutes later.
 *
 * ## How both Workers are reached from one test
 *
 * The five Workers are separately bundled and no app may import another's
 * module graph — that is what `wrangler deploy` would reject. This file is a
 * TEST, not a bundle, and it reaches the two sides differently on purpose:
 *
 *  - **DISCOVERY** is behavioural and end to end: the real `SELF.fetch` into
 *    the deployed `src/worker.ts` of THIS Worker, exactly as the sibling suite
 *    drives it. `apps/gateway/wrangler.toml` pins
 *    `GATEWAY_AGENT_UPSTREAMS = "{}"`, so anything published came from
 *    `CONTROL_DB`.
 *  - **DISPATCH** is the OTHER Worker's REAL production lookup —
 *    `d1AgentUpstreamPort` out of `apps/agent-runtime/src/agents/registry.ts` —
 *    invoked against the SAME `CONTROL_DB` handle. Not a reproduction of its
 *    SQL, and not a paraphrase: the function the agent-runtime request path
 *    calls on every `POST /v1/agents/{name}`.
 *
 * That import is only sound because `registry.ts` imports **types only** from
 * its own `../ports.js` and nothing else at all — it is D1 and no runtime
 * dependency. If that ever stopped being true, this file would quietly pull one
 * Worker's module graph into another's test bundle, so
 * {@link "the cross-app import stays a leaf"} asserts it off the file's own
 * source text rather than trusting the docblock that claims it.
 *
 * The complement — that `d1AgentUpstreamPort` is the port agent-runtime's
 * composition root actually MOUNTS, rather than a module that merely exists —
 * is `MOUNT-SEAMS.md` row **AR-P9**, proven by mutation over `SELF` in that
 * Worker's durable harness. A registry module that exists and is not wired is
 * this repo's dominant defect; the two halves together are what close it.
 */
import { SELF, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  AGENT_UPSTREAM_COLLECTION as AR_COLLECTION,
  RESOURCE_TABLE as AR_TABLE,
  TENANT_RESOURCE_TABLE as AR_TENANT_TABLE,
  d1AgentUpstreamPort,
} from "../../../agent-runtime/src/agents/registry.js";
import registrySource from "../../../agent-runtime/src/agents/registry.ts?raw";
import {
  AGENT_UPSTREAM_COLLECTION,
  RESOURCE_TABLE,
  TENANT_RESOURCE_TABLE,
} from "../../src/routes/agent-upstreams.js";

const bindings = env as unknown as Record<string, unknown>;
const FLEET_TENANT_KEY = "fg_fleet_tenant_a";
let originalNativeApiKeys: unknown;

beforeAll(async () => {
  originalNativeApiKeys = bindings.GATEWAY_NATIVE_API_KEYS;
  bindings.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
    {
      key: FLEET_TENANT_KEY,
      id: "key_fleet_tenant_a",
      tenant_id: "tenant-a",
      scopes: ["agents.read"],
    },
  ]);
  // `tenant-a` is not one of `test/setup-d1.ts`'s fixture tenants, and the
  // durable_object routing default reads the `tenant_databases` roster on
  // every authenticated request — without this row the DISCOVERY door answers
  // `503 quota_resolution_unavailable` for the tenant-attributed credential and
  // the both-doors case fails before reaching the withdrawal. `migration_state`
  // must be stated as `done`: the column's DDL default is the pre-cutover
  // `shared`, which routes the deployed dispatch to the legacy shared arm
  // (`env.DB`) — a database holding NONE of the rows this test writes into the
  // tenant object. Same explicit form as `test/assets/wiring.test.ts`. (The
  // DISPATCH door goes through `tenantRouter().forTenant`, whose resolution
  // reads nothing.)
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO tenant_databases " +
        "(tenant_id, storage_backend, provisioning_status, schema_version, migration_state, migration_epoch) " +
        "VALUES (?, 'durable_object', 'ready', 1, 'done', 0)",
    )
    .bind("tenant-a")
    .run();
});

afterAll(() => {
  bindings.GATEWAY_NATIVE_API_KEYS = originalNativeApiKeys;
});

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "the fleet withdrawal test expects the `CONTROL_DB` binding " +
        "(apps/gateway/wrangler.toml). Without it this file would prove nothing.",
    );
  }
  return binding;
}

function tenantRouter(): DurableObjectTenantDatabaseRouter {
  const namespace = bindings.TENANT_DATA as
    | import("@ferrogate/storage/durable-objects").TenantDataNamespace
    | undefined;
  if (namespace === undefined) throw new Error("fleet test expects TENANT_DATA");
  return new DurableObjectTenantDatabaseRouter(namespace, controlDb());
}

// ---------------------------------------------------------------------------
// `apps/control-plane`'s own statements, by row content
// ---------------------------------------------------------------------------

let clock = 1_700_000_000;

/** `D1ControlPlaneStore.create` (`apps/control-plane/src/store/d1.ts:370`). */
async function storeUpstream(
  document: Record<string, unknown>,
  tenantId: string | null,
): Promise<void> {
  const stored: Record<string, unknown> = { ...document, tenant_id: tenantId };
  const now = (clock += 1);
  const target = tenantId === null ? controlDb() : (await tenantRouter().forTenant(tenantId)).db;
  const table = tenantId === null ? RESOURCE_TABLE : TENANT_RESOURCE_TABLE;
  await target
    .prepare(
      `INSERT INTO ${table}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, ?, ?)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json`,
    )
    .bind(AGENT_UPSTREAM_COLLECTION, stored["id"], JSON.stringify(stored), now, now)
    .run();
}

/**
 * `DELETE /admin/v1/agent-upstreams/{id}` — `D1ControlPlaneStore.remove` (:489)
 * behind `resource.ts::deleteHandler` (:397). Returns the status the operator
 * is told: `200` when a row was removed, `404` when none matched, which is what
 * Rust's `delete_agent_upstream` answers on `Ok(None)`.
 */
async function adminDelete(id: string, tenantId: string | null): Promise<number> {
  const target = tenantId === null ? controlDb() : (await tenantRouter().forTenant(tenantId)).db;
  const table = tenantId === null ? RESOURCE_TABLE : TENANT_RESOURCE_TABLE;
  const result = await target
    .prepare(`DELETE FROM ${table} WHERE resource_kind = ? AND resource_id = ?`)
    .bind(AGENT_UPSTREAM_COLLECTION, id)
    .run();
  return (result.meta.changes ?? 0) > 0 ? 200 : 404;
}

// ---------------------------------------------------------------------------
// The two reach paths
// ---------------------------------------------------------------------------

interface DiscoveryDocument {
  readonly data: readonly { readonly id: string; readonly endpoint: string }[];
}

/** DOOR 1 — `apps/gateway` DISCOVERY, through the deployed Worker. */
async function discoveredEndpoints(token = "fg_root"): Promise<readonly string[]> {
  const res = await SELF.fetch("https://gw.test/.well-known/agent.json", {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as DiscoveryDocument).data.map((entry) => entry.endpoint);
}

/**
 * DOOR 2 — `apps/agent-runtime` A2A DISPATCH, through that Worker's real
 * registry lookup against the same rows.
 *
 * Returns the endpoint the dispatch would forward to, or `undefined` when the
 * reach set resolves nothing. `ingress.ts` computes
 * `new URL(upstream.url).hostname` from exactly this value and hands it to the
 * egress gate, so "what this returns" IS "what agent-runtime would contact".
 * A disabled row is `found` but never forwarded (`ingress.ts` refuses
 * `!upstream.enabled` with `404 agent_not_found`), so it is folded in here.
 */
async function dispatchEndpoint(id: string, tenantId: string | null): Promise<string | undefined> {
  const lookup = await d1AgentUpstreamPort(controlDb(), tenantRouter()).lookup(id, { tenantId });
  if (lookup.outcome !== "found" || !lookup.upstream.enabled) return undefined;
  return lookup.upstream.url;
}

const COMPROMISED = {
  id: "compromised",
  name: "Compromised Agent",
  endpoint: "https://attacker.example/a2a",
  capabilities: ["invoke"],
};

beforeEach(async () => {
  await controlDb()
    .prepare(`DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ?`)
    .bind(AGENT_UPSTREAM_COLLECTION)
    .run();
  await Promise.all(
    ["tenant-a", "tenant-b"].map(async (tenantId) => {
      await (await tenantRouter().forTenant(tenantId)).db
        .prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind = ?`)
        .bind(AGENT_UPSTREAM_COLLECTION)
        .run();
    }),
  );
});

// ---------------------------------------------------------------------------

describe("the two Workers reach the SAME rows", () => {
  it("names the same collection and the same table on both sides", () => {
    // The cheapest way to reopen the defect is for one Worker to read a
    // different `resource_kind`: both doors would still be individually
    // correct, and the withdrawal would cover neither reliably. The constants
    // are compared as VALUES, imported from each Worker's own module.
    expect(AR_COLLECTION).toBe(AGENT_UPSTREAM_COLLECTION);
    expect(AR_TABLE).toBe(RESOURCE_TABLE);
    expect(AR_TENANT_TABLE).toBe(TENANT_RESOURCE_TABLE);
  });

  it("the cross-app import stays a leaf — registry.ts pulls in no module graph", () => {
    // This file may import the other Worker's lookup ONLY because that module
    // has no value imports. Asserted off its source text, not off its docblock,
    // because a docblock cannot go red.
    const imports = [...registrySource.matchAll(/^import\s+([\s\S]*?)\s+from\s+"([^"]+)";/gm)];
    expect(imports.map(([, , specifier]) => specifier)).toEqual([
      "@ferrogate/storage",
      "../ports.js",
    ]);
    const portsImport = imports.find(([, , specifier]) => specifier === "../ports.js");
    expect(portsImport, "registry.ts has no ports import").toBeDefined();
    if (portsImport === undefined) return;
    expect(portsImport[1]?.startsWith("type "), "registry.ts imports ports as VALUES").toBe(true);
  });
});

describe("ONE withdrawal, BOTH reach paths", () => {
  it("withdraws a compromised upstream from discovery AND from A2A dispatch together", async () => {
    await storeUpstream(COMPROMISED, null);

    // BEFORE — the positive control, on BOTH doors. Without it the refusals
    // after the delete would pass against a fleet that reaches nothing at all,
    // which is the vacuous shape this repository keeps finding.
    expect(await discoveredEndpoints(), "discovery did not publish the upstream").toContain(
      COMPROMISED.endpoint,
    );
    expect(await dispatchEndpoint(COMPROMISED.id, null), "dispatch did not resolve it").toBe(
      COMPROMISED.endpoint,
    );

    // THE OPERATOR'S ONE ACTION.
    expect(await adminDelete(COMPROMISED.id, null), "the admin delete removed no row").toBe(200);

    // AFTER — no redeploy, no restart, no cache flush, and BOTH doors shut. A
    // failure on EITHER line is the defect, and it is the same test either way.
    expect(await discoveredEndpoints(), "still PUBLISHED after withdrawal").not.toContain(
      COMPROMISED.endpoint,
    );
    expect(
      await dispatchEndpoint(COMPROMISED.id, null),
      "still DISPATCHABLE after withdrawal",
    ).toBe(undefined);
  });

  it("holds for a tenant-attributed upstream on both doors", async () => {
    // The un-attributed platform row above and a tenant-owned row take
    // different branches of `agentUpstreamScopeSql` on the dispatch side, so
    // one passing does not imply the other.
    await storeUpstream({ ...COMPROMISED, id: "tenant-compromised" }, "tenant-a");
    expect(await dispatchEndpoint("tenant-compromised", "tenant-a")).toBe(COMPROMISED.endpoint);
    expect(await discoveredEndpoints(FLEET_TENANT_KEY)).toContain(COMPROMISED.endpoint);

    expect(await adminDelete("tenant-compromised", "tenant-a")).toBe(200);

    expect(await discoveredEndpoints(FLEET_TENANT_KEY)).not.toContain(COMPROMISED.endpoint);
    expect(await dispatchEndpoint("tenant-compromised", "tenant-a")).toBe(undefined);
  });

  it("a delete that removed nothing is a 404 and changes neither door", async () => {
    // The inverse guard: an operator must never be told a withdrawal happened
    // when no row matched, and a no-op delete must not be able to look
    // effective by taking something else down with it.
    await storeUpstream(COMPROMISED, null);
    expect(await adminDelete("never-stored", null)).toBe(404);
    expect(await discoveredEndpoints()).toContain(COMPROMISED.endpoint);
    expect(await dispatchEndpoint(COMPROMISED.id, null)).toBe(COMPROMISED.endpoint);
  });
});
