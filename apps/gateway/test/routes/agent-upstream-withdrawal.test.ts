/**
 * **A compromised agent upstream must be withdrawable.** (CUTOVER-READINESS
 * CLASS A, item A3 — the HOLD subset.)
 *
 * Rust implements the withdrawal as one operation on one process:
 * `handle_admin_agent_upstream_delete` (`server/local.rs:9702`) →
 * `state.rs:796 delete_agent_upstream` → the control-plane document is removed,
 * the candidate config is rebuilt, `validate()`d and hot-reloaded, and the very
 * next `GET /.well-known/agent.json` no longer carries the upstream. Deleting an
 * id with no control-plane document returns `Ok(None)` → **404
 * `agent_upstream_not_found`**, never a `200` that revoked nothing.
 *
 * In the TS tree the two halves live in two Workers, and only the WRITE half
 * existed: `apps/control-plane`'s `admin_agent_upstream` group removes the
 * `control_plane_resources` document of kind `agent-upstreams` and answers
 * `200 {"deleted": true}` — while this Worker built the discovery document
 * exclusively from the DEPLOY-TIME var `GATEWAY_AGENT_UPSTREAMS`. So the
 * operator was told the withdrawal took effect and the data plane kept
 * publishing the upstream until someone edited `wrangler.toml` and redeployed.
 * That is the situation the operation exists for, inverted.
 *
 * ## What this file asserts, and what it deliberately does not
 *
 * It asserts the **EFFECT**, not a status code: after the row is gone, the next
 * request through the real `createGatewayApp` must not publish the upstream's
 * endpoint. A caller reaches an A2A upstream by the `endpoint` this document
 * hands it, so "no longer in the document" IS "no longer routed to" for this
 * surface — and the assertions are written against `endpoint`, not just `id`,
 * for that reason.
 *
 * The two apps are sibling workspaces and neither depends on the other, so —
 * exactly as `test/guardrails/control-plane-projection.test.ts` does for the
 * guardrail write half — the join is **by row content**: {@link storeUpstream}
 * and {@link adminDelete} issue the statements
 * `apps/control-plane/src/store/d1.ts` issues (`create()` :370-379,
 * `remove()` :489-511 with `tenantWriteScopeSql` :167), and `adminDelete`
 * reproduces `resource.ts::deleteHandler`'s `if (!removed) throw notFound` —
 * i.e. **404**, the same status Rust answers. `apps/control-plane`'s own suite
 * owns the other side of the join: `test/store-conformance.test.ts:296-302`
 * pins `remove()` → `false` across the tenant boundary for BOTH store
 * implementations, which is what makes the 404 here the deployed answer.
 */
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { controlNamespaceOverD1 } from "../support/control-namespace.js";

import { AGENT_UPSTREAM_COLLECTION, RESOURCE_TABLE } from "../../src/routes/agent-upstreams.js";
import { createGatewayApp } from "../../src/routes/index.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "agent-upstream withdrawal tests expect the `CONTROL_DB` binding " +
        "(apps/gateway/wrangler.toml). Without it this file would prove nothing.",
    );
  }
  return binding;
}

// ---------------------------------------------------------------------------
// The control plane's own statements, by row content
// ---------------------------------------------------------------------------

/** Monotonic `created_at_unix`, so the list order is the insertion order. */
let clock = 1_700_000_000;

/**
 * `D1ControlPlaneStore.create` (`apps/control-plane/src/store/d1.ts:370`).
 *
 * `tenant_id` is written the way `create()` writes it: the caller's tenant for
 * a tenant-scoped admin, an explicit `null` for a platform operator.
 */
async function storeUpstream(
  document: Record<string, unknown>,
  tenantId: string | null,
): Promise<void> {
  const stored: Record<string, unknown> = { ...document, tenant_id: tenantId };
  clock += 1;
  const now = clock;
  await controlDb()
    .prepare(
      `INSERT INTO ${RESOURCE_TABLE}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, ?, ?)
       ON CONFLICT (resource_kind, resource_id) DO NOTHING
       RETURNING revision`,
    )
    .bind(AGENT_UPSTREAM_COLLECTION, stored.id, JSON.stringify(stored), now, now)
    .first<{ revision: number }>();
}

type AdminScope = { kind: "platform_operator" } | { kind: "tenant"; tenantId: string };

/**
 * `DELETE /admin/v1/agent-upstreams/{id}` — `D1ControlPlaneStore.remove`
 * (:489-511) behind `resource.ts::deleteHandler` (:397-408).
 *
 * The tenancy fence is `tenantWriteScopeSql` (:167): STRICT equality, no
 * `IS NULL` disjunct, so a tenant-scoped admin cannot remove another tenant's
 * row nor an un-attributed platform row. Zero rows changed is `remove() ===
 * false`, which `deleteHandler` turns into `throw notFound(...)` — **404**.
 */
async function adminDelete(id: string, scope: AdminScope): Promise<number> {
  const fence =
    scope.kind === "platform_operator"
      ? { sql: "", params: [] as string[] }
      : {
          sql: " AND json_extract(document_json, '$.tenant_id') = ?",
          params: [scope.tenantId],
        };
  const result = await controlDb()
    .prepare(
      `DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?${fence.sql}`,
    )
    .bind(AGENT_UPSTREAM_COLLECTION, id, ...fence.params)
    .run();
  return (result.meta.changes ?? 0) > 0 ? 200 : 404;
}

// ---------------------------------------------------------------------------
// Driving the REAL gateway app
// ---------------------------------------------------------------------------

/**
 * Three credentials with `agents.read`, one per tenant plus a platform
 * operator. `subject` (the api-key id) is what the `tenant_ids` visibility
 * filter matches — see `agentUpstreamVisibleToAuth`.
 */
const NATIVE_API_KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["agents.read"] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["agents.read"] },
]);

const STATIC_API_KEYS = JSON.stringify([
  { key: "fg_operator", id: "key_operator", platform_operator: true },
]);

interface DiscoveryDocument {
  readonly object: string;
  readonly data: readonly {
    readonly id: string;
    readonly name: string;
    readonly endpoint: string;
    readonly capabilities: readonly string[];
  }[];
}

/** One `GET /.well-known/agent.json` through the real composition root. */
async function discover(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<DiscoveryDocument> {
  const { app } = createGatewayApp();
  const res = await app.request(
    "https://gw.test/.well-known/agent.json",
    { headers: { authorization: `Bearer ${token}` } },
    {
      GATEWAY_NATIVE_API_KEYS: NATIVE_API_KEYS,
      GATEWAY_STATIC_API_KEYS: STATIC_API_KEYS,
      CONTROL_DB: controlDb(),
      CONTROL_DATA: bindings.CONTROL_DATA,
      ...overrides,
    },
  );
  expect(res.status).toBe(200);
  return (await res.json()) as DiscoveryDocument;
}

const endpointsOf = (document: DiscoveryDocument): readonly string[] =>
  document.data.map((entry) => entry.endpoint);

const PLANNER = {
  id: "planner",
  name: "Planner Agent",
  endpoint: "https://planner.example/a2a",
  capabilities: ["invoke", "read"],
};

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
});

// ---------------------------------------------------------------------------

describe("the admin agent-upstream registry reaches the data plane", () => {
  it("publishes an upstream the control plane stored, with no redeploy", async () => {
    await storeUpstream(PLANNER, null);
    expect(endpointsOf(await discover("fg_operator"))).toStrictEqual([
      "https://planner.example/a2a",
    ]);
  });

  it("applies the admin WRITE path's capability default to a stored document", async () => {
    // Rust `agent_upstream_from_mutation` (`local.rs:10633`) materialises
    // `[invoke, read]` when the mutation names no capabilities, BEFORE the
    // document is ever read back — so a stored document that omits them is not
    // an upstream with no capabilities.
    await storeUpstream({ id: "bare", name: "Bare", endpoint: "https://bare.example/a2a" }, null);
    expect(await discover("fg_operator")).toStrictEqual({
      object: "list",
      data: [
        {
          object: "agent_upstream",
          id: "bare",
          name: "Bare",
          description: null,
          protocol: "a2a",
          endpoint: "https://bare.example/a2a",
          capabilities: ["invoke", "read"],
        },
      ],
    });
  });

  it("is the source the DEPLOYED Worker reads — not only a hand-built app", async () => {
    // `apps/gateway/wrangler.toml` pins `GATEWAY_AGENT_UPSTREAMS = "{}"`, so
    // anything this answers came from `CONTROL_DB`. This is the mount gate: it
    // fails if the composition root stops binding the durable source, which no
    // `createGatewayApp()` test above can see.
    await storeUpstream(PLANNER, null);
    const res = await SELF.fetch("https://gw.test/.well-known/agent.json", {
      headers: { authorization: "Bearer fg_root" },
    });
    expect(res.status).toBe(200);
    expect(endpointsOf((await res.json()) as DiscoveryDocument)).toStrictEqual([
      "https://planner.example/a2a",
    ]);
  });
});

describe("DELETE withdraws a compromised upstream on the very next request", () => {
  it("stops publishing the endpoint, and leaves every other upstream alone", async () => {
    await storeUpstream(PLANNER, null);
    await storeUpstream(COMPROMISED, null);

    // Before: the operator can reach the compromised agent through us.
    expect(endpointsOf(await discover("fg_operator"))).toStrictEqual([
      "https://planner.example/a2a",
      "https://attacker.example/a2a",
    ]);

    expect(await adminDelete("compromised", { kind: "platform_operator" })).toBe(200);

    // After, on the NEXT request — no redeploy, no reload, no cache to drain.
    const after = await discover("fg_operator");
    expect(endpointsOf(after)).toStrictEqual(["https://planner.example/a2a"]);
    expect(endpointsOf(after)).not.toContain("https://attacker.example/a2a");
    expect(after.data.map((entry) => entry.id)).not.toContain("compromised");
  });

  it("withdraws it from a tenant caller too, not only from the operator", async () => {
    await storeUpstream(COMPROMISED, null);
    expect(endpointsOf(await discover("fg_a"))).toContain("https://attacker.example/a2a");
    expect(await adminDelete("compromised", { kind: "platform_operator" })).toBe(200);
    expect(endpointsOf(await discover("fg_a"))).toStrictEqual([]);
  });

  it("answers 404 for an unknown id — never a 200 that revoked nothing", async () => {
    await storeUpstream(PLANNER, null);
    expect(await adminDelete("no-such-upstream", { kind: "platform_operator" })).toBe(404);
    // And the registry is untouched: a 404 must not have removed anything.
    expect(endpointsOf(await discover("fg_operator"))).toStrictEqual([
      "https://planner.example/a2a",
    ]);
  });
});

describe("the withdrawal is tenant-fenced in both directions", () => {
  it("does not let tenant A withdraw tenant B's upstream", async () => {
    await storeUpstream(COMPROMISED, "tenant_b");
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual(["https://attacker.example/a2a"]);

    // `tenantWriteScopeSql` is strict equality: zero rows, so `deleteHandler`
    // answers 404 — indistinguishable from "no such row", which is the point.
    expect(await adminDelete("compromised", { kind: "tenant", tenantId: "tenant_a" })).toBe(404);

    // The effect assertion: B's upstream is STILL served to B.
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual(["https://attacker.example/a2a"]);
    // And B can still withdraw its own.
    expect(await adminDelete("compromised", { kind: "tenant", tenantId: "tenant_b" })).toBe(200);
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual([]);
  });

  it("does not publish tenant B's upstream to tenant A", async () => {
    await storeUpstream(PLANNER, "tenant_b");
    expect(endpointsOf(await discover("fg_a"))).toStrictEqual([]);
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual(["https://planner.example/a2a"]);
  });

  it("publishes an un-attributed platform upstream to every tenant", async () => {
    // Rust's `[[agent_upstreams]]` is a GLOBAL operator table, so a document
    // with no `tenant_id` must stay visible to every caller — narrowing it to
    // the operator would HIDE upstreams that are published today.
    await storeUpstream(PLANNER, null);
    expect(endpointsOf(await discover("fg_a"))).toStrictEqual(["https://planner.example/a2a"]);
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual(["https://planner.example/a2a"]);
  });

  it("still applies the `tenant_ids` credential filter over the durable rows", async () => {
    // `agent_upstream_visible_to_auth` matches `tenant_ids` against the API KEY
    // id, not the tenant (a Rust quirk reproduced verbatim in
    // `agent-discovery.ts`). The durable source must not lose it.
    await storeUpstream({ ...PLANNER, tenant_ids: ["key_a"] }, null);
    expect(endpointsOf(await discover("fg_a"))).toStrictEqual(["https://planner.example/a2a"]);
    expect(endpointsOf(await discover("fg_b"))).toStrictEqual([]);
  });

  it("never publishes a disabled durable upstream", async () => {
    await storeUpstream({ ...COMPROMISED, enabled: false }, null);
    expect(endpointsOf(await discover("fg_operator"))).toStrictEqual([]);
  });
});

describe("failure direction: every failure REMOVES an upstream", () => {
  it("serves nothing rather than falling back to the var when the read fails", async () => {
    // A withdrawal must not be undone by an outage. The var is NOT consulted
    // when a database is bound: an id removed from the durable registry cannot
    // reappear because a query failed.
    // Rejects ASYNCHRONOUSLY, as a real unreachable/unmigrated object does: a
    // synchronous throw from `prepare()` makes workerd flag the correctly
    // fail-closed rejection as UNHANDLED on a microtask boundary and fails the
    // suite even though the read fails closed exactly as pinned below.
    const outage = () => Promise.reject(new Error("D1_ERROR: no such table: control_plane_resources"));
    const brokenStatement = { bind() { return this; }, all: outage, first: outage, run: outage };
    const broken = {
      prepare() {
        return brokenStatement;
      },
      batch: outage,
    } as unknown as D1Database;
    expect(
      endpointsOf(
        await discover("fg_operator", {
          CONTROL_DATA: controlNamespaceOverD1(broken),
          GATEWAY_AGENT_UPSTREAMS: JSON.stringify([COMPROMISED]),
        }),
      ),
    ).toStrictEqual([]);
  });

  it("drops a stored document that could never have been a valid upstream", async () => {
    await storeUpstream({ id: "no-endpoint", name: "x" }, null);
    await storeUpstream({ id: "no-name", endpoint: "https://x.example/a2a" }, null);
    await storeUpstream(PLANNER, null);
    expect(endpointsOf(await discover("fg_operator"))).toStrictEqual([
      "https://planner.example/a2a",
    ]);
  });

  it("keeps the var as the source for a deployment with no control database", async () => {
    // The no-database posture is unchanged: `GATEWAY_AGENT_UPSTREAMS` is still
    // the whole registry when nothing durable is bound.
    await storeUpstream(COMPROMISED, null);
    const { app } = createGatewayApp();
    const res = await app.request(
      "https://gw.test/.well-known/agent.json",
      { headers: { authorization: "Bearer fg_operator" } },
      {
        GATEWAY_NATIVE_API_KEYS: NATIVE_API_KEYS,
        GATEWAY_STATIC_API_KEYS: STATIC_API_KEYS,
        GATEWAY_AGENT_UPSTREAMS: JSON.stringify([PLANNER]),
      },
    );
    expect(res.status).toBe(200);
    expect(endpointsOf((await res.json()) as DiscoveryDocument)).toStrictEqual([
      "https://planner.example/a2a",
    ]);
  });
});
