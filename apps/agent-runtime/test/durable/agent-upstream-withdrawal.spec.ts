/**
 * **A compromised agent upstream must be withdrawable FROM EVERY WORKER THAT
 * CAN REACH IT.** (CUTOVER-READINESS CLASS A, item A3 — leg 2.)
 *
 * ## The half wave 20 left open
 *
 * Wave 20 closed the GATEWAY leg: `DELETE /admin/v1/agent-upstreams/{id}`
 * removes the `control_plane_resources` document and
 * `apps/gateway/src/routes/agent-upstreams.ts` reads that table, so the very
 * next `GET /.well-known/agent.json` no longer publishes the endpoint
 * (`apps/gateway/test/routes/agent-upstream-withdrawal.test.ts`).
 *
 * Discovery is not the only reach path. **This** Worker owns the A2A DISPATCH
 * path — `POST /v1/agents/{name}`, `…/message:send`, `…/message:stream` — and
 * it resolved its catalog from its own deploy-time `AGENT_UPSTREAMS` var
 * through `inMemoryAgentUpstreamPort`, with zero durable references. So an
 * operator who withdrew a compromised upstream saw it vanish from discovery
 * and it stayed reachable for dispatch: the withdrawal covered one of the two
 * doors. That is the wave-16 admission-bypass shape ("call the other
 * endpoint") in a second capability, and it is what this file holds shut.
 *
 * ## What is asserted, and why it is not a status code
 *
 * The claim under test is an EFFECT: *after the row is gone, this Worker does
 * not contact the upstream's endpoint.* Every positive assertion below is
 * therefore anchored on the upstream's HOSTNAME appearing in the refusal the
 * egress gate produces, not on the upstream's id and not on a 2xx:
 *
 *  - the handler resolves the upstream, then computes
 *    `new URL(upstream.url).hostname` and hands THAT host to
 *    `governance.authorize` (`src/agents/ingress.ts`, the #471 egress gate);
 *  - with a non-empty governed allowlist that does not contain it, the denial
 *    message is `egress hosts outside the governed allowlist: <host>`
 *    (`src/ports.ts::inMemoryGovernancePort`).
 *
 * So a `422` whose body NAMES the upstream host is direct evidence that the
 * dispatch resolved that exact endpoint and had reached the point of contacting
 * it. A `404 agent_not_found` is evidence it resolved nothing. The pair is the
 * before/after of a withdrawal, observed one layer above the socket, and it is
 * the strongest observation available offline: `@cloudflare/vitest-pool-workers`
 * 0.18.8 exports no `fetchMock`, so an outbound interceptor is not on the table
 * and a real `fetch` would make this suite depend on DNS.
 *
 * `beforeAll` therefore configures a governed host that is deliberately NOT any
 * upstream's host. Sealed (`CONTAINER_GOVERNED_EGRESS_HOSTS = ""`, the harness
 * default) would also refuse the forward, but with a generic "the tier is
 * sealed" message that names no host — and a test that cannot tell WHICH
 * endpoint was about to be contacted cannot prove a withdrawal.
 *
 * ## The cross-app join is by ROW CONTENT
 *
 * `apps/agent-runtime` and `apps/control-plane` are sibling workspaces and
 * neither depends on the other, so — exactly as the gateway's leg does —
 * {@link storeUpstream} and {@link adminDelete} issue the statements
 * `apps/control-plane/src/store/d1.ts` issues (`create()` :370, `remove()` :489
 * behind `tenantWriteScopeSql` :167), and the table/kind names below are the
 * CONTROL PLANE's spellings written out literally rather than imported from
 * this app's own module. Importing this app's constants would make the join
 * agree with itself by construction.
 *
 * Everything goes through `SELF.fetch` into the real `src/worker.ts` with
 * `CONTROL_DB` bound and migrated and the `FG_DEV_*` bundle absent
 * (`harness/wrangler.toml`).
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  BASE,
  KEY_LIVE,
  KEY_TENANT_B,
  TENANT_A,
  TENANT_B,
  TENANT_RESOURCE_TABLE,
  bearer,
  tenantResourceDb,
  setupDurablePorts,
} from "./setup.js";

// ---------------------------------------------------------------------------
// The control plane's own names, written out (see the header)
// ---------------------------------------------------------------------------

const RESOURCE_TABLE = "control_plane_resources";
const AGENT_UPSTREAM_COLLECTION = "agent-upstreams";

/** In the allowlist, and no upstream's host. Its only job is to be non-empty. */
const GOVERNED_HOST = "governed.egress.invalid";

const MESSAGE = { message: { role: "user", parts: [{ kind: "text", text: "hello" }] } };

/** Distinct per upstream so a body assertion cannot match the wrong row. */
function hostFor(id: string): string {
  return `${id}.upstream.invalid`;
}

function endpointFor(id: string): string {
  return `https://${hostFor(id)}/a2a`;
}

/**
 * The admin document `POST /admin/v1/agent-upstreams` stores.
 *
 * `endpoint` is the Rust field name (`AgentUpstreamConfig::endpoint`) and the
 * one `agentUpstreamSchema` declares; `name` and `id` are the other two
 * required members.
 */
function upstreamDocument(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name: `upstream ${id}`,
    protocol: "a2a",
    endpoint: endpointFor(id),
    capabilities: ["invoke", "read"],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// `apps/control-plane`'s statements, by row content
// ---------------------------------------------------------------------------

/** Monotonic `created_at_unix`, so list order is insertion order. */
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
  const now = (clock += 1);
  const target = tenantId === null ? env.CONTROL_DB : await tenantResourceDb(tenantId);
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

type AdminScope = { kind: "platform_operator" } | { kind: "tenant"; tenantId: string };

/**
 * `DELETE /admin/v1/agent-upstreams/{id}` — `D1ControlPlaneStore.remove`
 * (:489) behind `resource.ts::deleteHandler` (:397).
 *
 * The fence is `tenantWriteScopeSql` (:167): STRICT equality, no `IS NULL`
 * disjunct, so a tenant-scoped admin can remove neither another tenant's row
 * nor an un-attributed platform one. Zero rows changed is `remove() === false`,
 * which `deleteHandler` turns into `throw notFound(...)` — **404**, the status
 * Rust's `delete_agent_upstream` answers on `Ok(None)`.
 */
async function adminDelete(id: string, scope: AdminScope): Promise<number> {
  if (scope.kind === "tenant") {
    const result = await (await tenantResourceDb(scope.tenantId))
      .prepare(
        `DELETE FROM ${TENANT_RESOURCE_TABLE}
           WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind(AGENT_UPSTREAM_COLLECTION, id)
      .run();
    return (result.meta.changes ?? 0) > 0 ? 200 : 404;
  }
  const result = await env.CONTROL_DB.prepare(
    `DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`,
  )
    .bind(AGENT_UPSTREAM_COLLECTION, id)
    .run();
  return (result.meta.changes ?? 0) > 0 ? 200 : 404;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

interface Dispatch {
  readonly status: number;
  readonly code: string | undefined;
  readonly body: string;
}

/** One A2A dispatch through the real router. */
async function dispatch(id: string, key: string, verb = ""): Promise<Dispatch> {
  const response = await SELF.fetch(`${BASE}/v1/agents/${id}${verb}`, {
    method: "POST",
    headers: bearer(key),
    body: JSON.stringify(MESSAGE),
  });
  const body = await response.text();
  let code: string | undefined;
  try {
    code = (JSON.parse(body) as { error?: { code?: string } }).error?.code;
  } catch {
    code = undefined;
  }
  return { status: response.status, code, body };
}

/**
 * The dispatch REACHED the upstream's endpoint.
 *
 * Anchored on the host, not the id: the withdrawal is about which endpoint this
 * Worker contacts.
 */
function expectReached(result: Dispatch, id: string): void {
  expect(result.status, result.body).toBe(422);
  expect(result.code).toBe("egress_host_not_governed");
  expect(result.body).toContain(hostFor(id));
}

/** The dispatch resolved NOTHING — no endpoint of any kind was reached. */
function expectNotDispatched(result: Dispatch, id: string): void {
  expect(result.status, result.body).toBe(404);
  expect(result.code).toBe("agent_not_found");
  expect(result.body).not.toContain(hostFor(id));
}

// ---------------------------------------------------------------------------

type MutableEnv = { CONTAINER_GOVERNED_EGRESS_HOSTS?: string; AGENT_UPSTREAMS?: string };

const mutableEnv = env as unknown as MutableEnv;
let originalGovernedHosts: string | undefined;

beforeAll(async () => {
  await setupDurablePorts();
  originalGovernedHosts = mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS;
  mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS = GOVERNED_HOST;
});

afterAll(() => {
  mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS = originalGovernedHosts;
});

/**
 * THE COMMITTED HARNESS CONFIG IS INERT — asserted, not asserted-in-prose.
 *
 * `harness/wrangler.toml` still declares `AGENT_UPSTREAMS = "[]"` and its
 * comment claims the value cannot influence anything below. A comment is not a
 * gate: if the var half were still consulted, every positive assertion in this
 * file would keep passing (the var is empty) while every NEGATIVE one — the
 * withdrawals, the tenancy refusals — would be proving the wrong thing, because
 * "nothing in the var either" is not "the durable table is the whole registry".
 *
 * So the claim is exercised in the only direction that can fail: put a LIVE
 * upstream in the var whose document was never written to D1, and require the
 * dispatch to resolve NOTHING.
 */
describe("nothing committed to the harness wrangler.toml reaches this suite", () => {
  it("binds a real CONTROL_DB, which is what selects the durable branch", () => {
    // `agentUpstreamPortFromEnv` falls back to the var port unless a D1 binding
    // with a callable `prepare` is present. Asserting this first means a later
    // GREEN cannot come from the harness quietly losing its database.
    expect(typeof (env.CONTROL_DB as D1Database | undefined)?.prepare).toBe("function");
  });

  it("declares AGENT_UPSTREAMS empty, so no committed row can be reached", () => {
    expect(JSON.parse(mutableEnv.AGENT_UPSTREAMS ?? "[]")).toEqual([]);
  });

  it("does not consult the var AT ALL while CONTROL_DB is bound", async () => {
    // The id is never stored in D1. If the var leaked into the reach set this
    // dispatch would resolve the endpoint and be refused 422 BY THE EGRESS GATE
    // with the host in the body; unmounted-var, it resolves nothing and 404s.
    const id = "var-only-never-stored";
    const originalVar = mutableEnv.AGENT_UPSTREAMS;
    mutableEnv.AGENT_UPSTREAMS = JSON.stringify([
      { id, enabled: true, url: endpointFor(id), visibleToTenantIds: [], operatorOnly: false },
    ]);
    try {
      expectNotDispatched(await dispatch(id, KEY_LIVE), id);
    } finally {
      mutableEnv.AGENT_UPSTREAMS = originalVar;
    }
  });
});

describe("the durable agent-upstream registry backs A2A dispatch", () => {
  it("dispatches to an upstream the operator wrote through the admin table", async () => {
    // Nothing in this harness sets a non-empty `AGENT_UPSTREAMS`, so the ONLY
    // way this endpoint can be reached is that the document was read out of
    // `CONTROL_DB`.
    const id = "durable-dispatchable";
    await storeUpstream(upstreamDocument(id), TENANT_A);
    expectReached(await dispatch(id, KEY_LIVE), id);
  });

  it("honours `enabled: false` on the durable row — 404, not a forward", async () => {
    const id = "durable-disabled";
    await storeUpstream(upstreamDocument(id, { enabled: false }), TENANT_A);
    expectNotDispatched(await dispatch(id, KEY_LIVE), id);
  });

  it("backs every A2A verb, not just the bare invoke", async () => {
    const id = "durable-verbs";
    await storeUpstream(upstreamDocument(id), TENANT_A);
    for (const verb of ["", "/message:send", "/message:stream"]) {
      expectReached(await dispatch(id, KEY_LIVE, verb), id);
    }
  });
});

describe("withdrawal takes effect on the very next dispatch", () => {
  it("a deleted document is unreachable on the request immediately after", async () => {
    const id = "durable-withdrawn";
    await storeUpstream(upstreamDocument(id), TENANT_A);

    // BEFORE: the operator's upstream is live and this Worker is contacting it.
    expectReached(await dispatch(id, KEY_LIVE), id);

    // The withdrawal, through the control plane's own statement.
    expect(await adminDelete(id, { kind: "tenant", tenantId: TENANT_A })).toBe(200);

    // AFTER, with no redeploy, no restart and no cache flush in between.
    expectNotDispatched(await dispatch(id, KEY_LIVE), id);
  });

  it("stays withdrawn across repeated dispatches (no memoised catalog)", async () => {
    const id = "durable-withdrawn-twice";
    await storeUpstream(upstreamDocument(id), TENANT_A);
    expectReached(await dispatch(id, KEY_LIVE), id);
    expect(await adminDelete(id, { kind: "tenant", tenantId: TENANT_A })).toBe(200);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expectNotDispatched(await dispatch(id, KEY_LIVE), id);
    }
  });

  it("the deploy-time var does not resurrect a withdrawn upstream", async () => {
    // A UNION of the var and the durable table would defeat the withdrawal for
    // any id the operator happened to configure twice — the same defect, one
    // misconfiguration away. With `CONTROL_DB` bound the durable table is the
    // WHOLE table, which is the precedence `apps/gateway` states too.
    const id = "durable-and-var";
    const originalVar = mutableEnv.AGENT_UPSTREAMS;
    mutableEnv.AGENT_UPSTREAMS = JSON.stringify([
      {
        id,
        enabled: true,
        url: endpointFor(id),
        visibleToTenantIds: [],
        operatorOnly: false,
      },
    ]);
    try {
      await storeUpstream(upstreamDocument(id), TENANT_A);
      expectReached(await dispatch(id, KEY_LIVE), id);
      expect(await adminDelete(id, { kind: "tenant", tenantId: TENANT_A })).toBe(200);
      expectNotDispatched(await dispatch(id, KEY_LIVE), id);
    } finally {
      mutableEnv.AGENT_UPSTREAMS = originalVar;
    }
  });
});

describe("the registry is tenant-fenced on both reach paths", () => {
  it("tenant A cannot dispatch to tenant B's upstream", async () => {
    const id = "durable-b-only";
    await storeUpstream(upstreamDocument(id), TENANT_B);

    // The POSITIVE control. Without it a Worker that resolves no upstream at
    // all would pass the refusal below, which is precisely the vacuous shape
    // this repository keeps finding.
    expectReached(await dispatch(id, KEY_TENANT_B), id);

    expectNotDispatched(await dispatch(id, KEY_LIVE), id);
  });

  it("tenant A cannot withdraw tenant B's upstream", async () => {
    const id = "durable-b-only-delete";
    await storeUpstream(upstreamDocument(id), TENANT_B);
    expectReached(await dispatch(id, KEY_TENANT_B), id);

    // 404: `tenantWriteScopeSql` matched no row, so nothing was removed.
    expect(await adminDelete(id, { kind: "tenant", tenantId: TENANT_A })).toBe(404);

    // And the effect matches the status — B's dispatch is untouched.
    expectReached(await dispatch(id, KEY_TENANT_B), id);
  });

  it("an un-attributed platform row is reachable by every tenant", async () => {
    // The `IS NULL` disjunct is load-bearing rather than lax: Rust's
    // `[[agent_upstreams]]` is a GLOBAL operator table, so dropping
    // un-attributed rows for tenants would HIDE upstreams that are published
    // today. `apps/gateway/src/routes/agent-upstreams.ts` reads the same fence.
    const id = "durable-platform";
    await storeUpstream(upstreamDocument(id), null);
    expectReached(await dispatch(id, KEY_LIVE), id);
    expectReached(await dispatch(id, KEY_TENANT_B), id);
  });
});

describe("the durable lookup fails CLOSED", () => {
  it("refuses the dispatch when the registry cannot be read", async () => {
    // A lookup that ADMITTED on error would recreate the bypass in a new form:
    // a database outage would re-open every withdrawn upstream. The gateway
    // argues the same posture for the quota ladder
    // (`apps/gateway/src/ratelimit/quota.ts`: `503
    // quota_resolution_unavailable`, never "no policies").
    const id = "durable-failclosed";
    await storeUpstream(upstreamDocument(id), TENANT_A);
    expectReached(await dispatch(id, KEY_LIVE), id);

    const tenantDb = await tenantResourceDb(TENANT_A);
    await tenantDb
      .prepare(
        `ALTER TABLE ${TENANT_RESOURCE_TABLE} RENAME TO ${TENANT_RESOURCE_TABLE}_quarantined`,
      )
      .run();
    try {
      const refused = await dispatch(id, KEY_LIVE);
      expect(refused.status, refused.body).toBe(503);
      expect(refused.code).toBe("agent_upstream_unavailable");
      // NOT a 404: "the registry is unreadable" must stay distinguishable from
      // "the operator withdrew it", or an outage is silently reported as a
      // successful withdrawal.
      expect(refused.body).not.toContain(hostFor(id));
    } finally {
      await tenantDb
        .prepare(
          `ALTER TABLE ${TENANT_RESOURCE_TABLE}_quarantined RENAME TO ${TENANT_RESOURCE_TABLE}`,
        )
        .run();
    }

    // …and when the WHOLE control table is unreachable, the FIRST control that
    // cannot be evaluated refuses instead — the operator drain, with its own
    // code. Two outages, two honest answers, and neither of them admits.
    await env.CONTROL_DB.prepare(
      `ALTER TABLE ${RESOURCE_TABLE} RENAME TO ${RESOURCE_TABLE}_quarantined`,
    ).run();
    try {
      const refused = await dispatch(id, KEY_LIVE);
      expect(refused.status, refused.body).toBe(503);
      expect(refused.code).toBe("drain_state_unavailable");
      expect(refused.body).not.toContain(hostFor(id));
    } finally {
      await env.CONTROL_DB.prepare(
        `ALTER TABLE ${RESOURCE_TABLE}_quarantined RENAME TO ${RESOURCE_TABLE}`,
      ).run();
    }

    // The refusal was the outage, not a withdrawal: the row is still there.
    expectReached(await dispatch(id, KEY_LIVE), id);
  });
});
