/**
 * Representative CRUD round-trips through `SELF` against the in-memory store.
 *
 * These cover the shapes the generic machinery in `routes/resource.ts` derives
 * for ~170 of the 214 operations, plus the bespoke ones most likely to be got
 * wrong: the composite-key resource (quota policies), the natural-key resource
 * (MCP servers), the revision lifecycle (guardrail policies), the ledger-backed
 * mutation (wallets), and — the one that actually keeps tenants apart — the
 * cross-tenant isolation the store enforces for every collection.
 *
 * Status parity with Rust is asserted explicitly, because it is the kind of
 * detail a port silently changes: POST → **201**, PUT/PATCH → **200**,
 * DELETE → **200** with `{object, id, deleted: true}`.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const KEY = operatorKey.secret;

beforeEach(() => {
  arm({ staticKeys: [operatorKey] });
});

describe("derived CRUD: /admin/v1/agent-schedules", () => {
  it("round-trips create → read → patch → replace → delete", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(KEY, "POST", { id: "sched_1", name: "nightly", schedule: "0 3 * * *" }),
    );
    // Rust: POST without a path id is 201 Created.
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({
      object: "agent_schedule",
      agent_schedule: { id: "sched_1", name: "nightly", schedule: "0 3 * * *" },
    });

    const read = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/sched_1`, {
      headers: bearer(KEY),
    });
    expect(read.status).toBe(200);

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/sched_1`,
      jsonRequest(KEY, "PATCH", { enabled: false }),
    );
    // Rust: an upsert WITH a path id is 200 OK, not 201.
    expect(patched.status).toBe(200);
    expect(await patched.json()).toMatchObject({
      agent_schedule: { id: "sched_1", name: "nightly", enabled: false },
    });

    const replaced = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/sched_1`,
      jsonRequest(KEY, "PUT", { schedule: "@hourly" }),
    );
    expect(replaced.status).toBe(200);
    // PUT is a full replace: the patched `name` is gone.
    const replacedBody = (await replaced.json()) as { agent_schedule: Record<string, unknown> };
    expect(replacedBody.agent_schedule.schedule).toBe("@hourly");
    expect(replacedBody.agent_schedule.name).toBeUndefined();

    const deleted = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/sched_1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({
      object: "agent_schedule",
      id: "sched_1",
      deleted: true,
    });

    const gone = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/sched_1`, {
      headers: bearer(KEY),
    });
    expect(gone.status).toBe(404);
  });

  it("refuses a duplicate id with 409", async () => {
    // Every body in this group now carries a firing spec, because
    // `routes/admin_agent_schedule.ts` validates one (a schedule that cannot
    // compute a next fire is a schedule that never fires, so it is refused at
    // write time). The ASSERTIONS below are unchanged — only the fixtures grew
    // the field the collection has always been about.
    const body = { id: "dup", cron_expr: "0 3 * * *" };
    await SELF.fetch(`${BASE}/admin/v1/agent-schedules`, jsonRequest(KEY, "POST", body));
    const again = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(KEY, "POST", body),
    );
    expect(again.status).toBe(409);
  });

  it("serves the bespoke sub-list and action routes", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(KEY, "POST", { id: "s2", cron_expr: "0 3 * * *" }),
    );

    const fires = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s2/fires`, {
      headers: bearer(KEY),
    });
    expect(fires.status).toBe(200);
    expect(await fires.json()).toEqual({ object: "list", data: [] });

    /**
     * This block used to assert `{ agent_schedule: { run_now: true } }` — it
     * pinned the DEFECT `docs/rewrite/parity-audit-storage.md` §4.2 found:
     * `run-now` merged a flag onto the document and dispatched nothing, and the
     * assertion made that look like working software. It is replaced, not
     * dropped, by the parity shape from Rust
     * `handle_admin_agent_schedule_run_now`: **202** with
     * `{ object: "agent_schedule_fire", fire }` — plus the thing the old
     * assertion could not see, that a fire row now exists.
     */
    const runNow = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s2/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(runNow.status).toBe(202);
    expect(await runNow.json()).toMatchObject({
      object: "agent_schedule_fire",
      fire: { schedule_id: "s2", outcome: "dispatched" },
    });

    const afterFire = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s2/fires`, {
      headers: bearer(KEY),
    });
    const history = (await afterFire.json()) as { data: { schedule_id: string }[] };
    expect(history.data).toHaveLength(1);
    expect(history.data[0]?.schedule_id).toBe("s2");
  });

  it("404s a sub-route whose parent does not exist", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/ghost/fires`, {
      headers: bearer(KEY),
    });
    expect(response.status).toBe(404);
  });
});

describe("the AdminList envelope (Rust admin_list_query::list_response)", () => {
  beforeEach(async () => {
    arm({ staticKeys: [operatorKey] });
    for (const id of ["a", "b", "c"]) {
      await SELF.fetch(`${BASE}/admin/v1/plans`, jsonRequest(KEY, "POST", { id, name: id }));
    }
  });

  it("omits total/offset/limit when the request carries NO query string", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer(KEY) });
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe("list");
    expect((body.data as unknown[]).length).toBe(3);
    expect("total" in body).toBe(false);
    expect("offset" in body).toBe(false);
    expect("limit" in body).toBe(false);
  });

  it("switches to the paginated envelope as soon as a query string is present", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans?limit=2`, { headers: bearer(KEY) });
    const body = (await response.json()) as { data: unknown[]; total: number; limit: number };
    expect(body.data).toHaveLength(2);
    expect(body.total).toBe(3);
    expect(body.limit).toBe(2);
  });

  it("applies offset", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans?offset=2&limit=10`, {
      headers: bearer(KEY),
    });
    const body = (await response.json()) as { data: { id: string }[]; total: number };
    expect(body.data.map((row) => row.id)).toEqual(["c"]);
    expect(body.total).toBe(3);
  });
});

describe("natural-key resource: /admin/v1/mcp-servers/{name}", () => {
  it("keys the row by `name`, so create → get by name round-trips", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(KEY, "POST", { name: "github", url: "https://mcp.example/sse" }),
    );
    expect(created.status).toBe(201);

    const read = await SELF.fetch(`${BASE}/admin/v1/mcp-servers/github`, { headers: bearer(KEY) });
    expect(read.status).toBe(200);
    expect((await read.json()) as { mcp_server: { name: string } }).toMatchObject({
      mcp_server: { name: "github" },
    });
  });

  it("rejects a body that fails its Zod schema with 400", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(KEY, "POST", { name: "bad", url: "not-a-url" }),
    );
    expect(response.status).toBe(400);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "invalid_request_body" },
    });
  });

  it("rejects a non-JSON body with 400", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/mcp-servers`, {
      method: "POST",
      headers: { ...bearer(KEY), "content-type": "application/json" },
      body: "not json",
    });
    expect(response.status).toBe(400);
  });
});

describe("composite-key resource: /admin/v1/quota-policies/{scope_type}/{scope_id}", () => {
  it("addresses a policy by its (scope_type, scope_id) pair", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies`,
      jsonRequest(KEY, "POST", { scope_type: "tenant", scope_id: "t1", rpm_limit: 60 }),
    );
    expect(created.status).toBe(201);

    const read = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t1`, {
      headers: bearer(KEY),
    });
    expect(read.status).toBe(200);
    expect((await read.json()) as { quota_policy: { rpm_limit: number } }).toMatchObject({
      quota_policy: { rpm_limit: 60 },
    });

    const deleted = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/t1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
  });

  it("404s an unknown scope kind rather than inventing a collection", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/nonsense/t1`, {
      headers: bearer(KEY),
    });
    expect(response.status).toBe(404);
  });

  it("denies a tenant caller a policy scoped to a project it does not own (#185)", async () => {
    arm({
      nativeKeys: [tenantKey("k-t1", "t1")],
      seed: { projects: [{ id: "proj_other", tenant_id: "t2" }] },
    });
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/project/proj_other`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });

  it("denies when the referenced scope cannot be resolved AT ALL — fails closed", async () => {
    // "Nonexistent means safe to touch" is explicitly the wrong default: an
    // absent row and an unavailable store both mean "unknown owner", and an
    // unknown owner is never the caller.
    arm({ nativeKeys: [tenantKey("k-t1", "t1")] });
    const response = await SELF.fetch(`${BASE}/admin/v1/quota-policies/workspace/ghost`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(403);
  });
});

/**
 * A COMPLETE, enforceable `PolicyRevision` body.
 *
 * These cases used to post `{policy_id, detectors: []}` and get a `201`. They
 * cannot any more, and the change is the point of the guardrail write-half
 * slice, not an inconvenience: `detectors` is not a field of Rust's
 * `PolicyRevision` (which is `deny_unknown_fields`), and a revision with no
 * `name`, no `checks` and no `on_*` actions is one `apps/gateway` could never
 * compile — so accepting it produced a revision history no request was ever
 * evaluated against. Admission now refuses it with `400
 * invalid_guardrail_policy`, which
 * `test/guardrail-write-half.test.ts` asserts directly. The fixtures below move
 * to a revision that IS enforceable; every assertion in these cases is
 * unchanged.
 */
function guardrailRevisionBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "crud fixture",
    checks: [
      {
        id: "kw",
        enabled: true,
        stage: "request",
        sources: ["user"],
        detector: { kind: "local", keywords: ["forbidden"], regex: [], secret_patterns: [] },
      },
    ],
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "guardrail_blocked", message: "blocked" }],
    on_error: [{ kind: "block", code: "guardrail_unavailable", message: "unavailable" }],
    ...overrides,
  };
}

describe("guardrail policy revisions are immutable and monotonic", () => {
  it("numbers revisions upward and activates one", async () => {
    const first = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ policy_id: "gp1" })),
    );
    expect(first.status).toBe(201);
    expect((await first.json()) as { policy: { revision: number } }).toMatchObject({
      policy: { revision: 1, status: "draft" },
    });

    const second = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp1/revisions`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ name: "second" })),
    );
    expect((await second.json()) as { policy: { revision: number } }).toMatchObject({
      policy: { revision: 2 },
    });

    const history = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies/gp1/revisions`, {
      headers: bearer(KEY),
    });
    expect(((await history.json()) as { data: unknown[] }).data).toHaveLength(2);

    const activated = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp1/activate`,
      jsonRequest(KEY, "POST", { revision: 2 }),
    );
    expect(activated.status).toBe(200);
    expect((await activated.json()) as { policy: { active_revision: number } }).toMatchObject({
      policy: { active_revision: 2 },
    });

    const rolledBack = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp1/rollback`,
      jsonRequest(KEY, "POST", {}),
    );
    expect(rolledBack.status).toBe(200);
    expect((await rolledBack.json()) as { policy: { active_revision: number } }).toMatchObject({
      policy: { active_revision: 1 },
    });
  });

  it("rejects an activate body with an unknown field (Rust deny_unknown_fields)", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ policy_id: "gp2" })),
    );
    const response = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp2/activate`,
      jsonRequest(KEY, "POST", { revision: 1, sneaky: true }),
    );
    expect(response.status).toBe(400);
  });

  it("dry-run dispatches NOTHING", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ policy_id: "gp3" })),
    );
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp3/activate`,
      jsonRequest(KEY, "POST", { revision: 1 }),
    );
    const response = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp3/dry-run`,
      jsonRequest(KEY, "POST", { stage: "request", text: "hello" }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      // The contract's `GuardrailPolicyDryRunResponse` constants
      // (`docs/openapi/admin-api.openapi.json`): the object name and the
      // `"planned"` result are `const` in the schema, so a port that renames
      // either is off-contract even though the request still answers 200.
      object: "guardrail_policy_dry_run",
      result: "planned",
      provider_dispatched: false,
      external_action_dispatched: false,
    });
  });

  it("rejects a stage outside Rust's DetectorStage (`request` | `response`)", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ policy_id: "gp4" })),
    );
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp4/activate`,
      jsonRequest(KEY, "POST", { revision: 1 }),
    );
    const response = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp4/dry-run`,
      jsonRequest(KEY, "POST", { stage: "input", text: "hello" }),
    );
    expect(response.status).toBe(400);
  });
});

describe("wallets: every balance movement writes a ledger entry", () => {
  beforeEach(async () => {
    arm({ staticKeys: [operatorKey] });
    await SELF.fetch(
      `${BASE}/admin/v1/wallets`,
      jsonRequest(KEY, "POST", { tenant_id: "t1", balance_cents: 1000, currency: "USD" }),
    );
  });

  it("adjusts, charges, and records both in the ledger", async () => {
    const adjusted = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(KEY, "POST", { amount_cents: 500, reason: "promo credit" }),
    );
    expect(adjusted.status).toBe(200);
    expect((await adjusted.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: 1500 },
    });

    const charged = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/charge`,
      jsonRequest(KEY, "POST", { amount_cents: 200 }),
    );
    expect((await charged.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: 1300 },
    });

    const ledger = await SELF.fetch(`${BASE}/admin/v1/wallets/t1/ledger`, { headers: bearer(KEY) });
    const entries = ((await ledger.json()) as { data: { kind: string; amount_cents: number }[] })
      .data;
    expect(entries.map((entry) => [entry.kind, entry.amount_cents])).toEqual([
      ["adjustment", 500],
      ["charge", -200],
    ]);
  });

  it("refuses to overdraw — 409, not a negative balance", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/charge`,
      jsonRequest(KEY, "POST", { amount_cents: 99999 }),
    );
    expect(response.status).toBe(409);

    const wallet = await SELF.fetch(`${BASE}/admin/v1/wallets/t1`, { headers: bearer(KEY) });
    expect((await wallet.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: 1000 },
    });
  });

  it("does not let a plain PATCH move the balance behind the ledger's back", async () => {
    const patched = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1`,
      jsonRequest(KEY, "PATCH", { balance_cents: 999999, currency: "EUR" }),
    );
    expect(patched.status).toBe(200);
    expect((await patched.json()) as { wallet: Record<string, unknown> }).toMatchObject({
      wallet: { balance_cents: 1000, currency: "EUR" },
    });
  });
});

describe("virtual keys: the secret is shown once and never again", () => {
  it("returns the plaintext on create, and only the projection on read", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/virtual-keys`,
      jsonRequest(KEY, "POST", { id: "vk1", name: "ci" }),
    );
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as {
      secret: string;
      virtual_key: Record<string, unknown>;
    };
    expect(createdBody.secret).toMatch(/^fg_[0-9a-f]{48}$/);
    expect(createdBody.virtual_key.key_prefix).toBe(createdBody.secret.slice(0, 16));
    expect(createdBody.virtual_key.last4).toBe(createdBody.secret.slice(-4));

    const read = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk1`, { headers: bearer(KEY) });
    const readBody = (await read.json()) as { virtual_key: Record<string, unknown> };
    // The plaintext is absent from every read path, and only the hash is stored.
    expect(JSON.stringify(readBody)).not.toContain(createdBody.secret);
    expect(String(readBody.virtual_key.key_hash)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("DELETE revokes rather than deleting — the row survives for attribution", async () => {
    await SELF.fetch(`${BASE}/admin/v1/virtual-keys`, jsonRequest(KEY, "POST", { id: "vk2" }));
    const revoked = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk2`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(revoked.status).toBe(200);

    const stillThere = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk2`, {
      headers: bearer(KEY),
    });
    expect(stillThere.status).toBe(200);
    expect((await stillThere.json()) as { virtual_key: Record<string, unknown> }).toMatchObject({
      virtual_key: { revoked: true, enabled: false },
    });
  });

  it("rotate mints a new secret and invalidates the old hash", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/virtual-keys`,
      jsonRequest(KEY, "POST", { id: "vk3" }),
    );
    const before = (await created.json()) as { virtual_key: { key_hash: string } };
    const rotated = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk3/rotate`, {
      method: "POST",
      headers: bearer(KEY),
    });
    const after = (await rotated.json()) as { secret: string; virtual_key: { key_hash: string } };
    expect(after.virtual_key.key_hash).not.toBe(before.virtual_key.key_hash);
    expect(after.secret).toMatch(/^fg_/);
  });
});

describe("cross-tenant isolation is a property of the store, not of each handler", () => {
  beforeEach(() => {
    arm({
      nativeKeys: [tenantKey("k-t1", "t1"), tenantKey("k-t2", "t2")],
      seed: {
        "agent-schedules": [
          { id: "s_t1", tenant_id: "t1", name: "t1 schedule" },
          { id: "s_t2", tenant_id: "t2", name: "t2 schedule" },
        ],
      },
    });
  });

  it("lists only the caller's own rows", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules`, {
      headers: bearer("k-t1"),
    });
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id)).toEqual(["s_t1"]);
  });

  it("404s (not 403s) another tenant's row — existence is not disclosed", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_t2`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(404);
  });

  it("refuses to mutate another tenant's row", async () => {
    const patched = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/s_t2`,
      jsonRequest("k-t1", "PATCH", { name: "hijacked" }),
    );
    expect(patched.status).toBe(404);

    const owner = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_t2`, {
      headers: bearer("k-t2"),
    });
    expect((await owner.json()) as { agent_schedule: { name: string } }).toMatchObject({
      agent_schedule: { name: "t2 schedule" },
    });
  });

  it("refuses to delete another tenant's row", async () => {
    const deleted = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_t2`, {
      method: "DELETE",
      headers: bearer("k-t1"),
    });
    expect(deleted.status).toBe(404);
  });

  it("stamps the caller's tenant on create — a tenant cannot mint into another", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest("k-t1", "POST", { id: "s_new", tenant_id: "t2" }),
    );
    const fromOther = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_new`, {
      headers: bearer("k-t2"),
    });
    expect(fromOther.status).toBe(404);
  });

  it("a platform operator sees every tenant's rows", async () => {
    arm({
      staticKeys: [operatorKey],
      seed: {
        "agent-schedules": [
          { id: "s_t1", tenant_id: "t1" },
          { id: "s_t2", tenant_id: "t2" },
        ],
      },
    });
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules`, { headers: bearer(KEY) });
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id).sort()).toEqual(["s_t1", "s_t2"]);
  });
});

describe("operator actions with no resource behind them", () => {
  it("reads and sets the drain state", async () => {
    const initial = await SELF.fetch(`${BASE}/admin/v1/drain`, { headers: bearer(KEY) });
    expect(await initial.json()).toEqual({
      object: "drain",
      draining: false,
      reason: null,
      accepting_new_requests: true,
    });

    const set = await SELF.fetch(
      `${BASE}/admin/v1/drain`,
      jsonRequest(KEY, "POST", { draining: true, reason: "deploy" }),
    );
    expect(set.status).toBe(200);
    // `propagation` is the honest statement FC-1 forced: the fleet reads a
    // durable row, so enforcement lands on each Worker's NEXT request rather
    // than instantly as Rust's in-process `AtomicBool` did.
    expect(await set.json()).toEqual({
      object: "drain",
      draining: true,
      reason: "deploy",
      accepting_new_requests: false,
      propagation: "on_next_request_per_worker",
    });

    const after = await SELF.fetch(`${BASE}/admin/v1/drain`, { headers: bearer(KEY) });
    expect((await after.json()) as { draining: boolean }).toMatchObject({ draining: true });
  });

  it("validates a candidate config without installing it", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/config/validate`,
      jsonRequest(KEY, "POST", { providers: [] }),
    );
    expect(response.status).toBe(200);
    expect((await response.json()) as { object: string }).toMatchObject({
      object: "config_validation",
      valid: true,
    });
  });
});

describe("tenant hierarchy", () => {
  it("assigns a plan only when the plan exists", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts`,
      jsonRequest(KEY, "POST", { id: "t1", name: "Acme" }),
    );

    const dangling = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/t1/plan`,
      jsonRequest(KEY, "PUT", { plan_id: "no_such_plan" }),
    );
    expect(dangling.status).toBe(404);

    await SELF.fetch(`${BASE}/admin/v1/plans`, jsonRequest(KEY, "POST", { id: "pro" }));
    const assigned = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/t1/plan`,
      jsonRequest(KEY, "PUT", { plan_id: "pro" }),
    );
    expect(assigned.status).toBe(200);

    const resolved = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/t1/resolved-defaults`, {
      headers: bearer(KEY),
    });
    expect((await resolved.json()) as { plan_id: string; resolved_from: string[] }).toMatchObject({
      object: "resolved_defaults",
      tenant_id: "t1",
      plan_id: "pro",
      resolved_from: ["tenant_account", "plan"],
    });
  });

  it("has no DELETE for a tenant account — teardown is a lifecycle status", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/t1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(response.status).toBe(405);
  });
});

describe("rbac bindings are addressed by tenant, not by a binding id", () => {
  it("binds and unbinds a role for a tenant", async () => {
    const bound = await SELF.fetch(
      `${BASE}/admin/v1/tenant-roles/t1`,
      jsonRequest(KEY, "POST", { role_id: "role_admin" }),
    );
    expect(bound.status).toBe(201);

    const listed = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/t1`, { headers: bearer(KEY) });
    expect(((await listed.json()) as { data: unknown[] }).data).toHaveLength(1);

    const unbound = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/t1/role_admin`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(unbound.status).toBe(200);
  });

  it("denies a tenant caller naming a DIFFERENT tenant in the path", async () => {
    arm({ nativeKeys: [tenantKey("k-t1", "t1")] });
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-roles/t2`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });
});

describe("billing outbox replay is at-most-once", () => {
  it("replays once, then 409s", async () => {
    arm({
      staticKeys: [operatorKey],
      seed: { "billing-outbox-dead-letters": [{ id: "dl1", status: "dead" }] },
    });

    const first = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters/dl1/replay`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(first.status).toBe(200);

    const second = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters/dl1/replay`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(second.status).toBe(409);
  });
});

describe("response headers", () => {
  it("echoes an inbound x-request-id on every response", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      headers: { ...bearer(KEY), "x-request-id": "req-abc" },
    });
    expect(response.headers.get("x-request-id")).toBe("req-abc");
    expect(response.headers.get("x-trace-id")).toBe("req-abc");
  });

  it("carries the request id into the error envelope", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      headers: { "x-request-id": "req-err" },
    });
    expect((await response.json()) as { error: { request_id: string } }).toMatchObject({
      error: { request_id: "req-err", type: "ferrogate_error" },
    });
  });
});

describe("KEPT MARKER: the open admin body keeps operator fields it cannot name", () => {
  /**
   * `routes/resource.ts` carries a sharpened `PORT-TODO(inventory-edge-control
   * §4)`: the per-collection Rust mutation structs are blocked on
   * `@ferrogate/schemas`, so the base body is `adminRecordSchema.passthrough()`.
   * The marker calls `passthrough()` the SAFE approximation because `strip()`
   * would silently DISCARD operator data and `strict()` would reject fields the
   * Rust surface accepts.
   *
   * Nothing asserted that. Swapping `.passthrough()` for `.strip()` left all
   * 442 tests green while every unrecognized operator field vanished on write —
   * a silent data loss, discoverable only in production. These are the
   * assertions that make the approximation observable, and they are exactly the
   * ones a real per-resource schema will replace (a tightened schema REJECTS
   * `weird_operator_field` rather than storing it, which is a deliberate
   * behavior change, not a green-to-green refactor).
   */
  const EXTRA = { weird_operator_field: { nested: [1, 2, 3] }, another_one: "kept" };

  it("stores an unrecognized field on create and returns it on read", async () => {
    // `gateway-configs` is the purest case: its spec is the base body itself
    // (`body: adminRecordSchema` in `routes/admin_gateway_config.ts`).
    const created = await SELF.fetch(
      `${BASE}/admin/v1/gateway-configs`,
      jsonRequest(KEY, "POST", { id: "cfg_open", name: "candidate", ...EXTRA }),
    );
    expect(created.status).toBe(201);
    expect((await created.json()) as { gateway_config: Record<string, unknown> }).toMatchObject({
      gateway_config: EXTRA,
    });

    const read = await SELF.fetch(`${BASE}/admin/v1/gateway-configs/cfg_open`, {
      headers: bearer(KEY),
    });
    // The round trip is what matters: a `strip()` body would answer 201 with a
    // clean-looking record and lose the field between the two calls.
    expect((await read.json()) as { gateway_config: Record<string, unknown> }).toMatchObject({
      gateway_config: EXTRA,
    });
  });

  it("keeps it through a collection that EXTENDS the base body too", async () => {
    // `.extend()` on a passthrough object stays passthrough — assert it rather
    // than assume it, since every real collection reaches the base this way.
    const created = await SELF.fetch(
      `${BASE}/admin/v1/plans`,
      jsonRequest(KEY, "POST", { id: "plan_open", name: "pro", ...EXTRA }),
    );
    expect(created.status).toBe(201);

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/plans/plan_open`,
      jsonRequest(KEY, "PATCH", { enabled: false }),
    );
    expect(patched.status).toBe(200);
    // A PATCH that names only a KNOWN field must not quietly rewrite the record
    // without the fields the schema cannot name.
    expect((await patched.json()) as { plan: Record<string, unknown> }).toMatchObject({
      plan: { enabled: false, ...EXTRA },
    });
  });

  it("CONTROL: the collections that DO have a real schema still reject unknowns", async () => {
    // Without this, the two tests above would read as "this app validates
    // nothing". The bespoke bodies are `strict()`, so the open base body is a
    // scoped approximation and not a blanket one.
    await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies`,
      jsonRequest(KEY, "POST", guardrailRevisionBody({ policy_id: "gp_open" })),
    );
    const response = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp_open/activate`,
      jsonRequest(KEY, "POST", { revision: 1, weird_operator_field: true }),
    );
    expect(response.status).toBe(400);
  });
});
