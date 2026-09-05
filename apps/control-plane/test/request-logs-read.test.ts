/**
 * The READ half of the per-request evidence trail (#664), driven end to end
 * through the exported Worker against a REAL D1 binding.
 *
 * ## The defect this file pins
 *
 * `GET /admin/v1/request-logs` and `GET /admin/v1/request-log-exports` were
 * mounted, authenticated and contract-listed, and answered
 * `{"object":"list","data":[]}` on EVERY deployment — because both were served
 * by the generic document-collection handler over `control_plane_resources`,
 * which nothing writes, while the evidence table `request_logs` sat beside it.
 *
 * That is strictly worse than an error. An operator debugging a bad response
 * and an auditor asking "what did this system do" are both answered *nothing
 * happened*, and the absence of a record is how you conclude a decision was not
 * made. EU AI Act Art. 12/72 record-keeping for high-risk systems started
 * 2026-08-02 and is per DECISION, not per report.
 *
 * ## What this file proves after the Zero-D1 object cutover
 *
 * The operator list/export is no longer served from the shared control
 * projection. Under Zero-D1 Plan B it is a live fan-out over each provisioned
 * tenant's authoritative object UNION the single platform object — the home of
 * the un-attributed (platform-operator) rows no roster tenant owns. So the
 * authoritative fixture for an attributed row is its tenant's OBJECT (the same
 * place the gateway writer lands it), and for an un-attributed row the PLATFORM
 * object, seeded directly. The control `request_logs` projection now has no
 * reader at all (Track A dropped both the SIEM pump and the one-time platform
 * backfill), so it is DROPped in this change.
 *
 * It does NOT prove the WRITER. That is `apps/gateway/src/requestlog/` — a
 * different Worker, a different `wrangler.toml`, unreachable from this suite —
 * held end to end by `apps/gateway/test/requestlog/`. The two halves meet at the
 * migration directories both suites apply from, so a column rename breaks both.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, platformDb, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

interface ListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
  source?: string;
  tenant_page?: Record<string, unknown>;
}

async function readLogs(secret: string, query = ""): Promise<ListBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/request-logs${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as ListBody;
}

async function exportLogs(
  secret: string,
  query = "",
): Promise<{ contentType: string; lines: Record<string, unknown>[] }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/request-log-exports${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  const text = await response.text();
  return {
    contentType: response.headers.get("content-type") ?? "",
    lines: text
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

/** One complete decision row, carrying every fact #664's "Done when" names. */
const FULL_ROW = {
  requestId: "fg-0000000000000001",
  tenant: "t-1",
  project: "proj-1",
  apiKeyId: "key_t-1",
  startedAtUnix: 1_700_000_100,
  completedAtUnix: 1_700_000_101,
  route: "openai.chat.completions",
  provider: "openai",
  logicalModel: "gpt-4o-mini",
  providerModel: "gpt-4o-mini-2024-07-18",
  statusCode: 200,
  latencyMs: 412,
  totalTokens: 15,
  guardrailVerdict: "allowed",
  document: { object: "request_log", streamed: false, prompt_tokens: 11, completion_tokens: 4 },
} as const;

type RowSeed = {
  readonly requestId: string;
  readonly tenant?: string | null;
  readonly project?: string | null;
  readonly apiKeyId?: string | null;
  readonly startedAtUnix: number;
  readonly completedAtUnix?: number | null;
  readonly route?: string | null;
  readonly provider?: string | null;
  readonly logicalModel?: string | null;
  readonly providerModel?: string | null;
  readonly statusCode?: number | null;
  readonly latencyMs?: number | null;
  readonly totalTokens?: number | null;
  readonly guardrailVerdict?: string | null;
  readonly document?: Record<string, unknown>;
};

async function exactTenantDatabase(tenantId: string): Promise<D1Database> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, NULL, 12, 'durable_object', 'ready', 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         storage_backend = 'durable_object', provisioning_status = 'ready', migration_state = 'done'`,
    )
    .bind(tenantId)
    .run();
  return (await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(tenantId))
    .db;
}

async function clearExactTenantRequestLogs(): Promise<void> {
  for (const tenantId of ["t-1", "t-2"]) {
    const tenant = await exactTenantDatabase(tenantId);
    await tenant.prepare("DELETE FROM request_logs").run();
  }
}

/**
 * Insert one full-shape row into an already-woken object handle, binding the
 * caller's `tenant` value. The tenant and platform `request_logs` tables share
 * the same column set (the platform one drops only `projection_key`), so the one
 * statement serves both write legs — the tenant object with its own id, the
 * platform object with `tenant` forced NULL.
 */
function insertFullRow(handle: D1Database, tenantValue: string | null, row: RowSeed) {
  return handle
    .prepare(
      `INSERT INTO request_logs
         (request_id, tenant, project, api_key_id, route, provider, logical_model,
          provider_model, status_code, latency_ms, total_tokens, guardrail_verdict,
          started_at_unix, completed_at_unix, request_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      row.requestId,
      tenantValue,
      row.project ?? null,
      row.apiKeyId ?? null,
      row.route ?? null,
      row.provider ?? null,
      row.logicalModel ?? null,
      row.providerModel ?? null,
      row.statusCode ?? null,
      row.latencyMs ?? null,
      row.totalTokens ?? null,
      row.guardrailVerdict ?? "not_screened",
      row.startedAtUnix,
      row.completedAtUnix ?? null,
      JSON.stringify(row.document ?? {}),
    );
}

/** Seed attributed rows into their authoritative tenant objects (skips null). */
async function seedTenantObjects(rows: readonly RowSeed[]): Promise<void> {
  for (const row of rows) {
    const tenantValue = row.tenant ?? null;
    if (tenantValue === null) continue;
    const tenant = await exactTenantDatabase(tenantValue);
    await insertFullRow(tenant, tenantValue, row).run();
  }
}

/** Seed un-attributed rows into the platform object, `tenant` normalized to NULL. */
async function seedPlatformObject(rows: readonly RowSeed[]): Promise<void> {
  for (const row of rows) {
    await insertFullRow(platformDb(), null, row).run();
  }
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    rbac: {},
  });
  await clearExactTenantRequestLogs();
});

describe("GET /admin/v1/request-logs returns the evidence the objects hold", () => {
  it("returns a seeded decision row with every fact the acceptance criteria names", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect((await readLogs(operatorKey.secret)).data).toHaveLength(0);

    // Under the object cutover the operator read fans out over the tenant OBJECTS
    // (union the platform object), so the authoritative fixture for an attributed
    // row is its tenant's object — the same place the gateway writer lands it.
    await seedTenantObjects([FULL_ROW]);

    const page = await readLogs(operatorKey.secret);
    expect(page.data).toHaveLength(1);
    expect(page.data[0]).toMatchObject({
      object: "request_log",
      request_id: FULL_ROW.requestId,
      tenant_id: "t-1",
      project_id: "proj-1",
      api_key_id: "key_t-1",
      logical_model: "gpt-4o-mini",
      provider_model: "gpt-4o-mini-2024-07-18",
      provider: "openai",
      route: "openai.chat.completions",
      status_code: 200,
      latency_ms: 412,
      total_tokens: 15,
      guardrail_verdict: "allowed",
      started_at_unix: FULL_ROW.startedAtUnix,
      completed_at_unix: FULL_ROW.completedAtUnix,
    });
    // The read is authority now, not a derived projection: the projection source
    // annotation the control read used to stamp is gone.
    expect(page.source).toBeUndefined();
    expect(page.tenant_page).toBeDefined();
  });

  /**
   * NEWEST FIRST. An evidence list is read to answer "what just happened", and
   * the fleet merge re-sorts every object's rows by `started_at_unix DESC,
   * request_id ASC`. `request_id` breaks the tie so a page boundary inside one
   * second can neither re-serve nor skip a row.
   */
  it("orders newest first with request_id as the tiebreaker", async () => {
    await seedTenantObjects([
      { ...FULL_ROW, requestId: "fg-b", startedAtUnix: 200 },
      { ...FULL_ROW, requestId: "fg-a", startedAtUnix: 200 },
      { ...FULL_ROW, requestId: "fg-c", startedAtUnix: 300 },
    ]);
    const page = await readLogs(operatorKey.secret);
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-c", "fg-a", "fg-b"]);
  });

  it("reports the pre-window total alongside the page", async () => {
    // Five in tenant t-1's object. The fan-out pages each object to `offset+limit`
    // but `count(*) OVER()` reports the object's full depth, so a clipped page
    // still yields the pre-window total of 5.
    await seedTenantObjects(
      Array.from({ length: 5 }, (_unused, index) => ({
        ...FULL_ROW,
        requestId: `fg-${index}`,
        startedAtUnix: 1_000 + index,
      })),
    );
    const page = await readLogs(operatorKey.secret, "?limit=2&offset=1");
    expect(page.data).toHaveLength(2);
    expect(page.total).toBe(5);
    expect(page.offset).toBe(1);
    expect(page.limit).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// The tenant fence — the property that must be proved by mutation, not read
// ---------------------------------------------------------------------------

describe("the tenant fence on request logs", () => {
  beforeEach(async () => {
    await seedTenantObjects([
      { ...FULL_ROW, requestId: "fg-t1", tenant: "t-1" },
      { ...FULL_ROW, requestId: "fg-t2", tenant: "t-2" },
    ]);
    // An UNATTRIBUTED row: a request whose credential resolved no tenant, i.e. a
    // platform-operator call. It is nobody's tenant data, so it lives only in the
    // platform object.
    await seedPlatformObject([{ ...FULL_ROW, requestId: "fg-none", tenant: null }]);
  });

  it("shows a tenant only its own rows", async () => {
    const page = await readLogs("k-tenant");
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-t1"]);
  });

  it("shows the OTHER tenant only its own rows", async () => {
    const page = await readLogs("k-other");
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-t2"]);
  });

  /**
   * STRICT equality, so `NULL` matches nobody — the same narrowing
   * `auditTenantFence` documents. A tenant read is `requestLogTenantPage` over
   * its own object (`WHERE tenant = ?`), which never touches the platform object,
   * so an un-attributed platform row is unreachable to any tenant by construction.
   */
  it("never shows a tenant the un-attributed platform rows", async () => {
    for (const secret of ["k-tenant", "k-other"]) {
      const ids = (await readLogs(secret)).data.map((row) => row.request_id);
      expect(ids).not.toContain("fg-none");
    }
  });

  it("shows a platform operator every row", async () => {
    const ids = (await readLogs(operatorKey.secret)).data.map((row) => row.request_id);
    expect(ids.sort()).toEqual(["fg-none", "fg-t1", "fg-t2"]);
  });

  /**
   * The fence has to hold on the EXPORT too. An export endpoint is the one an
   * auditor actually pipes into a SIEM, so a leak there is a bulk leak.
   */
  it("fences the JSONL export identically", async () => {
    const exported = await exportLogs("k-tenant");
    expect(exported.lines.map((row) => row.request_id)).toEqual(["fg-t1"]);
  });

  /** A pagination window must not be a way around the fence. */
  it("cannot be paged past", async () => {
    const page = await readLogs("k-tenant", "?limit=100&offset=0");
    expect(page.total).toBe(1);
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-t1"]);
  });
});

// ---------------------------------------------------------------------------
// The JSONL export
// ---------------------------------------------------------------------------

describe("GET /admin/v1/request-log-exports streams JSONL", () => {
  it("answers newline-delimited JSON, one decision per line", async () => {
    await seedTenantObjects([
      { ...FULL_ROW, requestId: "fg-1", startedAtUnix: 10 },
      { ...FULL_ROW, requestId: "fg-2", startedAtUnix: 20 },
    ]);
    const exported = await exportLogs(operatorKey.secret);
    expect(exported.contentType).toContain("application/x-ndjson");
    expect(exported.lines.map((row) => row.request_id)).toEqual(["fg-2", "fg-1"]);
    expect(exported.lines[0]).toMatchObject({
      object: "request_log",
      logical_model: "gpt-4o-mini",
      guardrail_verdict: "allowed",
    });
  });

  it("answers an EMPTY body — not `[]` — when there is nothing to export", async () => {
    const exported = await exportLogs(operatorKey.secret);
    expect(exported.lines).toEqual([]);
  });
});
