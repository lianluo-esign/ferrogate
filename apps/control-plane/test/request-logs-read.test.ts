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
 * ## What this file proves and what it deliberately does not
 *
 * It proves the READER: that the admin surface returns what `request_logs`
 * holds, in the documented order, fenced to the caller's tenant, in both the
 * JSON list and the JSONL export.
 *
 * It does NOT prove the WRITER, and it must not be read as if it did. The
 * writer is `apps/gateway/src/requestlog/` — a different Worker, a different
 * `wrangler.toml`, unreachable from this suite — and it is held end to end by
 * `apps/gateway/test/requestlog/write.test.ts`, which drives a real inference
 * request and asserts against these same columns. The two halves meet at
 * `sql/d1-ts/control/0003_request_log_columns.sql`, which both suites apply
 * from the deployed migration directory rather than from a fixture, so a column
 * rename breaks both.
 *
 * The seeded rows here are therefore honest fixtures for a cross-Worker seam,
 * not a substitute for the write path — see `test/d1.ts::seedRequestLogs`.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, resetD1, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

interface ListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
  source?: string;
  as_of_unix?: number;
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
): Promise<{
  contentType: string;
  source: string;
  asOfUnix: number;
  lines: Record<string, unknown>[];
}> {
  const response = await SELF.fetch(`${BASE}/admin/v1/request-log-exports${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  const text = await response.text();
  return {
    contentType: response.headers.get("content-type") ?? "",
    source: response.headers.get("x-ferrogate-evidence-source") ?? "",
    asOfUnix: Number(response.headers.get("x-ferrogate-evidence-as-of-unix") ?? "NaN"),
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

async function seedExactTenantRequestLogs(
  rows: readonly { requestId: string; tenant: string | null; startedAtUnix: number }[],
): Promise<void> {
  for (const row of rows) {
    if (row.tenant === null) continue;
    const tenant = await exactTenantDatabase(row.tenant);
    await tenant
      .prepare(
        `INSERT INTO request_logs
           (request_id, tenant, guardrail_verdict, started_at_unix, request_json)
         VALUES (?, ?, 'allowed', ?, '{}')`,
      )
      .bind(row.requestId, row.tenant, row.startedAtUnix)
      .run();
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

describe("GET /admin/v1/request-logs returns the evidence the table holds", () => {
  it("returns a seeded decision row with every fact the acceptance criteria names", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect((await readLogs(operatorKey.secret)).data).toHaveLength(0);

    await seedRequestLogs([FULL_ROW]);

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
    expect(page.source).toBe("derived_control_projection");
    expect(page.as_of_unix).toEqual(expect.any(Number));
  });

  /**
   * NEWEST FIRST. An evidence list is read to answer "what just happened", and
   * the index this query rides (`idx_request_logs_tenant_started`, DESC) exists
   * for exactly that read. `request_id` breaks the tie so a page boundary
   * inside one second can neither re-serve nor skip a row.
   */
  it("orders newest first with request_id as the tiebreaker", async () => {
    await seedRequestLogs([
      { ...FULL_ROW, requestId: "fg-b", startedAtUnix: 200 },
      { ...FULL_ROW, requestId: "fg-a", startedAtUnix: 200 },
      { ...FULL_ROW, requestId: "fg-c", startedAtUnix: 300 },
    ]);
    const page = await readLogs(operatorKey.secret);
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-c", "fg-a", "fg-b"]);
  });

  it("reports the pre-window total alongside the page", async () => {
    await seedRequestLogs(
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
    await seedRequestLogs([
      { ...FULL_ROW, requestId: "fg-t1", tenant: "t-1" },
      { ...FULL_ROW, requestId: "fg-t2", tenant: "t-2" },
      // An UNATTRIBUTED row: a request whose credential resolved no tenant, i.e.
      // a platform-operator call. It is nobody's tenant data.
      { ...FULL_ROW, requestId: "fg-none", tenant: null },
    ]);
    await seedExactTenantRequestLogs([
      { requestId: "fg-t1", tenant: "t-1", startedAtUnix: FULL_ROW.startedAtUnix },
      { requestId: "fg-t2", tenant: "t-2", startedAtUnix: FULL_ROW.startedAtUnix },
    ]);
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
   * `auditTenantFence` documents. A tenant that could read the un-attributed
   * rows would be reading the platform operator's own traffic.
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
    await seedRequestLogs([
      { ...FULL_ROW, requestId: "fg-1", startedAtUnix: 10 },
      { ...FULL_ROW, requestId: "fg-2", startedAtUnix: 20 },
    ]);
    const exported = await exportLogs(operatorKey.secret);
    expect(exported.contentType).toContain("application/x-ndjson");
    expect(exported.source).toBe("derived_control_projection");
    expect(exported.asOfUnix).toBeGreaterThan(1_700_000_000);
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
