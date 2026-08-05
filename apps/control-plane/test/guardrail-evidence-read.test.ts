/**
 * The READ half of guardrail screening evidence (#665), driven end to end
 * through the exported Worker against a REAL D1 binding.
 *
 * ## The defect this file pins
 *
 * `GET /admin/v1/guardrail-evaluations` and `GET /admin/v1/investigations` were
 * mounted, authenticated, RBAC-gated (`guardrails.evidence.read`) and
 * contract-listed, and answered `{"object":"list","data":[]}` on EVERY
 * deployment — because both were served by the generic document-collection
 * handler over `control_plane_resources`, which nothing writes, and because the
 * evidence tables **did not exist in `sql/d1-ts/` at all**. Guardrail evidence
 * was in-memory-only fleet-wide: an isolate ended and the record of what the
 * control decided ended with it.
 *
 * That is one step worse than the request-log case #664 closed. There, a table
 * with no writer at least meant the schema could hold the answer. Here a
 * security engineer investigating a BLOCKED request was told, by an
 * authenticated compliance API, that no guardrail had ever evaluated anything.
 *
 * ## What this file proves and what it deliberately does not
 *
 * It proves the READER: that the admin surface returns what
 * `guardrail_evaluations` / `guardrail_check_evaluations` hold, joined,
 * newest-first, paginated, and FENCED to the caller's tenant — and that the
 * investigation view joins one request's evidence across the tables.
 *
 * It does NOT prove the WRITER. That is `apps/gateway/src/guardrails/` — a
 * different Worker, a different `wrangler.toml`, unreachable from this suite —
 * and it is held end to end by `apps/gateway/test/guardrails/evidence-write.test.ts`,
 * which drives a real blocked inference request. The two halves meet at
 * `sql/d1-ts/control/0004_guardrail_evaluations.sql`, which both suites apply
 * from the deployed migration directory rather than from a fixture, so a column
 * rename breaks both.
 */
import { SELF, env } from "cloudflare:test";
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import {
  GUARDRAIL_EVIDENCE_BACKFILL_MARK,
  ensureTenantGuardrailEvidenceBackfill,
} from "../src/store/guardrail_evidence_backfill.js";
import {
  type GuardrailEvaluationSeed,
  applySchema,
  db,
  resetD1,
  seedAuditEvents,
  seedBillingEvents,
  seedGuardrailEvaluations,
  seedRequestLogs,
} from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

interface ListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
}

async function readEvaluations(secret: string, query = ""): Promise<ListBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/guardrail-evaluations${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as ListBody;
}

async function investigate(
  secret: string,
  query: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/investigations${query}`, {
    headers: bearer(secret),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function exactTenantDatabase(tenantId: string): Promise<D1Database> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, NULL, 13, 'durable_object', 'ready', 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         storage_backend = 'durable_object', provisioning_status = 'ready', migration_state = 'done'`,
    )
    .bind(tenantId)
    .run();
  return (await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(tenantId))
    .db;
}

async function clearExactTenantEvidence(): Promise<void> {
  for (const tenantId of ["t-1", "t-2"]) {
    const tenant = await exactTenantDatabase(tenantId);
    await tenant.batch([
      tenant.prepare("DELETE FROM guardrail_check_evaluations"),
      tenant.prepare("DELETE FROM guardrail_evaluations"),
      tenant.prepare("DELETE FROM agent_run_events"),
      tenant.prepare("DELETE FROM agent_runs"),
      tenant.prepare("DELETE FROM request_logs"),
      tenant
        .prepare("DELETE FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
        .bind(tenantId, GUARDRAIL_EVIDENCE_BACKFILL_MARK),
    ]);
  }
}

async function seedExactTenantGuardrailEvaluations(
  rows: readonly GuardrailEvaluationSeed[],
): Promise<void> {
  for (const row of rows) {
    if (row.tenant === undefined || row.tenant === null || row.tenant === "") continue;
    const tenant = await exactTenantDatabase(row.tenant);
    const statements = [
      tenant
        .prepare(
          `INSERT INTO guardrail_evaluations
             (id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type, scope_id,
              target, protocol, stage, mode, policy_id, policy_revision, verdict, action,
              enforcement_status, latency_ms, finding_count, input_fingerprint,
              action_fingerprint, occurred_at_unix, evaluation_json)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)`,
        )
        .bind(
          row.id,
          row.requestId,
          row.traceId ?? null,
          row.agentRunId ?? null,
          row.subjectId ?? null,
          row.tenant,
          row.scopeType ?? "organization",
          row.scopeId ?? null,
          row.target ?? "unspecified",
          row.protocol ?? "chat_completions",
          row.stage ?? "request",
          row.mode ?? "enforce",
          row.policyId ?? "policy",
          row.policyRevision ?? 1,
          row.verdict ?? "fail",
          row.action ?? "block",
          row.enforcementStatus ?? "enforced",
          row.latencyMs ?? 0,
          row.findingCount ?? 0,
          row.inputFingerprint ?? "hmac-sha256:unavailable",
          row.actionFingerprint ?? null,
          row.occurredAtUnix,
          JSON.stringify(row.document ?? {}),
        ),
    ];
    for (const check of row.checks ?? []) {
      statements.push(
        tenant
          .prepare(
            `INSERT INTO guardrail_check_evaluations
               (id, evaluation_id, tenant, check_id, detector_id, detector_version,
                config_digest, verdict, action, enforcement_status, error_kind, check_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
          )
          .bind(
            check.id,
            row.id,
            row.tenant,
            check.checkId,
            check.detectorId,
            check.detectorVersion,
            check.configDigest,
            check.verdict,
            check.action,
            check.enforcementStatus,
            check.errorKind ?? null,
            JSON.stringify(check.document ?? {}),
          ),
      );
    }
    await tenant.batch(statements);
  }
}

async function seedExactTenantRequestLog(
  requestId: string,
  tenantId: string,
  startedAtUnix: number,
): Promise<void> {
  const tenant = await exactTenantDatabase(tenantId);
  await tenant
    .prepare(
      `INSERT INTO request_logs
         (request_id, tenant, status_code, guardrail_verdict, started_at_unix, request_json)
       VALUES (?, ?, 403, 'blocked', ?, '{}')`,
    )
    .bind(requestId, tenantId, startedAtUnix)
    .run();
}

/** One complete evaluation row, carrying every fact #665's "Done when" names. */
const BLOCKED = {
  id: "fg-block-1/secret-scan@1/request",
  requestId: "fg-block-1",
  traceId: "0af7651916cd43dd8448eb211c80319c",
  tenant: "t-1",
  subjectId: "key_t-1",
  scopeType: "organization",
  scopeId: "t-1",
  target: "gpt-4o-mini/openai",
  protocol: "chat_completions",
  stage: "request",
  mode: "enforce",
  policyId: "secret-scan",
  policyRevision: 1,
  verdict: "fail",
  action: "block",
  enforcementStatus: "enforced",
  latencyMs: 3,
  findingCount: 1,
  occurredAtUnix: 1_700_000_100,
  inputFingerprint: "hmac-sha256:deadbeef",
  document: {
    object: "guardrail_evaluation",
    finding_category_counts: { aws_access_key_id: 1 },
    transformed: false,
  },
  checks: [
    {
      id: "fg-block-1/secret-scan@1/request/deterministic",
      checkId: "deterministic",
      detectorId: "deterministic",
      detectorVersion: "deterministic-1",
      configDigest: "sha256:abcd1234",
      verdict: "fail",
      action: "block",
      enforcementStatus: "enforced",
      document: {
        finding_count: 1,
        findings: [
          {
            category: "aws_access_key_id",
            severity: "critical",
            confidence: 0.99,
            segment_id: "chat:0",
            byte_start: 13,
            byte_end: 33,
            redacted_excerpt: "[aws_access_key_id] chat:0:13..33 ********************",
          },
        ],
      },
    },
  ],
} as const;

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    // Both tenant keys hold the evidence-read action; without it the endpoint
    // answers 403 and every fence assertion below would pass VACUOUSLY — a
    // tenant that cannot reach the endpoint at all proves nothing about what it
    // would see if it could.
    rbac: {
      "t-1": ["guardrails.evidence.read"],
      "t-2": ["guardrails.evidence.read"],
    },
  });
  await clearExactTenantEvidence();
});

describe("GET /admin/v1/guardrail-evaluations returns the evidence the tables hold", () => {
  it("returns a seeded decision with its detector, rule, confidence and REDACTED excerpt", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect((await readEvaluations(operatorKey.secret)).data).toHaveLength(0);

    await seedGuardrailEvaluations([BLOCKED]);

    const page = await readEvaluations(operatorKey.secret);
    expect(page.data).toHaveLength(1);
    const row = page.data[0] as Record<string, unknown>;
    expect(row).toMatchObject({
      object: "guardrail_evaluation",
      id: BLOCKED.id,
      request_id: "fg-block-1",
      trace_id: BLOCKED.traceId,
      tenant_id: "t-1",
      subject_id: "key_t-1",
      policy_id: "secret-scan",
      policy_revision: 1,
      stage: "request",
      mode: "enforce",
      verdict: "fail",
      action: "block",
      enforcement_status: "enforced",
      target: "gpt-4o-mini/openai",
      protocol: "chat_completions",
      latency_ms: 3,
      finding_count: 1,
      input_fingerprint: "hmac-sha256:deadbeef",
      occurred_at_unix: 1_700_000_100,
    });

    // The CHILD rows are joined in — an evaluation without its checks answers
    // "the policy blocked" and not "which detector, and on what".
    const checks = row.checks as Record<string, unknown>[];
    expect(checks).toHaveLength(1);
    expect(checks[0]).toMatchObject({
      check_id: "deterministic",
      detector_id: "deterministic",
      detector_version: "deterministic-1",
      config_digest: "sha256:abcd1234",
      verdict: "fail",
    });
    const findings = (checks[0] as Record<string, unknown>).findings as Record<string, unknown>[];
    expect(findings[0]).toMatchObject({
      category: "aws_access_key_id",
      confidence: 0.99,
      byte_start: 13,
      byte_end: 33,
    });
    expect(String(findings[0]?.redacted_excerpt)).toContain("aws_access_key_id");
  });

  /**
   * NEWEST FIRST, `id` as the tiebreaker. `occurred_at_unix` is whole SECONDS
   * and one request produces several evaluations inside one of them, so an
   * unstable sort lets a page boundary re-serve one row and skip another.
   */
  it("orders newest first with id as the tiebreaker", async () => {
    await seedGuardrailEvaluations([
      { ...BLOCKED, id: "ev-b", requestId: "r-b", occurredAtUnix: 200, checks: [] },
      { ...BLOCKED, id: "ev-a", requestId: "r-a", occurredAtUnix: 200, checks: [] },
      { ...BLOCKED, id: "ev-c", requestId: "r-c", occurredAtUnix: 300, checks: [] },
    ]);
    const page = await readEvaluations(operatorKey.secret);
    expect(page.data.map((row) => row.id)).toEqual(["ev-c", "ev-a", "ev-b"]);
  });

  it("reports the pre-window total alongside the page", async () => {
    await seedGuardrailEvaluations(
      Array.from({ length: 5 }, (_unused, index) => ({
        ...BLOCKED,
        id: `ev-${index}`,
        requestId: `r-${index}`,
        occurredAtUnix: 1_000 + index,
        checks: [],
      })),
    );
    const page = await readEvaluations(operatorKey.secret, "?limit=2&offset=1");
    expect(page.data).toHaveLength(2);
    expect(page.total).toBe(5);
  });

  it("backfills pre-cutover control evidence before the tenant authority read", async () => {
    await seedGuardrailEvaluations([BLOCKED]);
    expect(
      await (await exactTenantDatabase("t-1"))
        .prepare("SELECT id FROM guardrail_evaluations")
        .all(),
    ).toMatchObject({ results: [] });

    const page = await readEvaluations("k-tenant");
    expect(page.data.map((row) => row.id)).toEqual([BLOCKED.id]);

    const tenant = await exactTenantDatabase("t-1");
    expect(
      await tenant
        .prepare("SELECT id, tenant FROM guardrail_evaluations WHERE id = ?")
        .bind(BLOCKED.id)
        .first(),
    ).toMatchObject({ id: BLOCKED.id, tenant: "t-1" });
    expect(
      await tenant
        .prepare(
          "SELECT id, evaluation_id FROM guardrail_check_evaluations WHERE evaluation_id = ?",
        )
        .bind(BLOCKED.id)
        .first(),
    ).toMatchObject({ id: BLOCKED.checks[0]?.id, evaluation_id: BLOCKED.id });
    const mark = await tenant
      .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
      .bind("t-1", GUARDRAIL_EVIDENCE_BACKFILL_MARK)
      .first<{ detail: string }>();
    expect(JSON.parse(mark?.detail ?? "{}")).toMatchObject({
      state: "complete",
      evaluations: 1,
      checks: 1,
    });
  });

  it("does not let a stale concurrent backfill write after completion", async () => {
    await seedGuardrailEvaluations([BLOCKED]);
    const realRouter = resolveTenantDatabases(env as unknown as ControlPlaneBindings);
    const realHandle = await realRouter.forTenant("t-1");

    let releaseFirstEvaluationRead!: () => void;
    const firstEvaluationReadReleased = new Promise<void>((resolve) => {
      releaseFirstEvaluationRead = resolve;
    });
    let firstEvaluationReadReady!: () => void;
    const firstEvaluationReadReached = new Promise<void>((resolve) => {
      firstEvaluationReadReady = resolve;
    });
    let evaluationReads = 0;
    const controlDb = {
      prepare(sql: string) {
        const prepared = db().prepare(sql);
        return {
          bind(...values: unknown[]) {
            const bound = prepared.bind(...values);
            return {
              async all<T>() {
                if (
                  sql.includes("FROM guardrail_evaluations") &&
                  sql.includes("ORDER BY projection_key ASC")
                ) {
                  evaluationReads += 1;
                  if (evaluationReads === 1) {
                    firstEvaluationReadReady();
                    await firstEvaluationReadReleased;
                  }
                }
                return bound.all<T>();
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    let tenantBatches = 0;
    let secondBatchFinished!: () => void;
    const secondBatchDone = new Promise<void>((resolve) => {
      secondBatchFinished = resolve;
    });
    const gatedTenantDb = {
      prepare: realHandle.db.prepare.bind(realHandle.db),
      async batch(statements: D1PreparedStatement[]) {
        const result = await realHandle.db.batch(statements);
        tenantBatches += 1;
        // The first object batch belongs to the second call because the first
        // call is still paused before its CONTROL page query executes.
        if (tenantBatches === 1) secondBatchFinished();
        return result;
      },
    } as unknown as D1Database;
    const router = {
      backend: realRouter.backend,
      control: () => realRouter.control(),
      provisionedTenants: () => realRouter.provisionedTenants(),
      forTenant: async () => ({ ...realHandle, db: gatedTenantDb }),
    } as TenantDatabaseRouter;

    const first = ensureTenantGuardrailEvidenceBackfill(controlDb, router, "t-1");
    await firstEvaluationReadReached;
    const second = ensureTenantGuardrailEvidenceBackfill(controlDb, router, "t-1");
    await secondBatchDone;

    // The second call completed the marker before this late projection row
    // existed. The first call has already read the page, but its object writes
    // must be guarded by the completed marker when it is released.
    await seedGuardrailEvaluations([
      { ...BLOCKED, id: "ev-late", requestId: "req-late", checks: [] },
    ]);
    releaseFirstEvaluationRead();
    await Promise.all([first, second]);

    const tenant = await exactTenantDatabase("t-1");
    const rows = await tenant
      .prepare("SELECT id FROM guardrail_evaluations ORDER BY id ASC")
      .all<{ id: string }>();
    expect(rows.results.map((row) => row.id)).toEqual([BLOCKED.id]);
  });
});

// ---------------------------------------------------------------------------
// The tenant fence — the property that must be proved by mutation, not read
// ---------------------------------------------------------------------------

describe("the tenant fence on guardrail evidence", () => {
  beforeEach(async () => {
    const rows = [
      { ...BLOCKED, id: "ev-t1", requestId: "req-t1", tenant: "t-1", checks: [] },
      { ...BLOCKED, id: "ev-t2", requestId: "req-t2", tenant: "t-2", checks: [] },
      // An UNATTRIBUTED row: screening on a request whose credential resolved no
      // tenant, i.e. a platform-operator call. It is nobody's tenant data.
      { ...BLOCKED, id: "ev-none", requestId: "req-none", tenant: null, checks: [] },
    ] as const;
    await seedGuardrailEvaluations(rows);
    await seedExactTenantGuardrailEvaluations(rows);
  });

  it("shows a tenant only its own evaluations", async () => {
    const page = await readEvaluations("k-tenant");
    expect(page.data.map((row) => row.id)).toEqual(["ev-t1"]);
  });

  it("shows the OTHER tenant only its own evaluations", async () => {
    const page = await readEvaluations("k-other");
    expect(page.data.map((row) => row.id)).toEqual(["ev-t2"]);
  });

  it("does not use a control-only row as a tenant authority fallback", async () => {
    // The first read completes the one-time pre-cutover copy. A later row that
    // exists only in CONTROL is projection lag, not migration input.
    await readEvaluations("k-tenant");
    await seedGuardrailEvaluations([
      {
        ...BLOCKED,
        id: "projection-only",
        requestId: "req-projection-only",
        tenant: "t-1",
        checks: [],
      },
    ]);
    const page = await readEvaluations("k-tenant");
    expect(page.data.map((row) => row.id)).toEqual(["ev-t1"]);

    const investigation = await investigate("k-tenant", "?request_id=req-projection-only");
    expect(investigation.status).toBe(404);
    expect(investigation.body).toMatchObject({
      error: { code: "guardrail_investigation_not_found" },
    });
  });

  /**
   * STRICT equality, so `NULL` matches nobody — the same narrowing
   * `requestLogTenantFence` documents.
   */
  it("never shows a tenant the un-attributed platform rows", async () => {
    for (const secret of ["k-tenant", "k-other"]) {
      const ids = (await readEvaluations(secret)).data.map((row) => row.id);
      expect(ids).not.toContain("ev-none");
    }
  });

  it("shows a platform operator every row", async () => {
    const ids = (await readEvaluations(operatorKey.secret)).data.map((row) => row.id);
    expect(ids.sort()).toEqual(["ev-none", "ev-t1", "ev-t2"]);
  });

  it("cannot be paged past", async () => {
    const page = await readEvaluations("k-tenant", "?limit=100&offset=0");
    expect(page.total).toBe(1);
    expect(page.data.map((row) => row.id)).toEqual(["ev-t1"]);
  });

  /**
   * The fence has to hold on the INVESTIGATION too, and there it is the
   * difference between a 404 and a cross-tenant disclosure of who called what
   * model and why it was blocked.
   */
  it("answers 404 when a tenant investigates ANOTHER tenant's request", async () => {
    const own = await investigate("k-tenant", "?request_id=req-t1");
    expect(own.status).toBe(200);

    const theirs = await investigate("k-tenant", "?request_id=req-t2");
    expect(theirs.status).toBe(404);
    expect(JSON.stringify(theirs.body)).not.toContain("ev-t2");
  });
});

// ---------------------------------------------------------------------------
// The investigation view
// ---------------------------------------------------------------------------

describe("GET /admin/v1/investigations joins one request's evidence", () => {
  it("answers a timeline carrying the request, the guardrail decision and the audit trail", async () => {
    await seedGuardrailEvaluations([BLOCKED]);
    await seedRequestLogs([
      {
        requestId: "fg-block-1",
        tenant: "t-1",
        startedAtUnix: 1_700_000_100,
        completedAtUnix: 1_700_000_100,
        statusCode: 403,
        logicalModel: "gpt-4o-mini",
        provider: "openai",
        guardrailVerdict: "blocked",
      },
    ]);
    await seedExactTenantRequestLog("fg-block-1", "t-1", 1_700_000_100);
    await seedAuditEvents([
      {
        id: "audit-1",
        requestId: "fg-block-1",
        tenant: "t-1",
        occurredAtUnix: 1_700_000_100,
        audit: { action: "guardrail.deny", outcome: "blocked", message: "blocked at chat:0" },
      },
    ]);

    const { status, body } = await investigate(operatorKey.secret, "?request_id=fg-block-1");
    expect(status).toBe(200);
    expect(body.object).toBe("guardrail_investigation");
    expect(body.selector).toBe("request_id=fg-block-1");
    expect((body.requests as unknown[]).length).toBe(1);
    expect((body.audit_events as unknown[]).length).toBe(1);

    const evaluations = body.guardrail_evaluations as Record<string, unknown>[];
    expect(evaluations).toHaveLength(1);
    expect(evaluations[0]).toMatchObject({ policy_id: "secret-scan", action: "block" });
    expect((evaluations[0]?.checks as unknown[]).length).toBe(1);

    // WHY / TARGET / ACTION, from the one response — `docs/guardrails/investigation-view.md`.
    expect(body.final_outcome).toBe("blocked");
    expect(body.total_cost_usd).toBe(0);
  });

  it("joins unscoped request ids into the control-owned billing leg", async () => {
    await seedRequestLogs([
      {
        requestId: "fg-platform-request",
        tenant: null,
        startedAtUnix: 1_700_000_200,
        statusCode: 200,
        route: "platform.route",
      },
    ]);
    await seedBillingEvents([
      {
        id: "billing-platform-request",
        requestId: "fg-platform-request",
        occurredAtUnix: 1_700_000_201,
        event: { cost_usd: 1.25 },
      },
    ]);

    const { status, body } = await investigate(
      operatorKey.secret,
      "?request_id=fg-platform-request",
    );
    expect(status).toBe(200);
    expect(body.requests).toEqual([
      expect.objectContaining({ request_id: "fg-platform-request", tenant_id: null }),
    ]);
    expect(body.billing_events).toEqual([
      expect.objectContaining({ request_id: "fg-platform-request", cost_usd: 1.25 }),
    ]);
    expect(body.total_cost_usd).toBe(1.25);
  });

  it("finds the same request by trace_id", async () => {
    await seedGuardrailEvaluations([BLOCKED]);
    const { status, body } = await investigate(operatorKey.secret, `?trace_id=${BLOCKED.traceId}`);
    expect(status).toBe(200);
    expect((body.guardrail_evaluations as unknown[]).length).toBe(1);
  });

  it("answers 404 with a typed code when nothing matches", async () => {
    const { status, body } = await investigate(operatorKey.secret, "?request_id=fg-nothing");
    expect(status).toBe(404);
    expect((body.error as Record<string, unknown>)?.code).toBe("guardrail_investigation_not_found");
  });

  it("refuses a request that names no selector", async () => {
    const { status } = await investigate(operatorKey.secret, "");
    expect(status).toBe(400);
  });
});
