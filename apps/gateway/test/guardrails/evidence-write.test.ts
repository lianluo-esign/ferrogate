import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
/**
 * THE WRITER — a durable `guardrail_evaluations` row for every screening
 * decision, end to end on real Cloudflare bindings (#665).
 *
 * ## The defect
 *
 * There was no writer, and there was no table. `InMemoryGuardrailEvidenceSink`
 * held every evaluation in the isolate and the isolate threw them away; zero
 * `INSERT INTO guardrail_evaluations` anywhere in `apps/<app>/src` because
 * `sql/d1-ts/` had no such table to insert into. Meanwhile
 * `GET /admin/v1/guardrail-evaluations` and `GET /admin/v1/investigations`
 * answered — authenticated, RBAC-gated, contract-conformant — that nothing had
 * ever been screened. A blocked request could not be investigated.
 *
 * ## What is real here, and what is not
 *
 * Real: the composed gateway (`createGatewayApp`), the contract router, the
 * auth guard, the REAL guardrail middleware over a REAL `PolicyRevision` and
 * the REAL deterministic secret detector from `@ferrogate/guardrails`, the
 * `CONTROL_DB` D1 binding `wrangler.toml` declares, the deployed migration, and
 * an `ExecutionContext` created by `cloudflare:test` so `waitUntil` is the real
 * one. Nothing about a detector is stubbed to a convenient verdict, and nothing
 * here seeds the evidence tables: every row an assertion finds was put there by
 * an HTTP request flowing through the real middleware chain.
 *
 * ## The two properties this file exists for
 *
 *  1. **The evidence is DURABLE.** A blocked request leaves a row, with its
 *     policy, stage, verdict, action, tenant, detector and confidence.
 *  2. **The excerpt is REDACTED.** A guardrail that blocks a prompt for
 *     carrying a secret and then stores that secret verbatim in an evidence
 *     table an operator can list has MOVED the leak, not stopped it. Every
 *     assertion in "the stored evidence carries no plaintext" below reads the
 *     RAW STORED BYTES and looks for the probe secret in them.
 */
import type { GuardrailDetector } from "@ferrogate/guardrails";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GuardrailEvidenceEnvelope } from "../../src/guardrails/evidence-wire.js";
import {
  DurableGuardrailEvidenceSink,
  guardrailEvidencePlatformDatabaseFrom,
  guardrailEvidenceTenantDatabaseFromEnv,
  guardrails,
  sweepGuardrailEvidence,
  writePlatformGuardrailEvidence,
  writeTenantGuardrailEvidence,
} from "../../src/guardrails/index.js";
import { gatewayScheduled } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import { consumeRequestLogBatch } from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { RecordingQueue, applyControlMigrations } from "../requestlog/harness.js";
import type { StoredGuardrailCheck, StoredGuardrailEvaluation } from "../requestlog/harness.js";
import {
  EVIDENCE_HMAC_KEY,
  PROBE_SECRET,
  bodyWithProbeSecret,
  cleanBody,
  secretScanPolicy,
  sourceFor,
} from "./fixtures.js";

const BASE = "https://gw.test";

/**
 * A tenant-scoped native key carrying the inference scopes, declared here for
 * the reason `test/requestlog/write.test.ts` gives: the shared fixture keys are
 * tool/skill scoped, so an inference request made with one answers `403
 * scope_denied` before any guardrail runs — and a suite asserting on screening
 * evidence would then be asserting on nothing.
 */
const GUARDRAIL_TENANT_KEY = JSON.stringify([
  {
    key: "fg_guard_tenant",
    id: "key_guard_tenant",
    tenant_id: "tenant_a",
    project_id: "project_guard",
    scopes: ["chat.completions", "messages.create", "models.read"],
  },
]);

const AUTHED = {
  authorization: "Bearer fg_guard_tenant",
  "content-type": "application/json",
};

function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

interface Harness {
  readonly evidence: DurableGuardrailEvidenceSink;
  readonly queue: RecordingQueue;
  call(path: string, init: RequestInit): Promise<Response>;
  settle(): Promise<void>;
}

/**
 * The composition root, on real bindings — the same shape `src/index.ts` builds
 * when `CONTROL_DB` is bound.
 */
function gateway(
  options: {
    requestId?: string;
    queue?: RecordingQueue;
    policy?: ReturnType<typeof secretScanPolicy>;
    detectorOverrides?: Parameters<typeof sourceFor>[1];
  } = {},
): Harness {
  const queue = options.queue ?? new RecordingQueue();
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    TENANT_DATA: env.TENANT_DATA,
    // Only bound when the test asked for the queue arm; otherwise the sink
    // takes the direct-D1 arm, which is the `wrangler dev --local` posture.
    ...(options.queue === undefined ? { REQUEST_LOG: undefined } : { REQUEST_LOG: queue }),
    GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
  };

  const evidence = new DurableGuardrailEvidenceSink();
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        ...(options.requestId === undefined
          ? {}
          : { requestIds: fixedRequestIds(options.requestId) }),
      }),
    ],
    middleware: [
      guardrails({
        policies: sourceFor(options.policy ?? secretScanPolicy(), options.detectorOverrides ?? {}),
        evidence,
        evidenceHmacKey: EVIDENCE_HMAC_KEY,
        providerForModel: () => "openai",
      }),
    ],
  });

  let context: ExecutionContext | undefined;
  return {
    evidence,
    queue,
    async call(path, init): Promise<Response> {
      context = createExecutionContext();
      return app.fetch(new Request(`${BASE}${path}`, init), bindings, context);
    },
    async settle(): Promise<void> {
      if (context !== undefined) await waitOnExecutionContext(context);
    },
  };
}

function chatBody(body: Record<string, unknown>): string {
  return JSON.stringify({ ...body, model: "gpt-4o-mini" });
}

function manualEnvelope(tenantId: string): GuardrailEvidenceEnvelope {
  return {
    evaluation: {
      id: "same-evaluation-id",
      requestId: `request-${tenantId}`,
      tenant: { organizationId: tenantId },
      scopeType: "organization",
      scopeId: tenantId,
      target: "gpt-4o-mini/openai",
      protocol: "chat_completions",
      stage: "request",
      mode: "enforce",
      policyId: "secret-scan",
      policyRevision: 1,
      verdict: "pass",
      action: "allow",
      enforcementStatus: "enforced",
      latencyMs: 1,
      findingCategoryCounts: {},
      findingCount: 0,
      transformed: false,
      inputFingerprint: `hmac-sha256:${tenantId}`,
      occurredAtUnix: 1_700_000_200,
    },
    checks: [],
  };
}

/**
 * An UNSCOPED (`scope_type = 'platform'`) envelope: no `organizationId`, so the
 * sink's `flush` routes it to the PLATFORM_DATA singleton — and, in G1, still
 * dual-writes the control projection. Carries one check so the child-row leg is
 * exercised too, and pins `occurredAtUnix` old enough for the retention test.
 */
function platformEnvelope(id: string): GuardrailEvidenceEnvelope {
  return {
    evaluation: {
      id,
      requestId: `request-${id}`,
      // No organization — the whole point: this row has no owning tenant object.
      tenant: {},
      scopeType: "platform",
      scopeId: "platform",
      target: "gpt-4o-mini/openai",
      protocol: "chat_completions",
      stage: "request",
      mode: "enforce",
      policyId: "secret-scan",
      policyRevision: 1,
      verdict: "pass",
      action: "allow",
      enforcementStatus: "enforced",
      latencyMs: 1,
      findingCategoryCounts: {},
      findingCount: 0,
      transformed: false,
      inputFingerprint: `hmac-sha256:${id}`,
      occurredAtUnix: 1_700_000_200,
    },
    checks: [
      {
        id: `${id}/deterministic`,
        evaluationId: id,
        checkId: "deterministic",
        detectorId: "deterministic",
        detectorVersion: "det-1",
        configDigest: "sha256:platform",
        verdict: "pass",
        action: "allow",
        enforcementStatus: "enforced",
        latencyMs: 1,
        findingCategoryCounts: {},
        findingCount: 0,
        findings: [],
        transformed: false,
        usedFallback: false,
      },
    ],
  };
}

async function tenantGuardrailRows(tenantId: string): Promise<{
  evaluations: Record<string, unknown>[];
  checks: Record<string, unknown>[];
}> {
  const object = env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenantId));
  // SELECT * so the same helper serves both the identity assertions and the
  // headline/redaction tests that read the full row now that the tenant object
  // — not the retired control projection — is where attributed evidence lands.
  const evaluations = await object.query({
    tenantId,
    sql: "SELECT * FROM guardrail_evaluations ORDER BY occurred_at_unix ASC, id ASC",
  });
  const checks = await object.query({
    tenantId,
    sql: "SELECT * FROM guardrail_check_evaluations ORDER BY evaluation_id ASC, check_id ASC",
  });
  return { evaluations: evaluations.results, checks: checks.results };
}

async function resetTenantGuardrailEvidence(tenantId: string): Promise<void> {
  const object = env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenantId));
  await object.batch({
    tenantId,
    statements: [
      { sql: "DELETE FROM guardrail_check_evaluations" },
      { sql: "DELETE FROM guardrail_evaluations" },
    ],
  });
}

/**
 * The platform object's rows, read through the SAME facade the production write
 * and read paths use (`guardrailEvidencePlatformDatabaseFrom`). The whole table
 * IS the platform domain, so there is no tenant fence — every row here is
 * unattributed by construction.
 */
async function platformGuardrailRows(): Promise<{
  evaluations: Record<string, unknown>[];
  checks: Record<string, unknown>[];
}> {
  const db = guardrailEvidencePlatformDatabaseFrom(env);
  if (db === undefined) throw new Error("PLATFORM_DATA binding is required");
  const evaluations = (await db
    .prepare("SELECT * FROM guardrail_evaluations ORDER BY occurred_at_unix ASC, id ASC")
    .bind()
    .all()) as { results: Record<string, unknown>[] };
  const checks = (await db
    .prepare("SELECT * FROM guardrail_check_evaluations ORDER BY evaluation_id ASC, check_id ASC")
    .bind()
    .all()) as { results: Record<string, unknown>[] };
  return { evaluations: evaluations.results, checks: checks.results };
}

async function resetPlatformGuardrailEvidence(): Promise<void> {
  const db = guardrailEvidencePlatformDatabaseFrom(env);
  if (db === undefined) return;
  // Children first: the FK on `guardrail_check_evaluations.evaluation_id` rejects
  // deleting parents ahead of their checks on a database with enforcement on.
  await db.batch([
    db.prepare("DELETE FROM guardrail_check_evaluations").bind(),
    db.prepare("DELETE FROM guardrail_evaluations").bind(),
  ]);
}

let provider: ProviderInterceptor | undefined;

beforeAll(applyControlMigrations);

beforeEach(async () => {
  // 0045 (Track A) DROPPED the control `guardrail_evaluations` /
  // `guardrail_check_evaluations` mirrors; only the tenant and platform objects
  // remain, so only those are reset here.
  await resetTenantGuardrailEvidence("tenant_a");
  await resetTenantGuardrailEvidence("tenant_b");
  await resetPlatformGuardrailEvidence();
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// The headline: a blocked request leaves a row an operator can investigate
// ---------------------------------------------------------------------------

describe("a BLOCKED request produces durable evidence", () => {
  it("records the policy, stage, verdict, action, tenant and detector", async () => {
    // Track A retired the control projection; attributed evidence is now
    // authoritative in the owning tenant object, so the row is read from there.
    // Empty first, so the row below cannot be a leftover.
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(0);

    const h = gateway({ requestId: "fg-blocked-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    expect(response.status, await response.clone().text()).toBe(403);
    await h.settle();

    // The owning object is where a tenant-scoped reader gets the evidence without
    // trusting a shared-D1 fallback — the sole authoritative home now.
    const authoritative = await tenantGuardrailRows("tenant_a");
    const rows = authoritative.evaluations as unknown as StoredGuardrailEvaluation[];
    expect(rows).toHaveLength(1);
    const row = rows[0] as StoredGuardrailEvaluation;
    expect(row.tenant).toBe("tenant_a");
    expect(authoritative.checks).toEqual([
      expect.objectContaining({ evaluation_id: row.id, tenant: "tenant_a" }),
    ]);

    // The join key an incident report carries: the id the CLIENT was told.
    //
    // Read off the response rather than pinned to a fixture, because for a
    // BLOCKED request it cannot be pinned — `inferenceRouteModule`'s
    // `requestIds` factory belongs to a route the guardrail refuses to reach,
    // so the id here is the one `middleware/errors.ts::requestId` minted. That
    // the two agree is the whole assertion: an evidence row carrying an id the
    // caller was never given is an evidence row nobody can find.
    expect(row.request_id).toBe(response.headers.get("x-request-id"));
    expect(row.request_id.length).toBeGreaterThan(0);

    // WHO — the AUTHENTICATED tenant off the credential, never a header.
    expect(row.tenant).toBe("tenant_a");
    expect(row.subject_id).toBe("key_guard_tenant");

    // WHY — the policy, its revision, and what it decided.
    expect(row.policy_id).toBe("secret-scan");
    expect(row.policy_revision).toBe(1);
    expect(row.stage).toBe("request");
    expect(row.mode).toBe("enforce");
    expect(row.verdict).toBe("fail");
    expect(row.action).toBe("block");
    expect(row.enforcement_status).toBe("enforced");
    expect(row.finding_count).toBeGreaterThan(0);

    // The keyed, non-reversible identity of the screened content.
    expect(row.input_fingerprint).toMatch(/^hmac-sha256:[0-9a-f]+$/);

    // WHICH DETECTOR — the child row, with its version and config digest.
    const checks = authoritative.checks as unknown as StoredGuardrailCheck[];
    expect(checks).toHaveLength(1);
    const check = checks[0] as StoredGuardrailCheck;
    expect(check.evaluation_id).toBe(row.id);
    expect(check.check_id).toBe("deterministic");
    expect(check.verdict).toBe("fail");
    // The digest of the detector's own configuration, so an auditor can tell a
    // rule that was retuned from one that was not. Asserted non-empty rather
    // than against a `sha256:` prefix because `detectorConfigDigest` produces a
    // bare 4-byte hex prefix today — a pre-existing divergence from the
    // `ports.ts` docstring that this slice does not silently change.
    expect(check.config_digest.length).toBeGreaterThan(0);

    // …and the per-finding detail the "Done when" names: category, confidence,
    // and a REDACTED excerpt.
    const document = JSON.parse(check.check_json) as {
      findings?: { category: string; confidence?: number; redacted_excerpt?: string }[];
    };
    const finding = document.findings?.[0];
    expect(finding).toBeDefined();
    // The detector's own category token, sanitized but not renamed.
    expect(finding?.category).toBe("secret.aws_access_key_id");
    expect(finding?.confidence).toBeGreaterThan(0);
    expect(typeof finding?.redacted_excerpt).toBe("string");
  });

  /**
   * An ALLOW is evidence too. A trail that only records refusals cannot answer
   * "was this request screened at all", and `not_screened` and `allowed` are
   * the two answers a compliance review actually cares about telling apart.
   */
  it("records a request the policy PASSED", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const h = gateway({ requestId: "fg-allowed-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(cleanBody()),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();

    // Track A: the passed evaluation is authoritative in the tenant object.
    const rows = (await tenantGuardrailRows("tenant_a")).evaluations;
    expect(rows.map((entry) => entry.verdict)).toContain("pass");
    const requestId = response.headers.get("x-request-id");
    expect(rows.every((entry) => entry.request_id === requestId)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// THE property: the stored excerpt must not carry the thing that was blocked
// ---------------------------------------------------------------------------

describe("the stored evidence carries no plaintext", () => {
  it("never writes the secret that caused the block into any column", async () => {
    const h = gateway({ requestId: "fg-secret-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    expect(response.status).toBe(403);
    await h.settle();

    // Track A: read the RAW stored bytes from the authoritative tenant object.
    const { evaluations: rows, checks } = await tenantGuardrailRows("tenant_a");
    expect(rows).toHaveLength(1);
    expect(checks).toHaveLength(1);

    // Every byte of both rows, as stored. Not a projection of them — a
    // projection is exactly where a leak hides.
    const stored = JSON.stringify({ rows, checks });
    expect(stored).not.toContain(PROBE_SECRET);
    // …and not a fragment of it either: the secret's distinctive body would
    // identify the credential just as well as the whole string.
    expect(stored).not.toContain(PROBE_SECRET.slice(4));
    expect(stored).not.toContain("please store");

    // The excerpt is present and is a MASK — it says how wide the match was and
    // what it was, and nothing about what it said.
    const document = JSON.parse((checks[0] as { check_json: string }).check_json) as {
      findings?: { redacted_excerpt?: string }[];
    };
    const excerpt = document.findings?.[0]?.redacted_excerpt ?? "";
    expect(excerpt).toContain("aws_access_key_id");
    expect(excerpt).toMatch(/\*/);
    expect(excerpt).not.toContain(PROBE_SECRET);
  });

  /**
   * The case above cannot fail on its own, and saying so is the point.
   *
   * `packages/guardrails/src/deterministic.ts:364` hard-codes `matched_text:
   * null`, so the built-in scanner never HANDS the gateway the matched value —
   * an excerpt built from a detector that carries nothing carries nothing no
   * matter how it is built. Every OTHER detector is a different story:
   * `Finding.matched_text` is part of the public `DetectorResult` contract
   * (`contract.ts:89`) and an external detector — `custom_http`, Presidio, a
   * customer's own — is free to populate it.
   *
   * So this case scripts exactly that: a detector that returns the secret in
   * `matched_text`, as a hostile or merely verbose one would, and asserts the
   * stored bytes still do not contain it. This is the case that goes RED when
   * `sanitizedFindings` is made to trust the detector, and it is therefore the
   * one that actually holds the invariant.
   */
  it("drops matched_text even when the DETECTOR hands it over", async () => {
    const leaky: GuardrailDetector = {
      descriptor: () => ({
        id: "leaky",
        version: "leaky-1",
        supports_request: true,
        supports_response: true,
        supports_transform: false,
        supported_sources: ["user"],
        credential: "none",
        data_residency: "in_repo",
        max_payload_bytes: 65_536,
        declared_failure_modes: [],
      }),
      health: () => ({
        circuit_open: false,
        consecutive_failures: 0,
        in_flight: 0,
        request_total: 1,
        success_total: 1,
        failure_total: 0,
      }),
      evaluate: () =>
        Promise.resolve({
          verdict: "fail",
          findings: [
            {
              category: "secret.aws_access_key_id",
              severity: "critical",
              confidence: 0.99,
              segment_id: "chat:0",
              byte_start: 13,
              byte_end: 13 + PROBE_SECRET.length,
              fingerprint: null,
              // The whole point: the detector volunteers the raw value.
              matched_text: PROBE_SECRET,
              // …and a second smuggling channel, arbitrary JSON.
              attributes: { sample: PROBE_SECRET },
            },
          ],
          patches: [],
          detector_version: "leaky-1",
        }),
    };

    const h = gateway({ detectorOverrides: { deterministic: leaky } });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    expect(response.status).toBe(403);
    await h.settle();

    // Track A: read the RAW stored bytes from the authoritative tenant object.
    const { evaluations: rows, checks } = await tenantGuardrailRows("tenant_a");
    expect(rows).toHaveLength(1);
    expect(checks).toHaveLength(1);

    const stored = JSON.stringify({ rows, checks });
    expect(stored).not.toContain(PROBE_SECRET);
    expect(stored).not.toContain(PROBE_SECRET.slice(4));

    // The finding IS recorded — dropping the evidence entirely would be the
    // other way to pass this test and would defeat the issue.
    const document = JSON.parse((checks[0] as { check_json: string }).check_json) as {
      findings?: { category?: string; confidence?: number; redacted_excerpt?: string }[];
    };
    expect(document.findings?.[0]?.category).toBe("secret.aws_access_key_id");
    expect(document.findings?.[0]?.confidence).toBe(0.99);
    expect(document.findings?.[0]?.redacted_excerpt).toContain("*");
  });
});

// ---------------------------------------------------------------------------
// The Queue arm — the same producer/consumer pair #664 built
// ---------------------------------------------------------------------------

describe("the Queue producer/consumer pair carries guardrail evidence too", () => {
  it("sends to REQUEST_LOG instead of writing D1 inline when the queue is bound", async () => {
    const queue = new RecordingQueue();
    const h = gateway({ queue });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    await h.settle();

    expect(queue.sent.length).toBeGreaterThan(0);
    // The hot path is off the write, so the tenant object is still empty here.
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(0);

    // …and the SAME consumer #664 built is what lands it — in the tenant object,
    // the sole authoritative home now that the control projection is retired.
    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    expect(result.malformed).toBe(0);
    expect(result.retried).toBe(false);

    const rows = (await tenantGuardrailRows("tenant_a")).evaluations;
    expect(rows).toHaveLength(1);
    expect(rows[0]?.request_id).toBe(response.headers.get("x-request-id"));
    expect(rows).toEqual([expect.objectContaining({ tenant: "tenant_a" })]);
  });

  /** At-least-once delivery: the second copy must not fail, and must not double. */
  it("is idempotent on redelivery", async () => {
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-redelivered", queue });
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    await h.settle();

    const messages = queue.sent.map((body) => ({ body }));
    await consumeRequestLogBatch({ messages }, env);
    await consumeRequestLogBatch({ messages }, env);

    // At-least-once, but the id-keyed upsert means the tenant object holds one row.
    const { evaluations, checks } = await tenantGuardrailRows("tenant_a");
    expect(evaluations).toHaveLength(1);
    expect(checks).toHaveLength(1);
  });

  // Deleted: "stops the guardrail control projection while keeping the tenant
  // object" — Track A retired the control mirror and the `projectGuardrailToControl`
  // consumer option, so the consumer now writes ONLY the tenant object
  // unconditionally (proven by the two cases above); the flag it toggled is gone.
});

describe("tenant-qualified evidence identity", () => {
  it("does not overwrite same logical ids across tenant objects", async () => {
    await resetTenantGuardrailEvidence("tenant_b");
    const sink = new DurableGuardrailEvidenceSink();
    expect(sink.append(manualEnvelope("tenant_a").evaluation, [])).toBe(true);
    expect(sink.append(manualEnvelope("tenant_b").evaluation, [])).toBe(true);

    await sink.flush({
      env: {
        ...(env as unknown as Record<string, unknown>),
        REQUEST_LOG: undefined,
      },
    });

    const tenantA = await tenantGuardrailRows("tenant_a");
    const tenantB = await tenantGuardrailRows("tenant_b");
    expect(tenantA.evaluations).toEqual([
      expect.objectContaining({ id: "same-evaluation-id", tenant: "tenant_a" }),
    ]);
    expect(tenantB.evaluations).toEqual([
      expect.objectContaining({ id: "same-evaluation-id", tenant: "tenant_b" }),
    ]);
    // Track A retired the shared control projection; the two objects being the
    // sole homes is exactly why the shared logical id cannot collide any more.
  });
});

// ---------------------------------------------------------------------------
// The platform dual-write leg (Zero-D1 Plan B, G1)
// ---------------------------------------------------------------------------

describe("unscoped evidence lands in the platform object", () => {
  it("writes the parent and child to PLATFORM_DATA, both tenant NULL", async () => {
    // Empty first, so nothing below can be a leftover.
    expect((await platformGuardrailRows()).evaluations).toHaveLength(0);

    const sink = new DurableGuardrailEvidenceSink();
    const envelope = platformEnvelope("platform-ev-1");
    expect(sink.append(envelope.evaluation, envelope.checks)).toBe(true);
    await sink.flush({
      env: { ...(env as unknown as Record<string, unknown>), REQUEST_LOG: undefined },
    });

    // Track A retired the control projection; the platform object is the SOLE
    // authoritative home for these rows: parent AND child, both `tenant` NULL —
    // the whole object is the platform domain, so nothing carries an org id.
    const platform = await platformGuardrailRows();
    expect(platform.evaluations).toEqual([
      expect.objectContaining({
        id: "platform-ev-1",
        request_id: "request-platform-ev-1",
        tenant: null,
        scope_type: "platform",
      }),
    ]);
    expect(platform.checks).toEqual([
      expect.objectContaining({
        id: "platform-ev-1/deterministic",
        evaluation_id: "platform-ev-1",
        tenant: null,
      }),
    ]);
  });

  it("counts a platform-object write failure and requeues it, never a control fallback", async () => {
    // A platform object that refuses every batch. Track A retired the control
    // mirror, so a failed platform write is the COUNTED authority failing: it
    // credits `failed` and requeues for the next flush rather than falling back
    // to a shared projection that no longer exists.
    const sink = new DurableGuardrailEvidenceSink({
      platformDatabase: () => ({
        prepare: () => ({
          bind: () => ({ run: async () => ({}), all: async () => ({ results: [] }) }),
        }),
        batch: async () => {
          throw new Error("platform object unavailable");
        },
      }),
    });
    const envelope = platformEnvelope("platform-ev-2");
    expect(sink.append(envelope.evaluation, envelope.checks)).toBe(true);
    // NEVER rejects, even when the authoritative leg throws.
    await sink.flush({
      env: { ...(env as unknown as Record<string, unknown>), REQUEST_LOG: undefined },
    });

    // The REAL platform object got nothing (the failing double intercepted the
    // write); the failure is counted and requeued for a later flush.
    expect((await platformGuardrailRows()).evaluations).toHaveLength(0);
    expect(sink.stats).toMatchObject({ written: 0, failed: 1, dropped: 0 });
    expect(sink.pending).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Track A / G2: the direct-fallback control mirror is retired
// (red line: no tenant/unattributed guardrail mirror in the control singleton)
// ---------------------------------------------------------------------------

describe("the direct fallback never writes the retired control mirror", () => {
  it("writes unscoped evidence ONLY to the platform object, never the control projection", async () => {
    // Empty first, so nothing below can be a leftover. (0045 DROPPED the control
    // guardrail-evidence mirror, so only the platform object is checked.)
    expect((await platformGuardrailRows()).evaluations).toHaveLength(0);

    // Track A retired the `projectToControl` option; the direct path writes only
    // the authoritative object unconditionally.
    const sink = new DurableGuardrailEvidenceSink();
    const envelope = platformEnvelope("platform-g2-1");
    expect(sink.append(envelope.evaluation, envelope.checks)).toBe(true);
    // No queue → the DIRECT fallback path, the one this flag governs.
    await sink.flush({
      env: { ...(env as unknown as Record<string, unknown>), REQUEST_LOG: undefined },
    });

    // PLATFORM_DATA is now the SOLE authoritative home for unscoped rows: parent
    // and child both land, both with `tenant` NULL.
    const platform = await platformGuardrailRows();
    expect(platform.evaluations).toEqual([
      expect.objectContaining({ id: "platform-g2-1", tenant: null }),
    ]);
    expect(platform.checks).toHaveLength(1);

    // RED LINE (retired): 0045 DROPPED the control guardrail-evidence mirror, so
    // there is no control singleton left to assert "receives NOTHING" against —
    // the platform object above is now the sole authoritative home.

    // The unscoped row that landed on the platform object is still COUNTED as
    // written now that the platform leg is the authority rather than an additive
    // shadow (in G1 the count came from the control write).
    expect(sink.stats.written).toBe(1);
  });

  it("writes tenant-scoped evidence ONLY to the tenant object, never the control projection", async () => {
    // (0045 DROPPED the control guardrail-evidence mirror; the tenant object is
    // the sole authoritative home and is asserted below.)
    const sink = new DurableGuardrailEvidenceSink();
    const envelope = manualEnvelope("tenant_a");
    expect(sink.append(envelope.evaluation, envelope.checks)).toBe(true);
    await sink.flush({
      env: { ...(env as unknown as Record<string, unknown>), REQUEST_LOG: undefined },
    });

    // The tenant object is the authoritative home for the evidence.
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toEqual([
      expect.objectContaining({ tenant: "tenant_a" }),
    ]);

    // RED LINE (retired): 0045 DROPPED the control guardrail-evidence mirror, so
    // there is no control singleton left to assert "receives NOTHING" against —
    // the tenant object above is now the sole authoritative home.
  });
});

// ---------------------------------------------------------------------------
// An evidence failure is never a request failure
// ---------------------------------------------------------------------------

describe("the data plane does not depend on the evidence path", () => {
  it("serves the request normally when the D1 write itself fails", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const stages: string[] = [];
    // Track A: the attributed request lands in the tenant object, so a failing
    // tenant-object resolver is what exercises the "D1 write fails" branch now.
    const evidence = new DurableGuardrailEvidenceSink({
      queue: () => undefined,
      tenantDatabase: () => ({
        prepare: () => ({
          bind: () => ({
            run: async () => {
              throw new Error("D1_ERROR");
            },
            all: async () => {
              throw new Error("D1_ERROR");
            },
          }),
        }),
        batch: async () => {
          throw new Error("D1_ERROR");
        },
      }),
      diagnostics: { onError: (stage) => stages.push(stage) },
    });
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [
        guardrails({
          policies: sourceFor(secretScanPolicy()),
          evidence,
          evidenceHmacKey: EVIDENCE_HMAC_KEY,
          providerForModel: () => "openai",
        }),
      ],
    });

    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(cleanBody()),
      }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);

    expect(stages).toEqual(["d1"]);
    expect(evidence.stats.failed).toBeGreaterThan(0);
  });

  it("retains a failed direct object batch for the next flush", async () => {
    const envelope = manualEnvelope("tenant_a");
    const authoritative = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_a");
    if (authoritative === undefined) throw new Error("TENANT_DATA binding is required");

    let attempts = 0;
    const failingObject = {
      prepare: () => ({
        bind: () => ({
          run: async () => ({}),
          all: async () => ({ results: [] }),
        }),
      }),
      batch: async () => {
        throw new Error("tenant object unavailable");
      },
    };
    const evidence = new DurableGuardrailEvidenceSink({
      queue: () => undefined,
      tenantDatabase: () => {
        attempts += 1;
        return attempts === 1 ? failingObject : authoritative;
      },
    });

    expect(evidence.append(envelope.evaluation, envelope.checks)).toBe(true);
    await evidence.flush({ env: {} });
    expect(evidence.pending).toBe(1);

    await evidence.flush({ env: {} });
    expect(evidence.pending).toBe(0);
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(1);
  });

  // Deleted: "retains a failed direct projection batch and persists it after
  // recovery" — Track A retired the shared control projection and the sink's
  // `database` fallback option, so there is no second (projection) database leg
  // to fail and recover; the tenant-object retry is covered by the case above.

  /**
   * With NO queue and NO control database the sink counts a `dropped` and the
   * request is served. Counted rather than silent: "no rows" and "no writer"
   * are indistinguishable from the admin API, which is the whole defect.
   */
  it("serves the request normally with no evidence binding at all", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const evidence = new DurableGuardrailEvidenceSink();
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [
        guardrails({
          policies: sourceFor(secretScanPolicy()),
          evidence,
          evidenceHmacKey: EVIDENCE_HMAC_KEY,
          providerForModel: () => "openai",
        }),
      ],
    });

    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(cleanBody()),
      }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
        REQUEST_LOG: undefined,
        CONTROL_DB: undefined,
        CONTROL_DATA: undefined,
        TENANT_DATA: undefined,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);
    expect(evidence.stats.dropped).toBeGreaterThan(0);
  });
});

describe("guardrail evidence retention", () => {
  const NOW = 1_800_000_000;

  it("prunes a tenant object under its per-tenant override, leaving others", async () => {
    const tenantA = manualEnvelope("tenant_a");
    const tenantB = {
      ...tenantA,
      evaluation: {
        ...tenantA.evaluation,
        requestId: "request-tenant_b",
        tenant: { organizationId: "tenant_b" },
      },
    };
    const objectA = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_a");
    const objectB = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_b");
    if (objectA === undefined || objectB === undefined) {
      throw new Error("TENANT_DATA binding is required");
    }
    await writeTenantGuardrailEvidence(objectA, [tenantA]);
    await writeTenantGuardrailEvidence(objectB, [tenantB]);

    // Track A retired the control mirror; the sweep now takes env + the roster.
    // An override sweeps its own object regardless of the roster, so tenant_b —
    // absent from both the override and the (empty) roster — is untouched.
    const result = await sweepGuardrailEvidence(
      {
        TENANT_DATA: env.TENANT_DATA,
        REQUEST_LOG_RETENTION_POLICIES: JSON.stringify({ tenant_a: { days: 30 } }),
      },
      [],
      NOW,
    );

    expect(result.pruned).toBe(1);
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(0);
    expect((await tenantGuardrailRows("tenant_b")).evaluations).toHaveLength(1);
  });

  it("discovers old tenant objects from the provisioned roster", async () => {
    const tenantA = manualEnvelope("tenant_a");
    const tenantB = manualEnvelope("tenant_b");
    const objectA = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_a");
    const objectB = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_b");
    if (objectA === undefined || objectB === undefined) {
      throw new Error("TENANT_DATA binding is required");
    }
    await writeTenantGuardrailEvidence(objectA, [tenantA]);
    await writeTenantGuardrailEvidence(objectB, [tenantB]);

    // Track A: discovery is the provisioned roster handed to the sweep, NOT a
    // `SELECT DISTINCT tenant` off the retired control mirror.
    const result = await sweepGuardrailEvidence(
      { TENANT_DATA: env.TENANT_DATA, REQUEST_LOG_RETENTION_DAYS: "30" },
      ["tenant_a", "tenant_b"],
      NOW,
    );

    expect(result.pruned).toBe(2);
    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(0);
    expect((await tenantGuardrailRows("tenant_b")).evaluations).toHaveLength(0);
  });

  // Deleted: "keeps the projection when it fails after the object was pruned" —
  // Track A retired the shared control projection and the sweep's projection-db
  // argument, so there is no second database leg to fail, keep, and reconcile on
  // a later tick; the surviving per-object pruning is covered by the cases above.

  it("runs tenant retention from Cron with TENANT_DATA and no CONTROL_DB", async () => {
    const envelope = manualEnvelope("tenant_a");
    const object = guardrailEvidenceTenantDatabaseFromEnv(env, "tenant_a");
    if (object === undefined) throw new Error("TENANT_DATA binding is required");
    await writeTenantGuardrailEvidence(object, [envelope]);

    const ctx = createExecutionContext();
    await gatewayScheduled(
      {},
      {
        TENANT_DATA: env.TENANT_DATA,
        REQUEST_LOG_RETENTION_POLICIES: JSON.stringify({ tenant_a: { days: 30 } }),
      },
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect((await tenantGuardrailRows("tenant_a")).evaluations).toHaveLength(0);
  });

  it("sweeps the platform object under the fleet policy", async () => {
    const envelope = platformEnvelope("platform-old-1");
    const platformDb = guardrailEvidencePlatformDatabaseFrom(env);
    if (platformDb === undefined) throw new Error("PLATFORM_DATA binding is required");
    await writePlatformGuardrailEvidence(platformDb, [envelope]);
    expect((await platformGuardrailRows()).evaluations).toHaveLength(1);

    // The fleet default governs the WHOLE platform object — no tenant fence, and
    // no second database to reconcile. An empty roster means ONLY the platform
    // leg runs here.
    const result = await sweepGuardrailEvidence(
      { ...(env as unknown as Record<string, unknown>), REQUEST_LOG_RETENTION_DAYS: "30" },
      [],
      NOW,
    );

    expect(result.pruned).toBeGreaterThanOrEqual(1);
    // Parent gone, and its check followed through `ON DELETE CASCADE`.
    expect((await platformGuardrailRows()).evaluations).toHaveLength(0);
    expect((await platformGuardrailRows()).checks).toHaveLength(0);
  });
});
