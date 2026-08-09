/**
 * The SIEM EXPORT PUMP (#683) — evidence egress with at-least-once delivery and
 * a replayable cursor, driven against a REAL `env.DB` and a REAL R2 binding.
 *
 * ## The defect this file pins
 *
 * `request_logs` (#664) and the hash-chained `audit_events` (#684) are the
 * authoritative evidence this platform keeps, and until this slice there was NO
 * EGRESS PATH out of D1. The only way out was a PULL — an operator polling
 * `GET /admin/v1/request-log-exports?offset=` forever — which means a customer's
 * Splunk/Datadog/S3 estate contains whatever a script last happened to fetch,
 * and nothing anywhere records how far a delivery actually got. Cloudflare
 * Logpush cannot close it either: Logpush ships CF's OWN datasets and has no
 * ingest for ours (`docs/cloudflare-observability.md`).
 *
 * ## The three properties, and why each is tested adversarially
 *
 *  1. **The tenant fence.** A sink belongs to exactly one tenant. Evidence for
 *     any other tenant — and un-attributed PLATFORM rows, which are the
 *     operator's own traffic — must never reach it. This is the failure that
 *     cannot be walked back: once a row is in a customer's SIEM it has left.
 *  2. **At-least-once with a replayable cursor.** A pump that skips a window is
 *     worse than no pump, because the gap is invisible in the DESTINATION —
 *     nothing there says "rows 400..600 never arrived". So the tests kill the
 *     pump mid-window and assert the union of everything delivered across ticks
 *     covers every row, with duplication confined to the interrupted batch.
 *  3. **Credentials never surface.** The sink credential is a `env://` REFERENCE
 *     in configuration, never a literal, and no report, log line or error may
 *     echo the resolved value — including when the sink itself echoes it back
 *     in an error body, which real HEC endpoints do.
 *
 * ## What this file does NOT prove
 *
 * Nothing is deployed. Real Splunk/Datadog endpoints, a real R2 bucket and the
 * Cron Trigger firing on Cloudflare's schedule are all unexercised here; what
 * is exercised is the pump, its cursor, its fence and its transports inside
 * workerd, against the committed migration.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveTenantDatabases } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import { SIEM_EXPORT_SINKS_VAR, parseSiemSinks } from "../src/siem/config.js";
import { advanceSiemCursor, readSiemCursor } from "../src/siem/cursor.js";
import { redactSecrets } from "../src/siem/destination.js";
import { type SiemExportReport, runSiemExportPass } from "../src/siem/pump.js";
import { applySchema, db, resetD1, seedAuditEvents, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

// ---------------------------------------------------------------------------
// Test world
// ---------------------------------------------------------------------------

const HEC_TOKEN = "s3cr3t-hec-token-must-never-be-logged";
const HEC_TOKEN_VAR = "ACME_SIEM_TOKEN";
const ENDPOINT = "https://splunk.example.com/services/collector/raw";

/** `now` for every pass. Every seeded row is older than the visibility lag. */
const NOW = 1_700_100_000;
/** Comfortably outside the default visibility lag, so rows are eligible. */
const OLD = NOW - 3_600;

type MutableEnv = Record<string, string | undefined>;

function bindings(): ControlPlaneBindings {
  return env as unknown as ControlPlaneBindings;
}

interface Delivery {
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly lines: Record<string, unknown>[];
}

const realFetch = globalThis.fetch;
let deliveries: Delivery[] = [];
/** Per-call responses; `undefined` entries fall through to 200. */
let responses: (Response | Error)[] = [];

/**
 * A stand-in customer sink installed over `globalThis.fetch`.
 *
 * Installed globally rather than injected as a fake transport so the REAL HTTP
 * transport — its headers, its body framing, its status handling — is the code
 * under test. An injected `deliver()` double would prove only that the pump
 * calls something.
 */
function installSink(): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input as RequestInfo, init);
    const body = await request.text();
    deliveries.push({
      url: request.url,
      headers: Object.fromEntries(request.headers.entries()),
      body,
      lines: body
        .split("\n")
        .filter((line) => line.trim() !== "")
        .map((line) => JSON.parse(line) as Record<string, unknown>),
    });
    const scripted = responses[deliveries.length - 1];
    if (scripted instanceof Error) throw scripted;
    if (scripted !== undefined) return scripted;
    return new Response("", { status: 200 });
  }) as typeof globalThis.fetch;
}

/** Every JSONL document handed to the sink, across every delivery so far. */
function deliveredDocuments(): Record<string, unknown>[] {
  return deliveries.flatMap((delivery) => delivery.lines);
}

function deliveredIds(): string[] {
  return deliveredDocuments().map((document) => String(document.id));
}

interface SinkOptions {
  readonly tenant?: string;
  readonly streams?: string[];
  readonly batchSize?: number;
  readonly maxBatches?: number;
  readonly replay?: { epoch: number; from_unix: number };
  readonly lag?: number;
}

/** Arm `SIEM_EXPORT_SINKS` with one HTTP sink. */
function armSink(options: SinkOptions = {}): void {
  (env as unknown as MutableEnv)[SIEM_EXPORT_SINKS_VAR] = JSON.stringify([
    {
      id: "acme-splunk",
      tenant: options.tenant ?? "acme",
      streams: options.streams ?? ["request_logs"],
      batch_size: options.batchSize ?? 2,
      max_batches_per_tick: options.maxBatches ?? 8,
      visibility_lag_seconds: options.lag,
      destination: {
        kind: "http",
        endpoint: ENDPOINT,
        auth: { header: "Authorization", prefix: "Splunk ", secret_ref: `env://${HEC_TOKEN_VAR}` },
      },
      replay: options.replay,
    },
  ]);
}

/** `n` request-log rows for `tenant`, one second apart, oldest first. */
function rows(tenant: string, prefix: string, count: number, from = OLD) {
  return Array.from({ length: count }, (_, index) => ({
    requestId: `${prefix}-${String(index).padStart(3, "0")}`,
    tenant,
    startedAtUnix: from + index,
    completedAtUnix: from + index,
    route: "openai.chat.completions",
    statusCode: 200,
    guardrailVerdict: "not_screened",
    document: { object: "request_log" },
  }));
}

type RequestLogSeed = ReturnType<typeof rows>[number];

/** Register the tenant and mirror the SIEM fixture into its authoritative object. */
async function seedTenantRequestLogs(
  tenantId: string,
  records: readonly RequestLogSeed[],
): Promise<void> {
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
  const tenant = (
    await resolveTenantDatabases(env as unknown as ControlPlaneBindings).forTenant(tenantId)
  ).db;
  await tenant.prepare("DELETE FROM request_logs").run();
  await tenant.batch(
    records.map((record) =>
      tenant
        .prepare(
          `INSERT INTO request_logs
             (request_id, tenant, started_at_unix, completed_at_unix, route, status_code,
              guardrail_verdict, request_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          record.requestId,
          tenantId,
          record.startedAtUnix,
          record.completedAtUnix ?? null,
          record.route ?? null,
          record.statusCode ?? null,
          "not_screened",
          JSON.stringify(record.document ?? {}),
        ),
    ),
  );
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  deliveries = [];
  responses = [];
  installSink();
  arm({ store: "d1", staticKeys: [operatorKey], nativeKeys: [tenantKey("k-acme", "acme")] });
  (env as unknown as MutableEnv)[HEC_TOKEN_VAR] = HEC_TOKEN;
  armSink();
});

afterEach(async () => {
  globalThis.fetch = realFetch;
  const mutable = env as unknown as MutableEnv;
  // Restored rather than left set: `test/env-var-drift.test.ts` measures the
  // committed `[vars]` against the RUNTIME values, and a leaked override here
  // would make that gate report a drift this file caused.
  mutable[SIEM_EXPORT_SINKS_VAR] = "[]";
  mutable[HEC_TOKEN_VAR] = undefined;
  await db().prepare("DELETE FROM siem_export_cursors").run();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// 1. The tenant fence
// ---------------------------------------------------------------------------

describe("the tenant fence on what leaves the platform", () => {
  it("delivers this tenant's rows and NEVER another tenant's or a platform row", async () => {
    await seedRequestLogs(rows("acme", "acme", 3));
    await seedRequestLogs(rows("globex", "globex", 3));
    await seedRequestLogs([
      // An un-attributed row: a PLATFORM-operator call. Strict equality means
      // NULL matches nobody, so this must not reach a tenant's SIEM either.
      {
        requestId: "platform-000",
        tenant: null,
        startedAtUnix: OLD,
        completedAtUnix: OLD,
        document: { object: "request_log" },
      },
    ]);

    const report = await runSiemExportPass(bindings(), NOW);

    expect(report.streams).toHaveLength(1);
    expect(report.streams[0]).toMatchObject({ sink: "acme-splunk", status: "delivered", rows: 3 });
    expect(deliveredIds().sort()).toEqual(["acme-000", "acme-001", "acme-002"]);
    // Stated over the raw bytes too, because a leak through the `request_json`
    // document rather than through a column would still be a leak.
    const bodies = deliveries.map((delivery) => delivery.body).join("\n");
    expect(bodies).not.toContain("globex");
    expect(bodies).not.toContain("platform-000");
  });

  it("cannot be configured without a tenant — an unfenced sink is rejected", () => {
    // The fence is not a call-site check that a future edit can forget: a sink
    // with no tenant does not PARSE, so no configuration can produce a read
    // that spans tenants.
    expect(() =>
      parseSiemSinks(JSON.stringify([{ id: "x", destination: { kind: "r2" } }])),
    ).toThrow(/tenant/i);
  });

  it("fences the audit stream the same way", async () => {
    armSink({ streams: ["audit_events"] });
    await seedAuditEvents([
      { id: "a-1", requestId: "r-1", tenant: "acme", occurredAtUnix: OLD, audit: { action: "x" } },
      {
        id: "b-1",
        requestId: "r-2",
        tenant: "globex",
        occurredAtUnix: OLD,
        audit: { action: "y" },
      },
      { id: "p-1", requestId: "r-3", tenant: null, occurredAtUnix: OLD, audit: { action: "z" } },
    ]);

    const report = await runSiemExportPass(bindings(), NOW);

    expect(report.streams[0]).toMatchObject({ stream: "audit_events", rows: 1 });
    expect(deliveredIds()).toEqual(["a-1"]);
  });
});

// ---------------------------------------------------------------------------
// 2. At-least-once delivery and the replayable cursor
// ---------------------------------------------------------------------------

describe("at-least-once delivery across a killed pump", () => {
  it("resumes at the cursor with no loss, and no duplication beyond one batch", async () => {
    await seedRequestLogs(rows("acme", "acme", 7));
    // Batches of 2: the third delivery of tick 1 fails. Everything the pump
    // acknowledged before it stays acknowledged; the failed batch is retried.
    responses[2] = new Response("upstream exploded", { status: 502 });

    const first = await runSiemExportPass(bindings(), NOW);
    expect(first.streams[0]).toMatchObject({ status: "failed", batches: 2, rows: 4 });

    const afterFirst = await readSiemCursor(db(), "acme-splunk", "request_logs");
    expect(afterFirst?.position).toEqual({ ts: OLD + 3, id: "acme-003" });

    const firstTickIds = deliveredIds();
    const second = await runSiemExportPass(bindings(), NOW);
    expect(second.streams[0]).toMatchObject({ status: "delivered" });

    const all = deliveredIds();
    const seeded = rows("acme", "acme", 7).map((row) => row.requestId);
    // NO LOSS: every seeded row reached the sink at least once.
    expect([...new Set(all)].sort()).toEqual([...seeded].sort());
    // BOUNDED DUPLICATION: only the batch that was in flight when the pump died.
    const duplicated = [...new Set(all.filter((id) => all.indexOf(id) !== all.lastIndexOf(id)))];
    expect(duplicated.sort()).toEqual(["acme-004", "acme-005"]);
    expect(firstTickIds).toEqual([
      "acme-000",
      "acme-001",
      "acme-002",
      "acme-003",
      "acme-004",
      "acme-005",
    ]);

    // A third tick has nothing left to do — the cursor is at the end.
    deliveries = [];
    const third = await runSiemExportPass(bindings(), NOW);
    expect(third.streams[0]).toMatchObject({ status: "idle", rows: 0 });
    expect(deliveries).toHaveLength(0);
  });

  it("re-delivers a batch whose ACK was lost, rather than skipping it", async () => {
    // The nastiest real failure: the sink RECEIVED the rows and the response
    // never came back. At-least-once means we re-send; silently advancing would
    // be the invisible gap this whole slice exists to prevent.
    await seedRequestLogs(rows("acme", "acme", 2));
    responses[0] = new Error("connection reset after send");

    const failed = await runSiemExportPass(bindings(), NOW);
    expect(failed.streams[0]).toMatchObject({ status: "failed", rows: 0 });
    expect(deliveredIds()).toEqual(["acme-000", "acme-001"]);
    expect(await readSiemCursor(db(), "acme-splunk", "request_logs")).toBeNull();

    await runSiemExportPass(bindings(), NOW);
    expect(deliveredIds()).toEqual(["acme-000", "acme-001", "acme-000", "acme-001"]);
  });

  it("holds back rows inside the visibility lag instead of stepping over them", async () => {
    // A row is written when the request COMPLETES but is keyed on when it
    // STARTED, so a slow request lands behind a cursor that has already moved
    // past its timestamp. The lag is what stops that from being a silent skip.
    await seedRequestLogs(rows("acme", "settled", 1, NOW - 3_600));
    await seedRequestLogs(rows("acme", "inflight", 1, NOW - 5));

    const first = await runSiemExportPass(bindings(), NOW);
    expect(first.streams[0]).toMatchObject({ rows: 1 });
    expect(deliveredIds()).toEqual(["settled-000"]);

    // Later, once the row is older than the lag, it is delivered — not skipped.
    const later = await runSiemExportPass(bindings(), NOW + 3_600);
    expect(later.streams[0]).toMatchObject({ rows: 1 });
    expect(deliveredIds()).toEqual(["settled-000", "inflight-000"]);
  });
});

describe("the replayable cursor", () => {
  it("re-delivers a window on demand, and rewinds exactly once per epoch", async () => {
    await seedRequestLogs(rows("acme", "acme", 4));
    await runSiemExportPass(bindings(), NOW);
    expect(deliveredIds()).toEqual(["acme-000", "acme-001", "acme-002", "acme-003"]);

    // The operator asks for the last two rows again — a SIEM outage, a
    // mis-configured index, a compliance re-ingest.
    deliveries = [];
    armSink({ replay: { epoch: 1, from_unix: OLD + 2 } });
    const replayed = await runSiemExportPass(bindings(), NOW);
    expect(replayed.streams[0]).toMatchObject({ status: "delivered", rows: 2 });
    expect(deliveredIds()).toEqual(["acme-002", "acme-003"]);

    // The SAME epoch must not rewind again on the next tick, or the pump would
    // replay forever and the sink would never converge.
    deliveries = [];
    const steady = await runSiemExportPass(bindings(), NOW);
    expect(steady.streams[0]).toMatchObject({ status: "idle", rows: 0 });
    expect(deliveries).toHaveLength(0);

    // A NEW epoch rewinds again.
    armSink({ replay: { epoch: 2, from_unix: OLD } });
    await runSiemExportPass(bindings(), NOW);
    expect(deliveredIds()).toEqual(["acme-000", "acme-001", "acme-002", "acme-003"]);
  });

  it("never moves backwards when a slower tick acknowledges an older batch", async () => {
    // Found by mutation: deleting the forward-only `WHERE` on the upsert left
    // every other test green, because nothing else drives two acknowledgements
    // out of order. D1 has no interactive transaction, so this IS the ordering
    // control — two overlapping ticks (a cron tick that overran, a retry) would
    // otherwise let the older one drag the cursor back over rows the newer one
    // already delivered, and every later tick would re-send them forever.
    await seedRequestLogs(rows("acme", "acme", 3));
    await runSiemExportPass(bindings(), NOW);
    const ahead = { ts: OLD + 2, id: "acme-002" };
    expect((await readSiemCursor(db(), "acme-splunk", "request_logs"))?.position).toEqual(ahead);

    // An older position, as a straggler tick would report it.
    await advanceSiemCursor(db(), {
      sinkId: "acme-splunk",
      stream: "request_logs",
      tenant: "acme",
      position: { ts: OLD, id: "acme-000" },
      rows: 1,
      replayEpoch: 0,
      now: NOW,
    });
    expect((await readSiemCursor(db(), "acme-splunk", "request_logs"))?.position).toEqual(ahead);

    // And the tiebreaker arm: the same second, a lower id.
    await advanceSiemCursor(db(), {
      sinkId: "acme-splunk",
      stream: "request_logs",
      tenant: "acme",
      position: { ts: OLD + 2, id: "acme-001" },
      rows: 1,
      replayEpoch: 0,
      now: NOW,
    });
    expect((await readSiemCursor(db(), "acme-splunk", "request_logs"))?.position).toEqual(ahead);
  });

  it("records the durable cursor an operator can read back", async () => {
    await seedRequestLogs(rows("acme", "acme", 3));
    await runSiemExportPass(bindings(), NOW);

    const cursor = await readSiemCursor(db(), "acme-splunk", "request_logs");
    expect(cursor).toMatchObject({
      sinkId: "acme-splunk",
      stream: "request_logs",
      tenant: "acme",
      position: { ts: OLD + 2, id: "acme-002" },
      delivered: 3,
    });
  });
});

// ---------------------------------------------------------------------------
// 3. Credentials
// ---------------------------------------------------------------------------

describe("the customer sink credential", () => {
  it("is sent to the sink and appears in no report, log or error", async () => {
    const logs: string[] = [];
    for (const level of ["log", "warn", "error", "info", "debug"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(
          args
            .map((arg) => (arg instanceof Error ? (arg.stack ?? arg.message) : String(arg)))
            .join(" "),
        );
      });
    }
    await seedRequestLogs(rows("acme", "acme", 2));
    // The sink echoes the credential back in its error body, which real HEC
    // endpoints do ("Invalid token: <token>"). A pump that pastes a response
    // body into its error message would leak it into the operator's log.
    responses[0] = new Response(`Invalid authorization: ${HEC_TOKEN}`, { status: 401 });

    const report = await runSiemExportPass(bindings(), NOW);

    expect(deliveries[0]?.headers.authorization).toBe(`Splunk ${HEC_TOKEN}`);
    expect(JSON.stringify(report)).not.toContain(HEC_TOKEN);
    expect(logs.join("\n")).not.toContain(HEC_TOKEN);
    expect(report.streams[0]?.error ?? "").toMatch(/401/);
    // THE PRIMARY CONTROL, asserted separately from its outcome: the response
    // BODY is never consumed at all. Without this line the test passes even
    // when the body IS pasted into the error message, because `redactSecrets`
    // then removes the token on the way out — measured, not assumed: reverting
    // to `HTTP ${status}: ${await response.text()}` left all 16 tests green.
    // Two independent controls deserve two independent assertions.
    expect(
      (responses[0] as Response).bodyUsed,
      "the sink's error body must never be read — real collectors echo the presented token in it",
    ).toBe(false);
  });

  it("redacts a credential that reaches an error message anyway", () => {
    // The second lock, held on its own: even if some future edit builds a
    // message out of credential-bearing material, nothing reported carries it.
    expect(redactSecrets(`Invalid token: ${HEC_TOKEN} (401)`, [HEC_TOKEN])).toBe(
      "Invalid token: [redacted] (401)",
    );
    // Short strings are left alone deliberately — redacting a 2-character
    // "secret" would scrub unrelated text and make a log unreadable.
    expect(redactSecrets("abc def", ["ab"])).toBe("abc def");
  });

  it("refuses a configuration that inlines a secret instead of referencing one", () => {
    const inline = JSON.stringify([
      {
        id: "bad",
        tenant: "acme",
        destination: {
          kind: "http",
          endpoint: ENDPOINT,
          auth: { header: "Authorization", secret_ref: HEC_TOKEN },
        },
      },
    ]);
    // `wrangler.toml`'s `[vars]` are committed plaintext, so a parser that
    // accepted a literal token would invite one into git.
    expect(() => parseSiemSinks(inline)).toThrow(/secret reference/i);
  });

  it("refuses a secret reference this Worker cannot resolve", () => {
    // Found by mutation: disabling the `kind !== "env"` branch left every test
    // green, because a bare literal is already rejected one line earlier as an
    // unknown SCHEME. A `vault://` reference is the case that reaches it — it
    // parses fine and resolves to nothing inside a Worker, so accepting it
    // would mean a sink that looks configured and never delivers.
    const vault = JSON.stringify([
      {
        id: "bad",
        tenant: "acme",
        destination: {
          kind: "http",
          endpoint: ENDPOINT,
          auth: { header: "Authorization", secret_ref: "vault://secret/data/siem#token" },
        },
      },
    ]);
    expect(() => parseSiemSinks(vault)).toThrow(/env:\/\//);
  });

  it("refuses a plaintext http endpoint", () => {
    const plaintext = JSON.stringify([
      {
        id: "bad",
        tenant: "acme",
        destination: { kind: "http", endpoint: "http://splunk.example.com/collector" },
      },
    ]);
    expect(() => parseSiemSinks(plaintext)).toThrow(/https/i);
  });

  it("fails the delivery closed when the referenced secret is unset", async () => {
    (env as unknown as MutableEnv)[HEC_TOKEN_VAR] = undefined;
    await seedRequestLogs(rows("acme", "acme", 2));

    const report = await runSiemExportPass(bindings(), NOW);

    expect(report.streams[0]).toMatchObject({ status: "failed", rows: 0 });
    // Nothing left the platform, and the cursor did not move — so the rows are
    // still there to deliver once the operator provisions the secret.
    expect(deliveries).toHaveLength(0);
    expect(await readSiemCursor(db(), "acme-splunk", "request_logs")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 4. One read path, one wiring
// ---------------------------------------------------------------------------

describe("the pump is not a second read path over the same tables", () => {
  it("delivers exactly the documents the JSONL export serves that tenant", async () => {
    const acmeRows = rows("acme", "acme", 3);
    await seedRequestLogs(acmeRows);
    await seedRequestLogs(rows("globex", "globex", 2));
    await seedTenantRequestLogs("acme", acmeRows);

    await runSiemExportPass(bindings(), NOW);

    const response = await SELF.fetch(`${BASE}/admin/v1/request-log-exports`, {
      headers: bearer("k-acme"),
    });
    expect(response.status).toBe(200);
    const served = (await response.text())
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const byId = (records: Record<string, unknown>[]) =>
      [...records].sort((a, b) => String(a.id).localeCompare(String(b.id)));
    // The SIEM is a bounded fleet reader and remains on the control-D1 derived
    // projection until #825 supplies the common freshness/as-of contract. The
    // tenant list/export path is separately pinned to TenantDataObject in the
    // request-log reader tests; this test keeps the projection-backed SIEM and
    // its own JSONL control projection in lockstep.
    expect(byId(deliveredDocuments())).toEqual(byId(served));
  });
});

// ---------------------------------------------------------------------------
// 5. The R2 destination — the "R2-backed pump" the issue names
// ---------------------------------------------------------------------------

describe("the R2 destination", () => {
  function armR2Sink(): void {
    (env as unknown as MutableEnv)[SIEM_EXPORT_SINKS_VAR] = JSON.stringify([
      {
        id: "acme-r2",
        tenant: "acme",
        streams: ["request_logs"],
        batch_size: 2,
        destination: { kind: "r2", prefix: "acme/" },
      },
    ]);
  }

  async function keys(): Promise<string[]> {
    const bucket = (env as unknown as { SIEM_EXPORTS?: R2Bucket }).SIEM_EXPORTS;
    if (bucket === undefined) throw new Error("SIEM_EXPORTS is not bound in this runner");
    const listed = await bucket.list({ prefix: "siem-exports/" });
    return listed.objects.map((object) => object.key).sort();
  }

  it("writes NDJSON batches under a key derived from the cursor, so a retry overwrites", async () => {
    armR2Sink();
    await seedRequestLogs(rows("acme", "acme", 3));

    const report = await runSiemExportPass(bindings(), NOW);
    expect(report.streams[0]).toMatchObject({ status: "delivered", rows: 3, batches: 2 });

    const written = await keys();
    expect(written).toHaveLength(2);
    for (const key of written) {
      expect(key).toContain("acme/");
      expect(key).toContain("request_logs");
    }
    const bucket = (env as unknown as { SIEM_EXPORTS: R2Bucket }).SIEM_EXPORTS;
    const first = await bucket.get(written[0] as string);
    const lines = (await (first as R2ObjectBody).text())
      .split("\n")
      .filter((line) => line.trim() !== "");
    expect(lines.map((line) => (JSON.parse(line) as { id: string }).id)).toEqual([
      "acme-000",
      "acme-001",
    ]);

    // The key is a function of (sink, stream, cursor), so a redelivery of the
    // same window lands on the SAME object. That is what keeps at-least-once
    // from becoming an ever-growing pile of near-duplicate files in the
    // customer's bucket.
    await db().prepare("DELETE FROM siem_export_cursors").run();
    await runSiemExportPass(bindings(), NOW);
    expect(await keys()).toEqual(written);
  });
});

describe("the scheduled tick runs the pump", () => {
  it("reports the export pass on every cron tick", async () => {
    await seedRequestLogs(rows("acme", "acme", 2));

    const tick = await runScheduledTick(bindings(), NOW);

    const report = tick.siemExport as SiemExportReport;
    expect(report.sinks).toBe(1);
    expect(report.streams[0]).toMatchObject({ status: "delivered", rows: 2 });
    expect(deliveredIds()).toEqual(["acme-000", "acme-001"]);
  });

  it("is inert — not a crash — on a deployment that configures no sink", async () => {
    (env as unknown as MutableEnv)[SIEM_EXPORT_SINKS_VAR] = "[]";
    await seedRequestLogs(rows("acme", "acme", 2));

    const report = await runSiemExportPass(bindings(), NOW);

    expect(report).toMatchObject({ sinks: 0, streams: [] });
    expect(deliveries).toHaveLength(0);
  });
});
