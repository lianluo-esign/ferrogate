/**
 * Per-request cost attribution and the chargeback export (#677), driven end to
 * end through the exported Worker against a REAL D1 binding.
 *
 * ## The defect this file pins
 *
 * Finance could read a MONTHLY rollup by metadata key (`usage_metadata_rollups`)
 * and a per-agent burn (`agent_cost_burn`), and could not answer the only
 * question a chargeback conversation ever starts with: *which customer, which
 * project, which key, which model, which tag and which agent run produced this
 * $4,200*. There was no per-request cost surface anywhere in the tree and no
 * export to hand an FP&A team.
 *
 * Both halves of the answer existed and nothing joined them: `request_logs`
 * (#664) knows the tenant / project / key / model / agent run of every request,
 * and `billing_events` (#663, #667) knows what that request was PRICED at and
 * which metadata tags the caller attached. This file holds the join.
 *
 * ## Why fixtures, and what they are honest about
 *
 * Both tables are written by `apps/gateway` — a different Worker with a
 * different `wrangler.toml`, unreachable from this suite — so these are
 * cross-Worker-seam fixtures, exactly as `request-logs-read.test.ts` uses. What
 * they hold is that the READER joins what the tables hold, fences it by tenant,
 * and exports it losslessly. The writers are held by
 * `apps/gateway/test/requestlog/write.test.ts` and
 * `apps/gateway/test/metering/*`, against these same columns and this same
 * `event_json` shape.
 *
 * The `event_json` documents below are stated VERBATIM rather than built with
 * `billingEventToWire`: the reader reads them with `json_extract`, and a
 * fixture produced by the encoder under test could not show that the encoder
 * and the reader agree about where `cost_usd` lives.
 */
import { SELF } from "cloudflare:test";
import { parquetReadObjects } from "hyparquet";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1, seedBillingEvents, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

interface ListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
}

async function readCosts(secret: string, query = ""): Promise<ListBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/cost-records${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as ListBody;
}

async function ids(secret: string, query = ""): Promise<unknown[]> {
  return (await readCosts(secret, query)).data.map((row) => row.request_id);
}

async function exportCosts(secret: string, query = ""): Promise<Response> {
  const response = await SELF.fetch(`${BASE}/admin/v1/cost-record-exports${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return response;
}

/**
 * A minimal RFC 4180 reader, written here rather than imported so the export is
 * checked by something that does not share code with the writer. A CSV asserted
 * with the same quoting routine that produced it proves only that the routine
 * is self-consistent.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else quoted = false;
      } else field += char;
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r") field += char;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Header row → { column: value } for one CSV data row. */
function csvRecords(text: string): Record<string, string>[] {
  const rows = parseCsv(text);
  const header = rows[0] ?? [];
  return rows.slice(1).map((cells) => {
    const record: Record<string, string> = {};
    header.forEach((name, index) => {
      record[name] = cells[index] ?? "";
    });
    return record;
  });
}

/** One fully-attributed request: every dimension #677's "Done when" names. */
const REQUEST = {
  requestId: "fg-cost-1",
  traceId: "trace-1",
  agentRunId: "run-42",
  tenant: "t-1",
  project: "proj-alpha",
  workspace: "ws-1",
  apiKeyId: "key_t-1",
  startedAtUnix: 1_700_000_100,
  completedAtUnix: 1_700_000_101,
  route: "openai.chat.completions",
  provider: "openai",
  logicalModel: "gpt-4o-mini",
  providerModel: "gpt-4o-mini-2024-07-18",
  statusCode: 200,
  cacheStatus: "miss",
  latencyMs: 412,
  promptTokens: 11,
  completionTokens: 4,
  totalTokens: 15,
  guardrailVerdict: "allowed",
} as const;

/**
 * The settled metering document for {@link REQUEST}.
 *
 * `cost_usd` and the #667 counters are the two facts this surface exists to
 * publish, and both live only here — `request_logs` has neither.
 */
const EVENT = {
  request_id: REQUEST.requestId,
  provider_attempt_id: "attempt-0",
  provider_attempt_index: 0,
  tenant: { organization_id: "t-1", project_id: "proj-alpha", api_key_id: "key_t-1" },
  logical_model: "gpt-4o-mini",
  provider: "openai",
  provider_model: "gpt-4o-mini-2024-07-18",
  usage: {
    prompt_tokens: 11,
    completion_tokens: 4,
    total_tokens: 15,
    cached_input_tokens: 8,
    cache_write_tokens: 2,
    reasoning_tokens: 3,
  },
  usage_source: "provider_usage",
  status_code: 200,
  metadata: { team: "growth", feature: "summarizer" },
  occurred_at_unix: 1_700_000_101,
  cost_usd: 0.5,
} as const;

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The join itself
// ---------------------------------------------------------------------------

describe("GET /admin/v1/cost-records answers cost per REQUEST, joined not duplicated", () => {
  it("carries every chargeback dimension and the cost on ONE row", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect((await readCosts(operatorKey.secret)).data).toHaveLength(0);

    await seedRequestLogs([REQUEST]);
    await seedBillingEvents([
      { id: "be-1", requestId: REQUEST.requestId, occurredAtUnix: 1_700_000_101, event: EVENT },
    ]);

    const page = await readCosts(operatorKey.secret);
    expect(page.data).toHaveLength(1);
    expect(page.data[0]).toMatchObject({
      object: "cost_record",
      id: REQUEST.requestId,
      request_id: REQUEST.requestId,
      trace_id: "trace-1",
      agent_run_id: "run-42",
      tenant_id: "t-1",
      project_id: "proj-alpha",
      workspace_id: "ws-1",
      api_key_id: "key_t-1",
      provider: "openai",
      logical_model: "gpt-4o-mini",
      provider_model: "gpt-4o-mini-2024-07-18",
      route: "openai.chat.completions",
      status_code: 200,
      cache_status: "miss",
      latency_ms: 412,
      started_at_unix: REQUEST.startedAtUnix,
      completed_at_unix: REQUEST.completedAtUnix,
      // The money, and the #667 counters that price it. None of these is in
      // `request_logs`; all of them come from the joined metering document.
      cost_usd: 0.5,
      priced: true,
      metered: true,
      billed_attempts: 1,
      unpriced_attempts: 0,
      prompt_tokens: 11,
      completion_tokens: 4,
      total_tokens: 15,
      cached_input_tokens: 8,
      cache_write_tokens: 2,
      reasoning_tokens: 3,
      tags: { team: "growth", feature: "summarizer" },
    });
  });

  /**
   * #135: one REQUEST can be several provider ATTEMPTS, each with its own
   * `billing_events` row. The chargeback unit is the request, so the attempts
   * are SUMMED onto one row — a join that emitted one row per attempt would
   * double-count every retried request in a finance export.
   */
  it("sums the provider attempts of one request rather than emitting two rows", async () => {
    await seedRequestLogs([REQUEST]);
    await seedBillingEvents([
      {
        id: "be-a",
        requestId: REQUEST.requestId,
        attemptIndex: 0,
        occurredAtUnix: 1_700_000_101,
        event: { ...EVENT, cost_usd: 0.5 },
      },
      {
        id: "be-b",
        requestId: REQUEST.requestId,
        attemptIndex: 1,
        occurredAtUnix: 1_700_000_102,
        event: { ...EVENT, provider_attempt_index: 1, cost_usd: 0.25 },
      },
    ]);

    const page = await readCosts(operatorKey.secret);
    expect(page.data).toHaveLength(1);
    expect(page.total).toBe(1);
    expect(page.data[0]).toMatchObject({
      request_id: REQUEST.requestId,
      cost_usd: 0.75,
      billed_attempts: 2,
      // The #667 counters are per attempt too, and are summed for the same
      // reason the cost is: a retried request really did consume both.
      cached_input_tokens: 16,
      reasoning_tokens: 6,
    });
  });

  /**
   * #663: a usage nothing could price still leaves a durable, re-priceable
   * `billing_events` row with NO `cost_usd`. `null` and `0` are different
   * answers — one says "we do not know what this cost", the other says "this
   * was free" — and a chargeback export that collapsed them would under-bill
   * silently and invisibly.
   */
  it("reports an unpriced metering row as an UNKNOWN cost, never as $0", async () => {
    await seedRequestLogs([REQUEST]);
    await seedBillingEvents([
      {
        id: "be-unpriced",
        requestId: REQUEST.requestId,
        occurredAtUnix: 1_700_000_101,
        // `cost_usd` ABSENT, exactly as `LedgerStore.recordEvent` writes it.
        event: { ...EVENT, cost_usd: undefined },
      },
    ]);

    const record = (await readCosts(operatorKey.secret)).data[0];
    expect(record).toMatchObject({
      cost_usd: null,
      priced: false,
      metered: true,
      billed_attempts: 1,
      unpriced_attempts: 1,
    });
  });

  /** A partially-priced request is NOT `priced`, even though it has a cost. */
  it("flags a request whose attempts were only partly priced", async () => {
    await seedRequestLogs([REQUEST]);
    await seedBillingEvents([
      {
        id: "be-p",
        requestId: REQUEST.requestId,
        attemptIndex: 0,
        occurredAtUnix: 1_700_000_101,
        event: { ...EVENT, cost_usd: 0.5 },
      },
      {
        id: "be-u",
        requestId: REQUEST.requestId,
        attemptIndex: 1,
        occurredAtUnix: 1_700_000_102,
        event: { ...EVENT, provider_attempt_index: 1, cost_usd: undefined },
      },
    ]);

    expect((await readCosts(operatorKey.secret)).data[0]).toMatchObject({
      cost_usd: 0.5,
      priced: false,
      unpriced_attempts: 1,
      billed_attempts: 2,
    });
  });

  /**
   * A request the gateway refused (guardrail block, 429, auth failure) has a
   * request log and no metering row at all. It still belongs in the export —
   * "this tenant sent 40,000 requests we refused" is a chargeback fact — and it
   * must be distinguishable from a $0 one.
   */
  it("keeps a request that was never metered, marked as such", async () => {
    await seedRequestLogs([
      {
        ...REQUEST,
        requestId: "fg-blocked",
        statusCode: 403,
        guardrailVerdict: "blocked",
        promptTokens: null,
        completionTokens: null,
        totalTokens: null,
      },
    ]);

    expect((await readCosts(operatorKey.secret)).data[0]).toMatchObject({
      request_id: "fg-blocked",
      status_code: 403,
      metered: false,
      priced: false,
      cost_usd: null,
      billed_attempts: 0,
      // No metering document means no #667 counters — `0` would assert the
      // provider reported zero cached tokens, which nobody ever asked it.
      cached_input_tokens: null,
      reasoning_tokens: null,
    });
  });

  /**
   * A `billing_events` row for a request with no request log contributes
   * NOTHING. That is the deliberate cost of driving the join from the fenced
   * side — see `costRecordPage`'s docblock — and it is pinned here so the
   * limitation is a decision rather than a surprise.
   */
  it("does not invent a row for a metering event with no request log", async () => {
    await seedBillingEvents([
      { id: "be-orphan", requestId: "fg-no-log", occurredAtUnix: 1_700_000_101, event: EVENT },
    ]);
    expect((await readCosts(operatorKey.secret)).data).toHaveLength(0);
  });

  /**
   * A metering document that does not parse must not take the whole chargeback
   * surface down with it. `json_extract` RAISES on malformed JSON, so an
   * unguarded query would answer 500 for every caller because of one bad row —
   * and the row must not silently become a priced $0 either.
   */
  it("survives a corrupt metering document, counting it as an unknown cost", async () => {
    await seedRequestLogs([REQUEST]);
    await db()
      .prepare(
        `INSERT INTO billing_events
           (billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind("be-corrupt", REQUEST.requestId, 0, 1_700_000_101, "{not json")
      .run();

    const record = (await readCosts(operatorKey.secret)).data[0];
    expect(record).toMatchObject({
      request_id: REQUEST.requestId,
      metered: true,
      priced: false,
      cost_usd: null,
      billed_attempts: 1,
      unpriced_attempts: 1,
      tags: {},
    });
    // …and the tag filter, which is the other place a raw document is read,
    // must not raise on it either.
    expect(await ids(operatorKey.secret, "?tag=team:growth")).toEqual([]);
  });

  it("orders newest first with request_id as the tiebreaker and reports the total", async () => {
    await seedRequestLogs([
      { ...REQUEST, requestId: "fg-b", startedAtUnix: 200 },
      { ...REQUEST, requestId: "fg-a", startedAtUnix: 200 },
      { ...REQUEST, requestId: "fg-c", startedAtUnix: 300 },
    ]);
    expect(await ids(operatorKey.secret)).toEqual(["fg-c", "fg-a", "fg-b"]);

    const page = await readCosts(operatorKey.secret, "?limit=2&offset=1");
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-a", "fg-b"]);
    expect(page.total).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// The six dimensions the "Done when" names
// ---------------------------------------------------------------------------

describe("cost is queryable by tenant, project, key, model, tag and agent run", () => {
  beforeEach(async () => {
    await seedRequestLogs([
      { ...REQUEST, requestId: "fg-1" },
      {
        ...REQUEST,
        requestId: "fg-2",
        project: "proj-beta",
        apiKeyId: "key_other",
        agentRunId: "run-99",
        logicalModel: "claude-3-5-sonnet",
        providerModel: "claude-3-5-sonnet-20241022",
        provider: "anthropic",
        startedAtUnix: REQUEST.startedAtUnix + 60,
      },
      { ...REQUEST, requestId: "fg-3", tenant: "t-2", startedAtUnix: REQUEST.startedAtUnix + 120 },
    ]);
    await seedBillingEvents([
      {
        id: "be-1",
        requestId: "fg-1",
        occurredAtUnix: 1,
        event: { ...EVENT, request_id: "fg-1", metadata: { team: "growth", env: "prod" } },
      },
      {
        id: "be-2",
        requestId: "fg-2",
        occurredAtUnix: 2,
        event: { ...EVENT, request_id: "fg-2", metadata: { team: "platform", env: "prod" } },
      },
      {
        id: "be-3",
        requestId: "fg-3",
        occurredAtUnix: 3,
        event: { ...EVENT, request_id: "fg-3", metadata: {} },
      },
    ]);
  });

  it("by tenant", async () => {
    expect(await ids(operatorKey.secret, "?tenant=t-2")).toEqual(["fg-3"]);
  });

  it("by project", async () => {
    expect(await ids(operatorKey.secret, "?project=proj-beta")).toEqual(["fg-2"]);
  });

  it("by api key", async () => {
    expect(await ids(operatorKey.secret, "?api_key_id=key_other")).toEqual(["fg-2"]);
  });

  it("by agent run", async () => {
    expect(await ids(operatorKey.secret, "?agent_run_id=run-99")).toEqual(["fg-2"]);
  });

  /**
   * `model` matches EITHER spelling. Finance asks for "claude-3-5-sonnet" and
   * does not know whether the row holds the model the caller named or the
   * dated snapshot the provider was actually asked for; answering only one of
   * them would silently drop half the spend.
   */
  it("by model, under either the logical or the provider spelling", async () => {
    expect(await ids(operatorKey.secret, "?model=claude-3-5-sonnet")).toEqual(["fg-2"]);
    expect(await ids(operatorKey.secret, "?model=claude-3-5-sonnet-20241022")).toEqual(["fg-2"]);
    expect(await ids(operatorKey.secret, "?provider=anthropic")).toEqual(["fg-2"]);
  });

  it("by tag, as key:value and as key-presence", async () => {
    expect(await ids(operatorKey.secret, "?tag=team:platform")).toEqual(["fg-2"]);
    // Every metered request in this world carries `env`, except the one whose
    // metadata map is empty — so key-presence really does discriminate.
    expect((await ids(operatorKey.secret, "?tag=env")).sort()).toEqual(["fg-1", "fg-2"]);
    expect(await ids(operatorKey.secret, "?tag=team:nobody")).toEqual([]);
  });

  /** `since` is inclusive and `until` is EXCLUSIVE, so two months never overlap. */
  it("by time window", async () => {
    const start = REQUEST.startedAtUnix;
    expect((await ids(operatorKey.secret, `?since=${start + 60}`)).sort()).toEqual([
      "fg-2",
      "fg-3",
    ]);
    expect(await ids(operatorKey.secret, `?since=${start + 60}&until=${start + 120}`)).toEqual([
      "fg-2",
    ]);
  });

  it("combines filters as AND, not OR", async () => {
    expect(await ids(operatorKey.secret, "?project=proj-beta&tag=team:growth")).toEqual([]);
    expect(await ids(operatorKey.secret, "?project=proj-beta&tag=team:platform")).toEqual(["fg-2"]);
  });
});

// ---------------------------------------------------------------------------
// The tenant fence — the property proved by MUTATION, not by reading
// ---------------------------------------------------------------------------

describe("the tenant fence on cost records", () => {
  beforeEach(async () => {
    await seedRequestLogs([
      { ...REQUEST, requestId: "fg-t1", tenant: "t-1" },
      { ...REQUEST, requestId: "fg-t2", tenant: "t-2" },
      // An UNATTRIBUTED row: a request whose credential resolved no tenant,
      // i.e. a platform-operator call. It is nobody's tenant data.
      { ...REQUEST, requestId: "fg-none", tenant: null },
    ]);
    await seedBillingEvents([
      { id: "b1", requestId: "fg-t1", occurredAtUnix: 1, event: { ...EVENT, cost_usd: 1 } },
      { id: "b2", requestId: "fg-t2", occurredAtUnix: 2, event: { ...EVENT, cost_usd: 2 } },
      { id: "b3", requestId: "fg-none", occurredAtUnix: 3, event: { ...EVENT, cost_usd: 4 } },
    ]);
  });

  it("shows a tenant only its own rows", async () => {
    expect(await ids("k-tenant")).toEqual(["fg-t1"]);
  });

  it("shows the OTHER tenant only its own rows", async () => {
    expect(await ids("k-other")).toEqual(["fg-t2"]);
  });

  /** STRICT equality, so `NULL` matches nobody — the #664 narrowing, restated. */
  it("never shows a tenant the un-attributed platform rows", async () => {
    for (const secret of ["k-tenant", "k-other"]) {
      expect(await ids(secret)).not.toContain("fg-none");
    }
  });

  it("shows a platform operator every row", async () => {
    expect((await ids(operatorKey.secret)).sort()).toEqual(["fg-none", "fg-t1", "fg-t2"]);
  });

  /**
   * `?tenant=` is a NARROWING for an operator and must not be a widening for a
   * tenant. A filter that replaced the fence instead of intersecting it would
   * be a one-parameter cross-tenant read of the most sensitive report in the
   * product.
   */
  it("cannot be widened by asking for another tenant explicitly", async () => {
    expect(await ids("k-tenant", "?tenant=t-2")).toEqual([]);
    expect(await ids("k-tenant", "?tenant=t-1")).toEqual(["fg-t1"]);
  });

  /** Nor by any other filter: a filter narrows the fenced set, never replaces it. */
  it("cannot be escaped through the tag filter, which reads an UNFENCED table", async () => {
    // `billing_events` has no tenant column, so the tag predicate is the one
    // leg of this query that cannot fence itself. It must only ever narrow.
    expect(await ids("k-tenant", "?tag=team:growth")).toEqual(["fg-t1"]);
    expect(await ids("k-other", "?tag=team:growth")).toEqual(["fg-t2"]);
  });

  it("fences every export format identically", async () => {
    const csv = csvRecords(await (await exportCosts("k-tenant")).text());
    expect(csv.map((row) => row.request_id)).toEqual(["fg-t1"]);

    const jsonl = (await (await exportCosts("k-tenant", "?format=jsonl")).text())
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(jsonl.map((row) => row.request_id)).toEqual(["fg-t1"]);

    const parquet = await (await exportCosts("k-tenant", "?format=parquet")).arrayBuffer();
    const rows = await parquetReadObjects({ file: parquet });
    expect(rows.map((row) => row.request_id)).toEqual(["fg-t1"]);
  });

  it("cannot be paged past", async () => {
    const page = await readCosts("k-tenant", "?limit=100&offset=0");
    expect(page.total).toBe(1);
    expect(page.data.map((row) => row.request_id)).toEqual(["fg-t1"]);
  });
});

// ---------------------------------------------------------------------------
// The exports
// ---------------------------------------------------------------------------

describe("GET /admin/v1/cost-record-exports", () => {
  beforeEach(async () => {
    await seedRequestLogs([REQUEST, { ...REQUEST, requestId: "fg-cost-2", startedAtUnix: 1 }]);
    await seedBillingEvents([
      {
        id: "be-1",
        requestId: REQUEST.requestId,
        occurredAtUnix: 1_700_000_101,
        event: {
          ...EVENT,
          // A quote, a comma and a newline — the three characters that decide
          // whether a CSV writer is real or a `join(",")`.
          metadata: { note: 'a "quoted", multi\nline tag' },
        },
      },
    ]);
  });

  it("defaults to CSV with a stable header and RFC 4180 quoting", async () => {
    const response = await exportCosts(operatorKey.secret);
    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(response.headers.get("content-disposition")).toContain(".csv");

    const text = await response.text();
    const header = parseCsv(text)[0] ?? [];
    // The first columns are pinned because a chargeback CSV is loaded by a
    // spreadsheet macro that indexes them; reordering is a breaking change.
    expect(header.slice(0, 6)).toEqual([
      "request_id",
      "started_at_unix",
      "completed_at_unix",
      "tenant_id",
      "project_id",
      "workspace_id",
    ]);
    expect(header).toContain("cost_usd");
    expect(header).toContain("tags");

    const records = csvRecords(text);
    expect(records.map((row) => row.request_id)).toEqual([REQUEST.requestId, "fg-cost-2"]);
    expect(records[0]?.cost_usd).toBe("0.5");
    expect(JSON.parse(records[0]?.tags ?? "{}")).toEqual({
      note: 'a "quoted", multi\nline tag',
    });
    // An UNKNOWN cost is an EMPTY cell, never `0` — the #663 distinction has to
    // survive the format that finance actually opens.
    expect(records[1]?.cost_usd).toBe("");
  });

  it("answers JSON Lines on request", async () => {
    const response = await exportCosts(operatorKey.secret, "?format=jsonl");
    expect(response.headers.get("content-type")).toContain("application/x-ndjson");
    const lines = (await response.text()).split("\n").filter((line) => line.trim() !== "");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      object: "cost_record",
      request_id: REQUEST.requestId,
      cost_usd: 0.5,
    });
  });

  it("answers a REAL Parquet file an independent reader can open", async () => {
    const response = await exportCosts(operatorKey.secret, "?format=parquet");
    expect(response.headers.get("content-type")).toContain("parquet");
    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe("PAR1");
    expect(new TextDecoder().decode(bytes.slice(-4))).toBe("PAR1");

    // `hyparquet` shares no code with the writer, so this is a round trip
    // through a real reader rather than a self-consistency check.
    const rows = await parquetReadObjects({ file: buffer });
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      request_id: REQUEST.requestId,
      tenant_id: "t-1",
      project_id: "proj-alpha",
      api_key_id: "key_t-1",
      agent_run_id: "run-42",
      logical_model: "gpt-4o-mini",
      cost_usd: 0.5,
      priced: true,
      cached_input_tokens: 8n,
      reasoning_tokens: 3n,
    });
    // NULL survives the columnar encoding: an unpriced request must not read
    // as $0 in the format a data team joins against their warehouse.
    expect(rows[1]?.cost_usd).toBeNull();
    expect(JSON.parse(String(rows[0]?.tags))).toEqual({
      note: 'a "quoted", multi\nline tag',
    });
  });

  it("rejects a format it cannot write rather than silently answering CSV", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/cost-record-exports?format=xlsx`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(400);
  });

  it("exports an EMPTY file rather than failing when nothing matches", async () => {
    const csv = await (await exportCosts(operatorKey.secret, "?tenant=t-nobody")).text();
    // The header still ships: a zero-row CSV with no header is unloadable.
    expect(parseCsv(csv)).toHaveLength(1);

    const parquet = await (
      await exportCosts(operatorKey.secret, "?format=parquet&tenant=t-nobody")
    ).arrayBuffer();
    expect(await parquetReadObjects({ file: parquet })).toEqual([]);
  });
});
