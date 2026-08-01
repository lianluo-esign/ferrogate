/**
 * `GET /v1/agent-jobs/{run_id}/events` — the PAGED representation.
 *
 * Regression gate for cutover finding **D7**
 * (`docs/rewrite/cutover-parity-dataplane.md` §D7), which recorded three
 * independent divergences from `server/agent_jobs.rs` in this one feed:
 *
 *  1. the response `object` discriminator was `"list"` where Rust
 *     (`agent_jobs.rs:838`) emits `"agent_job_event_page"`;
 *  2. `AgentJobEventCursor::from_query` (`agent_jobs.rs:1411`) REFUSES a
 *     non-integer `limit` and `limit=0` with `400 invalid_event_cursor`, and
 *     only the UPPER bound is clamped — this tree folded both refusals into the
 *     default page size, so `?limit=0` answered 200 with 100 rows;
 *  3. the resume cursor had regressed to the pre-#474 BARE EVENT ID, so a
 *     cursor naming an event that retention had pruned was unresolvable and the
 *     feed answered `cursor_reset: true` — re-delivering the whole retained
 *     history to a long-lived poll loop instead of resuming it. Rust emits
 *     `"<occurred_at_unix>:<event id>"` (`agent_job_event_cursor_token`)
 *     precisely so the cursor survives its own event.
 *
 * Everything below is asserted through the HTTP surface a real polling client
 * sees. The two BACK-COMPAT cases (a bare id still resolves; an unresolvable
 * bare id still self-heals with `cursor_reset`) are asserted in the same file so
 * the fix cannot be "make the composite token work by breaking the old one".
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  post,
  submitJob,
  workerHeaders,
} from "./fixtures.js";

const NOW = 1_800_000_000;

beforeEach(async () => {
  await drainPlane(WORKER_A);
});

interface EventRow {
  readonly id: string;
  readonly kind: string;
  readonly occurred_at_unix: number;
}

interface EventPageBody {
  readonly object: string;
  readonly run_id: string;
  readonly data: readonly EventRow[];
  readonly limit: number;
  readonly after_event_id: string | null;
  readonly next_after_event_id: string | null;
  readonly has_more: boolean;
  readonly cursor_reset: boolean;
}

/** Append one non-lifecycle timeline row at a caller-chosen instant. */
async function appendEvent(runId: string, eventId: string, atUnix: number): Promise<void> {
  const response = await post("/v1/self-hosted-workers/events", workerHeaders(), {
    protocol_version: 1,
    identity: WORKER_A,
    session_id: "s1",
    run_id: runId,
    event_id: eventId,
    kind: "usage",
    event_json: { tokens: 1 },
    reported_at_unix: atUnix,
  });
  expect(response.status).toBe(201);
}

async function page(runId: string, query = ""): Promise<{ status: number; body: EventPageBody }> {
  const response = await get(`/v1/agent-jobs/${runId}/events${query}`, bearer(TENANT_A_KEY));
  return { status: response.status, body: (await response.json()) as EventPageBody };
}

async function errorCode(runId: string, query: string): Promise<{ status: number; code: string }> {
  const response = await get(`/v1/agent-jobs/${runId}/events${query}`, bearer(TENANT_A_KEY));
  const body = (await response.json()) as { error?: { code?: string } };
  return { status: response.status, code: body.error?.code ?? "" };
}

/** A run with four timeline rows at four distinct, ascending instants. */
async function runWithTimeline(): Promise<{ runId: string; events: readonly EventRow[] }> {
  const { runId } = await submitJob(TENANT_A_KEY);
  await appendEvent(runId, "e-1", NOW + 10);
  await appendEvent(runId, "e-2", NOW + 20);
  await appendEvent(runId, "e-3", NOW + 30);
  const { body } = await page(runId, "?limit=500");
  expect(body.data.length).toBe(4);
  return { runId, events: body.data };
}

describe("D7.1 — the response object discriminator", () => {
  it("is agent_job_event_page, the Rust discriminator, not list", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const { status, body } = await page(runId);
    expect(status).toBe(200);
    // `agent_jobs.rs:838`. A client discriminating on `object` breaks if this
    // is `"list"`.
    expect(body.object).toBe("agent_job_event_page");
  });
});

describe("D7.2 — 400 invalid_event_cursor", () => {
  it("refuses ?limit=0 rather than serving the default page", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    // Rust: `if limit == 0 { return Err("limit must be greater than zero") }`.
    expect(await errorCode(runId, "?limit=0")).toEqual({
      status: 400,
      code: "invalid_event_cursor",
    });
  });

  it("refuses a non-integer limit", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    // Rust: `value.trim().parse::<usize>()` → Err("limit must be an unsigned
    // integer") for every one of these.
    for (const raw of ["abc", "1.5", "-1", "1e3", " ", "0x10"]) {
      expect(await errorCode(runId, `?limit=${encodeURIComponent(raw)}`), raw).toEqual({
        status: 400,
        code: "invalid_event_cursor",
      });
    }
  });

  it('refuses an EMPTY limit — `"".parse::<usize>()` is an error in Rust too', async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    expect(await errorCode(runId, "?limit=")).toEqual({
      status: 400,
      code: "invalid_event_cursor",
    });
  });

  it("still defaults when limit is ABSENT, and still clamps the upper bound", async () => {
    // The negative control for the three refusals above: only the two Rust
    // refusals are refusals. An absent limit is the default page size and an
    // over-large one is clamped, never rejected.
    const { runId } = await submitJob(TENANT_A_KEY);
    expect((await page(runId)).body.limit).toBe(100);
    expect((await page(runId, "?limit=9999")).body.limit).toBe(500);
    expect((await page(runId, "?limit=7")).body.limit).toBe(7);
    // Rust trims before parsing, so surrounding whitespace is not a refusal.
    expect((await page(runId, "?limit=%207%20")).body.limit).toBe(7);
  });
});

describe("D7.3 — the resume cursor survives its own event (#474)", () => {
  it("emits next_after_event_id as <occurred_at_unix>:<event id>", async () => {
    const { runId, events } = await runWithTimeline();
    const first = await page(runId, "?limit=2");
    expect(first.body.data).toHaveLength(2);
    const last = first.body.data[1] as EventRow;
    // `agent_job_event_cursor_token`, verbatim.
    expect(first.body.next_after_event_id).toBe(`${last.occurred_at_unix}:${last.id}`);
    expect(first.body.has_more).toBe(true);
    expect(events).toHaveLength(4);
  });

  it("resumes from a composite token without re-delivering the page", async () => {
    const { runId } = await runWithTimeline();
    const first = await page(runId, "?limit=2");
    const token = first.body.next_after_event_id ?? "";
    const second = await page(runId, `?limit=2&after_event_id=${encodeURIComponent(token)}`);

    expect(second.body.cursor_reset).toBe(false);
    expect(second.body.data).toHaveLength(2);
    const delivered = new Set(second.body.data.map((event) => event.id));
    for (const seen of first.body.data) {
      expect(delivered.has(seen.id), `${seen.id} was re-delivered`).toBe(false);
    }
    expect(second.body.has_more).toBe(false);
  });

  it("RESUMES rather than restarting when the event the cursor names is gone", async () => {
    // The whole point of #474. The cursor names a position, so an event that
    // retention has pruned — modelled here by a token whose id never existed,
    // ordered between the run's second and third rows — must still resume.
    // With the bare-id cursor this answers `cursor_reset: true` and hands back
    // the WHOLE retained history.
    const { runId, events } = await runWithTimeline();
    const second = events[1] as EventRow;
    const pruned = `${second.occurred_at_unix}:${runId}-evt-999999`;

    const resumed = await page(runId, `?after_event_id=${encodeURIComponent(pruned)}`);
    expect(resumed.body.cursor_reset).toBe(false);
    expect(resumed.body.data.map((event) => event.id)).toEqual(
      events.slice(2).map((event) => event.id),
    );
  });

  it("still resolves a BARE event id copied out of data[].id", async () => {
    // Back-compat: Rust's `resolve_agent_job_cursor` accepts both forms.
    const { runId, events } = await runWithTimeline();
    const bare = (events[0] as EventRow).id;
    const resumed = await page(runId, `?after_event_id=${encodeURIComponent(bare)}`);
    expect(resumed.body.cursor_reset).toBe(false);
    expect(resumed.body.data.map((event) => event.id)).toEqual(
      events.slice(1).map((event) => event.id),
    );
  });

  it("still self-heals with cursor_reset on an unresolvable BARE id", async () => {
    // The other back-compat half, and the reason an unresolvable cursor is not
    // a 400: a poll loop restarts instead of dying.
    const { runId, events } = await runWithTimeline();
    const resumed = await page(runId, "?after_event_id=not-an-event-of-this-run");
    expect(resumed.body.cursor_reset).toBe(true);
    expect(resumed.body.data.map((event) => event.id)).toEqual(events.map((event) => event.id));
  });

  it("carries the cursor forward on an empty page instead of dropping it", async () => {
    // Rust: `next_after_event_id = data.last().map(token).or(after_event_id)`.
    // Dropping it would make a caught-up poller restart from the beginning.
    const { runId, events } = await runWithTimeline();
    const last = events[events.length - 1] as EventRow;
    const token = `${last.occurred_at_unix}:${last.id}`;
    const empty = await page(runId, `?after_event_id=${encodeURIComponent(token)}`);
    expect(empty.body.data).toEqual([]);
    expect(empty.body.has_more).toBe(false);
    expect(empty.body.next_after_event_id).toBe(token);
  });
});

/**
 * The aside recorded in the same §D7 paragraph: `getAgentJobResult` carried no
 * `work_products` key at all. Rust emits it ALONGSIDE `artifacts`
 * (`agent_jobs.rs:876-905`) — it was never a substitution — and the projection
 * is discriminated by `object: "coding_agent.work_product"` INSIDE an
 * `artifact` event's payload.
 *
 * `attribution_verified` is asserted on both sides of its own decision, because
 * it is the one verdict this tree re-derives rather than copies: an envelope
 * claiming a different run must not be able to assert its own provenance.
 */
interface ResultBody {
  readonly artifacts?: readonly { readonly id: string }[];
  readonly work_products?: readonly {
    readonly object: string;
    readonly run_id: string;
    readonly attribution_verified: boolean;
    readonly work_product: { readonly product_id?: string } | null;
  }[];
}

async function settleAndRead(runId: string, at: number): Promise<ResultBody> {
  await post("/v1/self-hosted-workers/events", workerHeaders(), {
    protocol_version: 1,
    identity: WORKER_A,
    session_id: "s1",
    run_id: runId,
    event_id: "e-done",
    kind: "lifecycle",
    event_json: { state: "completed", output: "done" },
    reported_at_unix: at,
  });
  const response = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
  expect(response.status).toBe(200);
  return (await response.json()) as ResultBody;
}

/** Write one `artifact` timeline row carrying `payload` as its event body. */
async function reportArtifactPayload(
  runId: string,
  eventId: string,
  payload: unknown,
  at: number,
): Promise<void> {
  const response = await post("/v1/self-hosted-workers/events", workerHeaders(), {
    protocol_version: 1,
    identity: WORKER_A,
    session_id: "s1",
    run_id: runId,
    event_id: eventId,
    kind: "artifact",
    event_json: payload,
    reported_at_unix: at,
  });
  expect(response.status).toBe(201);
}

describe("D7 — the /result work_products projection", () => {
  it("is present and EMPTY for a run with no work-product envelope", async () => {
    // Rust's own answer for every non-coding job. The key must exist: a client
    // reading `result.work_products.length` breaks on `undefined`.
    const { runId } = await submitJob(TENANT_A_KEY);
    const body = await settleAndRead(runId, NOW);
    expect(body.work_products).toEqual([]);
  });

  it("projects a work-product envelope and SKIPS an unrelated artifact", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    // An ordinary container artifact on the same run — Rust skips it rather
    // than failing the read.
    await reportArtifactPayload(runId, "a-plain", { name: "build.log" }, NOW + 1);
    await reportArtifactPayload(
      runId,
      "a-product",
      {
        object: "coding_agent.work_product",
        work_product: { product_id: "wp-1", run: { run_id: runId } },
      },
      NOW + 2,
    );
    const body = await settleAndRead(runId, NOW + 3);

    expect(body.work_products).toHaveLength(1);
    const product = body.work_products?.[0];
    expect(product?.object).toBe("coding_agent_work_product");
    expect(product?.work_product?.product_id).toBe("wp-1");
    // ...while the raw evidence rows still carry BOTH, as Rust does.
    expect((body.artifacts ?? []).length).toBe(2);
  });

  it("re-derives attribution_verified from the PATH run id, not the payload", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await reportArtifactPayload(
      runId,
      "a-mine",
      {
        object: "coding_agent.work_product",
        work_product: { product_id: "wp-mine", run: { run_id: runId } },
      },
      NOW + 1,
    );
    await reportArtifactPayload(
      runId,
      "a-theirs",
      {
        object: "coding_agent.work_product",
        work_product: { product_id: "wp-theirs", run: { run_id: "some-other-run" } },
      },
      NOW + 2,
    );
    const body = await settleAndRead(runId, NOW + 3);

    const verdicts = Object.fromEntries(
      (body.work_products ?? []).map((product) => [
        product.work_product?.product_id ?? "",
        product.attribution_verified,
      ]),
    );
    expect(verdicts).toEqual({ "wp-mine": true, "wp-theirs": false });
    // The projected run id is ALWAYS the path's — never the payload's claim.
    for (const product of body.work_products ?? []) {
      expect(product.run_id).toBe(runId);
    }
  });
});
