import { SELF } from "cloudflare:test";
/**
 * SSE framing for `GET /v1/agent-jobs/{run_id}/events`.
 *
 * `ROUTE-MAP.md` names this a streaming surface whose framing must be
 * preserved. The assertions are on the RAW bytes, not on a parsed convenience
 * object, because the framing IS the contract: a client that reads
 * `id:`/`event:`/`data:` lines separated by blank lines must keep working.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { sseFrame, wantsEventStream } from "../src/runs/events.js";
import {
  BASE,
  TENANT_A_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  post,
  readSseFrames,
  submitJob,
  workerHeaders,
} from "./fixtures.js";

const NOW = 1_800_000_000;

beforeEach(async () => {
  await drainPlane(WORKER_A);
});

/** Report a terminal state so the stream closes rather than staying open. */
async function settle(runId: string, output = "done"): Promise<void> {
  await post("/v1/self-hosted-workers/events", workerHeaders(), {
    protocol_version: 1,
    identity: WORKER_A,
    session_id: "s1",
    run_id: runId,
    event_id: "e-done",
    kind: "lifecycle",
    event_json: { state: "completed", output },
    reported_at_unix: NOW,
  });
}

describe("sseFrame encoding", () => {
  it("emits id / event / data lines and a terminating blank line", () => {
    expect(sseFrame({ id: "e1", event: "run.started", data: "{}" })).toBe(
      "id: e1\nevent: run.started\ndata: {}\n\n",
    );
  });

  it("splits a multi-line payload across repeated data lines", () => {
    // The spec requires this; `data: ${json}` silently corrupts the stream the
    // first time a payload contains a newline.
    expect(sseFrame({ data: "line one\nline two" })).toBe("data: line one\ndata: line two\n\n");
  });

  it("emits the reconnect hint first when present", () => {
    expect(sseFrame({ retryMs: 3000, event: "x", data: "y" })).toBe(
      "retry: 3000\nevent: x\ndata: y\n\n",
    );
  });

  it("negotiates on Accept, ignoring parameters and other media types", () => {
    expect(wantsEventStream(new Headers({ accept: "text/event-stream" }))).toBe(true);
    expect(
      wantsEventStream(new Headers({ accept: "application/json, text/event-stream;q=0.9" })),
    ).toBe(true);
    expect(wantsEventStream(new Headers({ accept: "application/json" }))).toBe(false);
    expect(wantsEventStream(new Headers())).toBe(false);
  });
});

describe("GET /v1/agent-jobs/{run_id}/events", () => {
  it("streams text/event-stream when the caller asks for it", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await settle(runId);

    const response = await get(`/v1/agent-jobs/${runId}/events`, {
      ...bearer(TENANT_A_KEY),
      accept: "text/event-stream",
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-cache, no-transform");
    // Without this an intermediary buffers the stream and the surface stops
    // being a stream at all.
    expect(response.headers.get("x-accel-buffering")).toBe("no");

    const body = await response.text();
    // Opens with the reconnect hint + the run's current status, so a client
    // that attaches mid-run knows where it stands without a second request.
    expect(body.startsWith("retry: 3000\nevent: run.status\ndata: ")).toBe(true);
    // Replays the backlog...
    expect(body).toContain("event: job_submitted\n");
    expect(body).toContain("event: run.completed\n");
    // ...and terminates with the sentinel because the run is settled.
    expect(body.endsWith("event: done\ndata: [DONE]\n\n")).toBe(true);
    // Every frame is blank-line terminated.
    expect(body.endsWith("\n\n")).toBe(true);
  });

  it("frames are individually parseable", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await settle(runId);
    const response = await get(`/v1/agent-jobs/${runId}/events`, {
      ...bearer(TENANT_A_KEY),
      accept: "text/event-stream",
    });
    const frames = await readSseFrames(response, 3);
    expect(frames.length).toBeGreaterThanOrEqual(3);

    const submitted = frames.find((frame) => frame.includes("event: job_submitted"));
    expect(submitted).toBeDefined();
    const dataLine = submitted?.split("\n").find((line) => line.startsWith("data: "));
    const parsed = JSON.parse((dataLine ?? "").slice("data: ".length)) as Record<string, unknown>;
    expect(parsed.run_id).toBe(runId);
    expect(parsed.kind).toBe("job_submitted");
    expect(parsed.source).toBe("control_plane");
  });

  it("resumes from Last-Event-ID, which wins over the query cursor", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await settle(runId);

    const full = await get(`/v1/agent-jobs/${runId}/events`, {
      ...bearer(TENANT_A_KEY),
      accept: "text/event-stream",
    });
    const frames = await readSseFrames(full, 10);
    const firstId = frames
      .find((frame) => frame.includes("event: job_submitted"))
      ?.split("\n")
      .find((line) => line.startsWith("id: "))
      ?.slice("id: ".length);
    expect(firstId).toBeDefined();

    const resumed = await SELF.fetch(
      // The query cursor is deliberately nonsense: `Last-Event-ID` must win,
      // because a reconnecting browser cannot rewrite its own URL.
      `${BASE}/v1/agent-jobs/${runId}/events?after_event_id=not-a-real-id`,
      {
        headers: {
          ...bearer(TENANT_A_KEY),
          accept: "text/event-stream",
          "last-event-id": firstId ?? "",
        },
      },
    );
    const body = await resumed.text();
    expect(body).not.toContain("event: job_submitted");
    expect(body).toContain("event: run.completed");
  });

  it("streams live frames as they are appended, then closes on the terminal state", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    // The run is NOT terminal, so the stream stays open and fans out.
    const response = await get(`/v1/agent-jobs/${runId}/events`, {
      ...bearer(TENANT_A_KEY),
      accept: "text/event-stream",
    });
    expect(response.status).toBe(200);

    const reader = response.body?.getReader();
    expect(reader).toBeDefined();
    const decoder = new TextDecoder();
    let seen = "";
    // Drain the open frame + the submit backlog first.
    while (!seen.includes("event: job_submitted")) {
      const chunk = await reader?.read();
      if (chunk?.value !== undefined) seen += decoder.decode(chunk.value, { stream: true });
      if (chunk?.done === true) break;
    }

    await post("/v1/self-hosted-workers/events", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      event_id: "e-live",
      kind: "log",
      event_json: { message: "compiling" },
      reported_at_unix: NOW,
    });
    await settle(runId);

    let live = "";
    for (let guard = 0; guard < 50; guard += 1) {
      const chunk = await reader?.read();
      if (chunk?.value !== undefined) live += decoder.decode(chunk.value, { stream: true });
      if (chunk?.done === true) break;
      if (live.includes("[DONE]")) break;
    }
    // The live event was fanned out to the already-open stream...
    expect(live).toContain("event: log\n");
    expect(live).toContain("compiling");
    // ...and the terminal state closed it.
    expect(live).toContain("event: done\ndata: [DONE]\n\n");
    await reader?.cancel().catch(() => undefined);
  });

  it("falls back to the cursored JSON page when Accept is not text/event-stream", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await settle(runId);
    const response = await get(`/v1/agent-jobs/${runId}/events`, bearer(TENANT_A_KEY));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe("list");
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.cursor_reset).toBe(false);
    expect(body.has_more).toBe(false);
  });

  it("an unknown cursor restarts from the oldest event and SAYS so", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await get(
      `/v1/agent-jobs/${runId}/events?after_event_id=invented`,
      bearer(TENANT_A_KEY),
    );
    const body = (await response.json()) as { cursor_reset: boolean; data: unknown[] };
    // The caller is never left with a permanently unusable cursor.
    expect(body.cursor_reset).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);
  });

  it("the page limit is clamped, not rejected", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await get(`/v1/agent-jobs/${runId}/events?limit=99999`, bearer(TENANT_A_KEY));
    expect(((await response.json()) as { limit: number }).limit).toBe(500);
  });
});
