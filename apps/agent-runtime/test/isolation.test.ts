/**
 * Run state isolation between tenants.
 *
 * The rule (Rust `agent_jobs.rs`): a cross-tenant `run_id` resolves to `None`
 * and is reported as **404, not 403**, so the surface is not an existence
 * oracle. Here that is obtained structurally — the Durable Object name is
 * `${tenant_id}:${run_id}`, so tenant B's stub for tenant A's run id is a
 * different, empty object.
 *
 * Every read AND write verb is asserted, because an isolation check that is
 * present on `GET` and missing on `POST .../cancel` is still a cross-tenant
 * write.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  TENANT_B_KEY,
  WORKER_A,
  WORKER_B,
  bearer,
  drainPlane,
  get,
  pollLease,
  post,
  submitJob,
  workerHeaders,
} from "./fixtures.js";

const NOW = 1_800_000_000;

beforeEach(async () => {
  await drainPlane(WORKER_A);
  await drainPlane(WORKER_B);
});

describe("cross-tenant run isolation", () => {
  it("tenant B cannot read tenant A's run — and gets 404, not 403", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);

    for (const path of [
      `/v1/agent-jobs/${runId}`,
      `/v1/agent-jobs/${runId}/events`,
      `/v1/agent-jobs/${runId}/result`,
    ]) {
      const response = await get(path, bearer(TENANT_B_KEY));
      expect(response.status, path).toBe(404);
      const body = (await response.json()) as { error: { code: string } };
      // 403 would confirm the run EXISTS. 404 does not.
      expect(body.error.code, path).toBe("agent_job_not_found");
    }
  });

  it("tenant B cannot cancel tenant A's run", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const denied = await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_B_KEY), {});
    expect(denied.status).toBe(404);

    // ...and the run is untouched: A can still cancel it itself, which proves
    // B's request did not terminalize it.
    const own = await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    expect(((await own.json()) as { cancelled: boolean }).cancelled).toBe(true);
  });

  it("the SAME run id in two tenants names two independent runs", async () => {
    // Identical idempotency key in both tenants: the derived ids differ because
    // the tenant is mixed into the digest, and even a hand-crafted collision
    // would address different Durable Objects.
    const a = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "same-key" },
      { input: "A's work" },
    );
    const b = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_B_KEY), "idempotency-key": "same-key" },
      { input: "B's work" },
    );
    const aId = ((await a.json()) as { run_id: string }).run_id;
    const bId = ((await b.json()) as { run_id: string }).run_id;
    expect(aId).not.toBe(bId);

    await post(`/v1/agent-jobs/${aId}/cancel`, bearer(TENANT_A_KEY), {});
    const bStatus = await get(`/v1/agent-jobs/${bId}`, bearer(TENANT_B_KEY));
    // Cancelling A's run left B's alone.
    expect(((await bStatus.json()) as { status: string }).status).toBe("queued");
  });

  it("tenant B's worker is never handed tenant A's dispatch", async () => {
    await submitJob(TENANT_A_KEY);
    // Worker B polls with every capability A's job needs. The only thing that
    // separates them is tenancy.
    expect(await pollLease(WORKER_B, { nowUnix: NOW })).toBeNull();
    // ...and A's own worker does get it, so the queue is not simply empty.
    expect(await pollLease(WORKER_A, { nowUnix: NOW })).not.toBeNull();
  });

  it("tenant B's worker cannot report evidence onto tenant A's run", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await post("/v1/self-hosted-workers/events", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_B,
      session_id: "s1",
      run_id: runId,
      event_id: "e1",
      kind: "lifecycle",
      event_json: { state: "completed", output: "forged" },
      reported_at_unix: NOW,
    });
    // The write is accepted for worker B's OWN tenant namespace (where the run
    // does not exist), so nothing lands on A's run.
    expect(response.status).toBe(201);

    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    const body = (await status.json()) as Record<string, unknown>;
    expect(body.status).toBe("queued");
    expect(body.runtime_reported_event_count).toBe(0);

    const result = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(result.status).toBe(409);
  });

  it("tenant B's worker cannot ack a dispatch in tenant A's plane", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    const response = await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_B,
      dispatch_id: lease?.dispatch_id,
      action: "start_run",
      lease_id: lease?.lease_id,
      run_id: runId,
      status: "completed",
      reported_at_unix: NOW + 1,
    });
    expect(response.status).toBe(400);
    // B's plane has no such dispatch at all — the queue is addressed by
    // (tenant, workspace), so B cannot even see A's row.
    expect(((await response.json()) as { error: { message: string } }).error.message).toContain(
      "unknown dispatch",
    );

    // A's run is still un-settled.
    const result = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(result.status).toBe(409);
  });

  it("a run id from another tenant does not leak through the SSE stream either", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await get(`/v1/agent-jobs/${runId}/events`, {
      ...bearer(TENANT_B_KEY),
      accept: "text/event-stream",
    });
    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).not.toContain("text/event-stream");
  });
});
