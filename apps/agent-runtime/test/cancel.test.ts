/**
 * Cancel: terminalization, idempotency, and WHICH runtime remedy ran.
 *
 * `runtime_cancel_dispatched` is the field most likely to be got wrong, because
 * it does NOT mean "the cancel took effect" — it reports which remedy the
 * serving node used. The two branches are asserted separately here: an UNLEASED
 * start dispatch is withdrawn locally (`false`), and a LEASED one cannot be, so
 * a `cancel_run` is handed to the runtime instead (`true`).
 *
 * The #502 supersession rule is asserted too: once a `cancel_run` exists for a
 * run, its `start_run` must never be handed out again — otherwise the start
 * holder's lease expiring would let a second worker begin work the caller had
 * already cancelled.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  pollLease,
  post,
  submitJob,
} from "./fixtures.js";

const NOW = 1_800_000_000;

beforeEach(async () => {
  await drainPlane(WORKER_A);
});

describe("cancel", () => {
  it("terminalizes the run and withdraws an UNLEASED start dispatch locally", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.cancelled).toBe(true);
    expect(body.status).toBe("cancelled");
    expect(body.terminal).toBe(true);
    // No worker held it, so the node withdrew its own copy — no `cancel_run`
    // was needed.
    expect(body.runtime_cancel_dispatched).toBe(false);

    // The withdrawn dispatch is gone: a worker polling now finds nothing.
    expect(await pollLease(WORKER_A, { nowUnix: NOW })).toBeNull();
  });

  it("emits a cancel_run when the start dispatch is already LEASED", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(lease?.run_id).toBe(runId);

    const response = await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.cancelled).toBe(true);
    expect(body.runtime_cancel_dispatched).toBe(true);

    // The runtime is handed the cancel to act on.
    const cancelLease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(cancelLease?.action).toBe("cancel_run");
    expect(cancelLease?.run_id).toBe(runId);
  });

  it("is idempotent: a second cancel answers 200 with cancelled: false", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    const second = await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    expect(second.status).toBe(200);
    const body = (await second.json()) as Record<string, unknown>;
    expect(body.cancelled).toBe(false);
    expect(body.status).toBe("cancelled");
  });

  it("#502: an expired start_run lease is not re-leasable once the run is cancelled", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    // Lease the start so the cancel path emits a `cancel_run` rather than
    // withdrawing it — both dispatches now exist for the same run.
    const start = await pollLease(WORKER_A, { nowUnix: NOW, leaseDurationSecs: 60 });
    expect(start?.action).toBe("start_run");
    await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});

    // Take the cancel out of contention by leasing it (unacked, so no
    // settled-run reclaim runs and the start_run row is still there).
    const cancel = await pollLease(WORKER_A, { nowUnix: NOW + 61, leaseDurationSecs: 600 });
    expect(cancel?.action).toBe("cancel_run");
    expect(cancel?.run_id).toBe(runId);

    // Now the ONLY leasable-looking row left is the start_run whose lease
    // expired at NOW+60. Everything else `canLeaseTo` tests — ack status,
    // tenant, workspace, adapter, capabilities, lease expiry — says yes.
    // Supersession is the only rule that says no, so a build without it hands
    // a second worker the START of work the caller already cancelled.
    expect(await pollLease(WORKER_A, { nowUnix: NOW + 62 })).toBeNull();
  });

  it("the cancelled run is collectible and its output is honest absence", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await post(`/v1/agent-jobs/${runId}/cancel`, bearer(TENANT_A_KEY), {});
    const result = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(result.status).toBe(200);
    const body = (await result.json()) as Record<string, unknown>;
    expect(body.status).toBe("cancelled");
    // Nothing ran, so nothing is fabricated.
    expect(body.output).toBe(null);
    expect(body.output_recorded).toBe(false);
  });

  it("cancelling an unknown run is 404, not 500", async () => {
    const response = await post(
      "/v1/agent-jobs/job-does-not-exist/cancel",
      bearer(TENANT_A_KEY),
      {},
    );
    expect(response.status).toBe(404);
  });

  it("a malformed run id is 404 rather than reaching storage", async () => {
    const response = await get("/v1/agent-jobs/not%2Fa%2Frun/", bearer(TENANT_A_KEY));
    expect(response.status).toBe(404);
  });
});
