/**
 * The run lifecycle end to end: submit → poll (lease) → ack → result.
 *
 * This is the loop that has to work for the async agent-job protocol (#474) to
 * mean anything: a caller submits, a self-hosted worker leases the dispatch
 * through the internal transport, acks it, and the caller collects the result.
 * If the ack→run projection were missing, `/result` would answer
 * `409 agent_job_not_terminal` forever — so every step is asserted through the
 * HTTP surface a real caller and a real worker see, not through internals.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  TENANT_A_READONLY_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  get,
  pollLease,
  post,
  submitJob,
  workerHeaders,
} from "./fixtures.js";

const NOW = 1_800_000_000;

// One `workerd` instance serves the whole project, so Durable Object storage
// survives between tests. Draining the dispatch queue first makes each test's
// lease assertions about ITS job rather than a leftover from an earlier one.
beforeEach(async () => {
  await drainPlane(WORKER_A);
});

describe("agent job lifecycle", () => {
  it("submit → poll → ack(completed) → result", async () => {
    const { runId, response, json } = await submitJob(TENANT_A_KEY);
    expect(response.status).toBe(202);
    expect(json.deduplicated).toBe(false);
    expect(json.status).toBe("queued");
    expect(runId).toMatch(/^job-[0-9a-f]{32}$/);

    // The run is queued and NOT collectible yet.
    const early = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(early.status).toBe(409);
    expect(((await early.json()) as { error: { code: string } }).error.code).toBe(
      "agent_job_not_terminal",
    );

    // The worker leases it.
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(lease).not.toBeNull();
    expect(lease?.run_id).toBe(runId);
    expect(lease?.action).toBe("start_run");
    expect(lease?.attempt).toBe(1);
    expect(lease?.trust_level).toBe("reported_by_self_hosted_worker");
    expect(lease?.lease_expires_at_unix).toBe(NOW + 300);
    // #305: the correlation identity rides the lease verbatim.
    expect(lease?.agent_run_id).toBe(runId);
    expect(typeof lease?.request_id).toBe("string");
    // #307: no governed parent was declared, so the key is OMITTED, not null.
    expect(Object.hasOwn(lease as object, "parent_action_fingerprint")).toBe(false);

    // A second poll finds nothing: the dispatch is leased.
    expect(await pollLease(WORKER_A, { nowUnix: NOW })).toBeNull();

    // The worker settles it.
    const ack = await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      dispatch_id: lease?.dispatch_id,
      action: "start_run",
      lease_id: lease?.lease_id,
      run_id: runId,
      status: "completed",
      output: "patch applied",
      reported_at_unix: NOW + 10,
    });
    expect(ack.status).toBe(200);
    expect(((await ack.json()) as { run_status: string }).run_status).toBe("completed");

    // The caller collects.
    const result = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(result.status).toBe(200);
    const body = (await result.json()) as Record<string, unknown>;
    expect(body.status).toBe("completed");
    expect(body.terminal).toBe(true);
    expect(body.output).toBe("patch applied");
    expect(body.completed_at_unix).toBe(NOW + 10);
  });

  it("status reflects the worker-reported lifecycle before it settles", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    await post("/v1/self-hosted-workers/events", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      event_id: "e1",
      kind: "lifecycle",
      event_json: { state: "started", turns_executed: 2 },
      reported_at_unix: NOW,
    });

    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    const body = (await status.json()) as Record<string, unknown>;
    expect(body.status).toBe("running");
    expect(body.terminal).toBe(false);
    expect(body.turns_executed).toBe(2);
    expect(body.runtime_reported_state).toBe("running");
  });

  it("an unrecognized lifecycle word leaves the run untouched", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const event = await post("/v1/self-hosted-workers/events", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      event_id: "e1",
      kind: "lifecycle",
      event_json: { state: "wobbling" },
      reported_at_unix: NOW,
    });
    expect(event.status).toBe(201);
    // Reported as "nothing was applied" rather than guessed into a state the
    // caller would then collect.
    expect(((await event.json()) as { applied_run_status: string | null }).applied_run_status).toBe(
      null,
    );
    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    expect(((await status.json()) as { status: string }).status).toBe("queued");
  });

  it("a worker-reported artifact lands on the run and is collected with the result", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const artifact = await post("/v1/self-hosted-workers/artifacts", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      artifact_id: "a1",
      name: "patch.diff",
      media_type: "text/x-diff",
      byte_len: 42,
      reported_at_unix: NOW,
    });
    expect(artifact.status).toBe(201);

    await post("/v1/self-hosted-workers/events", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      event_id: "e-done",
      kind: "lifecycle",
      event_json: { state: "completed", output: { pull_request: "https://example.test/pr/1" } },
      reported_at_unix: NOW + 5,
    });

    const result = await get(`/v1/agent-jobs/${runId}/result`, bearer(TENANT_A_KEY));
    expect(result.status).toBe(200);
    const body = (await result.json()) as {
      artifacts: Array<{ kind: string; worker_id: string }>;
      output: string;
    };
    expect(body.artifacts).toHaveLength(1);
    expect(body.artifacts[0]?.kind).toBe("artifact");
    expect(body.artifacts[0]?.worker_id).toBe("worker-a");
    // A structured output is re-serialized rather than silently dropped.
    expect(body.output).toContain("https://example.test/pr/1");
  });

  it("a checkpoint is recorded against the run", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const response = await post("/v1/self-hosted-workers/checkpoints", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      session_id: "s1",
      run_id: runId,
      checkpoint_id: "c1",
      checkpoint_name: "after-plan",
      size_bytes: 128,
      created_at_unix: NOW,
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { checkpoint: { trust_level: string } };
    expect(body.checkpoint.trust_level).toBe("reported_by_self_hosted_worker");
  });
});

describe("idempotency", () => {
  it("the same key returns the ORIGINAL run id with deduplicated: true and 200", async () => {
    const first = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "issue-42-attempt-1" },
      { input: "fix the bug" },
    );
    expect(first.status).toBe(202);
    const firstBody = (await first.json()) as Record<string, unknown>;
    expect(firstBody.deduplicated).toBe(false);
    expect(firstBody.idempotency_key_source).toBe("header");

    const retry = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "issue-42-attempt-1" },
      { input: "fix the bug" },
    );
    expect(retry.status).toBe(200);
    const retryBody = (await retry.json()) as Record<string, unknown>;
    expect(retryBody.deduplicated).toBe(true);
    expect(retryBody.run_id).toBe(firstBody.run_id);
  });

  it("the body field is accepted and the header wins when both are present", async () => {
    const viaBody = await post("/v1/agent-jobs", bearer(TENANT_A_KEY), {
      input: "x",
      idempotency_key: "body-key",
    });
    const viaBodyJson = (await viaBody.json()) as Record<string, unknown>;
    expect(viaBodyJson.idempotency_key_source).toBe("body");

    const both = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "header-key" },
      { input: "x", idempotency_key: "body-key" },
    );
    const bothJson = (await both.json()) as Record<string, unknown>;
    expect(bothJson.idempotency_key_source).toBe("header");
    expect(bothJson.idempotency_key).toBe("header-key");
    // Different key ⇒ different job, so the header genuinely decided.
    expect(bothJson.run_id).not.toBe(viaBodyJson.run_id);
  });

  it("the derived run id is namespaced by tenant", async () => {
    const a = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "shared-key" },
      { input: "x" },
    );
    const b = await post(
      "/v1/agent-jobs",
      { ...bearer("sk-tenant-b"), "idempotency-key": "shared-key" },
      { input: "x" },
    );
    const aJson = (await a.json()) as Record<string, unknown>;
    const bJson = (await b.json()) as Record<string, unknown>;
    // Identical keys in different tenants are different jobs, so one tenant's
    // key can never address (or collide with) another tenant's run.
    expect(aJson.run_id).not.toBe(bJson.run_id);
  });

  it("an over-long idempotency key is refused", async () => {
    const response = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "k".repeat(201) },
      { input: "x" },
    );
    expect(response.status).toBe(400);
  });
});

describe("scopes and validation", () => {
  it("a read-only key cannot submit but can read", async () => {
    const submit = await post("/v1/agent-jobs", bearer(TENANT_A_READONLY_KEY), { input: "x" });
    expect(submit.status).toBe(403);
    expect(((await submit.json()) as { error: { code: string } }).error.code).toBe("scope_denied");

    const { runId } = await submitJob(TENANT_A_KEY);
    const read = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_READONLY_KEY));
    expect(read.status).toBe(200);
  });

  it("an empty input is a 400", async () => {
    const response = await post("/v1/agent-jobs", bearer(TENANT_A_KEY), { input: "  " });
    expect(response.status).toBe(400);
  });

  it("a malformed parent-action fingerprint is a 400 and is never persisted", async () => {
    const response = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "x-ferrogate-parent-action-fingerprint": "sha256:nothex" },
      { input: "x" },
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_parent_action_fingerprint_header",
    );
  });

  it("a well-formed parent-action fingerprint rides the lease (#307)", async () => {
    const fingerprint = `sha256:${"ab".repeat(32)}`;
    const submitted = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "x-ferrogate-parent-action-fingerprint": fingerprint },
      { input: "x", required_capabilities: ["coding"] },
    );
    const runId = ((await submitted.json()) as { run_id: string }).run_id;
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(lease?.run_id).toBe(runId);
    expect(lease?.parent_action_fingerprint).toBe(fingerprint);
  });

  it("an egress request outside the governed allowlist is refused 422 (sealed by default)", async () => {
    const response = await post("/v1/agent-jobs", bearer(TENANT_A_KEY), {
      input: "x",
      egress_allowlist: ["evil.test"],
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "egress_host_not_governed",
    );
  });

  it("a submission that opens no egress is granted a sealed isolation posture", async () => {
    const { json } = await submitJob(TENANT_A_KEY);
    // #471 is load-bearing: both flags are pinned, and snapshotting is
    // advertised OFF because there is no CF primitive for it.
    expect(json.isolation).toMatchObject({
      backend: "cloudflare_sandbox",
      enableInternet: false,
      interceptHttps: true,
      allowedHosts: [],
      snapshotSupported: false,
    });
  });
});

describe("lease semantics", () => {
  it("a worker whose capabilities do not cover the dispatch is handed nothing", async () => {
    await submitJob(TENANT_A_KEY, { required_capabilities: ["coding"] });
    expect(await pollLease(WORKER_A, { nowUnix: NOW, capabilities: [] })).toBeNull();
    // ...but the same worker declaring the capability does get it.
    expect(await pollLease(WORKER_A, { nowUnix: NOW, capabilities: ["coding"] })).not.toBeNull();
  });

  it("an expired lease is re-leasable and the attempt counter advances", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const first = await pollLease(WORKER_A, { nowUnix: NOW, leaseDurationSecs: 60 });
    expect(first?.attempt).toBe(1);
    // Before expiry: nothing.
    expect(await pollLease(WORKER_A, { nowUnix: NOW + 30 })).toBeNull();
    // After expiry: re-leased as attempt 2, with a NEW lease id.
    const second = await pollLease(WORKER_A, { nowUnix: NOW + 61 });
    expect(second?.attempt).toBe(2);
    expect(second?.run_id).toBe(runId);
    expect(second?.lease_id).not.toBe(first?.lease_id);
  });

  it("an ack under a stale lease id is refused", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    const response = await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      dispatch_id: lease?.dispatch_id,
      action: "start_run",
      lease_id: "someone-elses-lease",
      run_id: runId,
      status: "completed",
      reported_at_unix: NOW + 1,
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { message: string } }).error.message).toContain(
      "lease_id does not match",
    );
  });

  it("an ack after the lease expired is refused", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW, leaseDurationSecs: 60 });
    const response = await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      dispatch_id: lease?.dispatch_id,
      action: "start_run",
      lease_id: lease?.lease_id,
      run_id: runId,
      status: "completed",
      reported_at_unix: NOW + 61,
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { message: string } }).error.message).toContain(
      "lease has expired",
    );
  });

  it("a double ack is refused", async () => {
    const { runId } = await submitJob(TENANT_A_KEY);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    const body = {
      protocol_version: 1,
      identity: WORKER_A,
      dispatch_id: lease?.dispatch_id,
      action: "start_run",
      lease_id: lease?.lease_id,
      run_id: runId,
      status: "accepted",
      reported_at_unix: NOW + 1,
    };
    expect((await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), body)).status).toBe(
      200,
    );
    const second = await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), body);
    expect(second.status).toBe(400);
    expect(((await second.json()) as { error: { message: string } }).error.message).toContain(
      "already acknowledged",
    );
  });

  it("polling with no queued work answers 204, not an empty 200", async () => {
    const response = await post("/v1/self-hosted-workers/runs/poll", workerHeaders(), {
      protocol_version: 1,
      identity: WORKER_A,
      supported_capabilities: ["coding"],
      now_unix: NOW,
      lease_duration_secs: 60,
    });
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
  });
});
