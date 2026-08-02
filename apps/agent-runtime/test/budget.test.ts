/**
 * The open-job concurrency bound and its retention backstop (#474 / #502).
 *
 * `/v1/agent-jobs` is the first surface that lets an ORDINARY tenant key
 * enqueue runtime dispatches at will, so it bounds concurrency per tenant. Two
 * properties have to hold together, and getting either wrong is a real outage:
 *
 *  - a runaway submit loop is refused `429 agent_job_open_limit_reached`;
 *  - a job stops counting the moment its RUN settles, and a never-leased
 *    dispatch is aged out, so a tenant is never locked out for the lifetime of
 *    the deployment.
 *
 * The bound is exercised through the RESPONSE a caller observes rather than an
 * internal counter — an assertion that cannot fail is not coverage.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TENANT_A_KEY,
  WORKER_A,
  bearer,
  drainPlane,
  getEnvVar,
  post,
  setEnvVar,
  submitJob,
} from "./fixtures.js";

const CAP = 3;
const original = {
  cap: getEnvVar("AGENT_JOB_MAX_OPEN_PER_TENANT"),
  ttl: getEnvVar("AGENT_JOB_DISPATCH_TTL_SECS"),
  enabled: getEnvVar("AGENT_RUNTIME_ENABLED"),
};

beforeEach(async () => {
  await drainPlane(WORKER_A);
  setEnvVar("AGENT_JOB_MAX_OPEN_PER_TENANT", String(CAP));
});

afterEach(() => {
  setEnvVar("AGENT_JOB_MAX_OPEN_PER_TENANT", original.cap);
  setEnvVar("AGENT_JOB_DISPATCH_TTL_SECS", original.ttl);
  setEnvVar("AGENT_RUNTIME_ENABLED", original.enabled);
});

/** Submit `count` distinct jobs and return their statuses in order. */
async function submitMany(count: number): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const response = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": `budget-${crypto.randomUUID()}` },
      { input: "work", required_capabilities: ["coding"] },
    );
    statuses.push(response.status);
  }
  return statuses;
}

describe("open-job budget", () => {
  it("refuses the submit that would exceed the cap, and names a real remedy", async () => {
    expect(await submitMany(CAP)).toEqual([202, 202, 202]);

    const over = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "budget-over" },
      { input: "work" },
    );
    expect(over.status).toBe(429);
    const body = (await over.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("agent_job_open_limit_reached");
    // The message must point at something that actually releases a slot.
    expect(body.error.message).toContain("/v1/agent-jobs/{run_id}/cancel");
  });

  it("cancelling a job releases its slot", async () => {
    const first = await submitJob(TENANT_A_KEY, { idempotency_key: "budget-release-1" });
    await submitMany(CAP - 1);
    expect(
      (
        await post(
          "/v1/agent-jobs",
          { ...bearer(TENANT_A_KEY), "idempotency-key": "budget-blocked" },
          { input: "work" },
        )
      ).status,
    ).toBe(429);

    await post(`/v1/agent-jobs/${first.runId}/cancel`, bearer(TENANT_A_KEY), {});

    const afterRelease = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "budget-after-release" },
      { input: "work" },
    );
    expect(afterRelease.status).toBe(202);
  });

  it("a RETRY of an existing key is never refused, even at the cap", async () => {
    const key = "budget-retry";
    const first = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": key },
      { input: "work" },
    );
    expect(first.status).toBe(202);
    await submitMany(CAP - 1);

    // A caller must always be able to re-poll and cancel what it already has,
    // so deduplication happens BEFORE the budget is consulted.
    const retry = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": key },
      { input: "work" },
    );
    expect(retry.status).toBe(200);
    expect(((await retry.json()) as { deduplicated: boolean }).deduplicated).toBe(true);
  });

  it("the tenant's cap is its own — another tenant is unaffected", async () => {
    await submitMany(CAP);
    const other = await post(
      "/v1/agent-jobs",
      { ...bearer("sk-tenant-b"), "idempotency-key": "budget-other-tenant" },
      { input: "work" },
    );
    expect(other.status).toBe(202);
  });

  it("a never-leased dispatch is aged out by the TTL, so a workerless tenant self-heals", async () => {
    // The three releases the 429 names all require some actor to touch the run.
    // A tenant with NO worker has none of them, so without the TTL sweep it is
    // locked out for the lifetime of the deployment.
    setEnvVar("AGENT_JOB_DISPATCH_TTL_SECS", "1");
    await submitMany(CAP);
    // One second of wall clock is enough because the sweep compares the
    // dispatch's `queued_at_unix` against the gateway clock.
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const afterTtl = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "budget-after-ttl" },
      { input: "work" },
    );
    expect(afterTtl.status).toBe(202);
  });
});

describe("operator kill switch", () => {
  it("AGENT_RUNTIME_ENABLED=0 refuses every run verb with 403", async () => {
    setEnvVar("AGENT_RUNTIME_ENABLED", "0");
    for (const path of ["/v1/agent-jobs", "/v1/agent-runs"]) {
      const response = await post(path, bearer(TENANT_A_KEY), { input: "work" });
      expect(response.status, path).toBe(403);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        "agent_runtime_disabled",
      );
    }
  });

  it("a mistyped cap falls back to the default rather than to zero", async () => {
    // Falling back to 0 would refuse EVERY submit — the failure mode a naive
    // `Number(...) || 0` produces.
    setEnvVar("AGENT_JOB_MAX_OPEN_PER_TENANT", "not-a-number");
    const response = await post(
      "/v1/agent-jobs",
      { ...bearer(TENANT_A_KEY), "idempotency-key": "budget-mistyped" },
      { input: "work" },
    );
    expect(response.status).toBe(202);
  });
});
