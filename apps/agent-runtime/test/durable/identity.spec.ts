/**
 * The worker-plane credential authority, ON THE DURABLE PATH — including the
 * invariant this Worker exists to hold: **a tenant bearer key cannot reach any
 * of the six `/v1/self-hosted-workers/*` callbacks.**
 *
 * `test/internal-auth.test.ts` already proves that against the in-memory
 * registry. This file re-proves it against `self_hosted_worker_registrations`
 * rows in a REAL control D1 database, because swapping the storage under a
 * credential authority is exactly when a taxonomy silently moves.
 *
 * It also pins Rust security fix **#113**: identity expiry is judged against
 * the SERVER's clock, so a worker whose registration expired cannot keep
 * authenticating by reporting `observed_at_unix: 0` — or by omitting the field.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  DURABLE_WORKER_A,
  DURABLE_WORKER_EXPIRED,
  DURABLE_WORKER_RETIRED,
  INTERNAL_PATHS,
  KEY_LIVE,
  bearer,
  errorCode,
  heartbeat,
  post,
  setupDurablePorts,
  workerEnvelopeFor,
  workerHeaders,
} from "./setup.js";

beforeAll(setupDurablePorts);

describe("D1 self_hosted_worker_registrations: admission", () => {
  it("a registered, active worker is admitted", async () => {
    const response = await heartbeat({ ...DURABLE_WORKER_A });
    expect(response.status, await response.clone().text()).toBe(201);
  });

  it("an unknown worker is 401 and a registered-but-INACTIVE worker is 403", async () => {
    const unknown = await heartbeat({ ...DURABLE_WORKER_A, worker_id: "not-registered" });
    expect(unknown.status).toBe(401);
    expect(await errorCode(unknown)).toBe("invalid_self_hosted_worker_identity");

    const inactive = await heartbeat({ ...DURABLE_WORKER_RETIRED });
    expect(inactive.status).toBe(403);
    expect(await errorCode(inactive)).toBe("inactive_self_hosted_worker");
  });

  it("a wrong token_secret is refused even with the right token_id", async () => {
    const response = await heartbeat({ ...DURABLE_WORKER_A, token_secret: "0".repeat(64) });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_self_hosted_worker_identity");
  });

  it("a TENANCY mismatch answers unknown_worker, never a different code", async () => {
    // `id` in the table is the worker id, so a caller naming another tenancy
    // FINDS the row. It must not learn that: the answer is the same 401 an
    // unregistered worker gets, so the surface is not an existence oracle.
    const response = await heartbeat({ ...DURABLE_WORKER_A, tenant_id: "tenant-b" });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_self_hosted_worker_identity");

    const wrongWorkspace = await heartbeat({ ...DURABLE_WORKER_A, workspace_id: "ws-other" });
    expect(wrongWorkspace.status).toBe(401);
    expect(await errorCode(wrongWorkspace)).toBe("invalid_self_hosted_worker_identity");
  });
});

describe("#113: identity expiry is judged against the SERVER's clock", () => {
  it("an expired registration is refused even when the caller reports observed_at_unix: 0", async () => {
    // Rust `validate_worker_identity` overwrites `observed_at_unix`
    // unconditionally before validating, precisely so a client cannot satisfy
    // the expiry check by lying. `src/middleware/auth.ts` does the same.
    const response = await heartbeat({ ...DURABLE_WORKER_EXPIRED, observed_at_unix: 0 });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_self_hosted_worker_identity");
  });

  it("an expired registration is refused when the field is OMITTED entirely", async () => {
    // The variant a `typeof x === "number"` guard would have let through: no
    // field at all means no comparison, which means never expired.
    const response = await heartbeat({ ...DURABLE_WORKER_EXPIRED });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_self_hosted_worker_identity");
  });

  it("a NON-expiring registration is still admitted (the check is not blanket)", async () => {
    // Without this, both assertions above would hold on a build that refused
    // every worker, which is a different and useless property.
    expect((await heartbeat({ ...DURABLE_WORKER_A, observed_at_unix: 0 })).status).toBe(201);
  });
});

describe("ROUTE-MAP invariant 2 holds on the durable registry too", () => {
  for (const path of INTERNAL_PATHS) {
    it(`${path} refuses a valid, fully-scoped D1 tenant key`, async () => {
      const response = await post(
        path,
        bearer(KEY_LIVE),
        workerEnvelopeFor(path, DURABLE_WORKER_A),
      );
      expect(response.status).toBe(401);
      // It fails at the FIRST worker-plane gate: the tenant credential is
      // never consulted, because there is no code path from one to a
      // registered worker identity.
      expect(await errorCode(response)).toBe("invalid_self_hosted_worker_transport_security");
    });

    it(`${path} refuses a D1 tenant key even with the transport marker forged`, async () => {
      const response = await post(
        path,
        { ...bearer(KEY_LIVE), ...workerHeaders() },
        // A tenant key grants no worker identity, so this is what a tenant
        // caller could actually produce.
        { protocol_version: 1 },
      );
      expect(response.status).toBe(400);
      expect(await errorCode(response)).toBe("invalid_self_hosted_worker_transport");
    });

    it(`${path} DOES admit the registered worker (not vacuous)`, async () => {
      const response = await post(path, workerHeaders(), workerEnvelopeFor(path, DURABLE_WORKER_A));
      const text = await response.clone().text();
      expect(response.status, `${path} -> ${text}`).not.toBe(401);
      expect(response.status, `${path} -> ${text}`).not.toBe(403);
      expect([200, 201, 204, 400], `${path} -> ${text}`).toContain(response.status);
      if (response.status === 400) {
        // Only `runs/ack` can land here: the envelope is well-formed, so the
        // auth leg cannot 400 it — this is the queue refusing an unknown
        // lease, which is reached ONLY after the worker was admitted.
        expect(path).toBe("/v1/self-hosted-workers/runs/ack");
      }
    });
  }
});
