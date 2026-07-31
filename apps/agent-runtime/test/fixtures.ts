/**
 * Shared fixtures. Keep the credential values in ONE place so a test cannot
 * accidentally assert against a key it also defined.
 */
import { SELF, env } from "cloudflare:test";
import type { AgentRuntimeBindings } from "../src/ports.js";

export const BASE = "https://agent-runtime.test";

/** Tenant bearer keys (see `vitest.config.ts`). */
export const TENANT_A_KEY = "sk-tenant-a";
export const TENANT_B_KEY = "sk-tenant-b";
export const TENANT_A_READONLY_KEY = "sk-tenant-a-readonly";
export const TENANT_A_SUSPENDED_KEY = "sk-tenant-a-suspended";

/** Self-hosted worker identity envelopes (see `vitest.config.ts`). */
export const WORKER_A = {
  tenant_id: "tenant-a",
  workspace_id: "ws-a",
  worker_id: "worker-a",
  token_id: "tok-a",
  token_secret: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
} as const;

export const WORKER_B = {
  tenant_id: "tenant-b",
  workspace_id: "ws-b",
  worker_id: "worker-b",
  token_id: "tok-b",
  token_secret: "0f9e8d7c6b5a49382716f5e4d3c2b1a00f9e8d7c6b5a49382716f5e4d3c2b1a0",
} as const;

/** The six `auth.kind: "internal"` worker-plane callbacks, by path. */
export const INTERNAL_ROUTES = [
  "/v1/self-hosted-workers/heartbeat",
  "/v1/self-hosted-workers/events",
  "/v1/self-hosted-workers/artifacts",
  "/v1/self-hosted-workers/checkpoints",
  "/v1/self-hosted-workers/runs/poll",
  "/v1/self-hosted-workers/runs/ack",
] as const;

/**
 * A worker-plane body that WOULD be accepted if the caller were an authorized
 * worker, for each of the six internal callbacks.
 *
 * Shared so the two suites that need it cannot drift apart:
 * `internal-auth.test.ts` posts it with a TENANT credential (and must be
 * refused), `contract.test.ts` posts it with the WORKER credential (and must be
 * served). Both directions have to be about the same request for the pair to
 * mean anything.
 */
export function workerEnvelopeFor(
  path: string,
  identity: typeof WORKER_A | typeof WORKER_B = WORKER_A,
): Record<string, unknown> {
  const base = { protocol_version: 1, identity };
  switch (path) {
    case "/v1/self-hosted-workers/heartbeat":
      return { ...base, status: "idle", reported_at_unix: 1_800_000_000 };
    case "/v1/self-hosted-workers/events":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        event_id: "e1",
        kind: "lifecycle",
        event_json: { state: "running" },
        reported_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/artifacts":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        artifact_id: "a1",
        name: "patch.diff",
        media_type: "text/x-diff",
        byte_len: 10,
        reported_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/checkpoints":
      return {
        ...base,
        session_id: "s1",
        run_id: "r1",
        checkpoint_id: "c1",
        created_at_unix: 1_800_000_000,
      };
    case "/v1/self-hosted-workers/runs/poll":
      return {
        ...base,
        supported_capabilities: [],
        now_unix: 1_800_000_000,
        lease_duration_secs: 60,
      };
    case "/v1/self-hosted-workers/runs/ack":
      return {
        ...base,
        dispatch_id: "d1",
        action: "start_run",
        lease_id: "l1",
        run_id: "r1",
        status: "completed",
        reported_at_unix: 1_800_000_000,
      };
    default:
      return base;
  }
}

export function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}`, "content-type": "application/json" };
}

/** A worker-plane request: the transport-security marker, never a bearer key. */
export function workerHeaders(
  security: "mutual_tls" | "symmetric_aead" = "symmetric_aead",
): Record<string, string> {
  return { "x-ferrogate-transport-security": security, "content-type": "application/json" };
}

export async function post(
  path: string,
  headers: Record<string, string>,
  body: unknown,
): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

export async function get(path: string, headers: Record<string, string>): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, { method: "GET", headers });
}

/** Submit a job and return its `run_id`. */
export async function submitJob(
  key: string,
  body: Record<string, unknown> = {},
): Promise<{
  readonly runId: string;
  readonly response: Response;
  readonly json: Record<string, unknown>;
}> {
  const response = await post("/v1/agent-jobs", bearer(key), {
    input: "write the patch",
    required_capabilities: ["coding"],
    ...body,
  });
  const json = (await response.json()) as Record<string, unknown>;
  return { runId: String(json.run_id ?? ""), response, json };
}

/** Lease the next dispatch as a worker. Returns `null` on 204 (no work). */
export async function pollLease(
  identity: typeof WORKER_A | typeof WORKER_B,
  options: {
    readonly nowUnix?: number;
    readonly leaseDurationSecs?: number;
    readonly capabilities?: readonly string[];
  } = {},
): Promise<Record<string, unknown> | null> {
  const response = await post("/v1/self-hosted-workers/runs/poll", workerHeaders(), {
    protocol_version: 1,
    identity,
    supported_capabilities: options.capabilities ?? ["coding"],
    now_unix: options.nowUnix ?? 1_800_000_000,
    lease_duration_secs: options.leaseDurationSecs ?? 300,
  });
  if (response.status === 204) return null;
  const json = (await response.json()) as Record<string, unknown>;
  return json.lease as Record<string, unknown>;
}

/**
 * Empty the worker plane for `identity`.
 *
 * This pool version keeps ONE `workerd` instance per project, so Durable Object
 * storage survives between tests — a dispatch enqueued by an earlier test would
 * otherwise be the one a later `poll` leases, and a lease assertion would be
 * about the wrong job. Draining in `beforeEach` makes each test's queue state
 * its own. It uses only the public transport (poll + ack), so it cannot mask a
 * bug in either.
 */
export async function drainPlane(
  identity: typeof WORKER_A | typeof WORKER_B,
  capabilities: readonly string[] = ["coding"],
): Promise<void> {
  const drainAt = 2_100_000_000;
  for (let guard = 0; guard < 200; guard += 1) {
    const lease = await pollLease(identity, {
      nowUnix: drainAt,
      leaseDurationSecs: 600,
      capabilities,
    });
    if (lease === null) return;
    await post("/v1/self-hosted-workers/runs/ack", workerHeaders(), {
      protocol_version: 1,
      identity,
      dispatch_id: lease.dispatch_id,
      action: lease.action,
      lease_id: lease.lease_id,
      run_id: lease.run_id,
      status: "cancelled",
      reported_at_unix: drainAt + 1,
    });
  }
  throw new Error("worker plane did not drain");
}

/** Read an SSE body up to `frames` blank-line-terminated frames or EOF. */
export async function readSseFrames(response: Response, frames: number): Promise<string[]> {
  const reader = response.body?.getReader();
  if (reader === undefined) return [];
  const decoder = new TextDecoder();
  let buffer = "";
  const out: string[] = [];
  while (out.length < frames) {
    const { done, value } = await reader.read();
    if (value !== undefined) buffer += decoder.decode(value, { stream: true });
    let index = buffer.indexOf("\n\n");
    while (index !== -1 && out.length < frames) {
      out.push(buffer.slice(0, index + 2));
      buffer = buffer.slice(index + 2);
      index = buffer.indexOf("\n\n");
    }
    if (done) break;
  }
  await reader.cancel().catch(() => undefined);
  return out;
}

/**
 * Override an operator `[vars]` value for one test.
 *
 * The Worker under `SELF` shares this isolate, so it observes the change on its
 * next request. Typed against {@link AgentRuntimeBindings} rather than `any` so
 * a renamed var fails the typecheck instead of quietly becoming a no-op.
 */
type MutableBindings = {
  -readonly [K in keyof AgentRuntimeBindings]: AgentRuntimeBindings[K];
};

export function setEnvVar<K extends keyof AgentRuntimeBindings>(
  key: K,
  value: AgentRuntimeBindings[K],
): void {
  (env as unknown as MutableBindings)[key] = value;
}

/** Read the current value of an operator `[vars]` value. */
export function getEnvVar<K extends keyof AgentRuntimeBindings>(key: K): AgentRuntimeBindings[K] {
  return (env as unknown as MutableBindings)[key];
}
