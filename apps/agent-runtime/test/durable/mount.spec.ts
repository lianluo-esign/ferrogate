/**
 * ANTI-UNMOUNT: `resolveDeps` really has a DURABLE branch, and the deployed
 * composition root really reaches it.
 *
 * `docs/rewrite/parity-audit-dead-packages.md` §7.1: *"This function has
 * EXACTLY ONE branch. There is no real-adapter path anywhere in this app — not
 * unbound, UNWRITTEN."* Every port was the in-memory dev bundle, and the only
 * test that touched the flag asserted the fail-closed direction, so the seam
 * was invisible to a green suite.
 *
 * Everything here goes through `SELF.fetch` — the REAL `src/worker.ts`, the
 * REAL `src/index.ts` app, the REAL `contractAuth` guard. Nothing is
 * substituted, no bespoke Hono app is built, and no port is injected.
 *
 * ## Why this file cannot pass vacuously
 *
 * `harness/wrangler.toml` binds `DB` + `CONTROL_DB` and DELIBERATELY omits
 * `FG_DEV_IN_MEMORY_PORTS`, `FG_DEV_API_KEYS` and `FG_DEV_SELF_HOSTED_WORKERS`.
 * Under the pre-existing `resolveDeps` — `if (env.FG_DEV_IN_MEMORY_PORTS !==
 * "1") return undefined;` — every request below answers
 * `503 agent_runtime_unavailable`. The suite therefore goes RED the moment the
 * durable branch is removed, and `test/contract.test.ts`'s fail-closed spec
 * (dev flag unset, no D1 bound ⇒ 503) still holds in the other config, so the
 * two directions are pinned independently.
 *
 * MUTATION RUN (verbatim observations in the slice report): deleting the
 * `env.DB !== undefined ? d1ApiKeyPort(env.DB) :` leg of `resolveDeps` turned
 * this file red with `503 agent_runtime_unavailable` where a `202` was
 * expected, and left `apps/agent-runtime`'s own 259-test suite green.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DURABLE_WORKER_A,
  KEY_LIVE,
  KEY_UNKNOWN,
  errorCode,
  heartbeat,
  setupDurablePorts,
  submitJob,
} from "./setup.js";

beforeAll(setupDurablePorts);

describe("the durable ports are mounted on the deployed composition root", () => {
  it("runs with the dev bundle ABSENT and both databases BOUND", () => {
    // The premise of every assertion below. If this ever flips, the file is
    // testing the dev bundle again and proves nothing about D1.
    expect(env.FG_DEV_IN_MEMORY_PORTS).toBeUndefined();
    expect(env.FG_DEV_API_KEYS).toBeUndefined();
    expect(env.FG_DEV_SELF_HOSTED_WORKERS).toBeUndefined();
    expect(env.DB).toBeDefined();
    expect(env.CONTROL_DB).toBeDefined();
  });

  it("a tenant key that exists only in D1 is admitted", async () => {
    const response = await submitJob(KEY_LIVE);
    const text = await response.clone().text();
    // Not 503: the bundle resolved. Not 401: `api_keys` in D1 answered.
    expect(response.status, text).toBe(202);
    expect((await response.json()) as { object: string }).toMatchObject({ object: "agent_job" });
  });

  it("a key absent from D1 is REFUSED — the authority is live, not bypassed", async () => {
    // The negative control. Without it, "not 503" could be produced by a build
    // that admitted everyone; with it, the same code path both admits and
    // denies, which is what "the port is really consulted" means.
    const response = await submitJob(KEY_UNKNOWN);
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_api_key");
  });

  it("a worker identity that exists only in D1 is admitted", async () => {
    const response = await heartbeat({ ...DURABLE_WORKER_A });
    const text = await response.clone().text();
    expect(response.status, text).toBe(201);
    expect((await response.json()) as { heartbeat: { worker_id: string } }).toMatchObject({
      heartbeat: { worker_id: DURABLE_WORKER_A.worker_id },
    });
  });

  it("a worker absent from D1 is REFUSED", async () => {
    const response = await heartbeat({ ...DURABLE_WORKER_A, worker_id: "never-registered" });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_self_hosted_worker_identity");
  });

  it("a LEFTOVER dev flag does not displace a bound database", async () => {
    // `apps/agent-runtime/wrangler.toml` commits `FG_DEV_IN_MEMORY_PORTS = "1"`
    // under a comment reading "Production MUST NOT set this". §7.2 of the audit
    // found `apps/mcp` in exactly this state: a fully-built durable identity
    // store bypassed by one leftover variable. `resolveDeps` resolves DURABLE
    // FIRST so that cannot happen here — this test is what holds that ordering.
    const originalFlag = env.FG_DEV_IN_MEMORY_PORTS;
    const originalKeys = env.FG_DEV_API_KEYS;
    const originalWorkers = env.FG_DEV_SELF_HOSTED_WORKERS;
    const mutable = env as unknown as Record<string, unknown>;
    mutable.FG_DEV_IN_MEMORY_PORTS = "1";
    mutable.FG_DEV_API_KEYS = JSON.stringify([
      { key: "sk-dev-ghost", tenantId: "tenant-ghost", scopes: ["*"] },
    ]);
    mutable.FG_DEV_SELF_HOSTED_WORKERS = JSON.stringify([
      {
        tenant_id: "tenant-a",
        workspace_id: "ws-a",
        worker_id: "dev-ghost-worker",
        framework_adapter: "native",
        token_id: "tok-ghost",
        token_secret: "0".repeat(64),
      },
    ]);
    try {
      // The dev tables are NOT consulted: neither credential authenticates.
      const devKey = await submitJob("sk-dev-ghost");
      expect(devKey.status).toBe(401);
      expect(await errorCode(devKey)).toBe("invalid_api_key");

      const devWorker = await heartbeat({
        tenant_id: "tenant-a",
        workspace_id: "ws-a",
        worker_id: "dev-ghost-worker",
        token_id: "tok-ghost",
        token_secret: "0".repeat(64),
      });
      expect(devWorker.status).toBe(401);

      // ...and the D1 rows still are.
      expect((await submitJob(KEY_LIVE)).status).toBe(202);
      expect((await heartbeat({ ...DURABLE_WORKER_A })).status).toBe(201);
    } finally {
      mutable.FG_DEV_IN_MEMORY_PORTS = originalFlag;
      mutable.FG_DEV_API_KEYS = originalKeys;
      mutable.FG_DEV_SELF_HOSTED_WORKERS = originalWorkers;
    }
  });

  it("a path this Worker does not own is still 404 — the reachability control", async () => {
    // Without a negative control, "the route answered" proves nothing: a
    // catch-all would answer everything. This Worker owns four prefixes; a
    // fifth must 404 even with a valid D1 credential.
    const response = await SELF.fetch("https://agent-runtime-durable.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: `Bearer ${KEY_LIVE}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(404);
  });
});
