/**
 * The WRITE half of the self-hosted worker registry — the MOUNT GATE.
 *
 * `apps/agent-runtime`'s `d1WorkerIdentityPort` authenticates the six
 * `auth.kind: "internal"` `/v1/self-hosted-workers/*` callbacks against
 * `self_hosted_worker_registrations` in the CONTROL database, and its §8.1
 * marker recorded that **nothing in this repo wrote that table**: every
 * deployment admitted no worker, and the ten `/admin/v1/self-hosted-workers`
 * operations wrote a document that reached nothing.
 *
 * These tests drive the DEPLOYED Worker over `SELF` in the `d1` posture (the
 * production default) and read the typed table back with RAW SQL, never through
 * the code under test. Four claims:
 *
 *  1. **The mount** — registering through the admin API writes the typed row,
 *     with every one of the five credential fields
 *     `registryRowFromDocument` requires. Deleting the projection turns this red.
 *  2. **The secret is returned exactly ONCE** and never appears in the document,
 *     in a `GET`, or in a `list` — including when the operator tries to supply
 *     one through the `passthrough()` body.
 *  3. **Rotation mints a FRESH secret**, not just a fingerprint, so a leaked
 *     credential actually stops working.
 *  4. **The two entry points cannot diverge**: `POST /admin/v1/status` is the
 *     same registration and provisions the same way.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { WORKER_REGISTRATION_TABLE } from "../src/store/worker_registry.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const KEY = operatorKey.secret;

interface RegistryDocument {
  tenant_id?: unknown;
  workspace_id?: unknown;
  worker_id?: unknown;
  token_id?: unknown;
  token_secret?: unknown;
  framework_adapter?: unknown;
  active?: unknown;
  identity_fingerprint?: unknown;
  identity_expires_at_unix?: unknown;
  capabilities?: unknown;
}

/** The typed row, read with raw SQL so the reader under test proves nothing. */
async function registryRow(workerId: string): Promise<RegistryDocument | null> {
  const row = await db()
    .prepare(`SELECT registration_json FROM ${WORKER_REGISTRATION_TABLE} WHERE id = ?`)
    .bind(workerId)
    .first<{ registration_json: string }>();
  return row === null ? null : (JSON.parse(row.registration_json) as RegistryDocument);
}

interface RegisterBody {
  self_hosted_worker: Record<string, unknown>;
  transport_token_secret?: unknown;
}

async function register(
  id: string,
  extra: Record<string, unknown> = {},
  path = "/admin/v1/self-hosted-workers",
): Promise<{ status: number; body: RegisterBody }> {
  const res = await SELF.fetch(
    `${BASE}${path}`,
    jsonRequest(KEY, "POST", {
      id,
      name: `worker ${id}`,
      tenant_id: "tenant-a",
      workspace_id: "ws-a",
      ...extra,
    }),
  );
  return { status: res.status, body: (await res.json()) as RegisterBody };
}

beforeAll(applySchema);

beforeEach(async () => {
  arm({ store: "d1", staticKeys: [operatorKey] });
  await resetD1();
  await db().prepare(`DELETE FROM ${WORKER_REGISTRATION_TABLE}`).run();
});

describe("MOUNT: registering a self-hosted worker provisions the typed registry row", () => {
  it("writes every credential field the agent-runtime reader requires", async () => {
    const { status, body } = await register("w1");
    expect(status).toBe(201);

    const row = await registryRow("w1");
    // `registryRowFromDocument` (apps/agent-runtime/src/durable/adapters.ts)
    // returns null — i.e. the row is indistinguishable from ABSENT — unless all
    // five of these are non-blank strings. Anything less is a worker the
    // operator can see and that authenticates nobody.
    expect(row).not.toBeNull();
    expect(row?.tenant_id).toBe("tenant-a");
    expect(row?.workspace_id).toBe("ws-a");
    expect(row?.worker_id).toBe("w1");
    expect(typeof row?.token_id).toBe("string");
    expect(String(row?.token_id)).not.toBe("");
    expect(typeof row?.token_secret).toBe("string");
    // Rust `generate_transport_token_secret`: 256 bits, hex.
    expect(String(row?.token_secret)).toMatch(/^[0-9a-f]{64}$/);
    expect(row?.active).toBe(true);
    expect(row?.framework_adapter).toBe("native");
    // Returned to the caller exactly once, and it is the row's secret.
    expect(body.transport_token_secret).toBe(row?.token_secret);
  });

  it("the secret is NOT derived from any value the admin surface publishes", async () => {
    const { body } = await register("w2");
    const row = await registryRow("w2");
    const secret = String(body.transport_token_secret);
    // Rust's own comment on `generate_transport_token_secret` says reusing a
    // public lookup key as the secret "lets anyone forge and decrypt frames".
    expect(secret).not.toBe(String(row?.token_id));
    expect(secret).not.toBe("w2");
    expect(secret).not.toContain(String(row?.token_id));
  });

  it("refuses to half-provision a worker with no workspace", async () => {
    const res = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(KEY, "POST", { id: "w3", tenant_id: "tenant-a" }),
    );
    // The reader keys on the (tenant, workspace, worker) triple, so a row with a
    // blank workspace is one nothing can ever present. Refusing tells the
    // operator what is missing; writing it would look provisioned and admit
    // nobody.
    expect(res.status).toBe(400);
    expect(await registryRow("w3")).toBeNull();
  });

  it("POST /admin/v1/status provisions identically — the two entry points cannot diverge", async () => {
    const { status, body } = await register("w4", {}, "/admin/v1/status");
    expect(status).toBe(201);
    const row = await registryRow("w4");
    expect(row?.worker_id).toBe("w4");
    expect(body.transport_token_secret).toBe(row?.token_secret);
  });

  it("a draining worker is NOT active on the registry row", async () => {
    await register("w5", { status: "draining" });
    // `draining` means "finish what you have"; admitting new dispatch leases
    // would defeat the state. `active: false` is a 403 `inactive_worker` at the
    // reader, distinct from the 401 an unknown worker gets.
    expect((await registryRow("w5"))?.active).toBe(false);
    // CONTROL: the default really is active, so `false` is the status and not a
    // projection that never sets the flag.
    await register("w6");
    expect((await registryRow("w6"))?.active).toBe(true);
  });
});

describe("the transport secret never reaches a reader of the collection", () => {
  it("is absent from the stored document, the GET and the list", async () => {
    const { body } = await register("w7");
    const secret = String(body.transport_token_secret);
    expect(secret).toMatch(/^[0-9a-f]{64}$/);

    // The document every `admin.read` caller can list.
    expect(body.self_hosted_worker.token_secret).toBeUndefined();
    // `token_id` IS published — it is the non-secret lookup key.
    expect(typeof body.self_hosted_worker.token_id).toBe("string");

    const read = await SELF.fetch(`${BASE}/admin/v1/self-hosted-workers/w7`, {
      headers: bearer(KEY),
    });
    expect(JSON.stringify(await read.json())).not.toContain(secret);

    const list = await SELF.fetch(`${BASE}/admin/v1/self-hosted-workers`, {
      headers: bearer(KEY),
    });
    expect(JSON.stringify(await list.json())).not.toContain(secret);
  });

  it("strips an operator-supplied token_secret instead of publishing it", async () => {
    const planted = "a".repeat(64);
    const { body } = await register("w8", { token_secret: planted });
    // `adminRecordSchema` is `passthrough()`, so without the strip this value
    // would be stored in a document every admin.read caller can list.
    expect(body.self_hosted_worker.token_secret).toBeUndefined();
    const list = await SELF.fetch(`${BASE}/admin/v1/self-hosted-workers`, {
      headers: bearer(KEY),
    });
    expect(JSON.stringify(await list.json())).not.toContain(planted);
    // And it is not the credential either — a caller must not be able to CHOOSE
    // the secret their worker authenticates with.
    expect((await registryRow("w8"))?.token_secret).not.toBe(planted);
  });
});

describe("rotation replaces the secret, not just the fingerprint", () => {
  it("mints a fresh credential and returns it once", async () => {
    const created = await register("w9");
    const before = await registryRow("w9");

    const res = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers/w9/rotate`,
      jsonRequest(KEY, "POST", {}),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      transport_token_secret: string;
      previous_identity_fingerprint: unknown;
      self_hosted_worker: Record<string, unknown>;
    };
    expect(body.object).toBe("self_hosted_worker_identity_rotation");

    const after = await registryRow("w9");
    // Rotating the fingerprint alone would leave a leaked secret working, so
    // this is the assertion that makes rotation a remediation.
    expect(after?.token_secret).not.toBe(before?.token_secret);
    expect(after?.token_id).not.toBe(before?.token_id);
    expect(String(after?.token_secret)).toMatch(/^[0-9a-f]{64}$/);
    expect(body.transport_token_secret).toBe(after?.token_secret);
    // The old secret is gone, not merely supplemented.
    expect(body.transport_token_secret).not.toBe(created.body.transport_token_secret);
    // The fingerprint the operator is replacing is reported so a rotation can
    // be correlated with the credential it retired.
    expect(body.previous_identity_fingerprint).toBeDefined();
  });

  it("404s for a worker the caller cannot see, without touching the registry", async () => {
    const res = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers/nope/rotate`,
      jsonRequest(KEY, "POST", {}),
    );
    expect(res.status).toBe(404);
    expect(await registryRow("nope")).toBeNull();
  });

  it("a heartbeat PRESERVES the credential — it is not a rotation", async () => {
    await register("w10");
    const before = await registryRow("w10");
    const res = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers/w10/heartbeat`,
      jsonRequest(KEY, "POST", {}),
    );
    expect(res.status).toBe(200);
    const after = await registryRow("w10");
    // Minting here would break the running worker that just sent the heartbeat.
    expect(after?.token_secret).toBe(before?.token_secret);
    expect(after?.token_id).toBe(before?.token_id);
  });

  it("a heartbeat re-activates a draining worker's registry row", async () => {
    await register("w11", { status: "draining" });
    expect((await registryRow("w11"))?.active).toBe(false);
    await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers/w11/heartbeat`,
      jsonRequest(KEY, "POST", {}),
    );
    // The heartbeat writes `status: "active"` on the document; if the row were
    // not re-projected the two would disagree about whether the worker may take
    // work, and the credential row is the one that decides.
    expect((await registryRow("w11"))?.active).toBe(true);
  });
});

describe("without a control database the registration REFUSES", () => {
  it("answers 503 rather than writing a document that authenticates nobody", async () => {
    arm({ staticKeys: [operatorKey] }); // memory posture: no control database
    const res = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(KEY, "POST", { id: "w12", tenant_id: "tenant-a", workspace_id: "ws-a" }),
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({
      error: { code: "control_database_unavailable" },
    });
  });
});
