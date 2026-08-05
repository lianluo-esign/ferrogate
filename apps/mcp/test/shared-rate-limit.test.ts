/**
 * ONE RPM window across the fleet — issue #666, CUTOVER-READINESS finding B10.
 *
 * ## The defect
 *
 * A virtual key capped at 60 rpm was charged 60 on `apps/gateway` **plus 60 per
 * `apps/mcp` isolate plus 60 per `apps/agent-runtime` isolate**, because the
 * cross-script
 *
 *     [[durable_objects.bindings]]
 *     name = "RATE_LIMIT"
 *     class_name = "RateLimiterDurableObject"
 *     script_name = "ferrogate-gateway"
 *
 * stanza was committed COMMENTED OUT — workerd refused to start a test session
 * on a `script_name` it could not resolve, so the tree that shipped was the
 * broken configuration and a human had to uncomment two lines at deploy time.
 * Nothing errored when they forgot: `limiterForEnv` fell back to the
 * per-isolate `InMemoryMcpRateLimiter` and the tenant simply got several times
 * the limit they were sold. It failed OPEN, on a control customers pay for.
 *
 * ## What makes this suite able to see it
 *
 * `vitest.config.ts` now registers an AUXILIARY WORKER named
 * `ferrogate-gateway` carrying the gateway's real `RateLimiterDurableObject`
 * (`apps/gateway/test/support/rate-limit-aux-worker.ts`), so the committed
 * binding resolves offline and the stanza is committed LIVE. The tests below
 * are then able to do the one thing three separate green admission suites never
 * could: charge a window from OUTSIDE this Worker and require this Worker to
 * see it.
 *
 * `env.RATE_LIMIT` in a test file and `env.RATE_LIMIT` inside `src/` are the
 * same binding — `vitest.config.ts` names `main` explicitly, so the Worker under
 * test runs in this isolate. A charge made here is therefore exactly the charge
 * `apps/gateway`'s `/v1/chat/completions` makes: same namespace, same
 * `idFromName(counterKey)`, same instance, same `consumeRequest` RPC.
 *
 * ## What it does NOT prove
 *
 * That the `ferrogate-gateway` script deployed to Cloudflare is this source, and
 * that it was deployed BEFORE this Worker. Neither is provable offline — but
 * both now fail the DEPLOY loudly (`wrangler deploy` rejects a `script_name`
 * binding whose target script does not exist), which is the mechanical backstop
 * issue #666 asked for in place of a comment.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  DurableObjectMcpRateLimiter,
  limiterForEnv,
  perKeyCounterKey,
} from "../src/admission/index.js";
import { hashApiKeySecret } from "../src/auth.js";
import { rpcRequest, seedFixture } from "./fixtures.js";
import { seedTenantRoleProjection, tenantObjectDb } from "./tenant-object.js";

interface SharedCounterBindings {
  readonly DB: D1Database;
  readonly RATE_LIMIT?: {
    idFromName(name: string): DurableObjectId;
    get(id: DurableObjectId): { consumeRequest(limit: number): Promise<{ allowed: boolean }> };
  };
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

function bindings(): SharedCounterBindings {
  return env as unknown as SharedCounterBindings;
}

const control = (): D1Database => bindings().DB;
const tenantDb = (tenantId: string): D1Database => tenantObjectDb(tenantId);

/**
 * Charge one request against a counter key THROUGH THE BINDING — i.e. do
 * precisely what `apps/gateway`'s `DurableObjectRateLimiter` does when the same
 * credential calls `/v1/chat/completions`.
 */
async function chargeAsGateway(counterKey: string, limit: number): Promise<boolean> {
  const namespace = bindings().RATE_LIMIT;
  if (namespace === undefined) {
    // Named rather than left as a `TypeError`, because this exact absence IS
    // the defect: an unbound RATE_LIMIT is the per-Worker quota multiplier.
    throw new Error(
      "RATE_LIMIT is not bound on apps/mcp — the cross-script gateway counter is missing (#666)",
    );
  }
  const result = await namespace.get(namespace.idFromName(counterKey)).consumeRequest(limit);
  return result.allowed;
}

let counter = 0;

interface Caller {
  readonly tenantId: string;
  readonly keyId: string;
  readonly secret: string;
}

/** A tenant / key / secret triple nothing else in this run shares. */
function mintCaller(): Caller {
  counter += 1;
  return {
    tenantId: `shared-rpm-tenant-${counter}`,
    keyId: `shared-rpm-key-${counter}`,
    secret: `fg_shared_rpm_secret_${counter}`,
  };
}

/**
 * Provision a virtual credential end to end, with the TOK-12 per-key RPM cap
 * on the `api_keys` row. The per-key window needs NO quota policy, which keeps
 * the seeding here to the credential itself — the quota-chain windows are
 * already covered by `test/admission.test.ts`.
 */
async function provision(caller: Caller, requestLimitPerMinute: number): Promise<void> {
  const keyHash = await hashApiKeySecret(caller.secret);
  await control().batch([
    control()
      .prepare(
        `INSERT INTO tenant_databases
           (tenant_id, binding_name, schema_version,
            storage_backend, provisioning_status,
            provisioned_at_unix, updated_at_unix)
         VALUES (?, NULL, 15, 'durable_object', 'ready', 1, 1)`,
      )
      .bind(caller.tenantId),
    control()
      .prepare(
        `INSERT INTO api_key_directory
           (key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
            enabled, expires_at_unix, revoked_at_unix)
         VALUES (?, ?, ?, 'proj-1', 'ws-1', 'fg_', 'key1', 1, NULL, NULL)`,
      )
      .bind(keyHash, caller.keyId, caller.tenantId),
    control()
      .prepare(
        `INSERT INTO roles (id, name, slug, description, permission_keys_json)
         VALUES (?, 'MCP', ?, '', ?)`,
      )
      .bind(`role-${caller.tenantId}`, `mcp-${caller.tenantId}`, JSON.stringify(["mcp.execute"])),
  ]);
  await seedTenantRoleProjection(caller.tenantId, `role-${caller.tenantId}`, ["mcp.execute"]);
  await tenantDb(caller.tenantId)
    .prepare(
      `INSERT INTO api_keys
         (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4,
          enabled, scopes_json, revoked_at_unix, request_limit_per_minute)
       VALUES (?, 'ws-1', ?, 'proj-1', 'mcp', 'fg_', ?, 'key1', 1, ?, NULL, ?)`,
    )
    .bind(
      caller.keyId,
      caller.tenantId,
      keyHash,
      JSON.stringify(["tools.read", "tools.execute", "assets.read"]),
      requestLimitPerMinute,
    )
    .run();
}

interface JsonBody {
  readonly error?: { code: string; message: string };
}

async function toolsCall(key: string): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(
    rpcRequest(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "srv-echo", arguments: {} } },
      { key },
    ),
  );
  return { status: res.status, body: (await res.json()) as JsonBody };
}

beforeAll(async () => {
  const b = bindings();
  await applyD1Migrations(b.DB, b.TEST_CONTROL_D1_SCHEMA);
});

beforeEach(async () => {
  await control().batch([
    control().prepare("DELETE FROM quota_policies"),
    control().prepare("DELETE FROM tenant_databases"),
    control().prepare("DELETE FROM api_key_directory"),
    control().prepare("DELETE FROM roles"),
  ]);
  seedFixture({ tenantId: "tenant-mcp-shared-rate-limit" });
});

describe("the committed config binds the gateway's counter, not a private one", () => {
  it("resolves env.RATE_LIMIT from the cross-script stanza", () => {
    // The whole defect in one assertion: with the stanza commented out (its
    // state before #666) this binding is `undefined` on every isolate.
    expect(
      bindings().RATE_LIMIT,
      "apps/mcp/wrangler.toml is not binding RATE_LIMIT cross-script",
    ).toBeDefined();
  });

  it("mounts the DURABLE limiter, never the per-isolate fallback", () => {
    // `limiterForEnv` is what `src/admission/gate.ts` calls on every request.
    // A bound namespace that the composition root ignored would leave the
    // 60·N multiplier in place with the config looking correct.
    expect(limiterForEnv(env)).toBeInstanceOf(DurableObjectMcpRateLimiter);
  });
});

describe("a window spent on apps/gateway is already spent on apps/mcp", () => {
  it("REFUSES the first tools/call when the gateway already used the only slot", async () => {
    const caller = mintCaller();
    await provision(caller, 1);

    // The credential's single slot, spent as `/v1/chat/completions` would.
    expect(await chargeAsGateway(perKeyCounterKey(caller.keyId), 1)).toBe(true);

    // ...therefore MCP has nothing left to give it. Under the per-isolate
    // fallback this is a 200: the MCP isolate's Map has never heard of this
    // key, which is the "call the other endpoint" bypass, priced in money.
    const first = await toolsCall(caller.secret);
    expect(first.status).toBe(429);
    expect(first.body.error?.code).toBe("rate_limit_exceeded");
  });

  it("charges the SAME instance in the other direction — MCP spends the gateway's window", async () => {
    const caller = mintCaller();
    await provision(caller, 2);
    const counterKey = perKeyCounterKey(caller.keyId);

    // One request through the real Worker...
    const admitted = await toolsCall(caller.secret);
    expect(admitted.status).toBe(200);
    expect(admitted.body.error).toBeUndefined();

    // ...leaves exactly one of the two slots for the gateway, and no more.
    // If MCP had counted in its own namespace, BOTH of these would be allowed.
    expect(await chargeAsGateway(counterKey, 2)).toBe(true);
    expect(await chargeAsGateway(counterKey, 2)).toBe(false);
  });

  it("keeps separate credentials on separate instances", async () => {
    // The negative control. Sharing one NAMESPACE must not mean sharing one
    // WINDOW: a collision here would let any tenant drain another's budget.
    const spent = mintCaller();
    const untouched = mintCaller();
    await provision(spent, 1);
    await provision(untouched, 1);

    expect(await chargeAsGateway(perKeyCounterKey(spent.keyId), 1)).toBe(true);

    const other = await toolsCall(untouched.secret);
    expect(other.status).toBe(200);
    expect(other.body.error).toBeUndefined();
  });
});
