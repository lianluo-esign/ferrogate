/**
 * `POST /admin/v1/drain` — the WRITE half of the operator drain (FC-1).
 *
 * `apps/mcp/test/drain-fleet.test.ts` proves the fleet effect: one write here,
 * both spend Workers shut. This file proves the three things about the WRITE
 * that the fleet test takes as given, and that are load-bearing precisely
 * because three separately-bundled Workers now read the row it produces.
 *
 *  1. **The document shape is the one the enforcers parse.** The write goes
 *     through `store/runtime_state.ts::drainDocument` and reads back through
 *     `parseDrainDocument` — the same functions `apps/mcp/src/drain.ts` and
 *     `apps/agent-runtime/src/drain.ts` carry a copy of. Before FC-1 the shape
 *     was spelled inline here and nothing read it, which is exactly how the
 *     writer and the enforcers came to have no source of truth in common.
 *  2. **A tenant-scoped admin cannot drain the deployment.** The contract gives
 *     this operation `admin.write`, which a tenant administrator can hold. That
 *     was harmless while nothing read the row; now every Worker resolves it by
 *     primary key, so a tenant able to mint it would take the whole deployment
 *     out of service for every other tenant. A cross-tenant denial of service
 *     reachable from an intended, correctly-scoped credential.
 *  3. **What an operator is TOLD matches what the enforcers DO.** `GET` parses
 *     the row with the enforcers' own parse, so a row they ignore reads back as
 *     "not draining" here too — rather than the admin API claiming a drain the
 *     data plane is not honouring, which is FC-1 in miniature.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { DRAIN_COLLECTION, DRAIN_ID } from "../src/routes/admin_config_ops.js";
import { drainDocument, parseDrainDocument } from "../src/store/runtime_state.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;
const TENANT_ADMIN_SECRET = "fg_tenant_admin_drain_key";
const tenantAdmin = tenantKey(TENANT_ADMIN_SECRET, "tenant-a");

beforeEach(() => {
  arm({ staticKeys: [operatorKey], nativeKeys: [tenantAdmin] });
});

async function readDrain(key: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/drain`, { headers: bearer(key) });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function setDrain(
  key: string,
  body: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/drain`, jsonRequest(key, "POST", body));
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe("the drain row is deployment state, not tenant state", () => {
  it("REFUSES a tenant-scoped admin with 403 tenant_scope_denied", async () => {
    // `admin.write` is not enough. The credential holds it (see `tenantKey`),
    // is authenticated, and is refused anyway — because the row it would write
    // is read by every Worker in the fleet by primary key.
    const refused = await setDrain(TENANT_ADMIN_SECRET, { draining: true, reason: "hostile" });
    expect(refused.status).toBe(403);
    expect((refused.body as { error?: { code?: string } }).error?.code).toBe("tenant_scope_denied");

    // And it left NOTHING behind: an operator reading the state afterwards must
    // not see a half-applied drain.
    expect((await readDrain(OPERATOR)).body).toMatchObject({ draining: false });
  });

  it("ADMITS the platform operator for the same request", async () => {
    // The negative control. Without it the refusal above could be "this route
    // refuses everyone", which would prove nothing about the fence.
    const accepted = await setDrain(OPERATOR, { draining: true, reason: "pre-migration" });
    expect(accepted.status).toBe(200);
    expect(accepted.body).toMatchObject({ draining: true, reason: "pre-migration" });
  });
});

describe("the stored document is the one the enforcers parse", () => {
  it("round-trips through drainDocument / parseDrainDocument", async () => {
    await setDrain(OPERATOR, { draining: true, reason: "pre-migration" });
    const read = await readDrain(OPERATOR);
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({
      object: "drain",
      draining: true,
      reason: "pre-migration",
      accepting_new_requests: false,
    });

    // The enforcers' parse, over the document the writer builds, agrees with
    // what the admin API just reported. These are the two copies FC-1 found
    // disconnected; asserting them together is what keeps them joined.
    const document = drainDocument({
      draining: true,
      reason: "pre-migration",
      changedAt: 1_700_000_000,
    });
    expect(parseDrainDocument(document as unknown as Record<string, unknown>)).toEqual({
      draining: true,
      accepting_new_requests: false,
      reason: "pre-migration",
      source: "durable",
    });
  });

  it("pins tenant_id to null, which is what makes the row fleet-wide", async () => {
    // The second, independent defence behind the 403 above: even a row written
    // by some other path cannot drain the fleet from inside one tenant, because
    // every enforcer IGNORES a drain document carrying a tenant. The writer
    // must therefore never produce one.
    const document = drainDocument({ draining: true, changedAt: 1 });
    expect(document.tenant_id).toBeNull();
    expect(document.id).toBe(DRAIN_ID);
    expect(DRAIN_COLLECTION).toBe("runtime-state");

    expect(
      parseDrainDocument({ ...document, tenant_id: "tenant-a" } as unknown as Record<
        string,
        unknown
      >).draining,
    ).toBe(false);
  });

  it("lifting the drain reads back as accepting again", async () => {
    await setDrain(OPERATOR, { draining: true, reason: "pre-migration" });
    expect((await readDrain(OPERATOR)).body).toMatchObject({ draining: true });

    const lifted = await setDrain(OPERATOR, { draining: false });
    expect(lifted.body).toMatchObject({
      draining: false,
      reason: null,
      accepting_new_requests: true,
    });
    expect((await readDrain(OPERATOR)).body).toMatchObject({
      draining: false,
      accepting_new_requests: true,
    });
  });

  it("reports propagation honestly rather than claiming an instant fleet swap", async () => {
    // Rust flipped an in-process `AtomicBool`; every request in that process saw
    // it immediately. Here three Workers read a durable row, so the truthful
    // statement is "on each Worker's next request". `reloadAdminConfig` refused
    // to ship `applied: true` for the same reason: an operator acts on this
    // answer during an incident.
    const set = await setDrain(OPERATOR, { draining: true });
    expect(set.body.propagation).toBe("on_next_request_per_worker");
  });
});
