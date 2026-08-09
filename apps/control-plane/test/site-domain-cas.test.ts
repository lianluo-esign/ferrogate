/**
 * #576: an `admin.write` credential must not be able to drive unbounded
 * outbound DNS.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.7 recorded that the TS port had the
 * cooldown DECISION (`siteDomainVerificationAttemptDecision`, ported and tested
 * in `@ferrogate/storage`) but not the atomic write that turns it into a limit:
 * the handler read the verification document, asked the decision function, and
 * then issued an UNCONDITIONAL merge. Two concurrent `POST …/verify` calls
 * therefore read the same `lastCheckedAtUnix`, were both told `allowed`, and
 * both reached `lookupTxt`. The package's own docblock states the contract every
 * backend owes it — "every backend then reserves the slot with an atomic
 * conditional write on exactly this predicate" — and no backend did.
 *
 * ## Where each half is proven, and why they are in different files
 *
 * The close is `ControlPlaneStore.mergeIf`, and it has two properties:
 *
 *  1. **the conditional write is genuinely atomic** — proven in
 *     `test/store-conformance.test.ts` ("admits exactly ONE of two concurrent
 *     claims"), against BOTH backends, with real `Promise.all` interleaving. That
 *     test is not decorative: it went red on the first in-memory implementation
 *     here, which used `await this.get(...)` and therefore let all five claims
 *     through.
 *  2. **this route uses it** — proven below.
 *
 * A route-level burst would be the obvious way to prove (2), and it is
 * **vacuous**: `@cloudflare/vitest-pool-workers` dispatches `SELF.fetch`
 * requests one at a time, so four "concurrent" verifies execute strictly in
 * sequence and a read-then-write handler produces exactly the same
 * `503, 429, 429, 429` a compare-and-set does. That was measured, not assumed.
 * So the gate here is structural instead: the handler's ONLY cooldown check
 * lives inside `mergeIf`'s precondition, so swapping it back to `merge` does not
 * merely weaken the limit under load — it removes the limit, and the plain
 * SEQUENTIAL retry below turns red.
 *
 * The resolver is left UNCONFIGURED on purpose, which makes the two outcomes
 * unambiguous: a call that WON the slot reaches the resolver and gets
 * `503 site_domain_resolver_unavailable` (proof it got past the limiter), and a
 * call that was refused gets `429 rate_limited` (proof it never touched the
 * network). Counting 429s alone would be satisfied by a handler that refused
 * everything; pairing them pins that exactly one call proceeded.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, tenantKey } from "./harness.js";
import { rawTenantDocument } from "./tenant-object.js";

const TENANT = "tenant_a";
const KEY = "key-tenant-a";
const HOST = "app.example.test";
const VERIFICATION_ID = `${TENANT}:${HOST}`;

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", nativeKeys: [tenantKey(KEY, TENANT)] });
});

/** Bind the hostname and mint its challenge (the first verify is always a 409). */
async function bindAndIssueChallenge(): Promise<void> {
  const bound = await SELF.fetch(
    `${BASE}/admin/v1/site-domains`,
    jsonRequest(KEY, "POST", { hostname: HOST, site_id: "site_1" }),
  );
  expect(bound.status).toBe(201);

  const challenge = await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
    method: "POST",
    headers: bearer(KEY),
  });
  // A challenge is minted, not assumed: nothing was verified, so a 200 here
  // would read as "checked, still pending".
  expect(challenge.status).toBe(409);
  const body = (await challenge.json()) as { error: { code: string } };
  expect(body.error.code).toBe("site_domain_challenge_issued");
}

const verify = (): Promise<Response> =>
  SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
    method: "POST",
    headers: bearer(KEY),
  });

describe("site-domain verification rate limit (#576)", () => {
  it("refuses the second attempt inside the cooldown — the CAS is the only check", async () => {
    // THE MOUNT GATE. The cooldown is evaluated exclusively inside `mergeIf`'s
    // precondition, so a handler that went back to an unconditional `merge`
    // would answer 503 here (reaching the resolver again) instead of 429.
    await bindAndIssueChallenge();
    expect((await verify()).status).toBe(503);

    const retry = await verify();
    expect(retry.status).toBe(429);
    const body = (await retry.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("rate_limited");
    // The retry-after is computed from the row that HOLDS the slot, so it is the
    // real remaining cooldown rather than a fabricated constant.
    expect(body.error.message).toMatch(/may be retried in \d+s/);
  });

  it("reserves the slot BEFORE the resolver is reached", async () => {
    await bindAndIssueChallenge();
    const minted = await rawTenantDocument(TENANT, "site-domain-verifications", VERIFICATION_ID);
    // Minting a challenge is not an attempt: the slot must still be free.
    expect(minted?.last_checked_at_unix ?? null).toBeNull();

    // The resolver is unbound, so this attempt ends in a 503 — and the
    // reservation must have landed anyway. Recording the attempt only on a
    // successful lookup is how a caller loops on an unreachable resolver for
    // free.
    expect((await verify()).status).toBe(503);
    const after = await rawTenantDocument(TENANT, "site-domain-verifications", VERIFICATION_ID);
    expect(typeof after?.last_checked_at_unix).toBe("number");
  });

  it("writes NOTHING for a refused attempt", async () => {
    await bindAndIssueChallenge();
    await verify();
    const held = await rawTenantDocument(TENANT, "site-domain-verifications", VERIFICATION_ID);

    expect((await verify()).status).toBe(429);
    // A refusal that still moved `last_checked_at_unix` would extend the
    // cooldown on every rejected retry — a caller hammering the endpoint would
    // lock itself out for longer and longer, which is not the limit #576
    // specifies.
    const afterRefusal = await rawTenantDocument(
      TENANT,
      "site-domain-verifications",
      VERIFICATION_ID,
    );
    expect(afterRefusal).toEqual(held);
  });

  it("only ever refuses under the cooldown — a repeated burst never verifies", async () => {
    // The pool serializes `SELF.fetch` (see the module docblock), so this pins
    // the SEQUENTIAL outcome of a burst rather than a race: exactly one call
    // reaches the resolver and every other is refused without I/O.
    await bindAndIssueChallenge();
    const statuses = (await Promise.all([verify(), verify(), verify(), verify()])).map(
      (response) => response.status,
    );
    expect(statuses.filter((status) => status === 503)).toHaveLength(1);
    expect(statuses.filter((status) => status === 429)).toHaveLength(3);
  });

  it("does not consume a slot for a hostname that is not bound", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/site-domains/unbound.test/verify`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(response.status).toBe(404);
  });
});
