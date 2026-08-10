/**
 * THE AUTO-THROTTLE (#697), driven through the DEPLOYED gateway.
 *
 * `apps/control-plane`'s spend-anomaly detector writes `spend_throttles` rows
 * when a CRITICAL burn-rate episode opens for a tenant that configured
 * `spend_anomaly_auto_throttle_rpm`. That write is worth nothing unless the
 * admission path reads it, and the admission path is a different Worker — which
 * is exactly the shape of defect this repository keeps shipping: the writer
 * mounted, the reader absent, both suites green against their own fixtures.
 *
 * So nothing here is mocked. `env.CONTROL_DB` is miniflare's real control
 * database with the DEPLOYED migration applied, `SELF` is `src/worker.ts`, and
 * the assertions are on the status code a real caller receives.
 *
 * ## The invariant these tests exist to hold
 *
 * A throttle may only ever NARROW. It cannot raise a limit, cannot enable a
 * disabled scope, cannot widen a model allowlist, and cannot outlive its
 * expiry. That is what makes it safe for an automated writer to touch a table
 * the admission path reads: the worst a detector bug can do is refuse traffic,
 * which is loud and self-expiring. The opposite direction would be a silent
 * free-traffic hole.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { resetSharedApiKeyCache } from "../../src/keys/index.js";
import { resetApiKeysTable, seedApiKey, testSecret } from "../keys/seed.js";

const controlDb = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;

const MODELS = "https://gateway.test/v1/models";

/**
 * A FRESH tenant and key per test.
 *
 * The RPM window lives in a Durable Object keyed on the binding scope
 * (`tenant:{id}`), and a DO outlives a test. Reusing one id would let an
 * earlier test's admitted request consume this test's 1-rpm allowance, so a
 * later assertion would pass on the wrong cause — the shape of vacuous green
 * this repository keeps finding.
 */
let scopeSequence = 0;
function freshScope(): { org: string; keyId: string } {
  scopeSequence += 1;
  return { org: `tenant_throttle_${scopeSequence}`, keyId: `key_throttle_${scopeSequence}` };
}

interface ErrorEnvelope {
  readonly error: { readonly code: string };
}

/** A `spend_throttles` row, in the shape the detector's `applyThrottle` writes. */
async function seedThrottle(
  scopeType: string,
  scopeId: string,
  rpmLimit: number,
  expiresAtUnix: number,
): Promise<void> {
  await controlDb
    .prepare(
      `INSERT OR REPLACE INTO spend_throttles
         (scope_type, scope_id, rpm_limit, reason, episode_id, created_at_unix, expires_at_unix)
       VALUES (?, ?, ?, 'spend anomaly burn_rate_spike (test)', 'ep_test', 0, ?)`,
    )
    .bind(scopeType, scopeId, rpmLimit, expiresAtUnix)
    .run();
}

async function seedPolicy(
  scopeType: string,
  scopeId: string,
  columns: Record<string, number | null>,
): Promise<void> {
  const names = Object.keys(columns);
  await controlDb
    .prepare(
      `INSERT OR REPLACE INTO quota_policies (id, scope_type, scope_id, enabled${names
        .map((name) => `, ${name}`)
        .join("")})
       VALUES (?, ?, ?, 1${names.map(() => ", ?").join("")})`,
    )
    .bind(`${scopeType}:${scopeId}`, scopeType, scopeId, ...names.map((n) => columns[n] ?? null))
    .run();
}

async function seedKey(scope: { org: string; keyId: string }): Promise<string> {
  // Each fresh tenant needs its own `tenant_databases` roster row: `test/setup-d1.ts`
  // seeds one only for the `[vars]` fixture tenants, and a tenant with no row is
  // the dispatching router's `not_found` — i.e. every request answers 503
  // `quota_resolution_unavailable` before the throttle is ever read.
  // `migration_state = 'done'` because the column DEFAULTs to 'shared'
  // (pre-cutover), which would route the tenant to the legacy shared `env.DB`.
  await controlDb
    .prepare(
      "INSERT OR REPLACE INTO tenant_databases " +
        "(tenant_id, storage_backend, provisioning_status, migration_state) " +
        "VALUES (?, 'durable_object', 'ready', 'done')",
    )
    .bind(scope.org)
    .run();
  return await seedApiKey({
    id: scope.keyId,
    secret: testSecret(scope.keyId),
    tenantId: scope.org,
    scopes: [],
  });
}

async function get(secret: string): Promise<Response> {
  return await SELF.fetch(MODELS, { headers: { Authorization: `Bearer ${secret}` } });
}

/** Far enough ahead that the window cannot lapse mid-test. */
const FUTURE = Math.floor(Date.now() / 1000) + 3_600;
const PAST = Math.floor(Date.now() / 1000) - 1;

beforeEach(async () => {
  await resetApiKeysTable();
  resetSharedApiKeyCache();
  await controlDb.prepare("DELETE FROM quota_policies").run();
  await controlDb.prepare("DELETE FROM spend_throttles").run();
});

afterEach(async () => {
  await controlDb.prepare("DELETE FROM spend_throttles").run();
});

describe("the deployed gateway reads spend_throttles on the admission path", () => {
  test("an unthrottled tenant with no policy is not rate limited at all", async () => {
    // The precondition every other test in this file depends on. Without it, a
    // 429 below could be some unrelated default cap and the test would pass
    // against a gateway that never read the throttle table.
    const scope = freshScope();
    const secret = await seedKey(scope);
    for (let n = 0; n < 3; n += 1) {
      expect((await get(secret)).status).toBe(200);
    }
  });

  test("a throttled tenant is refused past the throttle's RPM", async () => {
    const scope = freshScope();
    const secret = await seedKey(scope);
    await seedThrottle("tenant", scope.org, 1, FUTURE);

    expect((await get(secret)).status).toBe(200);
    const refused = await get(secret);
    expect(refused.status).toBe(429);
    expect(((await refused.json()) as ErrorEnvelope).error.code).toBe("rate_limit_exceeded");
  });

  test("an EXPIRED throttle does not bite", async () => {
    // The load-bearing half of the auto-throttle design. The control plane may
    // never run again, so nothing lifts a throttle except its own expiry — and
    // a throttle that outlived its incident would be an outage whose cause is
    // invisible from the request path.
    const scope = freshScope();
    const secret = await seedKey(scope);
    await seedThrottle("tenant", scope.org, 1, PAST);

    for (let n = 0; n < 3; n += 1) {
      expect((await get(secret)).status).toBe(200);
    }
  });

  test("a throttle NARROWS a configured limit and never widens it", async () => {
    // The operator configured 60 rpm; the throttle says 1. The tighter one
    // binds — that is the direction a brake must fail in.
    const scope = freshScope();
    const secret = await seedKey(scope);
    await seedPolicy("tenant", scope.org, { rpm_limit: 60 });
    await seedThrottle("tenant", scope.org, 1, FUTURE);

    expect((await get(secret)).status).toBe(200);
    expect((await get(secret)).status).toBe(429);
  });

  test("a LOOSER throttle cannot raise a tighter configured limit", async () => {
    // The inverse, and the one that would be a silent free-traffic hole. The
    // operator configured 1 rpm; a throttle of 5,000 must change nothing.
    const scope = freshScope();
    const secret = await seedKey(scope);
    await seedPolicy("tenant", scope.org, { rpm_limit: 1 });
    await seedThrottle("tenant", scope.org, 5_000, FUTURE);

    expect((await get(secret)).status).toBe(200);
    expect((await get(secret)).status).toBe(429);
  });

  test("a throttle for another tenant does not bite this one", async () => {
    const scope = freshScope();
    const secret = await seedKey(scope);
    await seedThrottle("tenant", "some_other_tenant", 1, FUTURE);

    for (let n = 0; n < 3; n += 1) {
      expect((await get(secret)).status).toBe(200);
    }
  });
});
