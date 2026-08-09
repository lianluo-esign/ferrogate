import { SELF } from "cloudflare:test";
/**
 * The three per-credential limits carried on an `api_keys` row, proven END TO
 * END on the app the Worker exports (`SELF`), not on a hand-built resolver.
 *
 * ## Why this file exists
 *
 * `src/keys/store.ts` has always LOADED `allowed_models_json`,
 * `allowed_providers_json` and `request_limit_per_minute`; `src/keys/resolver.ts`
 * then DROPPED all three, because `AuthContext` had no fields for them. Every
 * unit test stayed green: the columns were read, parsed, and thrown away, and
 * the only symptom was that an operator who set a cap on a virtual key got no
 * cap. That is the project's dominant defect mode — fully implemented, fully
 * tested, never mounted — so the assertions below are written to FAIL when the
 * transport is removed:
 *
 *  - "a per-key RPM cap is enforced by the DEPLOYED Worker" goes red if
 *    `subjectFor`'s `?? auth.requestLimitPerMinute` (src/ratelimit/middleware.ts)
 *    is removed, because the second request stops being refused;
 *  - "the allowlists reach AuthContext" goes red if either field is dropped from
 *    `toAuthContext` (src/keys/resolver.ts);
 *  - "a row that names no tenant answers 403 tenant_identity_required" goes red
 *    if the `tenant_identity_required` variant stops being returned or stops
 *    being mapped in `src/middleware/auth.ts`.
 *
 * Nothing here is mocked: `env.DB` is real local SQLite in `workerd`, the row is
 * seeded through the same hash the resolver verifies against, and `SELF.fetch`
 * runs the whole exported middleware chain including the real `RATE_LIMIT`
 * Durable Object.
 */
import { D1TwoHopApiKeyDirectory } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { D1ApiKeyResolver, resetSharedApiKeyCache } from "../../src/keys/index.js";
import { seedTenantRosterRows } from "../tenant-object.js";
import { controlDb, resetApiKeysTable, seedApiKey, tenantRouter, testSecret } from "./seed.js";

/** A resolver over the real two-hop objects, matching the deployed wiring. */
function directoryResolver(): D1ApiKeyResolver {
  return new D1ApiKeyResolver({
    directory: new D1TwoHopApiKeyDirectory(controlDb(), tenantRouter()),
  });
}

const BASE = "https://ferrogate.test";

/** A contract operation that needs a real bearer and a real scope. */
const GUARDED_PATH = `${BASE}/v1/tools`;

interface ErrorEnvelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

async function envelope(res: Response): Promise<ErrorEnvelope> {
  return (await res.json()) as ErrorEnvelope;
}

beforeAll(async () => {
  // Neither tenant is a vitest.config fixture tenant, so `test/setup-d1.ts`
  // seeds no `tenant_databases` roster row for them — and since #819/#824 an
  // authenticated request 503s downstream when the backend-dispatching router
  // cannot place the credential's tenant.
  await seedTenantRosterRows(["tenant_rpm", "tenant_allow"]);
});

beforeEach(async () => {
  await resetApiKeysTable();
  // The resolution cache is isolate-wide and keyed by secret digest; a stale
  // entry from a neighbouring file would let a deleted row keep authenticating.
  resetSharedApiKeyCache();
});

describe("TOK-12 per-credential request_limit_per_minute", () => {
  test("is enforced by the DEPLOYED Worker, with no test hook injected", async () => {
    const secret = await seedApiKey({
      id: "key_rpm_deployed",
      secret: testSecret("rpm-deployed"),
      tenantId: "tenant_rpm",
      scopes: ["tools.read"],
      requestLimitPerMinute: 1,
    });
    const headers = { authorization: `Bearer ${secret}` };

    // Request 1 consumes the single permit and reaches the route (501 is the
    // tooling stub — what matters is that it got PAST the limiter).
    const first = await SELF.fetch(GUARDED_PATH, { headers });
    expect(first.status).toBe(501);

    // Request 2 is refused by the limiter, before the route.
    const second = await SELF.fetch(GUARDED_PATH, { headers });
    expect(second.status).toBe(429);
    expect((await envelope(second)).error.code).toBe("rate_limit_exceeded");
  });

  test("a row with NO cap is not limited — a null column must never become 0", async () => {
    // The negative control for the branch above. `request_limit_per_minute` is
    // nullable, and `0` is a REAL Rust value meaning "refuse every request", so
    // a `null → 0` coercion would turn every uncapped virtual key into a key
    // that answers 429 to its very first request. This test is what makes that
    // coercion impossible to ship.
    const secret = await seedApiKey({
      id: "key_rpm_uncapped",
      secret: testSecret("rpm-uncapped"),
      tenantId: "tenant_rpm",
      scopes: ["tools.read"],
      requestLimitPerMinute: null,
    });
    const headers = { authorization: `Bearer ${secret}` };

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = await SELF.fetch(GUARDED_PATH, { headers });
      expect(res.status).toBe(501);
    }
  });
});

describe("allowed_models / allowed_providers reach AuthContext", () => {
  test("both allowlists are carried off the row, verbatim", async () => {
    const secret = await seedApiKey({
      id: "key_allowlists",
      secret: testSecret("allowlists"),
      tenantId: "tenant_allow",
      scopes: ["tools.read"],
      allowedModels: ["gpt-4o", "claude-sonnet"],
      allowedProviders: ["openai"],
      requestLimitPerMinute: 42,
    });

    const resolution = await directoryResolver().authenticate(secret);

    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;
    // Verbatim, and in row order: `callerCanUseModel` compares by exact string,
    // so a re-ordering or a normalization here would be a behaviour change.
    expect(resolution.auth.allowedModels).toEqual(["gpt-4o", "claude-sonnet"]);
    expect(resolution.auth.allowedProviders).toEqual(["openai"]);
    expect(resolution.auth.requestLimitPerMinute).toBe(42);
  });

  test("an EMPTY allowlist means no allowlist, never deny-everything", async () => {
    const secret = await seedApiKey({
      id: "key_no_allowlists",
      secret: testSecret("no-allowlists"),
      tenantId: "tenant_allow",
      scopes: ["tools.read"],
    });

    const resolution = await directoryResolver().authenticate(secret);

    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;
    expect(resolution.auth.allowedModels).toEqual([]);
    expect(resolution.auth.allowedProviders).toEqual([]);
    // ABSENT, not 0: `subjectFor` passes this straight into the quota subject,
    // where 0 would mean "refuse every request".
    expect(resolution.auth.requestLimitPerMinute).toBeUndefined();

    // And the deployed path still serves it.
    const res = await SELF.fetch(GUARDED_PATH, {
      headers: { authorization: `Bearer ${secret}` },
    });
    expect(res.status).toBe(501);
  });
});

describe("the 401 taxonomy for an unknown key is unchanged", () => {
  test("an unknown key is 401 invalid_api_key on the exported app", async () => {
    // In the TWO-HOP directory model the tenant id IS the routing key, so a
    // blank-tenant durable key is not representable: the old
    // `tenant_identity_required` (403) case belonged to the flat single-hop
    // model and moved to the config/static leg with #821. The unknown-key 401
    // taxonomy is what this file still pins here.
    const res = await SELF.fetch(GUARDED_PATH, {
      headers: { authorization: "Bearer fg_definitely_not_a_real_key" },
    });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_api_key");
  });
});
