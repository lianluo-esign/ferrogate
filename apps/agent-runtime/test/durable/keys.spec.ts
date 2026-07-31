/**
 * The 401-vs-403 taxonomy, ON THE DURABLE PATH.
 *
 * The suspension defect (`docs/rewrite/PORT-PLAN.md` "parity verification" #4)
 * is a repeat defect class in this codebase: a SUSPENDED native key must be
 * indistinguishable from an unknown one. Until this slice, the only tests that
 * asserted it in `apps/agent-runtime` ran against `inMemoryApiKeyPort` reading
 * a `[vars]` table — so the property was proven for a port production does not
 * use. These specs assert it against `api_keys` rows in a REAL D1 database,
 * through the REAL Worker.
 *
 * Every request goes through `SELF`, so the status codes asserted here are the
 * ones a caller actually receives: the adapter's outcome, rendered by
 * `src/middleware/auth.ts::resolveOrThrow`.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  KEY_BLAKE2B,
  KEY_DISABLED,
  KEY_EXPIRED,
  KEY_LIVE,
  KEY_NO_TENANT,
  KEY_READONLY,
  KEY_REVOKED,
  KEY_UNKNOWN,
  bearer,
  errorCode,
  get,
  setupDurablePorts,
  submitJob,
} from "./setup.js";

beforeAll(setupDurablePorts);

describe("D1 api_keys: key state is never disclosed", () => {
  it("a live key is admitted (so the refusals below are not vacuous)", async () => {
    expect((await submitJob(KEY_LIVE)).status).toBe(202);
  });

  for (const [label, key] of [
    ["unknown", KEY_UNKNOWN],
    ["disabled (enabled = 0)", KEY_DISABLED],
    ["revoked (revoked_at_unix set)", KEY_REVOKED],
    ["expired (expires_at_unix in the past)", KEY_EXPIRED],
  ] as const) {
    it(`a ${label} key answers 401 invalid_api_key — NEVER 403`, async () => {
      const response = await submitJob(key);
      // 403 here would disclose that the key exists. That is the defect.
      expect(response.status).toBe(401);
      expect(await errorCode(response)).toBe("invalid_api_key");
    });
  }

  it("the four refusals are byte-identical to each other", async () => {
    // Indistinguishability is the property, so assert it directly rather than
    // inferring it from four separate status checks.
    const bodies = await Promise.all(
      [KEY_UNKNOWN, KEY_DISABLED, KEY_REVOKED, KEY_EXPIRED].map(async (key) => {
        const response = await submitJob(key);
        const parsed = (await response.json()) as { error: Record<string, unknown> };
        // `request_id` is per-request by design; everything else must match.
        const { request_id: _ignored, ...rest } = parsed.error;
        return JSON.stringify(rest);
      }),
    );
    expect(new Set(bodies).size, bodies.join("\n")).toBe(1);
  });

  it("a stored blake2b: hash is REFUSED here (the documented, KEPT divergence)", async () => {
    // `apps/gateway/src/keys/hash.ts` accepts `sha256:` and `blake2b:`;
    // `src/durable/hash.ts` implements only `sha256:` and fails closed on any
    // other tag. That divergence is named in that module's PORT-TODO and it is
    // pinned HERE so it cannot change — in either direction — unnoticed.
    const response = await submitJob(KEY_BLAKE2B);
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_api_key");
  });

  it("a live key with the wrong SECRET but a seeded prefix is refused", async () => {
    // Same 16-char prefix as `KEY_LIVE`, different tail: the prefix index
    // finds the row and the hash comparison must reject it. If authentication
    // ever regressed to the prefix, this is what would catch it.
    const forged = `${KEY_LIVE.slice(0, 16)}_forged`;
    expect(forged.slice(0, 16)).toBe(KEY_LIVE.slice(0, 16));
    const response = await submitJob(forged);
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_api_key");
  });
});

describe("D1 api_keys: authenticated-but-forbidden is 403", () => {
  it("a read-only key is 403 scope_denied on a create operation", async () => {
    // The key IS valid, so this must be 403 and not 401 — the other half of
    // the taxonomy. `scopes_json` came out of D1.
    const response = await submitJob(KEY_READONLY);
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("scope_denied");
  });

  it("a read-only key IS served the read operation", async () => {
    // Without this, "403 on create" would also hold for a key that was simply
    // broken. The same credential must succeed where its scope allows —
    // `GET /v1/agent-jobs/{run_id}` declares `agent.runs.read`, which is
    // exactly the one scope this key's `scopes_json` carries.
    const created = await submitJob(KEY_LIVE);
    expect(created.status).toBe(202);
    const runId = ((await created.json()) as { run_id: string }).run_id;
    const read = await get(`/v1/agent-jobs/${encodeURIComponent(runId)}`, bearer(KEY_READONLY));
    expect(read.status, await read.clone().text()).toBe(200);
    expect((await read.json()) as { run_id: string }).toMatchObject({ run_id: runId });
  });

  it("a key naming NO tenant cannot address tenant-scoped state", async () => {
    // Rust `CallerScope`: an unclassified credential is confined, never
    // promoted to platform root (#515). `platformOperator` is the literal
    // `false` in the adapter, so no D1 value can flip it.
    const response = await submitJob(KEY_NO_TENANT);
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("tenant_scope_denied");
  });
});
