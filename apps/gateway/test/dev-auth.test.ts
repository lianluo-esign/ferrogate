/**
 * The local-development credential path, and — mostly — the gate that keeps it
 * out of production.
 *
 * Running a request end to end against a real upstream needs an API key that
 * resolves. `developmentApiKeys` (`src/adapters.ts`) supplies one so nobody has
 * to hand-edit `GATEWAY_NATIVE_API_KEYS` and accidentally commit a credential.
 * The whole value of that convenience depends on it being unreachable by
 * accident, so the majority of this file is negative controls: every single
 * condition of the gate is broken in isolation and the answer must stay
 * `401 invalid_api_key`.
 *
 * The most important test here is the FIRST one: with the vars exactly as
 * `wrangler.toml` ships them, a perfectly well-formed development key is
 * refused. That is the "off by default" property; the rest prove that no single
 * mistake is enough to turn it on.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import app from "../src/index.js";
import {
  DEV_API_KEY_PREFIX,
  DEV_API_KEY_SCOPES,
  developmentApiKeys,
} from "../src/adapters.js";
import { isPrivilegedScope } from "../src/ports.js";

const BASE = "https://gw.test";

/** A well-formed development key: correct prefix, long enough. Not a real one. */
const DEV_KEY = `${DEV_API_KEY_PREFIX}0123456789abcdef0123456789abcdef`;

/**
 * The `[vars]` block `wrangler.toml` actually ships. `GATEWAY_DEV_AUTH` is
 * `"false"` there; the secret is bound because a developer who set it once and
 * then deployed is precisely the accident being defended against.
 */
const SHIPPED_VARS = {
  GATEWAY_NATIVE_API_KEYS: "[]",
  GATEWAY_STATIC_API_KEYS: "[]",
  GATEWAY_DEV_AUTH: "false",
  GATEWAY_DEV_API_KEY: DEV_KEY,
};

async function withDevKey(env: Record<string, string>): Promise<Response> {
  return await app.request(
    `${BASE}/v1/models`,
    { headers: { authorization: `Bearer ${DEV_KEY}` } },
    env,
  );
}

async function code(res: Response): Promise<string> {
  return ((await res.json()) as { error: { code: string } }).error.code;
}

describe("the development key path is off in the shipped configuration", () => {
  it("refuses a well-formed development key under the committed wrangler.toml vars", async () => {
    const res = await withDevKey(SHIPPED_VARS);
    expect(res.status).toBe(401);
    expect(await code(res)).toBe("invalid_api_key");
  });

  it("refuses it when GATEWAY_DEV_AUTH is absent entirely", async () => {
    const res = await withDevKey({ GATEWAY_DEV_API_KEY: DEV_KEY });
    expect(res.status).toBe(401);
  });

  it("requires the literal string \"true\" — no truthy near-misses", async () => {
    for (const value of ["TRUE", "True", "1", "yes", " true ", "true\n", ""]) {
      const res = await withDevKey({ GATEWAY_DEV_AUTH: value, GATEWAY_DEV_API_KEY: DEV_KEY });
      expect(res.status, `GATEWAY_DEV_AUTH=${JSON.stringify(value)}`).toBe(401);
    }
  });

  it("refuses a key without the fg_dev_ prefix even with the gate open", async () => {
    const key = "fg_live_0123456789abcdef0123456789abcdef";
    const res = await app.request(
      `${BASE}/v1/models`,
      { headers: { authorization: `Bearer ${key}` } },
      { GATEWAY_DEV_AUTH: "true", GATEWAY_DEV_API_KEY: key },
    );
    expect(res.status).toBe(401);
  });

  it("refuses a short (guessable) key even with the gate open", async () => {
    const key = `${DEV_API_KEY_PREFIX}short`;
    const res = await app.request(
      `${BASE}/v1/models`,
      { headers: { authorization: `Bearer ${key}` } },
      { GATEWAY_DEV_AUTH: "true", GATEWAY_DEV_API_KEY: key },
    );
    expect(res.status).toBe(401);
  });

  it("contributes no key record at all whenever any condition fails", () => {
    expect(developmentApiKeys({})).toEqual([]);
    expect(developmentApiKeys({ GATEWAY_DEV_AUTH: "true" })).toEqual([]);
    expect(developmentApiKeys({ GATEWAY_DEV_AUTH: "false", GATEWAY_DEV_API_KEY: DEV_KEY })).toEqual(
      [],
    );
    expect(
      developmentApiKeys({ GATEWAY_DEV_AUTH: "true", GATEWAY_DEV_API_KEY: "fg_dev_tooshort" }),
    ).toEqual([]);
  });
});

describe("the development key, once all three conditions hold", () => {
  const ENABLED = { GATEWAY_DEV_AUTH: "true", GATEWAY_DEV_API_KEY: DEV_KEY };

  it("authenticates an inference operation", async () => {
    // A resolved credential must still get PAST the tenancy resolver, which
    // since #819 defaults to `durable_object` routing and refuses (503) when
    // `CONTROL_DB` / `TENANT_DATA` are unbound — bindings `wrangler dev` always
    // has. So this arm runs with the real bindings plus the dev vars, exactly
    // the developer's posture. `DB` is deliberately NOT passed: without it the
    // resolver keeps the pure zero-roster object router, so the ad-hoc
    // `tenant_local_dev` needs no `tenant_databases` row.
    const real = env as unknown as Record<string, unknown>;
    const res = await app.request(
      `${BASE}/v1/models`,
      { headers: { authorization: `Bearer ${DEV_KEY}` } },
      { ...ENABLED, CONTROL_DB: real.CONTROL_DB, TENANT_DATA: real.TENANT_DATA },
    );
    expect(res.status).toBe(200);
    // No models are configured in this env, so the listing is empty — the point
    // is that the credential resolved, not what it saw.
    expect(await res.json()).toEqual({ object: "list", data: [] });
  });

  it("cannot reach an admin operation — it holds no admin.* scope", async () => {
    const res = await app.request(
      `${BASE}/admin/v1/status`,
      { headers: { authorization: `Bearer ${DEV_KEY}` } },
      ENABLED,
    );
    expect(res.status).toBe(403);
    expect(await code(res)).toBe("scope_denied");
  });

  it("cannot reach an internal worker-plane operation", async () => {
    const res = await app.request(
      `${BASE}/v1/self-hosted-workers/heartbeat`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${DEV_KEY}`, "content-type": "application/json" },
        body: "{}",
      },
      ENABLED,
    );
    expect(res.status).toBe(401);
    expect(await code(res)).toBe("invalid_self_hosted_worker_identity");
  });

  it("grants inference scopes only — never the wildcard, never admin", () => {
    const [record] = developmentApiKeys(ENABLED);
    expect(record?.key).toBe(DEV_KEY);
    expect(record?.tenant_id).toBe("tenant_local_dev");
    expect(record?.scopes).toEqual(DEV_API_KEY_SCOPES);
    expect(record?.scopes).not.toContain("*");
    expect(record?.platform_operator).toBeUndefined();
    for (const scope of DEV_API_KEY_SCOPES) {
      expect(isPrivilegedScope(scope), scope).toBe(false);
    }
  });

  it("honours GATEWAY_DEV_TENANT_ID when the developer sets one", () => {
    const [record] = developmentApiKeys({ ...ENABLED, GATEWAY_DEV_TENANT_ID: "tenant_acme" });
    expect(record?.tenant_id).toBe("tenant_acme");
  });

  it("is a NATIVE key, so suspending it stays 401 rather than disclosing state", async () => {
    // A native record whose key collides with the dev key wins the native scan
    // (last match), and a disabled native key is `key_suspended` ⇒ 401, exactly
    // as an unknown key is. The dev path must not be able to soften that.
    const res = await withDevKey({
      ...ENABLED,
      GATEWAY_NATIVE_API_KEYS: JSON.stringify([
        { key: DEV_KEY, id: "shadow", tenant_id: "t", enabled: false },
      ]),
    });
    expect(res.status).toBe(401);
    expect(await code(res)).toBe("invalid_api_key");
  });
});
