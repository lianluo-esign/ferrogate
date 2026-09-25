import { env } from "cloudflare:test";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import { Hono } from "hono";
import { beforeAll, beforeEach, expect, it } from "vitest";
import { resolveDeps } from "../src/adapters.js";
import { controlPlaneErrorHandler, requestId } from "../src/middleware/errors.js";
import type { ControlPlaneEnv } from "../src/ports.js";
import { PasskeyStore } from "../src/session/passkey-store.js";
import { mountAdminConsoleSession } from "../src/session/routes.js";
import { signAdminAccessToken } from "../src/session/tokens.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { arm } from "./harness.js";
import { applyTenantSchema, resetTenantD1 } from "./tenant-db.js";
import { tenantObjectDb } from "./tenant-object.js";

const ORIGIN = "https://dash.token4ai.cloud";
const SECRET = "passkey-bridge-test-secret";
const JWT = "passkey-jwt-test-secret";
const binding = "a".repeat(43);
const app = new Hono<ControlPlaneEnv>();
app.onError(controlPlaneErrorHandler);
app.use("*", requestId);
app.use("*", async (c, next) => {
  c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));
  await next();
});
mountAdminConsoleSession(app);

interface Session {
  access_token: string;
  user: { id: string; email: string };
  tenant: { id: string };
  gateway_api_key: string;
}
interface Options {
  challengeId: string;
  options: {
    challenge: string;
    user?: { id: string };
    authenticatorSelection?: { residentKey: string; userVerification: string };
  };
}
async function call<T>(
  path: string,
  body?: unknown,
  token?: string,
  method = "POST",
  secret = SECRET,
) {
  const response = await app.request(
    `https://control.test/v1/admin/${path}`,
    {
      method,
      headers: {
        "content-type": "application/json",
        "x-ferrogate-oauth-bridge-secret": secret,
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
    env,
  );
  return { status: response.status, body: (await response.json()) as T };
}
async function account(email = "alice@passkey.test") {
  const result = await call<Session>("register", {
    email,
    organization_name: "Passkey tenant",
    password: "correct horse battery",
  });
  expect(result.status, JSON.stringify(result.body)).toBe(201);
  return result.body;
}
async function options(kind: string, token?: string) {
  const result = await call<Options>(
    `passkeys/${kind}/options`,
    { binding, client: "local-test-client" },
    token,
  );
  expect(result.status, JSON.stringify(result.body)).toBe(200);
  return result.body;
}
const bytes = (value: string) => new TextEncoder().encode(value);
const concat = (...parts: Uint8Array[]) => {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
};
const hash = async (value: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", value));
const b64 = isoBase64URL.fromBuffer;

/** Software authenticator: real P-256 keys, COSE/CBOR attestation and signed assertions. */
async function authenticator() {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  const id = crypto.getRandomValues(new Uint8Array(32));
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, isoBase64URL.toBuffer(jwk.x as string)],
      [-3, isoBase64URL.toBuffer(jwk.y as string)],
    ]),
  );
  function client(type: string, challenge: string, origin: string) {
    return bytes(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }
  async function authData(flags: number, counter: number, rp = "dash.token4ai.cloud") {
    const count = new Uint8Array(4);
    new DataView(count.buffer).setUint32(0, counter);
    return concat(await hash(bytes(rp)), new Uint8Array([flags]), count);
  }
  return {
    id: b64(id),
    async registration(
      challenge: string,
      origin = ORIGIN,
      flags = 0x45,
    ): Promise<RegistrationResponseJSON> {
      const data = concat(
        await authData(flags, 0),
        new Uint8Array(16),
        new Uint8Array([0, id.length]),
        id,
        cose,
      );
      const attestation = isoCBOR.encode(
        new Map<string, string | Uint8Array | Map<string, string>>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", data],
        ]),
      );
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          clientDataJSON: b64(client("webauthn.create", challenge, origin)),
          attestationObject: b64(attestation),
          transports: ["internal"],
        },
      };
    },
    async assertion(
      challenge: string,
      userHandle: string,
      changes: { origin?: string; flags?: number; rp?: string; counter?: number } = {},
    ): Promise<AuthenticationResponseJSON> {
      const clientData = client("webauthn.get", challenge, changes.origin ?? ORIGIN);
      const data = await authData(changes.flags ?? 0x05, changes.counter ?? 0, changes.rp);
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          pair.privateKey,
          concat(data, await hash(clientData)),
        ),
      );
      const integer = (raw: Uint8Array) => {
        let start = 0;
        while (start < raw.length - 1 && raw[start] === 0) start++;
        const value = raw.slice(start);
        const padded = (value[0] as number) & 0x80 ? concat(new Uint8Array([0]), value) : value;
        return concat(new Uint8Array([2, padded.length]), padded);
      };
      const der = concat(integer(signature.slice(0, 32)), integer(signature.slice(32)));
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64(clientData),
          authenticatorData: b64(data),
          signature: b64(concat(new Uint8Array([0x30, der.length]), der)),
          userHandle,
        },
      };
    },
  };
}
async function enroll(session: Session) {
  const device = await authenticator();
  const start = await options("register", session.access_token);
  const result = await call(
    "passkeys/register/verify",
    {
      binding,
      challengeId: start.challengeId,
      name: "My iPhone",
      response: await device.registration(start.options.challenge),
    },
    session.access_token,
  );
  expect(result.status, JSON.stringify(result.body)).toBe(201);
  return { device, handle: start.options.user?.id as string };
}
async function login(
  device: Awaited<ReturnType<typeof authenticator>>,
  handle: string,
  changes: Parameters<typeof device.assertion>[2] = {},
) {
  const start = await options("login");
  const payload = {
    binding,
    challengeId: start.challengeId,
    response: await device.assertion(start.options.challenge, handle, changes),
  };
  return { result: await call<Session>("passkeys/login/verify", payload), payload };
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});
beforeEach(async () => {
  arm({ store: "d1" });
  Object.assign(env, {
    ADMIN_CONSOLE_JWT_SECRET: JWT,
    OAUTH_BRIDGE_LOGIN_SECRET: SECRET,
    VEGA_PASSKEY_ORIGIN: ORIGIN,
  });
  await resetD1();
  await resetTenantD1();
  await db().batch([
    db().prepare("DELETE FROM admin_passkeys"),
    db().prepare("DELETE FROM admin_passkey_challenges"),
    db().prepare("DELETE FROM admin_passkey_rate_limits"),
  ]);
});

it("registers a discoverable, verified credential and mints the original tenant session; zero counters remain usable", async () => {
  const session = await account();
  const { device, handle } = await enroll(session);
  for (let i = 0; i < 2; i++) {
    const { result } = await login(device, handle);
    expect(result.status, JSON.stringify(result.body)).toBe(200);
    expect(result.body.user.id).toBe(session.user.id);
    expect(result.body.tenant.id).toBe(session.tenant.id);
    expect(result.body.gateway_api_key).toMatch(/^fg_/);
  }
  const listed = await call<{ passkeys: unknown[] }>(
    "passkeys",
    undefined,
    session.access_token,
    "GET",
  );
  expect(listed.body.passkeys).toHaveLength(1);
  expect(JSON.stringify(listed.body)).not.toMatch(/public_key|user_handle|counter/);
});

it.each([{ origin: "https://evil.test" }, { rp: "evil.test" }, { flags: 1 }])(
  "rejects invalid authentication security properties %j",
  async (changes) => {
    const { device, handle } = await enroll(await account());
    expect((await login(device, handle, changes)).result.status).toBe(401);
  },
);

it("rejects registration without user verification or with a different origin", async () => {
  const session = await account();
  const device = await authenticator();
  for (const [origin, flags] of [
    [ORIGIN, 0x41],
    ["https://evil.test", 0x45],
  ] as const) {
    const start = await options("register", session.access_token);
    expect(
      (
        await call(
          "passkeys/register/verify",
          {
            binding,
            challengeId: start.challengeId,
            response: await device.registration(start.options.challenge, origin, flags),
          },
          session.access_token,
        )
      ).status,
    ).toBe(401);
  }
});

it("consumes assertions only once, checks the browser binding and userHandle, rejects corrupt signatures", async () => {
  const { device, handle } = await enroll(await account());
  const { result, payload } = await login(device, handle);
  expect(result.status).toBe(200);
  expect((await call("passkeys/login/verify", payload)).status).toBe(401);
  expect((await login(device, "another-user")).result.status).toBe(401);
  const start = await options("login");
  const proof = {
    challengeId: start.challengeId,
    response: await device.assertion(start.options.challenge, handle),
  };
  expect((await call("passkeys/login/verify", { ...proof, binding: "wrong" })).status).toBe(401);
  proof.response.response.signature = b64(new Uint8Array(70));
  expect((await call("passkeys/login/verify", { ...proof, binding })).status).toBe(401);
});

it("denies foreign-user list/delete/enrollment and makes credential deletion effective immediately", async () => {
  const a = await account();
  const b = await account("bob@passkey.test");
  const { device, handle } = await enroll(a);
  const foreign = await call<{ passkeys: unknown[] }>("passkeys", undefined, b.access_token, "GET");
  expect(foreign.body.passkeys).toEqual([]);
  await call(`passkeys/${device.id}`, undefined, b.access_token, "DELETE");
  expect((await login(device, handle)).result.status).toBe(200);
  const start = await options("register", a.access_token);
  expect(
    (
      await call(
        "passkeys/register/verify",
        {
          binding,
          challengeId: start.challengeId,
          response: await device.registration(start.options.challenge),
        },
        b.access_token,
      )
    ).status,
  ).toBe(401);
  await call(`passkeys/${device.id}`, undefined, a.access_token, "DELETE");
  expect((await login(device, handle)).result.status).toBe(401);
});

it("fences credentials across two tenants of the same user", async () => {
  const a = await account();
  const b = await account("bob@passkey.test");
  const { device, handle } = await enroll(a);
  await db()
    .prepare(
      `INSERT INTO admin_user_tenant_memberships (id,user_id,tenant_id,role,created_at_unix) VALUES ('extra',?,?, 'viewer',0)`,
    )
    .bind(a.user.id, b.tenant.id)
    .run();
  const token = await signAdminAccessToken(JWT, {
    sub: a.user.id,
    email: a.user.email,
    tenant_id: b.tenant.id,
    role: "viewer",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  expect(
    (await call<{ passkeys: unknown[] }>("passkeys", undefined, token, "GET")).body.passkeys,
  ).toEqual([]);
  await call(`passkeys/${device.id}`, undefined, token, "DELETE");
  expect((await login(device, handle)).result.body.tenant.id).toBe(a.tenant.id);
});

it.each(["disabled", "membership", "deleted"])(
  "rejects an account after %s changes without reading stale identity KV",
  async (change) => {
    const session = await account();
    const { device, handle } = await enroll(session);
    if (change === "disabled")
      await db()
        .prepare("UPDATE admin_users SET disabled_at_unix = 1 WHERE id = ?")
        .bind(session.user.id)
        .run();
    if (change === "membership")
      await db()
        .prepare("DELETE FROM admin_user_tenant_memberships WHERE user_id = ?")
        .bind(session.user.id)
        .run();
    if (change === "deleted")
      await db().prepare("DELETE FROM admin_users WHERE id = ?").bind(session.user.id).run();
    expect((await login(device, handle)).result.status).toBe(401);
  },
);

it("fails closed for unauthenticated enrollment, missing bridge credential and invalid configured origin", async () => {
  expect((await call("passkeys/register/options", { binding, client: "test" })).status).toBe(401);
  expect(
    (await call("passkeys/login/options", { binding, client: "test" }, undefined, "POST", "wrong"))
      .status,
  ).toBe(401);
  Object.assign(env, { VEGA_PASSKEY_ORIGIN: "https://dash.token4ai.cloud/evil" });
  expect((await call("passkeys/login/options", { binding, client: "test" })).status).toBe(503);
});

it("rejects a suspended tenant and counter rollback", async () => {
  const session = await account();
  const { device, handle } = await enroll(session);
  expect((await login(device, handle, { counter: 3 })).result.status).toBe(200);
  expect((await login(device, handle, { counter: 2 })).result.status).toBe(401);
  await tenantObjectDb(session.tenant.id)
    .prepare(`UPDATE tenant_resources SET document_json = json_set(document_json, '$.status', 'suspended')
    WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`)
    .bind(session.tenant.id)
    .run();
  const result = (await login(device, handle, { counter: 4 })).result;
  expect(result.status).toBe(403);
});

it("does not reassign existing credentials and prevents concurrent counter updates after removal", async () => {
  const session = await account();
  const { device } = await enroll(session);
  const start = await options("register", session.access_token);
  expect(
    (
      await call(
        "passkeys/register/verify",
        {
          binding,
          challengeId: start.challengeId,
          response: await device.registration(start.options.challenge),
        },
        session.access_token,
      )
    ).status,
  ).toBe(409);
  const store = new PasskeyStore(db());
  const row = await store.get(device.id);
  expect(row).not.toBeNull();
  if (!row) throw new Error("missing test credential");
  const updates = await Promise.all([store.used(row, 0), store.used(row, 0)]);
  expect(updates.filter(Boolean)).toHaveLength(1);
  await store.remove(row.id, row.user_id, row.tenant_id);
  expect(await store.used(row, 0)).toBeNull();
});

it("atomically consumes challenges, enforces expiry and limits options requests", async () => {
  const store = new PasskeyStore(db());
  const id = await store.challenge("login", binding, "challenge");
  const results = await Promise.all([
    store.consume(id, "login", binding),
    store.consume(id, "login", binding),
  ]);
  expect(results.filter(Boolean)).toHaveLength(1);
  const expired = await store.challenge("login", binding, "expired");
  await db()
    .prepare("UPDATE admin_passkey_challenges SET expires_at = 0 WHERE id = ?")
    .bind(expired)
    .run();
  expect(await store.consume(expired, "login", binding)).toBeNull();
  for (let i = 0; i < 30; i++) await store.throttle("test-client");
  await expect(store.throttle("test-client")).rejects.toThrow("rate_limit");
});
