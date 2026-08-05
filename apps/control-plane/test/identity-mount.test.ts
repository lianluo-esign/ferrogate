/**
 * THE MOUNT GATE for the three enterprise-identity surfaces, driven through
 * `SELF` — i.e. through the REAL `export default` in real `workerd`.
 *
 * ## Why this file exists, and why the existing suites do not replace it
 *
 * `test/console-session.test.ts` builds its OWN `Hono` app and calls
 * `app.request(...)`. `packages/identity` and `packages/sso` test their handlers
 * against in-memory ports. All three prove the FACTORY, and
 * `docs/rewrite/MOUNT-SEAMS.md` §4 is the record of what that is worth: eleven
 * fully-implemented, fully-tested surfaces have shipped in this repo DEAD in
 * production while every suite stayed green, because a handler that exists is
 * not a handler that runs.
 *
 * Every assertion below therefore goes through `SELF.fetch`, and each one is
 * chosen so that ONLY the real mount can produce it — a `404 no route for …` is
 * what an unmounted surface answers, and `404` is also what a "not implemented
 * yet" surface answers, which is exactly how an unmounted route survives a
 * green suite.
 *
 * ## The three seams and their mutations
 *
 * | seam in `src/index.ts` | delete it ⇒ |
 * |---|---|
 * | `mountAdminConsoleSession(app)` | §1 goes RED (`404` on `POST /v1/admin/login`) |
 * | `app.route("/", IDENTITY_APP)` | §2 + §3 go RED (`404` on `/scim/v2/Users`, `/v1/admin/auth/sso/*`) |
 * | `mountSsoRoutes(app)` | §4 goes RED (`404` on `/v1/admin/auth/saml/acs`) |
 *
 * ## The adversarial half
 *
 * A mount test that only proves the happy path proves that the surface answers,
 * not that it REFUSES. Each section therefore carries at least one case where
 * an attacker's input must fail closed, exercised through the deployed Worker:
 *
 *  - **SAML** — a TAMPERED assertion (one byte of the signed payload flipped)
 *    must be `401 saml_signature_verification_failed`, and a byte-identical
 *    REPLAY of a redirect that already succeeded must be `401 unknown_saml_state`.
 *  - **OIDC** — an ID token minted for ANOTHER audience, correctly signed by the
 *    IdP's real key, must be `401`.
 *  - **SCIM** — a provisioning token from tenant A must not see, read or delete
 *    a user of tenant B, and must not be usable without the exact
 *    `scim.provision` scope.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type SigningKey,
  generateRs256Key,
  jwksDocument,
  signJwt,
} from "../../../packages/identity/test/jwt-fixtures.js";
import { IDP_CERT_PEM, IDP_KEY_PKCS8_PEM } from "../../../packages/sso/test/fixtures.js";
import { encodedResponse, signedQuery } from "../../../packages/sso/test/support.js";
import { resetIdentityJwksCache } from "../src/identity/adapters.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm } from "./harness.js";
import { applyTenantSchema, resetTenantD1 } from "./tenant-db.js";
import { registerDurableObjectTenant, tenantObjectDb } from "./tenant-object.js";

const JWT_SECRET = "identity-mount-console-signing-secret";
const OIDC_SECRET_BINDING = "TEST_OIDC_CLIENT_SECRET";
const OIDC_CLIENT_ID = "ferrogate-console";
const OIDC_ISSUER = "https://idp.mount.test";

type MutableEnv = Record<string, unknown>;

function armIdentity(): void {
  arm({ store: "d1" });
  const bindings = env as unknown as MutableEnv;
  bindings.ADMIN_CONSOLE_JWT_SECRET = JWT_SECRET;
  bindings[OIDC_SECRET_BINDING] = "idp-client-secret";
}

interface Json {
  readonly [field: string]: unknown;
}

interface Reply {
  readonly status: number;
  readonly body: Json;
  readonly text: string;
}

/** Every call in this file goes through the DEPLOYED Worker. No local app. */
async function call(
  method: string,
  path: string,
  options: { body?: unknown; token?: string } = {},
): Promise<Reply> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token !== undefined) headers.authorization = `Bearer ${options.token}`;
  const response = await SELF.fetch(`${BASE}${path}`, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  let body: Json = {};
  try {
    body = JSON.parse(text) as Json;
  } catch {
    body = {};
  }
  return { status: response.status, body, text };
}

function errorCode(body: Json): string {
  return (body.error as { code?: string } | undefined)?.code ?? "<none>";
}

interface Session {
  readonly access_token: string;
  readonly gateway_api_key: string;
  readonly user: { id: string; email: string };
  readonly tenant: { id: string; role: string };
}

async function register(email: string, organization: string): Promise<Session> {
  const reply = await call("POST", "/v1/admin/register", {
    body: { organization_name: organization, email, password: "correct horse battery" },
  });
  expect(reply.status, reply.text).toBe(201);
  return reply.body as unknown as Session;
}

async function login(email: string): Promise<Session> {
  const reply = await call("POST", "/v1/admin/login", {
    body: { email, password: "correct horse battery" },
  });
  expect(reply.status, reply.text).toBe(200);
  return reply.body as unknown as Session;
}

/**
 * Point a tenant at a real per-tenant D1, the way the provisioning flow would.
 *
 * An UPSERT since #820, not an INSERT: registering a tenant now provisions its
 * storage, which writes a `tenant_databases` row of its own — so a bare INSERT
 * here fails the primary key and takes the whole registration flow down with it.
 * Re-pointing the row at a D1 binding is exactly what this fixture means, and
 * `storage_backend` has to move with it or the binding router will (correctly)
 * refuse to serve a row that says the data lives in an object.
 *
 * A virtual key is TWO rows — `api_key_directory` in the control database and
 * `api_keys` in the tenant's own — and the SCIM token is an ordinary virtual
 * key. Without this the projection has nowhere to write the tenant leg and the
 * minted token would never authenticate.
 */
async function provisionTenantDatabase(
  tenantId: string,
  _binding: "TENANT_DB_A" | "TENANT_DB_B",
): Promise<void> {
  await registerDurableObjectTenant(tenantId);
}

// ---------------------------------------------------------------------------
// A stand-in IdP, installed over `globalThis.fetch`
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;

interface IdpState {
  key: SigningKey;
  /** What the token endpoint hands back next. */
  idToken: string;
}

let idp: IdpState | null = null;

/**
 * Serves discovery, the token endpoint and the JWKS.
 *
 * `src/identity/adapters.ts` passes `(url, init) => fetch(url, init)` rather
 * than the `fetch` reference itself, so the global is resolved at CALL time and
 * this override is visible to the handler running inside the Worker. That is
 * the whole reason the deployed OIDC ladder can be exercised end to end here
 * instead of only at unit level.
 */
function installIdp(): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (idp !== null && url === `${OIDC_ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: OIDC_ISSUER,
        authorization_endpoint: `${OIDC_ISSUER}/authorize`,
        token_endpoint: `${OIDC_ISSUER}/token`,
        jwks_uri: `${OIDC_ISSUER}/jwks`,
      });
    }
    if (idp !== null && url === `${OIDC_ISSUER}/jwks`) {
      return Response.json(jwksDocument([idp.key]));
    }
    if (idp !== null && url === `${OIDC_ISSUER}/token`) {
      return Response.json({ id_token: idp.idToken, token_type: "Bearer" });
    }
    return await realFetch(input as RequestInfo, init);
  }) as typeof fetch;
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
  installIdp();
});

beforeEach(async () => {
  armIdentity();
  idp = null;
  // The JWKS cache is per-ISOLATE by design (see `src/identity/adapters.ts`),
  // and `SELF` runs in THIS isolate, so without this every test after the first
  // verifies against the previous test's key and fails at rung 6 instead of the
  // rung it is actually about. Dropping the cache is a test-only seam; nothing
  // in production calls it.
  resetIdentityJwksCache();
  await resetD1();
  await resetTenantD1();
  await db().batch([
    db().prepare("DELETE FROM admin_users"),
    db().prepare("DELETE FROM admin_user_tenant_memberships"),
    db().prepare("DELETE FROM admin_user_refresh_tokens"),
    db().prepare("DELETE FROM api_key_directory"),
    db().prepare("DELETE FROM sso_pending_flows"),
    db().prepare("DELETE FROM tenant_databases"),
  ]);
});

// ---------------------------------------------------------------------------
// §1 — the admin-console SESSION surface is mounted on the deployed Worker
// ---------------------------------------------------------------------------

describe("§1 the admin-console session surface is MOUNTED", () => {
  it("serves POST /v1/admin/login through the deployed Worker (not 404)", async () => {
    const reply = await call("POST", "/v1/admin/login", {
      body: { email: "nobody@example.test", password: "x" },
    });
    // 401 is the surface REFUSING an unknown account. 404 is it being absent —
    // and `no route for POST /v1/admin/login` is exactly what deleting
    // `mountAdminConsoleSession(app)` from `src/index.ts` produces.
    expect(reply.status, reply.text).not.toBe(404);
    expect(reply.status).toBe(401);
  });

  it("registers a real tenant, user, membership and gateway key through SELF", async () => {
    const session = await register("owner@acme.test", "Acme");
    expect(session.access_token.split(".")).toHaveLength(3);
    expect(session.gateway_api_key.startsWith("fg_")).toBe(true);
    expect(session.tenant.role).toBe("owner");

    // The rows, read straight out of the tables the migration ships.
    const user = await db()
      .prepare("SELECT * FROM admin_users WHERE email = ?")
      .bind("owner@acme.test")
      .first<Record<string, unknown>>();
    expect(user).not.toBeNull();
    const membership = await db()
      .prepare("SELECT * FROM admin_user_tenant_memberships WHERE user_id = ?")
      .bind(session.user.id)
      .first<Record<string, unknown>>();
    expect(membership?.role).toBe("owner");
  });

  it("serves GET /v1/admin/me for a real session issued by the deployed Worker", async () => {
    const session = await register("owner@acme.test", "Acme");
    const me = await call("GET", "/v1/admin/me", { token: session.access_token });
    expect(me.status, me.text).toBe(200);
    expect((me.body.user as Json | undefined)?.email).toBe("owner@acme.test");
  });

  it("ADVERSARIAL: a forged session JWT is refused by the deployed Worker", async () => {
    await register("owner@acme.test", "Acme");
    // A structurally valid JWT signed with the WRONG key.
    const forged = [
      btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })),
      btoa(JSON.stringify({ sub: "user_x", tenant_id: "t", role: "owner", exp: 4102444800 })),
      "not-a-real-signature",
    ].join(".");
    const me = await call("GET", "/v1/admin/me", { token: forged });
    expect(me.status, me.text).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// §2 — SCIM
// ---------------------------------------------------------------------------

/** Mint a SCIM provisioning token the way the console does, through SELF. */
async function mintScimToken(session: Session): Promise<string> {
  const reply = await call("POST", "/v1/admin/team/scim-token", {
    token: session.access_token,
  });
  expect(reply.status, reply.text).toBe(201);
  const token = reply.body.token ?? reply.body.secret ?? reply.body.value;
  expect(typeof token, reply.text).toBe("string");
  return token as string;
}

describe("§2 the SCIM surface is MOUNTED and tenant-scoped", () => {
  it("routes /scim/v2/Users — an anonymous call is 401, never 404", async () => {
    const reply = await call("GET", "/scim/v2/Users");
    // THE gate. An unmounted sub-app answers 404 with the control plane's
    // `no route for GET /scim/v2/Users`; a mounted one reaches the SCIM guard,
    // which refuses a missing credential.
    expect(reply.status, reply.text).not.toBe(404);
    expect(reply.status).toBe(401);
  });

  it("ADVERSARIAL: a valid gateway key WITHOUT scim.provision is 403, not 200", async () => {
    const registered = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(registered.tenant.id, "TENANT_DB_A");
    // Log in AFTER the tenant database exists: a virtual key is two rows, and
    // the tenant leg has nowhere to go until the tenant is provisioned. This
    // key therefore really does authenticate — which is the point, because a
    // key that merely fails to resolve would give a 401 and prove nothing about
    // the SCOPE check.
    const session = await login("owner@acme.test");
    // The console session key is a REAL, live credential for this tenant — it
    // simply is not a directory-administration credential. Widening the scope
    // test to `startsWith` or to `admin.write` would make this 200.
    const reply = await call("GET", "/scim/v2/Users", { token: session.gateway_api_key });
    expect(reply.status, reply.text).toBe(403);
  });

  it("mints a provisioning token and lists ONLY its own tenant's users", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const globex = await register("owner@globex.test", "Globex");
    await provisionTenantDatabase(globex.tenant.id, "TENANT_DB_B");

    const token = await mintScimToken(acme);
    const list = await call("GET", "/scim/v2/Users", { token });
    expect(list.status, list.text).toBe(200);
    const emails = ((list.body.Resources as { userName?: string }[]) ?? []).map(
      (resource) => resource.userName,
    );
    expect(emails).toContain("owner@acme.test");
    // THE cross-tenant assertion (#161/#232). A SCIM token acquires its tenant
    // from the key it was minted for and from nowhere else — there is no path
    // segment, query parameter or body field through which it could ask for
    // another one.
    expect(emails).not.toContain("owner@globex.test");
  });

  it("ADVERSARIAL: tenant A's SCIM token cannot READ tenant B's user by id", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const globex = await register("owner@globex.test", "Globex");
    await provisionTenantDatabase(globex.tenant.id, "TENANT_DB_B");

    const token = await mintScimToken(acme);
    const stolen = await call("GET", `/scim/v2/Users/${globex.user.id}`, { token });
    expect(stolen.status, stolen.text).toBe(404);
  });

  it("ADVERSARIAL: tenant A's SCIM token cannot DEPROVISION tenant B's user", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const globex = await register("owner@globex.test", "Globex");
    await provisionTenantDatabase(globex.tenant.id, "TENANT_DB_B");

    const token = await mintScimToken(acme);
    const attack = await call("DELETE", `/scim/v2/Users/${globex.user.id}`, { token });
    expect(attack.status, attack.text).toBe(404);

    // The refusal has to be REAL, not merely a status: B's membership must
    // still be there. A 404 with the row already deleted is the failure mode a
    // status-only assertion cannot see.
    const survivors = await db()
      .prepare("SELECT * FROM admin_user_tenant_memberships WHERE tenant_id = ?")
      .bind(globex.tenant.id)
      .all<Record<string, unknown>>();
    expect(survivors.results).toHaveLength(1);
    expect(survivors.results[0]?.user_id).toBe(globex.user.id);
  });
});

// ---------------------------------------------------------------------------
// §3 — OIDC
// ---------------------------------------------------------------------------

async function configureOidc(session: Session): Promise<void> {
  const reply = await call("POST", "/v1/admin/team/sso-config", {
    token: session.access_token,
    body: {
      provider_kind: "oidc",
      oidc_issuer: OIDC_ISSUER,
      oidc_client_id: OIDC_CLIENT_ID,
      oidc_client_secret_ref: `env://${OIDC_SECRET_BINDING}`,
      oidc_redirect_uri: "https://console.test/callback",
      default_role: "member",
    },
  });
  expect(reply.status, reply.text).toBe(200);
}

/** Start the handshake through SELF and return the `state` the Worker stored. */
async function startOidc(tenantId: string): Promise<string> {
  const reply = await call("GET", `/v1/admin/auth/sso/authorize?tenant_id=${tenantId}`);
  expect(reply.status, reply.text).toBe(200);
  return reply.body.state as string;
}

/** The `nonce` the Worker put in the pending-flow row, read back from D1. */
async function storedNonce(state: string): Promise<string> {
  const row = await db()
    .prepare("SELECT nonce FROM sso_pending_flows WHERE state = ?")
    .bind(state)
    .first<{ nonce: string | null }>();
  expect(row?.nonce, "the authorize leg must persist a nonce").toBeTruthy();
  return row?.nonce as string;
}

describe("§3 the OIDC relying party is MOUNTED", () => {
  it("routes /v1/admin/auth/sso/authorize — an unconfigured tenant is 404 not_found, with an envelope", async () => {
    const reply = await call("GET", "/v1/admin/auth/sso/authorize?tenant_id=tenant_missing");
    expect(reply.status).toBe(404);
    // The distinguishing bit: an UNMOUNTED route answers the control plane's
    // own `no route for GET …`. A mounted one answers the identity package's
    // "SSO is not configured for this tenant".
    expect(reply.text).toContain("SSO is not configured");
    expect(reply.text).not.toContain("no route for");
  });

  it("ADVERSARIAL: a forged state is refused before any outbound call", async () => {
    const reply = await call("GET", "/v1/admin/auth/sso/callback?code=abc&state=forged-state");
    expect(reply.status, reply.text).toBe(401);
    expect(reply.text).toContain("unknown, expired, or already-used SSO state");
  });

  it("completes a real OIDC login end to end through the deployed Worker", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const key = await generateRs256Key("k1");
    idp = { key, idToken: "" };
    await configureOidc(acme);

    const state = await startOidc(acme.tenant.id);
    const now = Math.floor(Date.now() / 1000);
    idp.idToken = await signJwt(key, {
      iss: OIDC_ISSUER,
      aud: OIDC_CLIENT_ID,
      sub: "idp-subject-1",
      nonce: await storedNonce(state),
      email: "owner@acme.test",
      name: "Ada Lovelace",
      iat: now,
      exp: now + 600,
    });

    const reply = await call("GET", `/v1/admin/auth/sso/callback?code=xyz&state=${state}`);
    expect(reply.status, reply.text).toBe(200);
    expect(reply.body.access_token, reply.text).toBeTruthy();
  });

  it("ADVERSARIAL: an ID token minted for ANOTHER audience is refused with 401", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const key = await generateRs256Key("k1");
    idp = { key, idToken: "" };
    await configureOidc(acme);

    const state = await startOidc(acme.tenant.id);
    const now = Math.floor(Date.now() / 1000);
    // Correctly signed by the IdP's REAL key, correct issuer, correct nonce —
    // and minted for a DIFFERENT relying party. This is the token an attacker
    // who controls any other client of the same IdP can obtain legitimately,
    // which is why `aud` is the check that must not be skipped.
    idp.idToken = await signJwt(key, {
      iss: OIDC_ISSUER,
      aud: "some-other-relying-party",
      sub: "idp-subject-1",
      nonce: await storedNonce(state),
      email: "owner@acme.test",
      iat: now,
      exp: now + 600,
    });

    const reply = await call("GET", `/v1/admin/auth/sso/callback?code=xyz&state=${state}`);
    expect(reply.status, reply.text).toBe(401);
    expect(reply.text).toContain("ID token validation failed");
    expect(reply.body.access_token).toBeUndefined();
  });

  it("ADVERSARIAL: the state is SINGLE-USE — replaying a completed callback fails", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    const key = await generateRs256Key("k1");
    idp = { key, idToken: "" };
    await configureOidc(acme);

    const state = await startOidc(acme.tenant.id);
    const now = Math.floor(Date.now() / 1000);
    idp.idToken = await signJwt(key, {
      iss: OIDC_ISSUER,
      aud: OIDC_CLIENT_ID,
      sub: "idp-subject-1",
      nonce: await storedNonce(state),
      email: "owner@acme.test",
      iat: now,
      exp: now + 600,
    });

    expect((await call("GET", `/v1/admin/auth/sso/callback?code=xyz&state=${state}`)).status).toBe(
      200,
    );
    // The SECOND call proves `takeSsoPendingFlow` really CONSUMED the row —
    // i.e. that the D1 implementation is the atomic `DELETE … RETURNING` and
    // not a `SELECT`. Nothing in `packages/identity` can see this: its tests
    // run against the in-memory map.
    const replay = await call("GET", `/v1/admin/auth/sso/callback?code=xyz&state=${state}`);
    expect(replay.status, replay.text).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// §4 — SAML
// ---------------------------------------------------------------------------

const SP_ENTITY_ID = "sp-entity-id";
const IDP_ENTITY_ID = "https://idp.example/entity";

async function configureSaml(session: Session): Promise<void> {
  const reply = await call("POST", "/v1/admin/team/sso-config", {
    token: session.access_token,
    body: {
      provider_kind: "saml",
      saml_idp_entity_id: IDP_ENTITY_ID,
      saml_idp_sso_url: "https://idp.example/sso",
      saml_idp_certificate: IDP_CERT_PEM,
      saml_sp_entity_id: SP_ENTITY_ID,
      saml_acs_url: "https://console.test/v1/admin/auth/saml/acs",
      default_role: "member",
    },
  });
  expect(reply.status, reply.text).toBe(200);
}

/** The `AuthnRequest` id the Worker stored for this state — the `InResponseTo`. */
async function storedRequestId(state: string): Promise<string> {
  const row = await db()
    .prepare("SELECT request_id FROM sso_pending_flows WHERE state = ?")
    .bind(state)
    .first<{ request_id: string | null }>();
  expect(row?.request_id, "the SAML authorize leg must persist a request id").toBeTruthy();
  return row?.request_id as string;
}

async function startSaml(tenantId: string): Promise<string> {
  const reply = await call("GET", `/v1/admin/auth/saml/authorize?tenant_id=${tenantId}`);
  expect(reply.status, reply.text).toBe(200);
  expect(String(reply.body.authorize_url)).toContain("SAMLRequest=");
  return reply.body.state as string;
}

describe("§4 the SAML service provider is MOUNTED", () => {
  it("routes /v1/admin/auth/saml/acs — a bare call is a SAML refusal, never 404", async () => {
    const reply = await call("GET", "/v1/admin/auth/saml/acs");
    expect(reply.status, reply.text).not.toBe(404);
    expect(reply.text).not.toContain("no route for");
    // `missing SAMLResponse`/`missing RelayState` — the package's own vocabulary,
    // which only the mounted handler can produce.
    expect(errorCode(reply.body)).not.toBe("not_found");
  });

  it("completes a real SAML login end to end through the deployed Worker", async () => {
    const acme = await register("ada@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    await configureSaml(acme);
    const state = await startSaml(acme.tenant.id);

    const response = await encodedResponse({
      inResponseTo: await storedRequestId(state),
      issuer: IDP_ENTITY_ID,
      audience: SP_ENTITY_ID,
      email: "ada@acme.test",
    });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, state);
    const reply = await call("GET", `/v1/admin/auth/saml/acs?${query}`);
    expect(reply.status, reply.text).toBe(200);
    expect(reply.body.access_token, reply.text).toBeTruthy();
  });

  it("ADVERSARIAL: a TAMPERED assertion is refused with 401 and the ported code", async () => {
    const acme = await register("ada@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    await configureSaml(acme);
    const state = await startSaml(acme.tenant.id);

    const honest = await encodedResponse({
      inResponseTo: await storedRequestId(state),
      issuer: IDP_ENTITY_ID,
      audience: SP_ENTITY_ID,
      email: "ada@acme.test",
    });
    // Swap the IdP's assertion for one asserting a DIFFERENT identity, keeping
    // the IdP's real signature. The detached RSA signature is over the query
    // octets, so this must not verify.
    const forged = await encodedResponse({
      inResponseTo: await storedRequestId(state).catch(() => "_req-123"),
      issuer: IDP_ENTITY_ID,
      audience: SP_ENTITY_ID,
      email: "attacker@evil.test",
    });
    expect(forged).not.toBe(honest);
    const honestQuery = await signedQuery(IDP_KEY_PKCS8_PEM, honest, state);
    const tampered = honestQuery.replace(
      /SAMLResponse=[^&]*/,
      `SAMLResponse=${encodeURIComponent(forged)}`,
    );

    const reply = await call("GET", `/v1/admin/auth/saml/acs?${tampered}`);
    expect(reply.status, reply.text).toBe(401);
    expect(errorCode(reply.body)).toBe("saml_signature_verification_failed");
    expect(reply.body.access_token).toBeUndefined();

    // No account was created for the asserted attacker address.
    const intruder = await db()
      .prepare("SELECT * FROM admin_users WHERE email = ?")
      .bind("attacker@evil.test")
      .first<Record<string, unknown>>();
    expect(intruder).toBeNull();
  });

  it("ADVERSARIAL: an assertion signed by ANOTHER key is refused with 401", async () => {
    const acme = await register("ada@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    await configureSaml(acme);
    const state = await startSaml(acme.tenant.id);

    const response = await encodedResponse({
      inResponseTo: await storedRequestId(state),
      issuer: IDP_ENTITY_ID,
      audience: SP_ENTITY_ID,
      email: "ada@acme.test",
    });
    // A structurally perfect, correctly-signed redirect — signed by a key the
    // tenant never pinned. The configured certificate IS the trust anchor.
    const { OTHER_KEY_PKCS8_PEM } = await import("../../../packages/sso/test/fixtures.js");
    const query = await signedQuery(OTHER_KEY_PKCS8_PEM, response, state);
    const reply = await call("GET", `/v1/admin/auth/saml/acs?${query}`);
    expect(reply.status, reply.text).toBe(401);
    expect(errorCode(reply.body)).toBe("saml_signature_verification_failed");
  });

  it("ADVERSARIAL: a byte-identical REPLAY of an accepted redirect is refused", async () => {
    const acme = await register("ada@acme.test", "Acme");
    await provisionTenantDatabase(acme.tenant.id, "TENANT_DB_A");
    await configureSaml(acme);
    const state = await startSaml(acme.tenant.id);

    const response = await encodedResponse({
      inResponseTo: await storedRequestId(state),
      issuer: IDP_ENTITY_ID,
      audience: SP_ENTITY_ID,
      email: "ada@acme.test",
    });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, state);
    expect((await call("GET", `/v1/admin/auth/saml/acs?${query}`)).status).toBe(200);

    // The signature stays valid forever — single-use state is the ONLY replay
    // defence, and it lives in the control plane's D1 `DELETE … RETURNING`.
    const replay = await call("GET", `/v1/admin/auth/saml/acs?${query}`);
    expect(replay.status, replay.text).toBe(401);
    expect(errorCode(replay.body)).toBe("unknown_saml_state");
  });
});

// ---------------------------------------------------------------------------
// §5 — the shared sso-config row
// ---------------------------------------------------------------------------

describe("§5 the shared /v1/admin/team/sso-config row is MOUNTED", () => {
  it("routes it — an anonymous call is 401, never 404", async () => {
    const reply = await call("GET", "/v1/admin/team/sso-config");
    expect(reply.status, reply.text).not.toBe(404);
    expect(reply.status).toBe(401);
  });

  it("never returns a resolved client secret, only the reference", async () => {
    const acme = await register("owner@acme.test", "Acme");
    await configureOidc(acme);
    const reply = await call("GET", "/v1/admin/team/sso-config", {
      token: acme.access_token,
    });
    expect(reply.status, reply.text).toBe(200);
    expect(reply.body.oidc_client_secret_ref).toBe(`env://${OIDC_SECRET_BINDING}`);
    expect(reply.text).not.toContain("idp-client-secret");
  });

  it("ADVERSARIAL: a non-owner cannot write the tenant's IdP configuration", async () => {
    const acme = await register("owner@acme.test", "Acme");
    // Demote in SQL — the same ladder `console-session.test.ts` exercises.
    await db()
      .prepare("UPDATE admin_user_tenant_memberships SET role = 'member' WHERE user_id = ?")
      .bind(acme.user.id)
      .run();
    const reply = await call("POST", "/v1/admin/team/sso-config", {
      token: acme.access_token,
      body: {
        provider_kind: "oidc",
        oidc_issuer: OIDC_ISSUER,
        oidc_client_id: OIDC_CLIENT_ID,
        oidc_client_secret_ref: `env://${OIDC_SECRET_BINDING}`,
        oidc_redirect_uri: "https://console.test/callback",
      },
    });
    expect(reply.status, reply.text).toBe(403);
    const row = await tenantObjectDb(acme.tenant.id)
      .prepare("SELECT * FROM sso_provider_configs WHERE tenant_id = ?")
      .bind(acme.tenant.id)
      .first<Record<string, unknown>>();
    expect(row).toBeNull();
  });

  it("ADVERSARIAL: a plaintext client secret is refused — the column takes a REFERENCE", async () => {
    const acme = await register("owner@acme.test", "Acme");
    const reply = await call("POST", "/v1/admin/team/sso-config", {
      token: acme.access_token,
      body: {
        provider_kind: "oidc",
        oidc_issuer: OIDC_ISSUER,
        oidc_client_id: OIDC_CLIENT_ID,
        oidc_client_secret_ref: "super-secret-value",
        oidc_redirect_uri: "https://console.test/callback",
      },
    });
    expect(reply.status, reply.text).toBe(422);
    expect(reply.text).toContain("must be a secret reference URI");
  });
});
