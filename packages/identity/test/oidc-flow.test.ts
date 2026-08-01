/**
 * The OIDC Authorization Code + PKCE flow end to end, driven adversarially.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/sso.rs`
 * (`handle_sso_authorize` / `handle_sso_callback` / `complete_sso_login`),
 * issues #160 / #283 / #517 / #232.
 */
import { beforeEach, describe, expect, test } from "vitest";
import { completeOidcCallback, startOidcAuthorize } from "../src/oidc/flow.js";
import type { OidcDeps } from "../src/oidc/flow.js";
import { JwksCache } from "../src/oidc/jwks.js";
import type { StoredSsoProviderConfig } from "../src/ports.js";
import {
  type SigningKey,
  generateRs256Key,
  jwksDocument,
  signJwt,
  unsignedJwt,
} from "./jwt-fixtures.js";
import {
  CountingRandom,
  FakeClock,
  MemoryApiKeyAuthenticator,
  MemoryIdentityRepository,
} from "./memory-store.js";

const ISSUER = "https://idp.test";
const CLIENT_ID = "client-abc";
const TENANT = "tenant_a";

interface Harness {
  deps: OidcDeps;
  repo: MemoryIdentityRepository;
  clock: FakeClock;
  /** Mutable: what the fake token endpoint returns for the next exchange. */
  tokenResponse: { body: unknown; status: number };
  /** Every form body the token endpoint received, in order. */
  tokenRequests: string[];
  publishedJwks: () => unknown;
  setJwks: (document: unknown) => void;
  signingKey: SigningKey;
  issuedSessions: { userId: string; tenantId: string; role: string }[];
  provisionedKeys: { userId: string; tenantId: string; role: string }[];
  /** Set to make `provisionGatewayApiKey` fail the way a suspended tenancy does. */
  provisionFailure: Error | null;
}

function oidcConfig(overrides: Partial<StoredSsoProviderConfig> = {}): StoredSsoProviderConfig {
  return {
    tenantId: TENANT,
    providerKind: "oidc",
    defaultRole: "member",
    groupRoleMapping: { "eng-admins": "admin" },
    oidcIssuer: ISSUER,
    oidcClientId: CLIENT_ID,
    oidcClientSecretRef: "env://OIDC_SECRET",
    oidcRedirectUri: "https://console.test/callback",
    oidcGroupClaim: "groups",
    createdAtUnix: 1,
    updatedAtUnix: 1,
    ...overrides,
  };
}

async function harness(): Promise<Harness> {
  const signingKey = await generateRs256Key("k1");
  const repo = new MemoryIdentityRepository();
  const clock = new FakeClock(1_000_000);
  let published: unknown = jwksDocument([signingKey]);
  const state: Harness = {
    repo,
    clock,
    signingKey,
    tokenResponse: { body: {}, status: 200 },
    tokenRequests: [],
    publishedJwks: () => published,
    setJwks: (document: unknown) => {
      published = document;
    },
    issuedSessions: [],
    provisionedKeys: [],
    provisionFailure: null,
    deps: undefined as unknown as OidcDeps,
  };

  const fetchLike = async (url: string, init?: RequestInit): Promise<Response> => {
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
      });
    }
    if (url === `${ISSUER}/jwks`) return Response.json(published);
    if (url === `${ISSUER}/token`) {
      state.tokenRequests.push(String(init?.body ?? ""));
      return new Response(JSON.stringify(state.tokenResponse.body), {
        status: state.tokenResponse.status,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  };

  state.deps = {
    repository: repo,
    secrets: { resolve: async (ref) => (ref === "env://OIDC_SECRET" ? "s3cr3t" : null) },
    session: {
      currentAdminSession: async () => null,
      issueSession: async (args) => {
        state.issuedSessions.push({
          userId: args.userId,
          tenantId: args.tenantId,
          role: args.role,
        });
        return { accessToken: "at", refreshToken: "rt", expiresIn: 900 };
      },
      provisionGatewayApiKey: async (args) => {
        if (state.provisionFailure) throw state.provisionFailure;
        state.provisionedKeys.push({
          userId: args.userId,
          tenantId: args.tenantId,
          role: args.role,
        });
        return "fg_live_key";
      },
      mintVirtualApiKeySecret: async () => ({
        secret: "fg_scim_secret",
        keyPrefix: "fg_scim",
        keyHash: "hash",
        last4: "cret",
      }),
    },
    clock,
    random: new CountingRandom(),
    fetch: fetchLike,
    jwks: new JwksCache({ fetch: fetchLike, clock }),
  };

  repo.ssoConfigs.set(TENANT, oidcConfig());
  repo.tenants.set(TENANT, { id: TENANT, name: "Tenant A" });
  repo.workspaces.set(TENANT, { id: "ws_1", projectId: "proj_1", tenantId: TENANT });
  return state;
}

/** Runs authorize, then returns the persisted flow so a test can forge against it. */
async function authorize(h: Harness) {
  const response = await startOidcAuthorize(h.deps, TENANT);
  expect(response.status).toBe(200);
  const body = response.body as { authorize_url: string; state: string };
  const flow = h.repo.pendingFlows.get(body.state);
  if (!flow) throw new Error("authorize did not persist a pending flow");
  return { body, url: new URL(body.authorize_url), flow };
}

async function idToken(h: Harness, overrides: Record<string, unknown> = {}, key?: SigningKey) {
  const flow = [...h.repo.pendingFlows.values()][0];
  return signJwt(key ?? h.signingKey, {
    iss: ISSUER,
    aud: CLIENT_ID,
    exp: h.clock.nowUnix() + 300,
    iat: h.clock.nowUnix(),
    nonce: flow?.nonce,
    sub: "idp-user-1",
    email: "person@example.com",
    email_verified: true,
    name: "A Person",
    groups: ["eng-admins"],
    ...overrides,
  });
}

describe("startOidcAuthorize", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
  });

  test("builds an authorize URL with state, S256 PKCE and a nonce", async () => {
    const { url, flow, body } = await authorize(h);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe("https://console.test/callback");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBe(body.state);
    expect(url.searchParams.get("nonce")).toBe(flow.nonce);

    // The challenge is the S256 of the STASHED verifier — not the verifier
    // itself, which would make PKCE decorative.
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(flow.codeVerifier ?? ""),
    );
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(url.searchParams.get("code_challenge")).toBe(expected);
    expect(url.searchParams.get("code_challenge")).not.toBe(flow.codeVerifier);
  });

  test("the state and the verifier are distinct high-entropy values", async () => {
    const { flow, body } = await authorize(h);
    expect(flow.codeVerifier).not.toBe(body.state);
    expect(flow.nonce).not.toBe(body.state);
  });

  test("the pending flow expires", async () => {
    const { flow } = await authorize(h);
    expect(flow.expiresAtUnix).toBeGreaterThan(h.clock.nowUnix());
    expect(flow.expiresAtUnix - flow.createdAtUnix).toBe(600);
  });

  test("404 when the tenant has no SSO configured", async () => {
    h.repo.ssoConfigs.delete(TENANT);
    expect((await startOidcAuthorize(h.deps, TENANT)).status).toBe(404);
  });

  test("422 when the tenant is configured for SAML, not OIDC", async () => {
    h.repo.ssoConfigs.set(TENANT, oidcConfig({ providerKind: "saml" }));
    expect((await startOidcAuthorize(h.deps, TENANT)).status).toBe(422);
  });

  test("fails closed when a required OIDC field is missing", async () => {
    h.repo.ssoConfigs.set(TENANT, oidcConfig({ oidcClientId: null }));
    expect((await startOidcAuthorize(h.deps, TENANT)).status).toBe(422);
  });

  test("does NOT persist a pending flow when discovery fails", async () => {
    h.repo.ssoConfigs.set(TENANT, oidcConfig({ oidcIssuer: "https://unreachable.test" }));
    const response = await startOidcAuthorize(h.deps, TENANT);
    expect(response.status).toBe(500);
    expect(h.repo.pendingFlows.size).toBe(0);
  });
});

describe("completeOidcCallback — the happy path", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
  });

  test("verifies, JIT-provisions and issues a session", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const response = await completeOidcCallback(h.deps, { code: "auth-code", state: body.state });
    expect(response.status).toBe(200);
    const session = response.body as { access_token: string; tenant: { role: string } };
    expect(session.access_token).toBe("at");
    // `eng-admins` maps to `admin` in the config.
    expect(session.tenant.role).toBe("admin");
    expect(h.repo.memberships).toHaveLength(1);
    expect(h.repo.memberships[0]).toMatchObject({ tenantId: TENANT, role: "admin" });
    expect(h.provisionedKeys).toEqual([
      { userId: h.repo.memberships[0]?.userId ?? "", tenantId: TENANT, role: "admin" },
    ]);
  });

  test("sends the stashed PKCE verifier to the token endpoint", async () => {
    const { body, flow } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    await completeOidcCallback(h.deps, { code: "auth-code", state: body.state });
    const form = new URLSearchParams(h.tokenRequests[0] ?? "");
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("auth-code");
    expect(form.get("code_verifier")).toBe(flow.codeVerifier);
    expect(form.get("client_secret")).toBe("s3cr3t");
    expect(form.get("redirect_uri")).toBe("https://console.test/callback");
  });

  test("an unmapped group falls back to default_role", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { groups: ["randoms"] }) },
    };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(200);
    expect(h.repo.memberships[0]?.role).toBe("member");
  });

  test("a legacy junk role in the stored config resolves to viewer, never owner", async () => {
    h.repo.ssoConfigs.set(TENANT, oidcConfig({ defaultRole: "superuser", groupRoleMapping: {} }));
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h, { groups: [] }) } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(200);
    expect(h.repo.memberships[0]?.role).toBe("viewer");
    expect(h.provisionedKeys[0]?.role).toBe("viewer");
  });

  test("never overwrites a role an owner set after the first login", async () => {
    h.repo.users.set("user_1", {
      id: "user_1",
      email: "person@example.com",
      displayName: "A Person",
      passwordHash: "!",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: null,
    });
    h.repo.memberships.push({
      id: "m1",
      userId: "user_1",
      tenantId: TENANT,
      role: "viewer",
      createdAtUnix: 1,
    });
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(200);
    // `eng-admins` → admin in the mapping, but the stored viewer role wins.
    expect(h.repo.memberships[0]?.role).toBe("viewer");
    expect(h.provisionedKeys[0]?.role).toBe("viewer");
  });
});

describe("completeOidcCallback — adversarial", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
  });

  test("REFUSES a state this service never issued (CSRF / state mismatch)", async () => {
    await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const response = await completeOidcCallback(h.deps, {
      code: "c",
      state: "attacker-chosen-state",
    });
    expect(response.status).toBe(401);
    // The code was never exchanged: the guard fired before any outbound call.
    expect(h.tokenRequests).toHaveLength(0);
  });

  test("REFUSES a REPLAYED state (single use)", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const first = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(first.status).toBe(200);
    const replay = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(replay.status).toBe(401);
  });

  test("REFUSES an expired flow", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    h.clock.advance(601);
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.tokenRequests).toHaveLength(0);
  });

  test("REFUSES an ID token minted for a DIFFERENT audience", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { aud: "some-other-client" }) },
    };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
    expect(h.repo.memberships).toHaveLength(0);
  });

  test("REFUSES an EXPIRED ID token", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { exp: h.clock.nowUnix() - 3_600 }) },
    };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("REFUSES an ID token signed by a key that is NOT in the JWKS", async () => {
    const attackerKey = await generateRs256Key("k1");
    const { body } = await authorize(h);
    // Same advertised `kid`, different private key — the classic forged token.
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h, {}, attackerKey) } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("REFUSES an ID token whose kid is not published at all", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    h.setJwks({ keys: [] });
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
  });

  test("REFUSES an ID token with no kid", async () => {
    const { body } = await authorize(h);
    const flow = [...h.repo.pendingFlows.values()][0];
    const token = await signJwt(
      h.signingKey,
      {
        iss: ISSUER,
        aud: CLIENT_ID,
        exp: h.clock.nowUnix() + 300,
        iat: h.clock.nowUnix(),
        nonce: flow?.nonce,
        sub: "s",
        email: "person@example.com",
      },
      { kid: undefined },
    );
    h.tokenResponse = { status: 200, body: { id_token: token } };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
  });

  test('REFUSES an unsigned alg:"none" ID token', async () => {
    const { body } = await authorize(h);
    const flow = [...h.repo.pendingFlows.values()][0];
    h.tokenResponse = {
      status: 200,
      body: {
        id_token: unsignedJwt({
          iss: ISSUER,
          aud: CLIENT_ID,
          exp: h.clock.nowUnix() + 300,
          iat: h.clock.nowUnix(),
          nonce: flow?.nonce,
          sub: "s",
          email: "person@example.com",
        }),
      },
    };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
  });

  test("REFUSES an ID token carrying the WRONG nonce (token injection)", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { nonce: "nonce-from-another-flow" }) },
    };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("REFUSES an ID token with NO nonce", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h, { nonce: undefined }) } };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
  });

  test("REFUSES an ID token from a different issuer", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { iss: "https://evil" }) },
    };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
  });

  test("REFUSES an email the IdP marks unverified", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = {
      status: 200,
      body: { id_token: await idToken(h, { email_verified: false }) },
    };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
    expect(h.repo.memberships).toHaveLength(0);
  });

  test("REFUSES a token with no usable email claim", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h, { email: "not-email" }) } };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(422);
  });

  test("REFUSES cross-tenant sign-in of a pre-existing account (#232 takeover guard)", async () => {
    // A victim account exists globally but is NOT a member of this tenant. A
    // tenant owner running their own IdP must not be able to assert it.
    h.repo.users.set("victim", {
      id: "victim",
      email: "person@example.com",
      displayName: "Victim",
      passwordHash: "x",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: null,
    });
    h.repo.memberships.push({
      id: "m-other",
      userId: "victim",
      tenantId: "tenant_b",
      role: "owner",
      createdAtUnix: 1,
    });
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
    expect(h.provisionedKeys).toHaveLength(0);
    // and no membership was silently grafted onto the victim
    expect(h.repo.memberships.map((m) => m.tenantId)).toEqual(["tenant_b"]);
  });

  test("REFUSES a disabled account", async () => {
    h.repo.users.set("u", {
      id: "u",
      email: "person@example.com",
      displayName: "P",
      passwordHash: "x",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: 42,
    });
    h.repo.memberships.push({
      id: "m",
      userId: "u",
      tenantId: TENANT,
      role: "member",
      createdAtUnix: 1,
    });
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    expect((await completeOidcCallback(h.deps, { code: "c", state: body.state })).status).toBe(401);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("fails closed when the token endpoint returns no id_token", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { access_token: "opaque" } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("fails closed when the token endpoint errors", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 400, body: { error: "invalid_grant" } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(h.issuedSessions).toHaveLength(0);
  });

  test("fails closed when the client secret ref does not resolve", async () => {
    h.repo.ssoConfigs.set(TENANT, oidcConfig({ oidcClientSecretRef: "env://MISSING" }));
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBe(500);
    expect(h.tokenRequests).toHaveLength(0);
  });

  test("does not issue a session when the gateway key mint is refused", async () => {
    const { body } = await authorize(h);
    h.tokenResponse = { status: 200, body: { id_token: await idToken(h) } };
    h.provisionFailure = new Error("tenancy_suspended");
    const response = await completeOidcCallback(h.deps, { code: "c", state: body.state });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(h.issuedSessions).toHaveLength(0);
  });
});
