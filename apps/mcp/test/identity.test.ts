/**
 * `SELF` integration tests for the four per-user MCP identity operations.
 *
 * The security properties under test are the ones the Rust
 * `state_mcp_identity.rs` fails closed on:
 *  - the callback is ANONYMOUS, so its authorization is carried entirely by a
 *    single-use, time-bounded `state` plus the OIDC subject binding;
 *  - the provider's `sub` MUST equal the FerroGate user that started the flow;
 *  - a revoked identity stops being dispatchable even if the upstream
 *    revocation endpoint fails;
 *  - dispatch NEVER falls back to an unauthenticated upstream call.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  setOauthProvider,
  setSecretResolver,
  type OauthProviderPort,
  type OidcDiscovery,
} from "../src/ports.js";
import {
  EXEC_KEY,
  READ_KEY,
  rpcRequest,
  seedFixture,
  upstreamConfig,
  USER,
  type Fixture,
} from "./fixtures.js";

const DISCOVERY: OidcDiscovery = {
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksUri: "https://idp.test/jwks",
  revocationEndpoint: "https://idp.test/revoke",
};

interface FakeProvider extends OauthProviderPort {
  subject: string;
  revokeSucceeds: boolean;
  revoked: string[];
}

function fakeProvider(): FakeProvider {
  const provider: FakeProvider = {
    subject: USER,
    revokeSucceeds: true,
    revoked: [],
    discover: async () => DISCOVERY,
    exchangeAuthorizationCode: async () => ({
      accessToken: "upstream-access-token",
      refreshToken: "upstream-refresh-token",
      tokenType: "Bearer",
      expiresIn: 3600,
      scope: "read write",
      idToken: "fake.id.token",
    }),
    refresh: async () => ({
      accessToken: "refreshed-access-token",
      tokenType: "Bearer",
      expiresIn: 3600,
    }),
    validateIdToken: async () => provider.subject,
    revoke: async (_discovery, _oauth, token) => {
      provider.revoked.push(token);
      return provider.revokeSucceeds;
    },
  };
  return provider;
}

let fixture: Fixture;
let provider: FakeProvider;

beforeEach(() => {
  fixture = seedFixture();
  provider = fakeProvider();
  setOauthProvider(provider);
  setSecretResolver({ resolve: async () => "client-secret" });
  // Re-register `srv` as a per-user-OAuth upstream.
  fixture.ports.upstreams.register(
    upstreamConfig({
      authType: "per_user_oauth",
      oauth: {
        issuer: "https://idp.test",
        clientId: "ferrogate-client",
        clientSecretRef: "env://MCP_OAUTH_SECRET",
        redirectUri: "https://gateway.test/v1/mcp/identity/callback",
        scopes: ["openid", "profile"],
      },
    }),
    [{ name: "echo", input_schema: { type: "object" } }],
    // eslint-disable-next-line @typescript-eslint/require-await
    async (tool, args, identity, context) => {
      fixture.calls.push({ tool, args, identity, context });
      return { content: { content: [] }, isError: false };
    },
  );
});

async function authorize(key = EXEC_KEY): Promise<Response> {
  return SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/identity/srv/authorize", {
      method: "POST",
      headers: { authorization: `Bearer ${key}` },
    }),
  );
}

async function connect(): Promise<{ state: string }> {
  const started = (await (await authorize()).json()) as { state: string };
  const callback = await SELF.fetch(
    `https://ferrogate.test/v1/mcp/identity/callback?code=auth-code&state=${encodeURIComponent(started.state)}`,
  );
  expect(callback.status).toBe(200);
  return started;
}

describe("POST /v1/mcp/identity/{server}/authorize", () => {
  it("mints a PKCE S256 authorization URL and an opaque state", async () => {
    const res = await authorize();
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      authorize_url: string;
      state: string;
      expires_at_unix: number;
    };
    expect(body.object).toBe("mcp_oauth_authorization");
    const url = new URL(body.authorize_url);
    expect(url.origin + url.pathname).toBe("https://idp.test/authorize");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.get("state")).toBe(body.state);
    expect(url.searchParams.get("nonce")).toBeTruthy();
    // The PKCE verifier itself must NEVER appear in the redirect.
    expect(url.searchParams.get("code_verifier")).toBeNull();
    expect(body.expires_at_unix).toBeGreaterThan(0);
  });

  it("requires tools.execute", async () => {
    expect((await authorize(READ_KEY)).status).toBe(403);
  });

  it("audits the authorization with the operation's target", async () => {
    await authorize();
    const row = fixture.ports.audit
      .events()
      .find((event) => event.action === "mcp.identity.authorize");
    expect(row?.target).toBe("mcp:srv/identity");
    expect(row?.outcome).toBe("created");
  });

  it("404s an unknown server", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/nope/authorize", {
        method: "POST",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_identity_not_found",
    );
  });
});

describe("GET /v1/mcp/identity/callback", () => {
  it("completes the flow anonymously and records the connect audit", async () => {
    await connect();
    const row = fixture.ports.audit
      .events()
      .find((event) => event.action === "mcp.identity.connect");
    expect(row?.outcome).toBe("connected");
    expect(row?.target).toBe(`mcp:srv/subject:${USER}`);
  });

  it("requires both code and state", async () => {
    const res = await SELF.fetch("https://ferrogate.test/v1/mcp/identity/callback?code=only");
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_oauth_callback_invalid",
    );
  });

  it("refuses a replayed state — the flow is single use", async () => {
    const { state } = await connect();
    const replay = await SELF.fetch(
      `https://ferrogate.test/v1/mcp/identity/callback?code=auth-code&state=${encodeURIComponent(state)}`,
    );
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_oauth_state_invalid",
    );
  });

  it("refuses an unknown state", async () => {
    const res = await SELF.fetch(
      "https://ferrogate.test/v1/mcp/identity/callback?code=c&state=never-issued",
    );
    expect(res.status).toBe(401);
  });

  it("refuses a provider subject that is not the user who started the flow", async () => {
    const started = (await (await authorize()).json()) as { state: string };
    provider.subject = "someone-else";
    const res = await SELF.fetch(
      `https://ferrogate.test/v1/mcp/identity/callback?code=c&state=${encodeURIComponent(started.state)}`,
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_identity_subject_mismatch",
    );
  });

  it("refuses the commit when the actor's authorization changed mid-flow", async () => {
    const started = (await (await authorize()).json()) as { state: string };
    fixture.ports.credentials.bumpGeneration(
      { tenantId: "tenant-1", workspaceId: "ws-1", userId: USER },
      "srv",
    );
    const res = await SELF.fetch(
      `https://ferrogate.test/v1/mcp/identity/callback?code=c&state=${encodeURIComponent(started.state)}`,
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_oauth_authorization_changed",
    );
  });

  it("rejects a non-GET method", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/callback", { method: "POST" }),
    );
    expect(res.status).toBe(405);
  });
});

describe("GET /v1/mcp/identity/{server}", () => {
  it("reports a disconnected identity before any flow", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        headers: { authorization: `Bearer ${READ_KEY}` },
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { connected: boolean; subject: string | null };
    expect(body.connected).toBe(false);
    expect(body.subject).toBeNull();
  });

  it("reports a connected identity after the callback", async () => {
    await connect();
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        headers: { authorization: `Bearer ${READ_KEY}` },
      }),
    );
    const body = (await res.json()) as {
      connected: boolean;
      subject: string;
      auth_type: string;
      expires_at_unix: number;
    };
    expect(body.connected).toBe(true);
    expect(body.subject).toBe(USER);
    expect(body.auth_type).toBe("per_user_oauth");
    expect(body.expires_at_unix).toBeGreaterThan(0);
  });

  it("requires tools.read", async () => {
    fixture.ports.auth.register("fg_scopeless", {
      apiKeyId: "k",
      organizationId: "tenant-1",
      workspaceId: "ws-1",
      userId: USER,
      scopes: [],
      permissions: [],
      platformOperator: false,
    });
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        headers: { authorization: "Bearer fg_scopeless" },
      }),
    );
    expect(res.status).toBe(403);
  });
});

describe("DELETE /v1/mcp/identity/{server}", () => {
  it("revokes locally and best-effort upstream", async () => {
    await connect();
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        method: "DELETE",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      connected: boolean;
      revoked_at_unix: number;
      last_revocation_outcome: string;
    };
    expect(body.connected).toBe(false);
    expect(body.revoked_at_unix).toBeGreaterThan(0);
    expect(body.last_revocation_outcome).toBe("upstream_revoked");
    // The refresh token is what gets revoked upstream when present.
    expect(provider.revoked).toEqual(["upstream-refresh-token"]);
    expect(fixture.ports.metrics.identityRevocations).toBe(1);
  });

  it("still revokes locally when the upstream revocation fails", async () => {
    await connect();
    provider.revokeSucceeds = false;
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        method: "DELETE",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    const body = (await res.json()) as { connected: boolean; last_revocation_outcome: string };
    expect(body.connected).toBe(false);
    expect(body.last_revocation_outcome).toBe("upstream_revocation_failed");
  });

  it("404s when nothing is connected", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        method: "DELETE",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    expect(res.status).toBe(404);
  });
});

describe("dispatch-time identity resolution fails closed", () => {
  it("refuses tools/call when no per-user identity is connected", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.message).toMatch(/not connected/);
    // The upstream is never called without an identity.
    expect(fixture.calls).toHaveLength(0);
  });

  it("dispatches the resolved grant as a redacting Authorization header", async () => {
    await connect();
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
    const identity = fixture.calls[0]?.identity;
    expect(identity?.entries()).toEqual([["Authorization", "Bearer upstream-access-token"]]);
    // A stray log line must never spill the token.
    expect(String(identity)).not.toContain("upstream-access-token");
    expect(String(identity)).toContain("<redacted>");
    expect(JSON.stringify(identity)).not.toContain("upstream-access-token");
  });

  it("refuses to dispatch a revoked grant", async () => {
    await connect();
    await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv", {
        method: "DELETE",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    expect(((await res.json()) as { error: { message: string } }).error.message).toMatch(
      /not connected/,
    );
    expect(fixture.calls).toHaveLength(0);
  });
});
