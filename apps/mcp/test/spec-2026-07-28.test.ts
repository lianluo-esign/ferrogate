/**
 * Conformance with the FINAL MCP `2026-07-28` specification (#686).
 *
 * The tree shipped the *candidate*. `src/protocol.ts` said so in its own header
 * ("a candidate contract under validation, not a final-conformance claim"), and
 * four behaviours diverge from what was published on 2026-07-28. Each `it` below
 * names the change it pins, quoting the changelog clause, so a future revision
 * can be diffed against this file rather than against prose.
 *
 * Deliberately NOT covered here (see the PR body): `subscriptions/listen`, the
 * Tasks / MCP Apps extensions, and MRTR's client half are unimplemented, and
 * this file pins that they are unimplemented *honestly* — refused or
 * unadvertised — rather than half-served.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { parseCallResult, parseToolsList } from "../src/jsonrpc.js";
import {
  completeModernResult,
  MCP_METHOD_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_HEADER,
  modernRequestMeta,
  SERVER_INFO_META,
} from "../src/protocol.js";
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

// ---------------------------------------------------------------------------
// SEP-2322 — Multi Round-Trip Requests
// ---------------------------------------------------------------------------

describe("MRTR: an interim result is never mistaken for a tool result (SEP-2322)", () => {
  /**
   * Changelog major change 7/8: a server that needs more information answers
   * `resultType: "input_required"` with `inputRequests`, and the client is
   * expected to RETRY the original request carrying `inputResponses`.
   * FerroGate implements no client half of MRTR, so the only correct behaviour
   * is a loud refusal. Returning the interim envelope as the tool's output
   * would hand an agent a protocol control message as if it were data.
   */
  it("refuses an input_required tools/call result instead of returning it as content", () => {
    expect(() =>
      parseCallResult({
        jsonrpc: "2.0",
        id: 1,
        result: {
          resultType: "input_required",
          inputRequests: [{ method: "elicitation/create", params: { message: "which repo?" } }],
        },
      }),
    ).toThrow(/input_required/);
  });

  it("refuses an input_required tools/list result", () => {
    expect(() =>
      parseToolsList({
        jsonrpc: "2.0",
        id: 1,
        result: { resultType: "input_required", inputRequests: [] },
      }),
    ).toThrow(/input_required/);
  });

  /**
   * Changelog major change 8, second sentence: "Clients MUST treat results from
   * earlier-protocol servers that omit the field as `complete`." The dual-era
   * fallback depends on this — a `2025-06-18` upstream never sends `resultType`.
   */
  it("treats a result with no resultType as complete (earlier-protocol servers)", () => {
    const parsed = parseCallResult({
      jsonrpc: "2.0",
      id: 1,
      result: { content: [{ type: "text", text: "hi" }] },
    });
    expect(parsed.isError).toBe(false);
    expect(parsed.content).toMatchObject({ content: [{ type: "text", text: "hi" }] });
  });

  it("accepts an explicit complete result", () => {
    expect(
      parseToolsList({
        jsonrpc: "2.0",
        id: 1,
        result: { resultType: "complete", tools: [{ name: "echo", inputSchema: {} }] },
      }),
    ).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Server identity + capability advertisement
// ---------------------------------------------------------------------------

function modernHeaders(method: string, key: string): Record<string, string> {
  return {
    [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION,
    [MCP_METHOD_HEADER]: method,
    authorization: `Bearer ${key}`,
  };
}

describe("stateless server identity and capabilities", () => {
  beforeEach(() => {
    seedFixture();
  });

  /**
   * Changelog major change 2: "servers SHOULD identify themselves in each
   * result's `_meta` (`io.modelcontextprotocol/serverInfo`)". With the
   * `initialize` handshake gone there is no other moment at which a client can
   * learn who answered, so a result without it is unattributable.
   */
  it("stamps serverInfo into every modern result's _meta, not just server/discover", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: modernRequestMeta() } },
        { headers: modernHeaders("tools/list", READ_KEY) },
      ),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { _meta?: Record<string, unknown>; resultType?: string };
    };
    expect(body.result.resultType).toBe("complete");
    expect(body.result._meta?.[SERVER_INFO_META]).toMatchObject({
      name: expect.any(String) as unknown as string,
      version: expect.any(String) as unknown as string,
    });
  });

  /**
   * The multiplex ambiguity report (#687) lives on the SAME `_meta` object.
   * Stamping serverInfo must MERGE into it — replacing it would silently drop
   * the collision report that `test/multiplex-wire.test.ts` depends on.
   */
  it("merges serverInfo into an existing result _meta rather than replacing it", () => {
    const result: Record<string, unknown> = {
      tools: [],
      _meta: { "ferrogate/ambiguousTools": [{ name: "a-b", servers: ["a", "a-b"] }] },
    };
    completeModernResult(result as never, "tools/list");
    expect(result["_meta"]).toMatchObject({
      "ferrogate/ambiguousTools": [{ name: "a-b", servers: ["a", "a-b"] }],
    });
    expect((result["_meta"] as Record<string, unknown>)[SERVER_INFO_META]).toBeDefined();
  });

  /**
   * Changelog minor change 1: "Add `extensions` field to `ClientCapabilities`
   * and `ServerCapabilities`". FerroGate implements NO extension, so the
   * conformant advertisement is an EMPTY map — that tells a client the field is
   * understood and that nothing (Tasks, MCP Apps, Skills) may be assumed.
   */
  it("advertises an empty extensions map on server/discover", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "server/discover",
          params: { _meta: modernRequestMeta() },
        },
        { headers: modernHeaders("server/discover", READ_KEY) },
      ),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { capabilities: Record<string, unknown>; supportedVersions: string[] };
    };
    expect(body.result.capabilities["extensions"]).toEqual({});
    // The dual-era promise: an older client still sees its revision offered.
    expect(body.result.supportedVersions).toContain("2025-11-25");
    expect(body.result.supportedVersions).toContain("2025-06-18");
    expect(body.result.supportedVersions[0]).toBe(MCP_PROTOCOL_VERSION);
  });
});

// ---------------------------------------------------------------------------
// Authorization SEPs
// ---------------------------------------------------------------------------

const ISSUER = "https://idp.test";
const DISCOVERY: OidcDiscovery = {
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksUri: "https://idp.test/jwks",
  revocationEndpoint: "https://idp.test/revoke",
};

interface CountingProvider extends OauthProviderPort {
  exchanges: number;
}

function countingProvider(): CountingProvider {
  const provider: CountingProvider = {
    exchanges: 0,
    discover: async () => DISCOVERY,
    exchangeAuthorizationCode: async () => {
      provider.exchanges += 1;
      return {
        accessToken: "upstream-access-token",
        refreshToken: "upstream-refresh-token",
        tokenType: "Bearer",
        expiresIn: 3600,
        scope: "read",
        idToken: "fake.id.token",
      };
    },
    refresh: async () => ({
      accessToken: "refreshed-access-token",
      tokenType: "Bearer",
      expiresIn: 3600,
    }),
    validateIdToken: async () => USER,
    revoke: async () => true,
  };
  return provider;
}

function perUserOauthUpstream(issuer: string, fixture: Fixture): void {
  fixture.ports.upstreams.register(
    upstreamConfig({
      authType: "per_user_oauth",
      oauth: {
        issuer,
        clientId: "ferrogate-client",
        clientSecretRef: "env://MCP_OAUTH_SECRET",
        redirectUri: "https://gateway.test/v1/mcp/identity/callback",
        scopes: ["openid"],
      },
    }),
    [{ name: "echo", input_schema: { type: "object" } }],
    // eslint-disable-next-line @typescript-eslint/require-await
    async (tool, args, identity, context) => {
      fixture.calls.push({ tool, args, identity, context });
      return { content: { content: [] }, isError: false };
    },
  );
}

describe("authorization hardening", () => {
  let fixture: Fixture;
  let provider: CountingProvider;

  beforeEach(() => {
    fixture = seedFixture();
    provider = countingProvider();
    setOauthProvider(provider);
    setSecretResolver({ resolve: async () => "client-secret" });
    perUserOauthUpstream(ISSUER, fixture);
  });

  async function startFlow(): Promise<string> {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/identity/srv/authorize", {
        method: "POST",
        headers: { authorization: `Bearer ${EXEC_KEY}` },
      }),
    );
    expect(res.status).toBe(200);
    return ((await res.json()) as { state: string }).state;
  }

  function callback(state: string, extra = ""): Promise<Response> {
    return SELF.fetch(
      `https://ferrogate.test/v1/mcp/identity/callback?code=auth-code&state=${encodeURIComponent(state)}${extra}`,
    );
  }

  /**
   * SEP-2468 / RFC 9207: "MCP clients MUST validate a present `iss` against the
   * recorded issuer BEFORE redeeming the authorization code." This is the
   * authorization-server mix-up defence: an attacker who can steer the redirect
   * gets FerroGate to redeem an honest AS's code at their own token endpoint.
   * The assertion that matters is `provider.exchanges === 0` — refusing after
   * the exchange would already have burned the code at the wrong server.
   */
  it("refuses a callback whose iss is not the recorded issuer, before redeeming the code", async () => {
    const state = await startFlow();
    const res = await callback(state, `&iss=${encodeURIComponent("https://evil.test")}`);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_oauth_issuer_mismatch",
    );
    expect(provider.exchanges).toBe(0);
  });

  it("accepts a callback whose iss matches the recorded issuer", async () => {
    const state = await startFlow();
    const res = await callback(state, `&iss=${encodeURIComponent(ISSUER)}`);
    expect(res.status).toBe(200);
    expect(provider.exchanges).toBe(1);
  });

  /**
   * RFC 9207 §2.4 / SEP-2468 say a *present* `iss` must be validated. An AS that
   * predates RFC 9207 omits it, and the dual-era promise covers authorization
   * servers too, so an omitted `iss` must still complete.
   */
  it("still completes when the authorization server sends no iss at all", async () => {
    const state = await startFlow();
    expect((await callback(state)).status).toBe(200);
    expect(provider.exchanges).toBe(1);
  });

  /**
   * SEP-2352: "clients MUST key persisted credentials by the issuer identifier,
   * MUST NOT reuse them with a different authorization server, and MUST
   * re-register when the authorization server changes." FerroGate already
   * PERSISTS `issuer` on the credential; nothing read it back, so repointing an
   * upstream at a new AS silently replayed the old AS's access token to the new
   * one.
   */
  it("refuses to dispatch a credential minted by a different authorization server", async () => {
    expect((await callback(await startFlow())).status).toBe(200);
    // The operator repoints `srv` at a different authorization server.
    perUserOauthUpstream("https://other-idp.test", fixture);

    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toMatch(/authorization server/i);
    // Fail CLOSED: the stale grant never reaches the new upstream.
    expect(fixture.calls).toHaveLength(0);
  });

  it("keeps dispatching while the issuer is unchanged", async () => {
    expect((await callback(await startFlow())).status).toBe(200);
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
  });
});
