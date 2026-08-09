/**
 * MOUNT GATE — `resolvePorts` binds `@ferrogate/secrets`, not a stub.
 *
 * ## Why this file exists
 *
 * `apps/mcp/src/ports.ts` used to bind
 *
 *     secrets: { resolve: async () => undefined }
 *
 * in EVERY posture, including the durable one. `@ferrogate/secrets` — three
 * backends (`env://`, `vault://`, `cf://`), 79 tests — had zero importers in
 * any app. The observable consequence on a deployed Worker: a `per_user_oauth`
 * upstream carrying a `client_secret_ref` could never complete a token
 * exchange, because `resolveClientSecret` saw `undefined` and answered
 * `503 mcp_identity_secret_unavailable` every time. The whole suite stayed
 * green because `test/identity.test.ts` installs its own fake through
 * `setSecretResolver`, so nothing ever asked the production seam to resolve
 * anything.
 *
 * Every test below therefore deliberately does NOT call `setSecretResolver`,
 * and drives the real Worker over `SELF`. Remove the
 * `secrets: secretResolverOverride ?? workerSecretResolver(env)` binding in
 * `resolvePorts` and each one goes red with a 503.
 *
 * The negative control is the last describe block: a reference naming nothing
 * bound must still fail. "Not 503" only means something because "503" is
 * reachable.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  type McpEnv,
  type OauthProviderPort,
  type OidcDiscovery,
  resolvePorts,
} from "../src/ports.js";
import { setOauthProvider } from "../src/ports.js";
import { EXEC_KEY, type Fixture, USER, seedFixture, upstreamConfig } from "./fixtures.js";

const DISCOVERY: OidcDiscovery = {
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksUri: "https://idp.test/jwks",
};

/**
 * Write an OPERATOR-NAMED secret slot onto the Worker `env`.
 *
 * Deliberately not routed through `setMcpEnvVar`: these names are chosen by the
 * operator in a `secret_ref`, so they are not — and must not become — fields of
 * `McpEnv`. Widening `McpEnv` with an index signature to accommodate them would
 * turn every typo in a REAL binding name into a silently-typed `undefined`.
 */
function setEnvSlot(name: string, value: unknown): void {
  (env as unknown as Record<string, unknown>)[name] = value;
}

function clearEnvSlot(name: string): void {
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
  delete (env as unknown as Record<string, unknown>)[name];
}

/** Records the `clientSecret` the OAuth exchange was handed. */
interface RecordingProvider extends OauthProviderPort {
  exchangedClientSecret: string | undefined;
}

function recordingProvider(): RecordingProvider {
  const provider: RecordingProvider = {
    exchangedClientSecret: undefined,
    discover: async () => DISCOVERY,
    exchangeAuthorizationCode: async (_discovery, _oauth, params) => {
      provider.exchangedClientSecret = params.clientSecret;
      return {
        accessToken: "upstream-access-token",
        refreshToken: "upstream-refresh-token",
        tokenType: "Bearer",
        expiresIn: 3600,
        idToken: "fake.id.token",
      };
    },
    refresh: async () => ({ accessToken: "refreshed", tokenType: "Bearer", expiresIn: 3600 }),
    validateIdToken: async () => USER,
    revoke: async () => true,
  };
  return provider;
}

let fixture: Fixture;
let provider: RecordingProvider;
const touchedSlots = new Set<string>();

function bindSlot(name: string, value: unknown): void {
  touchedSlots.add(name);
  setEnvSlot(name, value);
}

/** Register `srv` as a per-user-OAuth upstream carrying `clientSecretRef`. */
function registerOauthUpstream(clientSecretRef: string | undefined): void {
  fixture.ports.upstreams.register(
    upstreamConfig({
      authType: "per_user_oauth",
      oauth: {
        issuer: "https://idp.test",
        clientId: "ferrogate-client",
        ...(clientSecretRef === undefined ? {} : { clientSecretRef }),
        redirectUri: "https://gateway.test/v1/mcp/identity/callback",
        scopes: ["openid"],
      },
    }),
    [{ name: "echo", input_schema: { type: "object" } }],
    // eslint-disable-next-line @typescript-eslint/require-await
    async () => ({ content: { content: [] }, isError: false }),
  );
}

/** Run authorize → callback and return the callback response. */
async function runOauthExchange(): Promise<Response> {
  const authorized = await SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/identity/srv/authorize", {
      method: "POST",
      headers: { authorization: `Bearer ${EXEC_KEY}` },
    }),
  );
  expect(authorized.status).toBe(200);
  const { state } = (await authorized.json()) as { state: string };
  return SELF.fetch(
    `https://ferrogate.test/v1/mcp/identity/callback?code=auth-code&state=${encodeURIComponent(state)}`,
  );
}

beforeEach(() => {
  fixture = seedFixture();
  provider = recordingProvider();
  setOauthProvider(provider);
  // NOTE: `setSecretResolver` is intentionally NOT called anywhere in this file.
});

afterEach(() => {
  for (const name of touchedSlots) clearEnvSlot(name);
  touchedSlots.clear();
});

describe("resolvePorts binds the real @ferrogate/secrets registry", () => {
  it("resolves env:// from the Worker's own env, end to end over SELF", async () => {
    bindSlot("MCP_OAUTH_CLIENT_SECRET", "sk-from-worker-env");
    registerOauthUpstream("env://MCP_OAUTH_CLIENT_SECRET");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(200);
    // The exact value had to travel: env slot → SecretResolverRegistry →
    // McpPorts.secrets → resolveClientSecret → the token exchange.
    expect(provider.exchangedClientSecret).toBe("sk-from-worker-env");
  });

  it("resolves cf:// through the FERROGATE_CF_SECRET_<NAME> convention", async () => {
    bindSlot("FERROGATE_CF_SECRET_MCP_CLIENT_SECRET", "sk-from-cf-binding");
    registerOauthUpstream("cf://provider-keys/mcp-client-secret");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(200);
    expect(provider.exchangedClientSecret).toBe("sk-from-cf-binding");
  });

  it("resolves a [[secrets_store_secrets]] binding by awaiting get()", async () => {
    // The slot is an OBJECT, exactly as workerd presents `SecretsStoreSecret`.
    // Nothing on this path can produce the string below except the
    // `await slot.get()` read in `@ferrogate/secrets`.
    bindSlot("FERROGATE_CF_SECRET_MCP_STORE_SECRET", {
      get: () => Promise.resolve("sk-from-secrets-store"),
    });
    registerOauthUpstream("cf://provider-keys/mcp-store-secret");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(200);
    expect(provider.exchangedClientSecret).toBe("sk-from-secrets-store");
  });

  it("the port bound by resolvePorts IS the registry, not the placeholder", async () => {
    // A direct assertion on the production composition function, so the mount
    // is pinned even if the OAuth surface is later restructured.
    bindSlot("MCP_DIRECT_PROBE_SECRET", "sk-direct");
    const ports = resolvePorts({ ...(env as unknown as McpEnv) });
    await expect(ports.secrets.resolve("env://MCP_DIRECT_PROBE_SECRET")).resolves.toBe("sk-direct");
  });
});

describe("the seam still fails closed — the negative control", () => {
  it("an unbound reference is 503 mcp_identity_secret_unavailable", async () => {
    registerOauthUpstream("env://MCP_SECRET_THAT_IS_NOT_BOUND");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(503);
    const body = (await callback.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe("mcp_identity_secret_unavailable");
    // The exchange must not have happened with an empty or guessed secret.
    expect(provider.exchangedClientSecret).toBeUndefined();
  });

  it("an ambiguous cf:// name is REFUSED, and the reason survives to the client", async () => {
    // The lossy-name guard in `@ferrogate/secrets` throws rather than serve a
    // credential the operator did not name. That throw must arrive as a typed
    // 503 carrying the resolver's diagnostic, not as a bare 500.
    bindSlot("FERROGATE_CF_SECRET_MCP_CLIENT_SECRET", "sk-shared-across-names");
    registerOauthUpstream("cf://provider-keys/MCP.Client_Secret");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(503);
    const body = (await callback.json()) as { error?: { code?: string; message?: string } };
    expect(body.error?.code).toBe("mcp_identity_secret_unavailable");
    expect(body.error?.message).toMatch(/not canonical/);
    // And the credential it would have collided with never left the Worker.
    expect(body.error?.message).not.toContain("sk-shared-across-names");
    expect(provider.exchangedClientSecret).toBeUndefined();
  });

  it("a PUBLIC client (no client_secret_ref) still exchanges, with no secret", async () => {
    // The mount must not turn a legitimately secret-less public OAuth client
    // into a 503 — otherwise "everything 503s" would satisfy the tests above
    // for the wrong reason.
    registerOauthUpstream(undefined);

    const callback = await runOauthExchange();

    expect(callback.status).toBe(200);
    expect(provider.exchangedClientSecret).toBe("");
  });

  it("a blank client_secret_ref is a MALFORMED reference, not a public client", async () => {
    // `""` is configured-but-empty. Treating it as "no secret" would let a
    // truncated config silently downgrade a confidential client to a public
    // one, so the reference parser refuses it and the reason is carried.
    registerOauthUpstream("");

    const callback = await runOauthExchange();

    expect(callback.status).toBe(503);
    const body = (await callback.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe("mcp_identity_secret_unavailable");
    expect(provider.exchangedClientSecret).toBeUndefined();
  });
});
