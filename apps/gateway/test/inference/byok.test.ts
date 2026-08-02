import {
  BYOK_MASTER_KEY_ENV,
  type SealedTenantCredential,
  type TenantCredentialStore,
  byokKeyringFromEnv,
  generateByokMasterKey,
  sealTenantCredential,
} from "@ferrogate/secrets";
/**
 * Per-tenant BYOK on the request path (issue #682).
 *
 * The assertion that matters is the LAST one a request makes: what ends up in
 * the outbound `Authorization` header. Everything else — the store, the
 * envelope, the alias grammar — is machinery in service of that, and a test that
 * stopped at "the resolver returned the right string" would not catch a wiring
 * mistake that never reached the adapter. So every case here drives the real
 * router, the real catalog and the real dispatch path, and reads the header off
 * the intercepted outbound call.
 *
 * The one that would be a shipped security defect if it regressed:
 * **tenant B sending tenant A's alias must never be signed with tenant A's key.**
 */
import { afterEach, describe, expect, it } from "vitest";
import type { ByokPorts } from "../../src/inference/byok.js";
import type { InferenceDeps, PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness, tenantCaller } from "./fixtures.js";
import { interceptProviderFetch } from "./provider-mock.js";

const MASTER_KEY = generateByokMasterKey();
const KEYRING = byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: MASTER_KEY });

const PLATFORM_KEY = "sk-platform-owned";

/** One provider, one model, carrying FerroGate's OWN credential by default. */
const ROUTE: PhysicalRoute = {
  logicalModel: "gpt-4o-mini",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1/",
  apiKey: PLATFORM_KEY,
  enabled: true,
};

/** The same provider row, but declaring a per-ROUTE BYOK default. */
const ROUTE_WITH_ALIAS: PhysicalRoute = { ...ROUTE, byokAlias: "openai-enterprise" };

/** A second provider, so a credential can be shown NOT to cross providers. */
const ANTHROPIC_ROUTE: PhysicalRoute = {
  logicalModel: "claude-logical",
  provider: "anthropic-main",
  providerModel: "claude-3-5-sonnet-20241022",
  providerKind: "anthropic",
  baseUrl: "https://api.anthropic.example/v1",
  apiKey: "sk-platform-anthropic",
  enabled: true,
};

class MapStore implements TenantCredentialStore {
  private readonly rows = new Map<string, SealedTenantCredential>();

  async put(tenantId: string, alias: string, provider: string, value: string): Promise<void> {
    this.rows.set(
      `${tenantId} ${alias}`,
      await sealTenantCredential(KEYRING, { tenantId, alias, provider, value }),
    );
  }

  async lookup(tenantId: string, alias: string): Promise<SealedTenantCredential | null> {
    return this.rows.get(`${tenantId} ${alias}`) ?? null;
  }
}

function ports(store: TenantCredentialStore): ByokPorts {
  return { store, keyring: async () => KEYRING };
}

const CHAT_BODY = {
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "hi" }],
};

/** A canned OpenAI chat completion, enough for the handler to finish. */
function openAiOk(): Response {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-1",
      object: "chat.completion",
      created: 1,
      model: "gpt-4o-mini-2024-07-18",
      choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

let interceptor: ReturnType<typeof interceptProviderFetch> | null = null;

afterEach(() => {
  interceptor?.restore();
  interceptor = null;
});

async function dispatch(
  deps: InferenceDeps,
  routes: readonly PhysicalRoute[],
  headers: Record<string, string> = {},
): Promise<{ response: Response; authorization: string | undefined }> {
  interceptor = interceptProviderFetch(() => openAiOk());
  const app = harness(deps, routes);
  const response = await app.post("/v1/chat/completions", CHAT_BODY, { headers });
  const authorization =
    interceptor.requests.length === 0
      ? undefined
      : interceptor.lastRequest().headers["authorization"];
  return { response, authorization };
}

describe("per-request alias selection", () => {
  it("signs with the TENANT's key, not the platform's", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: ports(store) },
      [ROUTE],
      { "x-ferrogate-byok-alias": "openai-enterprise" },
    );

    expect(response.status).toBe(200);
    expect(authorization).toBe("Bearer sk-acme-negotiated");
  });

  it("accepts the Cloudflare AI Gateway spelling of the header", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    const { authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: ports(store) },
      [ROUTE],
      { "cf-aig-byok-alias": "openai-enterprise" },
    );

    expect(authorization).toBe("Bearer sk-acme-negotiated");
  });

  it("THE FENCE: tenant B sending tenant A's alias is refused, never signed with A's key", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_b"), byok: ports(store) },
      [ROUTE],
      { "x-ferrogate-byok-alias": "openai-enterprise" },
    );

    expect(response.status).toBe(403);
    expect((await errorBody(response)).error.code).toBe("byok_alias_not_found");
    // The decisive assertion: NOTHING was dispatched, so tenant A's credential
    // cannot have been put on a wire under tenant B's request.
    expect(authorization).toBeUndefined();
  });

  it("FAILS CLOSED: an unknown alias never falls back to the platform credential", async () => {
    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: ports(new MapStore()) },
      [ROUTE],
      { "x-ferrogate-byok-alias": "not-registered" },
    );

    expect(response.status).toBe(403);
    // If this were `Bearer sk-platform-owned`, FerroGate would be paying for
    // traffic the tenant believes is on its own agreement — the whole point.
    expect(authorization).toBeUndefined();
  });

  it("a credential registered for one provider is not presented to another", async () => {
    const store = new MapStore();
    // Registered for `openai-main`; the request routes to `anthropic-main`.
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    interceptor = interceptProviderFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "msg_1",
            type: "message",
            role: "assistant",
            model: "claude-3-5-sonnet-20241022",
            content: [{ type: "text", text: "ok" }],
            stop_reason: "end_turn",
            usage: { input_tokens: 1, output_tokens: 1 },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    const app = harness({ caller: tenantCaller("tenant_a"), byok: ports(store) }, [
      ANTHROPIC_ROUTE,
    ]);
    const response = await app.post(
      "/v1/chat/completions",
      { model: "claude-logical", messages: [{ role: "user", content: "hi" }] },
      { headers: { "x-ferrogate-byok-alias": "openai-enterprise" } },
    );

    expect(response.status).toBe(200);
    const headers = interceptor.lastRequest().headers;
    // The Anthropic route keeps NO credential (it was BYOK-selected but the
    // alias belongs to another provider) — it is emphatically not signed with
    // the OpenAI key, and not with Anthropic's platform key either.
    expect(headers["x-api-key"]).toBeUndefined();
    expect(JSON.stringify(headers)).not.toContain("sk-acme-negotiated");
  });

  it("a malformed alias header is a 400, not a silent fall-through", async () => {
    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: ports(new MapStore()) },
      [ROUTE],
      { "x-ferrogate-byok-alias": "../other-tenant/openai" },
    );

    expect(response.status).toBe(400);
    expect((await errorBody(response)).error.code).toBe("invalid_byok_alias");
    expect(authorization).toBeUndefined();
  });
});

describe("per-route alias selection", () => {
  it("uses the provider row's byok_alias with no header at all", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: ports(store) },
      [ROUTE_WITH_ALIAS],
    );

    expect(response.status).toBe(200);
    expect(authorization).toBe("Bearer sk-acme-negotiated");
  });

  it("serves EACH tenant its own key from the one shared route", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-key-of-a");
    await store.put("tenant_b", "openai-enterprise", "openai-main", "sk-key-of-b");

    const a = await dispatch({ caller: tenantCaller("tenant_a"), byok: ports(store) }, [
      ROUTE_WITH_ALIAS,
    ]);
    expect(a.authorization).toBe("Bearer sk-key-of-a");

    const b = await dispatch({ caller: tenantCaller("tenant_b"), byok: ports(store) }, [
      ROUTE_WITH_ALIAS,
    ]);
    expect(b.authorization).toBe("Bearer sk-key-of-b");
  });

  it("a route-level alias the tenant has not registered dispatches with NO credential", async () => {
    const { authorization } = await dispatch(
      { caller: tenantCaller("tenant_c"), byok: ports(new MapStore()) },
      [ROUTE_WITH_ALIAS],
    );

    // Loudly wrong (the provider will 401) rather than quietly expensive.
    expect(authorization).toBeUndefined();
  });
});

describe("rotation", () => {
  it("a rotated credential takes effect on the NEXT request, with no deploy", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-old");

    const before = await dispatch({ caller: tenantCaller("tenant_a"), byok: ports(store) }, [
      ROUTE_WITH_ALIAS,
    ]);
    expect(before.authorization).toBe("Bearer sk-old");

    // The entire rotation: one row write. No binding, no wrangler.toml, no
    // redeploy, no isolate restart.
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-new");

    const after = await dispatch({ caller: tenantCaller("tenant_a"), byok: ports(store) }, [
      ROUTE_WITH_ALIAS,
    ]);
    expect(after.authorization).toBe("Bearer sk-new");
  });
});

describe("deployments that have not enabled BYOK", () => {
  it("are byte-for-byte unchanged when no alias is selected", async () => {
    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: null },
      [ROUTE],
    );

    expect(response.status).toBe(200);
    expect(authorization).toBe(`Bearer ${PLATFORM_KEY}`);
  });

  it("refuse a request that explicitly asks for an alias", async () => {
    const { response, authorization } = await dispatch(
      { caller: tenantCaller("tenant_a"), byok: null },
      [ROUTE],
      { "x-ferrogate-byok-alias": "openai-enterprise" },
    );

    expect(response.status).toBe(503);
    expect((await errorBody(response)).error.code).toBe("byok_not_configured");
    expect(authorization).toBeUndefined();
  });

  it("refuse a platform-operator credential asking for an alias — it has no tenant scope", async () => {
    const store = new MapStore();
    await store.put("tenant_a", "openai-enterprise", "openai-main", "sk-acme-negotiated");

    const { response, authorization } = await dispatch(
      // The default caller in `harness` is a platform operator.
      { byok: ports(store) },
      [ROUTE],
      { "x-ferrogate-byok-alias": "openai-enterprise" },
    );

    expect(response.status).toBe(403);
    expect((await errorBody(response)).error.code).toBe("byok_not_available");
    expect(authorization).toBeUndefined();
  });
});
