/**
 * Model DISCOVERY: `GET /v1/models` metadata and `GET /v1/models/{model}`
 * (issue #670).
 *
 * ## The two defects this suite pins
 *
 *  1. **Nothing on the wire described a model.** The listing answered the bare
 *     OpenAI quartet (`id`/`object`/`created`/`owned_by`), so a client could not
 *     tell whether a logical model does vision, tools, streaming or 200k of
 *     context, nor what a token costs — even though `[[models]]` carries all
 *     four and `catalog.ts` already parses them onto `PhysicalRoute`. The only
 *     way to find out was to read operator config a tenant has no access to.
 *  2. **The listing was not scoped to the credential's `allowed_models`.**
 *     `handleModels` filtered on tenancy (`scopeCanSeeModel`, issue #515) but
 *     never on `callerCanUseModel`, so a key restricted to one model listed the
 *     whole catalog and could enumerate logical names it gets a 403 on. The
 *     invocation gate and the discovery gate have to agree for exactly the
 *     reason #515 gave: a filter that disagrees with the gate is an oracle.
 *
 * Everything below drives `createInferenceRouter` with the SHIPPED
 * `InMemoryModelResolver`, over a catalog that declares real capabilities,
 * context windows and prices — the fixtures in `./fixtures.ts` are deliberately
 * capability-NEUTRAL (declaring capabilities there would change the eligibility
 * gate for every other suite), so this file carries its own.
 */
import { describe, expect, it } from "vitest";
import {
  InMemoryModelResolver,
  callerFromAuth,
  createInferenceRouter,
} from "../../src/inference/index.js";
import type { Caller, PhysicalRoute } from "../../src/inference/index.js";
import type { AuthContext } from "../../src/ports.js";
import { errorBody, fixedRequestIds } from "./fixtures.js";

/** The primary leg of `vision-chat`: the one that serves and the one priced. */
const VISION_PRIMARY: PhysicalRoute = {
  logicalModel: "vision-chat",
  provider: "anthropic-main",
  providerModel: "claude-3-5-sonnet-20241022",
  providerKind: "anthropic",
  baseUrl: "https://api.anthropic.example/v1",
  apiKey: "sk-test",
  enabled: true,
  ownedBy: "anthropic",
  capabilities: ["chat", "streaming", "tools", "vision"],
  contextWindow: 200_000,
  inputPricePer1m: 3,
  outputPricePer1m: 15,
  priority: 0,
  weight: 1,
};

/**
 * A FALLBACK leg of the same logical model: cheaper, smaller, and the only leg
 * that declares `structured_output`. It is what makes the aggregation
 * observable — a describe-the-primary-only implementation reports neither the
 * extra capability nor the larger window.
 */
const VISION_FALLBACK: PhysicalRoute = {
  ...VISION_PRIMARY,
  provider: "openai-main",
  providerModel: "gpt-4o",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  capabilities: ["chat", "structured_output"],
  contextWindow: 128_000,
  inputPricePer1m: 2.5,
  outputPricePer1m: 10,
  priority: 100,
  weight: 1,
};

const EMBED: PhysicalRoute = {
  logicalModel: "embed-only",
  provider: "openai-main",
  providerModel: "text-embedding-3-small",
  providerKind: "openai-compatible",
  baseUrl: "https://api.openai.example/v1",
  enabled: true,
  capabilities: ["embeddings"],
  contextWindow: 8_192,
  inputPricePer1m: 0.02,
  outputPricePer1m: 0,
};

/** Declares `images` and NO price — the unpriced case must stay distinguishable. */
const IMAGE: PhysicalRoute = {
  logicalModel: "image-gen",
  provider: "openai-main",
  providerModel: "dall-e-3",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  enabled: true,
  capabilities: ["images"],
};

/** The legacy capability-NEUTRAL row: no declaration at all. */
const LEGACY: PhysicalRoute = {
  logicalModel: "legacy-undeclared",
  provider: "openai-main",
  providerModel: "gpt-3.5-turbo",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  enabled: true,
};

const PRIVATE: PhysicalRoute = { ...LEGACY, logicalModel: "acme-private", tenantId: "acme" };
const DISABLED: PhysicalRoute = { ...LEGACY, logicalModel: "retired-model", enabled: false };

const CATALOG: readonly PhysicalRoute[] = [
  VISION_PRIMARY,
  VISION_FALLBACK,
  EMBED,
  IMAGE,
  LEGACY,
  PRIVATE,
  DISABLED,
];

interface ModelBody {
  id: string;
  object: string;
  created: number;
  owned_by: string;
  capabilities: string[];
  context_window: number | null;
  modalities: { input: string[]; output: string[] };
  pricing: { currency: string; unit: string; input: number | null; output: number | null };
}

function router(caller?: () => Caller) {
  return createInferenceRouter({
    models: new InMemoryModelResolver(CATALOG),
    requestIds: fixedRequestIds,
    ...(caller === undefined ? {} : { caller }),
  });
}

async function get(path: string, caller?: () => Caller): Promise<Response> {
  return await router(caller).request(`https://gw.test${path}`, { method: "GET" });
}

async function listing(caller?: () => Caller): Promise<ModelBody[]> {
  const res = await get("/v1/models", caller);
  expect(res.status).toBe(200);
  return ((await res.json()) as { data: ModelBody[] }).data;
}

async function one(model: string, caller?: () => Caller): Promise<ModelBody> {
  const res = await get(`/v1/models/${model}`, caller);
  expect(res.status).toBe(200);
  return (await res.json()) as ModelBody;
}

/** The `AuthContext` `keys/resolver.ts::toAuthContext` builds for a durable key. */
function durableKey(allowedModels: readonly string[]): AuthContext {
  return {
    subject: "key_1",
    tenancy: { tenantId: null },
    scopes: [],
    platformOperator: true,
    source: "durable_native",
    allowedModels,
  };
}

// ---------------------------------------------------------------------------
// 1. The listing describes each model
// ---------------------------------------------------------------------------

describe("GET /v1/models carries capabilities, context, modality and price", () => {
  it("describes a vision+tools model from its declared config", async () => {
    const model = (await listing()).find((entry) => entry.id === "vision-chat");
    expect(model).toBeDefined();
    expect(model?.capabilities).toEqual([
      "chat",
      "streaming",
      "vision",
      "tools",
      "structured_output",
    ]);
    expect(model?.context_window).toBe(200_000);
    expect(model?.modalities).toEqual({ input: ["text", "image"], output: ["text"] });
    expect(model?.pricing).toEqual({
      currency: "USD",
      unit: "per_1m_tokens",
      input: 3,
      output: 15,
    });
  });

  it("keeps the OpenAI quartet exactly as it was", async () => {
    const model = (await listing()).find((entry) => entry.id === "vision-chat");
    expect(model?.object).toBe("model");
    expect(model?.created).toBe(0);
    // `owned_by` still echoes `owned_by` / the provider name, unchanged.
    expect(model?.owned_by).toBe("anthropic");
  });

  it("reports an embeddings model's output modality as embedding, not text", async () => {
    const model = (await listing()).find((entry) => entry.id === "embed-only");
    expect(model?.capabilities).toEqual(["embeddings"]);
    expect(model?.modalities).toEqual({ input: ["text"], output: ["embedding"] });
    // A genuinely FREE completion price (0) is not the same as unpriced.
    expect(model?.pricing.input).toBe(0.02);
    expect(model?.pricing.output).toBe(0);
  });

  it("reports an image model's output modality as image", async () => {
    const model = (await listing()).find((entry) => entry.id === "image-gen");
    expect(model?.modalities).toEqual({ input: ["text"], output: ["image"] });
  });

  it("says UNPRICED with null rather than pretending a model is free", async () => {
    const model = (await listing()).find((entry) => entry.id === "image-gen");
    expect(model?.pricing.input).toBeNull();
    expect(model?.pricing.output).toBeNull();
    expect(model?.context_window).toBeNull();
  });

  it("describes a capability-neutral legacy row as plain text chat", async () => {
    // `docs/model-route-capabilities.md`: an empty declaration stays eligible
    // only for a chat-style request with no extra feature — so text→text is the
    // honest answer, and the empty `capabilities` array says it is undeclared.
    const model = (await listing()).find((entry) => entry.id === "legacy-undeclared");
    expect(model?.capabilities).toEqual([]);
    expect(model?.modalities).toEqual({ input: ["text"], output: ["text"] });
  });

  it("still omits disabled models", async () => {
    expect((await listing()).map((entry) => entry.id)).not.toContain("retired-model");
  });
});

// ---------------------------------------------------------------------------
// 2. GET /v1/models/{model}
// ---------------------------------------------------------------------------

describe("GET /v1/models/{model}", () => {
  it("returns the single model object, identical to its listing entry", async () => {
    const fromList = (await listing()).find((entry) => entry.id === "vision-chat");
    expect(await one("vision-chat")).toEqual(fromList);
  });

  it("carries the gateway response headers", async () => {
    const res = await get("/v1/models/vision-chat");
    expect(res.headers.get("x-request-id")).toBe("fg-000000000000002a");
    expect(res.headers.get("x-ferrogate-runtime")).toBe("workers");
  });

  it("404s an unknown model", async () => {
    const res = await get("/v1/models/no-such-model");
    expect(res.status).toBe(404);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });

  it("404s a DISABLED model, exactly as the listing hides it", async () => {
    const res = await get("/v1/models/retired-model");
    expect(res.status).toBe(404);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });
});

// ---------------------------------------------------------------------------
// 3. Tenant scoping — discovery must agree with the invocation gate
// ---------------------------------------------------------------------------

const OTHER_TENANT = (): Caller => ({ scope: { kind: "tenant", tenantId: "globex" } });
const OWNING_TENANT = (): Caller => ({ scope: { kind: "tenant", tenantId: "acme" } });

describe("another tenant's private model is undiscoverable", () => {
  it("is absent from the listing", async () => {
    const ids = (await listing(OTHER_TENANT)).map((entry) => entry.id);
    expect(ids).not.toContain("acme-private");
    expect(ids).toContain("vision-chat");
  });

  it("404s on the single-model read", async () => {
    const res = await get("/v1/models/acme-private", OTHER_TENANT);
    expect(res.status).toBe(404);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });

  it("is visible to the owning tenant — the control", async () => {
    expect((await listing(OWNING_TENANT)).map((entry) => entry.id)).toContain("acme-private");
    expect((await one("acme-private", OWNING_TENANT)).id).toBe("acme-private");
  });
});

// ---------------------------------------------------------------------------
// 4. The key's allowed_models — a key must not discover what it cannot call
// ---------------------------------------------------------------------------

const RESTRICTED = (): Caller => callerFromAuth(durableKey(["vision-chat"]));
const DENYING = (): Caller => ({
  scope: { kind: "platform_operator" },
  deniedModels: ["vision-chat"],
});

describe("discovery is scoped to the credential's allowed_models", () => {
  it("lists ONLY the models the key may call", async () => {
    // The whole chain: `AuthContext.allowedModels` -> `callerFromAuth` ->
    // the listing filter. Every model below IS in the catalog and IS visible to
    // this (platform-operator) scope; only the allowlist keeps them out.
    expect((await listing(RESTRICTED)).map((entry) => entry.id)).toEqual(["vision-chat"]);
  });

  it("404s a model outside the allowlist instead of describing it", async () => {
    const res = await get("/v1/models/embed-only", RESTRICTED);
    expect(res.status).toBe(404);
    // The SAME answer as a model that does not exist: no existence oracle.
    expect((await errorBody(res)).error.code).toBe("model_not_found");
    expect((await errorBody(await get("/v1/models/no-such-model", RESTRICTED))).error.code).toBe(
      "model_not_found",
    );
  });

  it("still serves the model INSIDE the allowlist — the control", async () => {
    expect((await one("vision-chat", RESTRICTED)).id).toBe("vision-chat");
  });

  it("honours a DENYlist too (deny wins over any allowlist)", async () => {
    const ids = (await listing(DENYING)).map((entry) => entry.id);
    expect(ids).not.toContain("vision-chat");
    expect(ids).toContain("embed-only");
    expect((await get("/v1/models/vision-chat", DENYING)).status).toBe(404);
  });

  it("a credential with NO allowlist sees everything — fail-open, correctly", async () => {
    // An empty/absent `allowed_models` means "no allowlist" in Rust; reading it
    // as "may use nothing" would empty the catalog for every static, dev and
    // external credential, none of which carries the column.
    // The default caller is a platform operator, so `acme-private` is in reach
    // of the tenancy filter too — this is the widest answer the surface gives.
    const ids = (await listing()).map((entry) => entry.id);
    expect(ids).toEqual([
      "vision-chat",
      "embed-only",
      "image-gen",
      "legacy-undeclared",
      "acme-private",
    ]);
  });
});
