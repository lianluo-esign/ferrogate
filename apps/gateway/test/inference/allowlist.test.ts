/**
 * ANTI-UNMOUNT: the per-key model ALLOWLIST reaches the 403 gate.
 *
 * ## Why this is its own suite
 *
 * `keys/store.ts` reads `allowed_models_json` off the `api_keys` row,
 * `keys/resolver.ts::toAuthContext` puts it on `AuthContext.allowedModels`, and
 * `ports.ts::callerCanUseModel` implements the Rust `can_use_model` predicate
 * with unit tests on both legs. All three were green while
 * `identity.ts::callerFromAuth` dropped the field on the floor — so a key with
 * `allowed_models = ["fast-chat"]` could call every model in the catalog, and
 * nothing in the suite noticed. That is the two-hop version of the defect this
 * wave exists to remove: no single file is wrong, the CHAIN is broken.
 *
 * The gates here span the whole chain and are named:
 *
 *  - "refuses a model outside the credential's allowlist" — red if
 *    `callerFromAuth` stops forwarding `allowedModels`, and red if
 *    `planUpstream` stops calling `callerCanUseModel`.
 *  - "admits a model INSIDE the allowlist" — the control: without it, a
 *    `callerFromAuth` that returned `allowedModels: []` for everything would
 *    also pass the refusal test by refusing nothing… and a `callerFromAuth`
 *    that returned a bogus non-empty list would pass by refusing everything.
 *  - "a credential with no allowlist is unrestricted" — fail-OPEN in the
 *    correct direction: a static/dev/external credential has no such column and
 *    must not read as "may use nothing".
 */
import { describe, expect, it } from "vitest";
import {
  InMemoryModelResolver,
  callerCanUseModel,
  callerFromAuth,
  createInferenceRouter,
} from "../../src/inference/index.js";
import type { Caller, PhysicalRoute } from "../../src/inference/index.js";
import type { AuthContext } from "../../src/ports.js";
import { errorBody, fixedRequestIds } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const ROUTES: readonly PhysicalRoute[] = ["fast-chat", "smart-chat"].map((logicalModel) => ({
  logicalModel,
  provider: "p",
  providerModel: "m",
  providerKind: "openai",
  baseUrl: "https://p.test/v1",
  apiKey: "sk-test",
  enabled: true,
}));

/** The `AuthContext` `keys/resolver.ts::toAuthContext` builds for a durable key. */
function durableKey(allowedModels?: readonly string[]): AuthContext {
  return {
    subject: "key_1",
    tenancy: { tenantId: "acme" },
    scopes: [],
    platformOperator: false,
    source: "durable_native",
    ...(allowedModels === undefined ? {} : { allowedModels }),
  };
}

async function chat(auth: AuthContext, model: string): Promise<Response> {
  const router = createInferenceRouter({
    models: new InMemoryModelResolver(ROUTES),
    requestIds: fixedRequestIds,
    caller: (): Caller => callerFromAuth(auth),
  });
  return await router.request("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "hi" }] }),
  });
}

describe("callerFromAuth carries the credential's model allowlist", () => {
  it("copies a NON-EMPTY allowlist onto the caller", () => {
    expect(callerFromAuth(durableKey(["fast-chat"])).allowedModels).toEqual(["fast-chat"]);
  });

  it("omits an EMPTY allowlist rather than forwarding it", () => {
    // Rust reads an empty `allowed_models` as "no allowlist"; forwarding `[]`
    // would rely on `callerCanUseModel` making the same reading twice. Belt and
    // braces, in the fail-open direction the Rust semantics demand.
    expect(callerFromAuth(durableKey([])).allowedModels).toBeUndefined();
    expect(callerFromAuth(durableKey()).allowedModels).toBeUndefined();
  });

  it("still carries the scope and api-key id it always did", () => {
    const caller = callerFromAuth(durableKey(["fast-chat"]));
    expect(caller.scope).toEqual({ kind: "tenant", tenantId: "acme" });
    expect(caller.apiKeyId).toBe("key_1");
  });

  it("implements the Rust can_use_model predicate on both legs", () => {
    // `!denied.contains(m) && (allowed.is_empty() || allowed.contains(m))`.
    const restricted: Caller = {
      scope: { kind: "tenant", tenantId: "acme" },
      allowedModels: ["fast-chat"],
    };
    expect(callerCanUseModel(restricted, "fast-chat")).toBe(true);
    expect(callerCanUseModel(restricted, "smart-chat")).toBe(false);
    // Deny wins even over an allowlist that names the model.
    expect(
      callerCanUseModel(
        { ...restricted, deniedModels: ["fast-chat"] },
        "fast-chat",
      ),
    ).toBe(false);
  });
});

describe("the allowlist reaches the 403 on the request path", () => {
  it("refuses a model outside the credential's allowlist — MOUNT GATE", async () => {
    // `interceptProviderFetch` throws on any outbound call, so a dispatch would
    // fail this test rather than pass it quietly.
    const provider = interceptProviderFetch(() => undefined);
    try {
      const res = await chat(durableKey(["fast-chat"]), "smart-chat");
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("model_not_allowed");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("admits a model INSIDE the allowlist — the control", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "m",
        choices: [
          { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
        ],
      }),
    );
    try {
      const res = await chat(durableKey(["fast-chat"]), "fast-chat");
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("leaves a credential with NO allowlist unrestricted", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-2",
        object: "chat.completion",
        model: "m",
        choices: [
          { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
        ],
      }),
    );
    try {
      const res = await chat(durableKey(), "smart-chat");
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });
});
