/**
 * MOUNT GATE + fail-closed proof for provider-credential resolution through
 * `@ferrogate/secrets`.
 *
 * ## Why this file exists
 *
 * `@ferrogate/secrets` had ONE importer under any app's `src` (`apps/mcp`), so on
 * the gateway — the app that actually presents credentials to paid upstreams —
 * `api_key_var` was a raw `env[name]` string read:
 *
 *     const value = secrets[provider.api_key_var];
 *     if (typeof value !== "string" || value.trim() === "") … refuse
 *
 * An operator who wrote `api_key_var: "cf://provider-keys/openai-api-key"` (the
 * documented reference syntax, ported and tested in the package) got "which is
 * not bound" — the whole catalog refused — because the literal reference string
 * was being used as a binding NAME. And a credential bound the way Cloudflare
 * Secrets Store actually binds one (`[[secrets_store_secrets]]`, an object with
 * `await get()`) failed the `typeof === "string"` test and refused too.
 *
 * ## What "unmount" means here, and what must go red
 *
 * The mount is `src/inference/catalog.ts::boundSecret` delegating to
 * `resolveProviderSecret`. Restore the raw read above and:
 *
 *  - "an env:// reference resolves…" goes red (400 model_not_found: the string
 *    `env://OPENAI_KEY_SLOT` is not a binding name);
 *  - "a PRE-BOUND cf:// reference resolves…" goes red, likewise;
 *  - "…every refusal names the reference" goes red (the detail disappears).
 *
 * The bare-name tests below are the NEGATIVE CONTROL: they pass either way, on
 * purpose, because "the legacy form still works" is the compatibility half of
 * the same wiring and would otherwise be unstated.
 *
 * Only the outbound provider `fetch` is faked (`../inference/provider-mock.ts`).
 * The registry, adapters, dispatcher, auth guard and composition root are real:
 * every end-to-end case drives the DEFAULT EXPORT of `src/index.ts`.
 */
import { describe, expect, it } from "vitest";

import app from "../../src/index.js";
import { buildModelCatalog } from "../../src/inference/index.js";
import type { ModelRecord, ProviderRecord } from "../../src/inference/index.js";
import { providerSecretRefusal, resolveProviderSecret } from "../../src/keys/index.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";

const BASE = "https://gw.test";

/** Never a real credential; the value only has to survive the resolution. */
const KEY_FROM_ENV_REF = "sk-value-behind-an-env-reference";
const KEY_FROM_CF_BINDING = "sk-value-behind-a-cf-binding";
const KEY_FROM_BARE_NAME = "sk-value-behind-a-bare-binding-name";

const MODEL: ModelRecord = {
  name: "logical-model",
  provider: "p",
  provider_model: "physical-model",
};

function providerWith(apiKeyVar: string): ProviderRecord {
  return {
    name: "p",
    kind: "openai",
    base_url: "https://upstream.test/v1",
    api_key_var: apiKeyVar,
  };
}

// ---------------------------------------------------------------------------
// The resolver itself
// ---------------------------------------------------------------------------

describe("resolveProviderSecret: each scheme resolves from the Worker env", () => {
  it("reads a BARE binding name — the legacy api_key_var form, unchanged", () => {
    expect(
      resolveProviderSecret({ OPENAI_KEY_SLOT: KEY_FROM_BARE_NAME }, "OPENAI_KEY_SLOT"),
    ).toEqual({ ok: true, value: KEY_FROM_BARE_NAME });
  });

  it("reads env://NAME", () => {
    expect(
      resolveProviderSecret({ OPENAI_KEY_SLOT: KEY_FROM_ENV_REF }, "env://OPENAI_KEY_SLOT"),
    ).toEqual({ ok: true, value: KEY_FROM_ENV_REF });
  });

  it("reads a PRE-BOUND cf:// name through FERROGATE_CF_SECRET_<NAME>", () => {
    expect(
      resolveProviderSecret(
        { FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING },
        "cf://provider-keys/openai-api-key",
      ),
    ).toEqual({ ok: true, value: KEY_FROM_CF_BINDING });
  });

  it("ignores the cf:// STORE component — the binding is per-secret, not per-store", () => {
    // `[[secrets_store_secrets]]` binds one secret; the store is addressed at
    // deploy time. Two references differing only in store must therefore agree.
    const env = { FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING };
    expect(resolveProviderSecret(env, "cf://store-a/openai-api-key")).toEqual(
      resolveProviderSecret(env, "cf://store-b/openai-api-key"),
    );
  });

  it("trims the operator's text before reading it", () => {
    expect(
      resolveProviderSecret({ OPENAI_KEY_SLOT: KEY_FROM_ENV_REF }, "  env://OPENAI_KEY_SLOT  "),
    ).toEqual({ ok: true, value: KEY_FROM_ENV_REF });
  });
});

describe("resolveProviderSecret FAILS CLOSED — never an empty credential", () => {
  /**
   * The single assertion that matters most in this file. An empty string is a
   * well-formed `Authorization` header, so a resolver that degraded instead of
   * refusing would send unauthenticated traffic to a paid upstream forever.
   */
  function expectRefused(resolution: ReturnType<typeof resolveProviderSecret>): string | undefined {
    expect(resolution.ok).toBe(false);
    expect(resolution).not.toHaveProperty("value");
    return resolution.ok ? undefined : resolution.detail;
  }

  it("an unset bare name is refused, not empty", () => {
    expectRefused(resolveProviderSecret({}, "MISSING"));
  });

  it("an unset env:// target is refused, not empty", () => {
    expectRefused(resolveProviderSecret({}, "env://MISSING"));
  });

  it("a whitespace-only binding is UNSET, not a credential", () => {
    expectRefused(resolveProviderSecret({ BLANK: "   " }, "env://BLANK"));
  });

  it("an unbound cf:// name is refused — there is no REST read of a value", () => {
    const detail = expectRefused(resolveProviderSecret({}, "cf://provider-keys/openai-api-key"));
    // No detail is fine here (it is the plain "unset" case), but if one is
    // given it must never claim a REST fallback exists.
    expect(detail ?? "").not.toMatch(/fetch(ed)? from the API/i);
  });

  it("an EMPTY reference is refused rather than read as a binding named ''", () => {
    expect(expectRefused(resolveProviderSecret({ "": "x" }, "   "))).toContain("empty");
  });

  it("a MALFORMED reference is refused, not silently re-read as a bare name", () => {
    // `env:/NAME` (one slash) is a typo. Falling back to `env["env:/NAME"]`
    // would report a misconfiguration as a merely-unbound binding.
    const detail = expectRefused(resolveProviderSecret({ "env:/NAME": "x" }, "env:/NAME"));
    expect(detail).toBeDefined();
  });

  it("an UNSUPPORTED scheme is refused and names the schemes that exist", () => {
    const detail = expectRefused(resolveProviderSecret({}, "aws-sm://prod/openai"));
    expect(detail).toContain("env://");
  });

  it("a NON-CANONICAL cf:// name is refused because its variable is shared", () => {
    // `OpenAI.API_Key` and `openai-api-key` both map to
    // FERROGATE_CF_SECRET_OPENAI_API_KEY. Serving the bound value would hand
    // back a credential the operator did not name.
    const detail = expectRefused(
      resolveProviderSecret(
        { FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING },
        "cf://provider-keys/OpenAI.API_Key",
      ),
    );
    expect(detail).toContain("not canonical");
    expect(detail).not.toContain(KEY_FROM_CF_BINDING);
  });

  it("a KV/D1/R2 binding named as a secret is refused, not stringified", () => {
    // Without the guard this reaches `.trim()` on an object and either throws a
    // bare TypeError or, at a call site that formats first, puts the literal
    // text `[object Object]` into an Authorization header.
    const detail = expectRefused(
      resolveProviderSecret(
        { SOME_KV: { get: () => undefined, put: () => undefined, list: () => undefined } },
        "env://SOME_KV",
      ),
    );
    expect(detail).toContain("not a secret");
  });
});

/**
 * PORT-TODO pins — the two limits `src/keys/provider-secrets.ts` KEEPS.
 *
 * These assert the REFUSAL, not the feature. If either limit is ever closed
 * (by making `ModelResolverFactory` async), these tests fail loudly and demand
 * to be rewritten as success cases — which is the point of pinning them.
 */
describe("the limits that remain are refusals, not wrong answers", () => {
  it("a [[secrets_store_secrets]] slot cannot be awaited here, and says so", () => {
    // The exact shape workerd binds: an object whose plaintext needs `get()`.
    const slot = { get: (): Promise<string> => Promise.resolve(KEY_FROM_CF_BINDING) };
    const resolution = resolveProviderSecret(
      { FERROGATE_CF_SECRET_OPENAI_API_KEY: slot },
      "cf://provider-keys/openai-api-key",
    );
    expect(resolution.ok).toBe(false);
    expect(resolution.ok === false && resolution.detail).toMatch(/asynchronously/);
    // And the value it could not read never leaked into the diagnostic.
    expect(JSON.stringify(resolution)).not.toContain(KEY_FROM_CF_BINDING);
  });

  it("the same slot bound as a plain STRING is the closest behavior that DOES work", () => {
    expect(
      resolveProviderSecret(
        { FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING },
        "cf://provider-keys/openai-api-key",
      ),
    ).toEqual({ ok: true, value: KEY_FROM_CF_BINDING });
  });

  it("vault:// is refused on this synchronous seam, naming the reason", () => {
    const resolution = resolveProviderSecret(
      { VAULT_ADDR: "https://vault.test", VAULT_TOKEN: "t" },
      "vault://secret/data/openai#api_key",
    );
    expect(resolution.ok).toBe(false);
    expect(resolution.ok === false && resolution.detail).toMatch(/synchronous/);
  });
});

describe("providerSecretRefusal never renders a credential", () => {
  it("carries the field, the reference and the detail — and nothing else", () => {
    const message = providerSecretRefusal("p", "api_key_var", "env://MISSING", {
      ok: false,
      detail: "because",
    });
    expect(message).toBe("provider p names api_key_var env://MISSING, which is not bound: because");
  });

  it("keeps the bare wording when there is no more specific reason", () => {
    expect(providerSecretRefusal("p", "api_key_var", "MISSING", { ok: false })).toBe(
      "provider p names api_key_var MISSING, which is not bound",
    );
  });
});

// ---------------------------------------------------------------------------
// THE MOUNT — the catalog resolves references, or the catalog is refused
// ---------------------------------------------------------------------------

describe("buildModelCatalog resolves api_key_var THROUGH the resolver", () => {
  it("an env:// reference reaches the route's apiKey", () => {
    const result = buildModelCatalog([providerWith("env://OPENAI_KEY_SLOT")], [MODEL], {
      OPENAI_KEY_SLOT: KEY_FROM_ENV_REF,
    });
    expect(result.ok).toBe(true);
    expect(result.ok && result.routes[0]?.apiKey).toBe(KEY_FROM_ENV_REF);
  });

  it("a pre-bound cf:// reference reaches the route's apiKey", () => {
    const result = buildModelCatalog([providerWith("cf://provider-keys/openai-api-key")], [MODEL], {
      FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING,
    });
    expect(result.ok).toBe(true);
    expect(result.ok && result.routes[0]?.apiKey).toBe(KEY_FROM_CF_BINDING);
  });

  it("an unresolvable reference refuses the WHOLE catalog with no route built", () => {
    const result = buildModelCatalog(
      [providerWith("cf://provider-keys/openai-api-key")],
      [MODEL],
      {},
    );
    expect(result.ok).toBe(false);
    // No partially-built route survives a refusal.
    expect(result).not.toHaveProperty("routes");
  });

  it("the refusal names the reference AND the specific reason", () => {
    const result = buildModelCatalog(
      [providerWith("vault://secret/data/openai#api_key")],
      [MODEL],
      {},
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("api_key_var vault://secret/data/openai#api_key");
    expect(result.reason).toMatch(/synchronous/);
  });

  it("the Bedrock composite halves resolve through the same seam", () => {
    const result = buildModelCatalog(
      [
        {
          name: "p",
          kind: "bedrock",
          base_url: "https://bedrock.test",
          aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key_var: "cf://provider-keys/aws-secret-access-key",
          region: "us-east-1",
        },
      ],
      [MODEL],
      { FERROGATE_CF_SECRET_AWS_SECRET_ACCESS_KEY: "aws-secret-value" },
    );
    expect(result.ok).toBe(true);
    expect(result.ok && result.routes[0]?.awsCredentials?.secretAccessKey).toBe("aws-secret-value");
  });

  it("the Vertex token resolves through the same seam", () => {
    const result = buildModelCatalog(
      [
        {
          name: "p",
          kind: "vertex",
          base_url: "https://us-central1-aiplatform.googleapis.com",
          gcp_project_id: "ferrogate-prod",
          gcp_access_token_var: "env://GCP_TOKEN_SLOT",
          region: "us-central1",
        },
      ],
      [MODEL],
      { GCP_TOKEN_SLOT: "ya29.TOKEN" },
    );
    expect(result.ok).toBe(true);
    expect(result.ok && result.routes[0]?.gcpCredentials?.accessToken).toBe("ya29.TOKEN");
  });
});

// ---------------------------------------------------------------------------
// End to end, through the composition root the Worker exports
// ---------------------------------------------------------------------------

function envWith(apiKeyVar: string, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    GATEWAY_PROVIDERS: JSON.stringify([providerWith(apiKeyVar)]),
    GATEWAY_MODELS: JSON.stringify([MODEL]),
    GATEWAY_STATIC_API_KEYS: JSON.stringify([
      { key: "fg_root", id: "key_root", platform_operator: true },
    ]),
    ...extra,
  };
}

async function chat(env: Record<string, unknown>): Promise<Response> {
  return await app.request(
    `${BASE}/v1/chat/completions`,
    {
      method: "POST",
      headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
      body: JSON.stringify({ model: "logical-model", messages: [{ role: "user", content: "hi" }] }),
    },
    env,
  );
}

const UPSTREAM_OK = {
  id: "chatcmpl-1",
  object: "chat.completion",
  model: "physical-model",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

describe("the deployed Worker presents a REFERENCE-resolved credential upstream", () => {
  it("env://SLOT — the resolved value is the Authorization the provider sees", async () => {
    const provider = interceptProviderFetch(() => providerJson(UPSTREAM_OK));
    try {
      const res = await chat(
        envWith("env://OPENAI_KEY_SLOT", { OPENAI_KEY_SLOT: KEY_FROM_ENV_REF }),
      );
      expect(res.status).toBe(200);
      // Nothing on this path can produce the string below except the resolver:
      // the literal `env://OPENAI_KEY_SLOT` is not a binding name.
      expect(provider.lastRequest().headers.authorization).toBe(`Bearer ${KEY_FROM_ENV_REF}`);
    } finally {
      provider.restore();
    }
  });

  it("cf://store/name — a PRE-BOUND Secrets Store name resolves end to end", async () => {
    const provider = interceptProviderFetch(() => providerJson(UPSTREAM_OK));
    try {
      const res = await chat(
        envWith("cf://provider-keys/openai-api-key", {
          FERROGATE_CF_SECRET_OPENAI_API_KEY: KEY_FROM_CF_BINDING,
        }),
      );
      expect(res.status).toBe(200);
      expect(provider.lastRequest().headers.authorization).toBe(`Bearer ${KEY_FROM_CF_BINDING}`);
    } finally {
      provider.restore();
    }
  });

  it("NEGATIVE CONTROL: the legacy bare binding name still works", async () => {
    const provider = interceptProviderFetch(() => providerJson(UPSTREAM_OK));
    try {
      const res = await chat(envWith("OPENAI_KEY_SLOT", { OPENAI_KEY_SLOT: KEY_FROM_BARE_NAME }));
      expect(res.status).toBe(200);
      expect(provider.lastRequest().headers.authorization).toBe(`Bearer ${KEY_FROM_BARE_NAME}`);
    } finally {
      provider.restore();
    }
  });

  it("an UNRESOLVABLE reference dispatches NOTHING — no unauthenticated upstream call", async () => {
    const provider = interceptProviderFetch(() => providerJson(UPSTREAM_OK));
    try {
      const res = await chat(envWith("cf://provider-keys/openai-api-key", {}));
      // The catalog is refused whole, so the logical model does not exist.
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
        "model_not_found",
      );
      // THE point: the gateway did not fall back to an empty credential.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("a Secrets Store OBJECT binding also dispatches nothing, rather than [object Object]", async () => {
    const provider = interceptProviderFetch(() => providerJson(UPSTREAM_OK));
    try {
      const res = await chat(
        envWith("cf://provider-keys/openai-api-key", {
          FERROGATE_CF_SECRET_OPENAI_API_KEY: {
            get: (): Promise<string> => Promise.resolve(KEY_FROM_CF_BINDING),
          },
        }),
      );
      expect(res.status).toBe(400);
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});
