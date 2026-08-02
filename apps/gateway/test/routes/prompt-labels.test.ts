/**
 * Prompt deployment labels RESOLVED AT THE EDGE, and prompt-by-reference on the
 * inference path.
 *
 * ## Why every case here goes through `SELF.fetch`
 *
 * The claim is "the pointer is resolved at the edge", so the unit under test is
 * the deployed Worker with its real KV binding — not a factory a test calls.
 * A resolver that exists but is never reached by `src/worker.ts` would pass a
 * unit test and serve the wrong prompt in production.
 *
 * ## The two properties, and why each assertion is not vacuous
 *
 * **The label must actually decide the revision.** `tpl_greeting` has an ACTIVE
 * revision 2 and an older revision 1, and the fixtures point `production` at
 * REVISION 1. So a handler that ignored the label and rendered "the active
 * version" would return revision 2's text and every case below would fail. The
 * assertion is on the rendered CONTENT, which only revision 1 can produce.
 *
 * **A missing label must fail loudly.** The cases assert a 404 with a specific
 * code, and — the part that matters — that the response is not a rendered
 * prompt at all. "Unknown label ⇒ empty system prompt" is a failure nobody sees
 * until the output quality or the bill moves, so it is pinned as an explicit
 * refusal rather than left to inference from a 200 body.
 *
 * **The fence.** Tenant B labels the SAME template id with the SAME label name
 * at a different revision. Tenant A's request must be unaffected, and a tenant
 * with no pointer of its own must get the loud refusal even while another
 * tenant's pointer exists under the same name.
 */
import { promptLabelPointerKey } from "@ferrogate/config";
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resetSharedApiKeyCache } from "../../src/keys/index.js";
import { resetApiKeysTable, seedApiKey, testSecret } from "../keys/seed.js";

const BASE = "https://ferrogate.test";

const PROVIDERS = [
  { name: "primary", kind: "openai", base_url: "https://api.primary.example/v1" },
];

const MODELS = [{ name: "prompt-model", provider: "primary", provider_model: "physical-1" }];

/**
 * Revision 1 and revision 2 render DIFFERENT text, and revision 2 is the active
 * one. That asymmetry is what makes "the label chose the revision" provable.
 */
const TEMPLATES = [
  {
    id: "tpl_greeting",
    name: "Greeting",
    status: "active",
    target: "chat_completions",
    model: "prompt-model",
    variables: [{ name: "who", required: true }],
    versions: [
      {
        revision: 1,
        status: "active",
        messages: [{ role: "system", content: "revision one, {{who}}" }],
      },
      {
        revision: 2,
        status: "active",
        messages: [{ role: "system", content: "revision two, {{who}}" }],
      },
      { revision: 3, status: "draft", messages: [{ role: "system", content: "draft {{who}}" }] },
    ],
  },
];

const OVERRIDES: Record<string, unknown> = {
  GATEWAY_PROMPT_TEMPLATES: JSON.stringify(TEMPLATES),
  GATEWAY_PROVIDERS: JSON.stringify(PROVIDERS),
  GATEWAY_MODELS: JSON.stringify(MODELS),
};

const mutable = env as unknown as Record<string, unknown>;
const ORIGINAL: Record<string, unknown> = {};

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

interface ErrorEnvelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

function kv(): KVNamespace {
  const namespace = (env as { PROMPT_LABELS?: KVNamespace }).PROMPT_LABELS;
  if (namespace === undefined) {
    throw new Error(
      "no KV binding `PROMPT_LABELS` — add [[kv_namespaces]] to apps/gateway/wrangler.toml",
    );
  }
  return namespace;
}

/** Write a pointer the way `apps/control-plane` writes it. */
async function label(
  tenantId: string | null,
  templateId: string,
  name: string,
  revision: number,
): Promise<void> {
  await kv().put(
    promptLabelPointerKey({ tenantId, templateId, label: name }),
    JSON.stringify({
      tenant_id: tenantId,
      template_id: templateId,
      label: name,
      revision,
      updated_at_unix: 1_700_000_000,
      updated_by: null,
    }),
  );
}

async function clearLabels(): Promise<void> {
  const namespace = kv();
  const listed = await namespace.list({ prefix: "prompt-label/" });
  for (const key of listed.keys) await namespace.delete(key.name);
}

const TENANT_A = "tenant_a";
/**
 * NOT `tenant_b`: `vitest.config.ts` pins `TENANCY_LIFECYCLE` with `tenant_b`
 * SUSPENDED, so a credential there is refused by the lifecycle gate long before
 * any label is read — which would make the fence cases pass for the wrong
 * reason. This tenant is healthy, so a cross-tenant refusal below can only come
 * from the label fence itself.
 */
const TENANT_B = "tenant_other";
let secretA = "";

beforeEach(async () => {
  await clearLabels();
  await resetApiKeysTable();
  resetSharedApiKeyCache();
  secretA = await seedApiKey({
    id: "key_label_tenant_a",
    secret: testSecret("label-tenant-a"),
    tenantId: TENANT_A,
    scopes: ["prompts.render", "chat.completions"],
  });
});

function render(secret: string, id: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/prompts/${id}/render`, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// POST /v1/prompts/{id}/render — by label
// ---------------------------------------------------------------------------

describe("EDGE: POST /v1/prompts/{id}/render resolves a label", () => {
  it("renders THE LABELLED revision, not the active one", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const res = await render(secretA, "tpl_greeting", {
      label: "production",
      variables: { who: "Ada" },
    });
    expect(res.status).toBe(200);
    // Revision 1's text. The active revision is 2, so this string is only
    // reachable by way of the pointer.
    expect(await res.json()).toEqual({
      model: "prompt-model",
      messages: [{ role: "system", content: "revision one, Ada" }],
    });
  });

  it("follows the label when it MOVES, with no deploy in between", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const before = (await (
      await render(secretA, "tpl_greeting", { label: "production", variables: { who: "Ada" } })
    ).json()) as { messages: { content: string }[] };
    expect(before.messages[0]?.content).toBe("revision one, Ada");

    await label(TENANT_A, "tpl_greeting", "production", 2);
    const after = (await (
      await render(secretA, "tpl_greeting", { label: "production", variables: { who: "Ada" } })
    ).json()) as { messages: { content: string }[] };
    expect(after.messages[0]?.content).toBe("revision two, Ada");
  });

  it("404s an unknown label LOUDLY — never an empty or default prompt", async () => {
    const res = await render(secretA, "tpl_greeting", {
      label: "production",
      variables: { who: "Ada" },
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("prompt_label_not_found");
    expect(body.error.message).toContain("production");
    // Nothing renderable came back: no messages, no model, no silent default.
    expect(body).not.toHaveProperty("messages");
    expect(body).not.toHaveProperty("model");
  });

  it("400s a request that names BOTH a label and a revision", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const res = await render(secretA, "tpl_greeting", { label: "production", revision: 2 });
    expect(res.status).toBe(400);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("invalid_request_body");
  });

  it("409s a label pointing at a DRAFT revision", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 3);
    const res = await render(secretA, "tpl_greeting", {
      label: "production",
      variables: { who: "Ada" },
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe(
      "prompt_template_version_inactive",
    );
  });

  it("404s a label pointing at a revision the template does not have", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 99);
    const res = await render(secretA, "tpl_greeting", { label: "production" });
    expect(res.status).toBe(404);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe(
      "prompt_template_version_not_found",
    );
  });
});

describe("EDGE: the label pointer is fenced by tenant", () => {
  it("never resolves ANOTHER tenant's pointer under the same template + label", async () => {
    // Only tenant B has a `production` label, pointing at revision 2.
    await label(TENANT_B, "tpl_greeting", "production", 2);

    const res = await render(secretA, "tpl_greeting", {
      label: "production",
      variables: { who: "Ada" },
    });
    // Tenant A must NOT inherit it — and must not silently fall back to the
    // active revision either. Both wrong answers are 200s; the right one is a
    // refusal.
    expect(res.status).toBe(404);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("prompt_label_not_found");
  });

  it("serves each tenant its OWN revision for the same label name", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    await label(TENANT_B, "tpl_greeting", "production", 2);

    const secretB = await seedApiKey({
      id: "key_label_tenant_b",
      secret: testSecret("label-tenant-b"),
      tenantId: TENANT_B,
      scopes: ["prompts.render"],
    });

    const a = (await (
      await render(secretA, "tpl_greeting", { label: "production", variables: { who: "Ada" } })
    ).json()) as { messages: { content: string }[] };
    const b = (await (
      await render(secretB, "tpl_greeting", { label: "production", variables: { who: "Ada" } })
    ).json()) as { messages: { content: string }[] };

    expect(a.messages[0]?.content).toBe("revision one, Ada");
    expect(b.messages[0]?.content).toBe("revision two, Ada");
  });
});

// ---------------------------------------------------------------------------
// Prompt-by-reference on the inference path
// ---------------------------------------------------------------------------

/** One outbound provider call, recorded, so the EXPANDED body is inspectable. */
function interceptUpstream(): { last: () => Record<string, unknown>; restore: () => void } {
  const original = globalThis.fetch;
  let body: Record<string, unknown> = {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes("api.primary.example")) {
      return await original(input as RequestInfo, init);
    }
    body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    return new Response(
      JSON.stringify({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "physical-1",
        choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof globalThis.fetch;
  return { last: () => body, restore: () => { globalThis.fetch = original; } };
}

function chat(secret: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("EDGE: an inference request references a prompt BY LABEL", () => {
  it("expands the reference into the labelled revision's messages and model", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const upstream = interceptUpstream();
    try {
      const res = await chat(secretA, {
        prompt: { id: "tpl_greeting", label: "production", variables: { who: "Ada" } },
      });
      expect(res.status).toBe(200);

      const sent = upstream.last();
      // The PHYSICAL model name, i.e. the request really went through the whole
      // inference path after expansion — not just through a renderer.
      expect(sent["model"]).toBe("physical-1");
      expect(sent["messages"]).toEqual([{ role: "system", content: "revision one, Ada" }]);
    } finally {
      upstream.restore();
    }
  });

  it("REFUSES an unknown label instead of dispatching an empty prompt", async () => {
    const upstream = interceptUpstream();
    try {
      const res = await chat(secretA, {
        prompt: { id: "tpl_greeting", label: "production", variables: { who: "Ada" } },
      });
      expect(res.status).toBe(404);
      expect(((await res.json()) as ErrorEnvelope).error.code).toBe("prompt_label_not_found");
      // The load-bearing half: nothing reached a provider. A gateway that
      // dispatched with no system prompt would still have answered 200 above.
      expect(upstream.last()).toEqual({});
    } finally {
      upstream.restore();
    }
  });

  it("never expands ANOTHER tenant's label", async () => {
    await label(TENANT_B, "tpl_greeting", "production", 2);
    const upstream = interceptUpstream();
    try {
      const res = await chat(secretA, {
        prompt: { id: "tpl_greeting", label: "production", variables: { who: "Ada" } },
      });
      expect(res.status).toBe(404);
      expect(upstream.last()).toEqual({});
    } finally {
      upstream.restore();
    }
  });

  it("400s a request that carries BOTH a prompt reference and its own messages", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const res = await chat(secretA, {
      prompt: { id: "tpl_greeting", label: "production", variables: { who: "Ada" } },
      messages: [{ role: "user", content: "smuggled" }],
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("invalid_request");
  });

  it("lets the caller's own sampling parameters survive the expansion", async () => {
    await label(TENANT_A, "tpl_greeting", "production", 1);
    const upstream = interceptUpstream();
    try {
      const res = await chat(secretA, {
        prompt: { id: "tpl_greeting", label: "production", variables: { who: "Ada" } },
        temperature: 0.9,
      });
      expect(res.status).toBe(200);
      expect(upstream.last()["temperature"]).toBe(0.9);
    } finally {
      upstream.restore();
    }
  });
});
