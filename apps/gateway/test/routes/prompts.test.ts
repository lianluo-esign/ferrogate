/**
 * `POST /v1/prompts/{id}/render` — server-side prompt-template rendering.
 *
 * ## What makes the deployed cases MOUNT GATES
 *
 * This operation answered `501 not_implemented` until this slice. A 200 alone
 * would not prove the mount — a stub returning `{}` would also be a 200 — so
 * every deployed case asserts a rendered body whose CONTENT comes from
 * `GATEWAY_PROMPT_TEMPLATES` (the operator's message text with the caller's
 * variable substituted into it). Remove the `router.register(
 * "renderPromptTemplate", …)` line in `src/routes/index.ts` and every case in
 * the MOUNT block fails; swap it for `registerDropped` and they fail with 501.
 *
 * The model-ladder cases are equally load-bearing: this endpoint hands back a
 * request body naming a model, so an ungated render is a model-enumeration
 * oracle. Each 4xx below is a leg of the Rust ladder and each one is driven
 * through the real credential path (`env.DB` for the per-key allowlists, seeded
 * through the same hash the resolver verifies against).
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resetSharedApiKeyCache } from "../../src/keys/index.js";
import {
  PromptRenderError,
  activePromptTemplateVersion,
  findPromptTemplateVersion,
  parsePromptTemplates,
  promptVariableToString,
  renderPromptTemplate,
  renderPromptText,
} from "../../src/routes/prompts.js";
import { resetApiKeysTable, seedApiKey, testSecret } from "../keys/seed.js";
const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;

const BASE = "https://ferrogate.test";

const PROVIDERS = [
  { name: "primary", kind: "openai", base_url: "https://api.primary.example/v1" },
  { name: "secondary", kind: "openai", base_url: "https://api.secondary.example/v1" },
];

const MODELS = [
  { name: "prompt-model", provider: "primary", provider_model: "physical-1" },
  { name: "second-provider-model", provider: "secondary", provider_model: "physical-2" },
  // Disabled: resolves in the catalog, never as a candidate ⇒ `model_disabled`.
  { name: "retired-model", provider: "primary", provider_model: "physical-3", enabled: false },
  // Owned by ANOTHER tenant ⇒ `model_not_visible` for tenant_a.
  {
    name: "tenant-b-model",
    provider: "primary",
    provider_model: "physical-4",
    tenant_id: "tenant_b",
  },
];

const TEMPLATES = [
  {
    id: "tpl_greeting",
    name: "Greeting",
    status: "active",
    target: "chat_completions",
    model: "prompt-model",
    variables: [
      { name: "who", required: true },
      { name: "tone", required: false, default: "cheerful" },
    ],
    versions: [
      {
        revision: 1,
        status: "active",
        messages: [{ role: "system", content: "old revision, {{who}}" }],
      },
      {
        revision: 2,
        status: "active",
        messages: [
          { role: "system", content: "Be {{tone}}." },
          { role: "user", content: "Hello {{ who }}!" },
        ],
        temperature: 0.25,
        max_tokens: 512,
      },
    ],
  },
  {
    id: "tpl_responses",
    name: "Responses target",
    status: "active",
    target: "responses",
    model: "prompt-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "hi" }] }],
  },
  {
    id: "tpl_archived",
    name: "Archived",
    status: "archived",
    model: "prompt-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "x" }] }],
  },
  {
    id: "tpl_no_active_version",
    name: "Draft only",
    status: "active",
    model: "prompt-model",
    versions: [{ revision: 3, status: "draft", messages: [{ role: "user", content: "x" }] }],
  },
  {
    id: "tpl_disabled_model",
    name: "Disabled model",
    status: "active",
    model: "retired-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "x" }] }],
  },
  {
    id: "tpl_unknown_model",
    name: "Unknown model",
    status: "active",
    model: "ghost-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "x" }] }],
  },
  {
    id: "tpl_other_tenant_model",
    name: "Other tenant model",
    status: "active",
    model: "tenant-b-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "x" }] }],
  },
  {
    id: "tpl_second_provider",
    name: "Second provider",
    status: "active",
    model: "second-provider-model",
    versions: [{ revision: 1, status: "active", messages: [{ role: "user", content: "x" }] }],
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

async function render(id: string, secret: string, body?: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}/v1/prompts/${id}/render`, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

// ---------------------------------------------------------------------------
// The renderer, as pure functions
// ---------------------------------------------------------------------------

const templates = parsePromptTemplates(JSON.stringify(TEMPLATES));
const greeting = nn(templates.find((t) => t.id === "tpl_greeting"));

describe("parsePromptTemplates — fail-closed, entry by entry", () => {
  it("treats absent, blank, non-JSON and non-array values as NO templates", () => {
    expect(parsePromptTemplates(undefined)).toEqual([]);
    expect(parsePromptTemplates("  ")).toEqual([]);
    expect(parsePromptTemplates("{oops")).toEqual([]);
    expect(parsePromptTemplates('{"id":"tpl"}')).toEqual([]);
  });

  it("drops only the entry the schema refuses", () => {
    const parsed = parsePromptTemplates(
      JSON.stringify([
        {
          id: "ok",
          name: "Ok",
          model: "m",
          versions: [{ messages: [{ role: "user", content: "c" }] }],
        },
        { id: "missing-versions", name: "Bad", model: "m" },
      ]),
    );
    expect(parsed.map((t) => t.id)).toEqual(["ok"]);
    // The config schema's defaults — `status`, `target` and `revision`.
    expect(parsed[0]?.status).toBe("active");
    expect(parsed[0]?.target).toBe("chat_completions");
    expect(parsed[0]?.versions[0]?.revision).toBe(1);
  });
});

describe("version selection", () => {
  it("picks the HIGHEST active revision when none is requested", () => {
    expect(activePromptTemplateVersion(greeting)?.revision).toBe(2);
    expect(findPromptTemplateVersion(greeting, null)?.revision).toBe(2);
  });

  it("honours an explicit revision, including an older one", () => {
    expect(findPromptTemplateVersion(greeting, 1)?.revision).toBe(1);
    expect(findPromptTemplateVersion(greeting, 99)).toBeUndefined();
  });

  it("falls back to the newest INACTIVE version so the refusal can say 'inactive'", () => {
    // Rust's `.or_else(...)`. Returning undefined here would turn a 409
    // `prompt_template_version_inactive` into a 404, losing the reason.
    const draftOnly = nn(templates.find((t) => t.id === "tpl_no_active_version"));
    const chosen = activePromptTemplateVersion(draftOnly);
    expect(chosen?.revision).toBe(3);
    expect(chosen?.status).toBe("draft");
  });
});

describe("promptVariableToString", () => {
  it("renders null as the EMPTY STRING, never the word null", () => {
    expect(promptVariableToString(null)).toBe("");
    expect(promptVariableToString(undefined)).toBe("");
  });

  it("passes a string through and stringifies scalars", () => {
    expect(promptVariableToString("x")).toBe("x");
    expect(promptVariableToString(7)).toBe("7");
    expect(promptVariableToString(true)).toBe("true");
  });

  it("re-serializes arrays and objects as compact JSON", () => {
    expect(promptVariableToString([1, "a"])).toBe('[1,"a"]');
    expect(promptVariableToString({ b: 2 })).toBe('{"b":2}');
  });
});

describe("renderPromptText", () => {
  it("substitutes declared variables and trims placeholder whitespace", () => {
    expect(renderPromptText(greeting, "Hello {{ who }}!", { who: "Ada" })).toBe("Hello Ada!");
  });

  it("uses the declared default when the client omits an optional variable", () => {
    expect(renderPromptText(greeting, "Be {{tone}}.", {})).toBe("Be cheerful.");
  });

  it("refuses a missing REQUIRED variable", () => {
    expect(() => renderPromptText(greeting, "{{who}}", {})).toThrow(PromptRenderError);
    expect(() => renderPromptText(greeting, "{{who}}", {})).toThrow(
      "required prompt variable who is missing",
    );
  });

  it("refuses an UNDECLARED variable even when the client supplies a value", () => {
    // The template's `variables` list is the contract: a client cannot smuggle
    // a placeholder the operator never declared.
    expect(() => renderPromptText(greeting, "{{secret}}", { secret: "s" })).toThrow(
      "prompt variable secret is not declared",
    );
  });

  it("refuses an unterminated placeholder rather than emitting it literally", () => {
    expect(() => renderPromptText(greeting, "Hello {{who", {})).toThrow("unclosed prompt variable");
  });

  it("does NOT re-expand a substituted value — single pass, forward only", () => {
    // If the renderer recursed, this would become "cheerful" (or throw).
    expect(renderPromptText(greeting, "{{who}}", { who: "{{tone}}" })).toBe("{{tone}}");
  });
});

describe("renderPromptTemplate", () => {
  it("emits `messages` for a chat_completions target", () => {
    const version = nn(findPromptTemplateVersion(greeting, 2));
    expect(renderPromptTemplate(greeting, version, { who: "Ada" })).toEqual({
      model: "prompt-model",
      messages: [
        { role: "system", content: "Be cheerful." },
        { role: "user", content: "Hello Ada!" },
      ],
      temperature: 0.25,
      max_tokens: 512,
    });
  });

  it("emits `input` for a responses target, and omits absent sampling fields", () => {
    const responses = nn(templates.find((t) => t.id === "tpl_responses"));
    const rendered = renderPromptTemplate(
      responses,
      responses.versions[0] as NonNullable<(typeof responses.versions)[0]>,
      {},
    );
    expect(rendered).toEqual({ model: "prompt-model", input: [{ role: "user", content: "hi" }] });
    expect(Object.keys(rendered)).not.toContain("temperature");
    expect(Object.keys(rendered)).not.toContain("top_p");
    expect(Object.keys(rendered)).not.toContain("max_tokens");
  });
});

// ---------------------------------------------------------------------------
// MOUNT — the app the Worker exports
// ---------------------------------------------------------------------------

/** `fg_root` is the static platform-operator key: wildcard scope, no allowlists. */
const ROOT = "fg_root";

describe("MOUNT: the deployed Worker renders prompt templates", () => {
  it("renders the ACTIVE revision, substituting the caller's variables", async () => {
    const res = await render("tpl_greeting", ROOT, { variables: { who: "Ada" } });
    expect(res.status).toBe(200);
    // Every value below comes from GATEWAY_PROMPT_TEMPLATES + the request body.
    // No stub can produce it, and neither can a handler that skipped the render.
    expect(await res.json()).toEqual({
      model: "prompt-model",
      messages: [
        { role: "system", content: "Be cheerful." },
        { role: "user", content: "Hello Ada!" },
      ],
      temperature: 0.25,
      max_tokens: 512,
    });
  });

  it("renders an EXPLICIT older revision when one is requested", async () => {
    const res = await render("tpl_greeting", ROOT, { revision: 1, variables: { who: "Ada" } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      model: "prompt-model",
      messages: [{ role: "system", content: "old revision, Ada" }],
    });
  });

  it("accepts an EMPTY body and renders with declared defaults", async () => {
    // Rust checks `body.is_empty()` before parsing, so no body is not a 400.
    const res = await SELF.fetch(`${BASE}/v1/prompts/tpl_responses/render`, {
      method: "POST",
      headers: { authorization: `Bearer ${ROOT}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      model: "prompt-model",
      input: [{ role: "user", content: "hi" }],
    });
  });

  it("400s a body that is present but not a JSON object", async () => {
    const res = await SELF.fetch(`${BASE}/v1/prompts/tpl_greeting/render`, {
      method: "POST",
      headers: { authorization: `Bearer ${ROOT}` },
      body: "not json at all",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("invalid_request_body");
  });

  it("400s prompt_template_render_failed when a required variable is missing", async () => {
    const res = await render("tpl_greeting", ROOT, { variables: {} });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("prompt_template_render_failed");
    expect(body.error.message).toBe("required prompt variable who is missing");
  });

  it("404s an unknown template id", async () => {
    const res = await render("tpl_nope", ROOT, {});
    expect(res.status).toBe(404);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("prompt_template_not_found");
  });

  it("409s an ARCHIVED template", async () => {
    const res = await render("tpl_archived", ROOT, {});
    expect(res.status).toBe(409);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("prompt_template_inactive");
  });

  it("404s an unknown revision and 409s a DRAFT one — two different refusals", async () => {
    const missing = await render("tpl_greeting", ROOT, { revision: 99 });
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as ErrorEnvelope).error.code).toBe(
      "prompt_template_version_not_found",
    );

    const draft = await render("tpl_no_active_version", ROOT, {});
    expect(draft.status).toBe(409);
    const body = (await draft.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("prompt_template_version_inactive");
    // Names the revision the fallback selected, which is how the operator finds it.
    expect(body.error.message).toContain("3");
  });

  it("refuses an anonymous caller BEFORE the handler runs", async () => {
    const res = await SELF.fetch(`${BASE}/v1/prompts/tpl_greeting/render`, { method: "POST" });
    expect(res.status).toBe(401);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("missing_api_key");
  });
});

describe("MOUNT: the model ladder gates the render", () => {
  it("400 model_not_found for a template naming a model no provider serves", async () => {
    const res = await render("tpl_unknown_model", ROOT, {});
    expect(res.status).toBe(400);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("model_not_found");
  });

  it("400 model_disabled — distinct from model_not_found", async () => {
    const res = await render("tpl_disabled_model", ROOT, {});
    expect(res.status).toBe(400);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("model_disabled");
  });
});

describe("MOUNT: per-credential allowlists gate the render", () => {
  beforeEach(async () => {
    await resetApiKeysTable();
    resetSharedApiKeyCache();
  });

  it("403 model_not_allowed when the key's allowed_models excludes the template's model", async () => {
    const secret = await seedApiKey({
      id: "key_prompt_allowlist",
      secret: testSecret("prompt-allowlist"),
      tenantId: "tenant_a",
      scopes: ["prompts.render"],
      allowedModels: ["some-other-model"],
    });
    const res = await render("tpl_greeting", secret, { variables: { who: "Ada" } });
    expect(res.status).toBe(403);
    const body = (await res.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("model_not_allowed");
    // Refused BEFORE resolution, so no template content leaked.
    expect(body.error.message).toBe("API key is not allowed to use model prompt-model");
  });

  it("renders for the SAME key once the model is on its allowlist (positive control)", async () => {
    const secret = await seedApiKey({
      id: "key_prompt_allowlist_ok",
      secret: testSecret("prompt-allowlist-ok"),
      tenantId: "tenant_a",
      scopes: ["prompts.render"],
      allowedModels: ["prompt-model"],
    });
    const res = await render("tpl_greeting", secret, { variables: { who: "Ada" } });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { messages: unknown[] }).messages).toHaveLength(2);
  });

  it("403 model_not_visible for a model owned by ANOTHER tenant", async () => {
    const secret = await seedApiKey({
      id: "key_prompt_tenant_a",
      secret: testSecret("prompt-tenant-a"),
      tenantId: "tenant_a",
      scopes: ["prompts.render"],
    });
    const res = await render("tpl_other_tenant_model", secret, {});
    expect(res.status).toBe(403);
    expect(((await res.json()) as ErrorEnvelope).error.code).toBe("model_not_visible");
  });

  it("403 provider_not_allowed when allowed_providers excludes every candidate", async () => {
    const secret = await seedApiKey({
      id: "key_prompt_provider",
      secret: testSecret("prompt-provider"),
      tenantId: "tenant_a",
      scopes: ["prompts.render"],
      allowedProviders: ["primary"],
    });
    // `second-provider-model` only routes through `secondary`.
    const refused = await render("tpl_second_provider", secret, {});
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as ErrorEnvelope).error.code).toBe("provider_not_allowed");

    // Positive control on the SAME key: a model on the allowed provider renders.
    const allowed = await render("tpl_responses", secret, {});
    expect(allowed.status).toBe(200);
  });
});
