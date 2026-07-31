/**
 * `ai_response_cache_key` — `src/cache/key.ts`.
 *
 * The key IS the isolation boundary of a store shared by every tenant of a
 * deployment, so this file is written as one property repeated over every
 * field: **changing that field must change the digest.** A field that failed
 * this would be a field two different callers could collide on, and the whole
 * table below is what stops a future edit from quietly dropping one.
 */
import { describe, expect, it } from "vitest";
import {
  type CacheKeyInput,
  aiResponseCacheKey,
  cacheKeyMaterial,
  canonicalJson,
  scopeDigest,
  sha256Hex,
} from "../../src/cache/key.js";

const BASE: CacheKeyInput = {
  route: "createChatCompletion",
  path: "/v1/chat/completions",
  tenantId: "tenant_a",
  workspaceId: "workspace_1",
  projectId: "project_1",
  userId: "user_1",
  apiKeyId: "key_a",
  keySource: "durable_native",
  platformOperator: false,
  scopeDigest: scopeDigest(["chat.completions"]),
  logicalModel: "gpt-4o-mini",
  stream: false,
  requestBody: { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
  guardrailPolicyFingerprint: "gfp-1",
  registryFingerprint: "rfp-1",
};

/** Every field, with a value that differs from {@link BASE}. */
const VARIANTS: ReadonlyArray<[string, Partial<CacheKeyInput>]> = [
  ["route", { route: "createResponse" }],
  ["path", { path: "/v1/responses" }],
  ["tenantId", { tenantId: "tenant_b" }],
  ["tenantId → null", { tenantId: null }],
  ["workspaceId", { workspaceId: "workspace_2" }],
  ["projectId", { projectId: "project_2" }],
  ["userId", { userId: "user_2" }],
  ["apiKeyId", { apiKeyId: "key_b" }],
  ["apiKeyId → null", { apiKeyId: null }],
  ["keySource", { keySource: "static_config" }],
  ["platformOperator", { platformOperator: true }],
  ["scopeDigest", { scopeDigest: scopeDigest(["chat.completions", "admin.tenants.read"]) }],
  ["logicalModel", { logicalModel: "claude-logical" }],
  ["requestBody", { requestBody: { model: "gpt-4o-mini", messages: [] } }],
  ["guardrailPolicyFingerprint", { guardrailPolicyFingerprint: "gfp-2" }],
  ["registryFingerprint", { registryFingerprint: "rfp-2" }],
];

describe("aiResponseCacheKey", () => {
  it("is stable for identical input", async () => {
    expect(await aiResponseCacheKey(BASE)).toBe(await aiResponseCacheKey({ ...BASE }));
  });

  it("looks like a `ai-cache:` + SHA-256 digest, not a 64-bit FNV hash", async () => {
    const key = await aiResponseCacheKey(BASE);
    expect(key).toMatch(/^ai-cache:[0-9a-f]{64}$/);
    // Rust formatted `ai-cache:{:016x}` — 16 hex chars of `fnv1a64`. The store
    // here is the Cache API, a namespace every tenant shares and which is
    // addressed by the digest alone, so a forgeable digest would be a
    // cross-tenant read primitive. See the header of `src/cache/key.ts`.
    expect(key.length).toBeGreaterThan("ai-cache:".length + 16);
  });

  it.each(VARIANTS)("changing %s changes the digest", async (_label, patch) => {
    const base = await aiResponseCacheKey(BASE);
    const other = await aiResponseCacheKey({ ...BASE, ...patch });
    expect(other).not.toBe(base);
  });

  it("separates two tenants whose request is otherwise byte-identical", async () => {
    // The single most important case in this file, and the one
    // `test/cache/middleware.test.ts` mutation-proves end to end.
    const a = await aiResponseCacheKey({ ...BASE, tenantId: "tenant_a", apiKeyId: "k" });
    const b = await aiResponseCacheKey({ ...BASE, tenantId: "tenant_b", apiKeyId: "k" });
    expect(a).not.toBe(b);
  });

  it("separates two credentials that both carry NO api-key id", async () => {
    // Rust keyed on `api_key_id` alone, which is `Option`: a static operator key
    // and an external-auth principal both resolve `None`, so under the Rust
    // field set they would share an entry whenever their tenancy matched.
    const staticKey = await aiResponseCacheKey({
      ...BASE,
      apiKeyId: null,
      keySource: "static_config",
      platformOperator: true,
    });
    const external = await aiResponseCacheKey({
      ...BASE,
      apiKeyId: null,
      keySource: "external_auth_service",
      platformOperator: false,
    });
    expect(staticKey).not.toBe(external);
  });

  it("separates two keys of the same tenant that hold DIFFERENT scopes", async () => {
    const narrow = await aiResponseCacheKey({ ...BASE, scopeDigest: scopeDigest(["a"]) });
    const wide = await aiResponseCacheKey({ ...BASE, scopeDigest: scopeDigest(["a", "b"]) });
    expect(narrow).not.toBe(wide);
  });
});

describe("canonicalJson", () => {
  it("sorts object keys recursively so member ORDER is not identity", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe(
      canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
    );
  });

  it("preserves ARRAY order, which is semantic in `messages`", () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });

  it("keeps two different bodies apart", () => {
    expect(canonicalJson({ a: 1 })).not.toBe(canonicalJson({ a: 2 }));
  });
});

describe("cacheKeyMaterial", () => {
  it("carries the layout version, so a layout change cannot reuse old entries", () => {
    expect(cacheKeyMaterial(BASE)).toContain("fg-ai-cache-v1");
  });

  it("always pins stream:false — a streaming request is never keyed", () => {
    expect(JSON.parse(cacheKeyMaterial(BASE)).stream).toBe(false);
  });
});

describe("scopeDigest", () => {
  it("ignores order", () => {
    expect(scopeDigest(["b", "a"])).toBe(scopeDigest(["a", "b"]));
  });

  it("cannot be confused by a separator inside a scope name", () => {
    expect(scopeDigest(["a b", "c"])).not.toBe(scopeDigest(["a", "b c"]));
  });
});

describe("sha256Hex", () => {
  it("is the real SHA-256", async () => {
    // NIST vector for the empty string.
    expect(await sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
