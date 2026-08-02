/**
 * Prompt DEPLOYMENT LABELS — `/admin/v1/prompt-templates/{id}/labels/{label}`.
 *
 * ## What these cases hold
 *
 * A label is the indirection that turns "ship a prompt change" from a deploy
 * into an API call: it names a revision, and the data plane resolves it at the
 * edge. So the assertions below are about the two things that make that safe
 * rather than merely convenient.
 *
 * 1. **The tenant fence.** Every case that crosses a tenant boundary asserts
 *    BOTH halves — the refusal, and that the other tenant's pointer is
 *    untouched afterwards. A handler that 404s the request and still wrote the
 *    KV pointer would pass the first half alone, and the pointer is the thing
 *    the gateway actually reads.
 * 2. **The pointer really moves.** Every write case reads the KV entry back
 *    through {@link promptLabelPointerKey} — the SAME derivation
 *    `apps/gateway` reads with. Asserting only the 200 would leave "the
 *    control plane says it moved and the edge never sees it" green, which is
 *    the exact shape of the write-half defects this repo has shipped before.
 *
 * `SELF.fetch` drives `src/worker.ts`, so the operations go through the real
 * contract table, the real auth middleware and the real store — a handler
 * wired into the group module but missing from the contract JSON 404s here.
 */
import { promptLabelPointerKey } from "@ferrogate/config";
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const TENANT_A = "tenant_a";
const TENANT_B = "tenant_b";
const KEY_A = "secret-tenant-a";
const KEY_B = "secret-tenant-b";

/**
 * Two templates with the SAME label name in two tenants. The shared name is the
 * point: `production` is what every tenant will call its label, so the fence
 * cannot rely on names happening to differ.
 */
const SEED = {
  "prompt-templates": [
    { id: "tpl_shared", name: "Shared id", tenant_id: TENANT_A, status: "active" },
    { id: "tpl_shared", name: "Shared id", tenant_id: TENANT_B, status: "active" },
    { id: "tpl_archived", name: "Archived", tenant_id: TENANT_A, status: "archived" },
  ],
};

function kv(): KVNamespace {
  const namespace = (env as { PROMPT_LABELS?: KVNamespace }).PROMPT_LABELS;
  if (namespace === undefined) {
    throw new Error(
      "no KV binding `PROMPT_LABELS` — add [[kv_namespaces]] to apps/control-plane/wrangler.toml",
    );
  }
  return namespace;
}

/** Read a pointer back the way `apps/gateway` will. */
async function pointer(
  tenantId: string | null,
  templateId: string,
  label: string,
): Promise<Record<string, unknown> | null> {
  const raw = await kv().get(promptLabelPointerKey({ tenantId, templateId, label }), "text");
  return raw === null ? null : (JSON.parse(raw) as Record<string, unknown>);
}

async function clearLabels(): Promise<void> {
  const namespace = kv();
  const listed = await namespace.list({ prefix: "prompt-label/" });
  for (const key of listed.keys) await namespace.delete(key.name);
}

beforeEach(async () => {
  arm({
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(KEY_A, TENANT_A), tenantKey(KEY_B, TENANT_B)],
    seed: SEED,
  });
  await clearLabels();
});

function put(secret: string, id: string, label: string, body: unknown): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/prompt-templates/${id}/labels/${label}`,
    jsonRequest(secret, "PUT", body),
  );
}

describe("PUT /admin/v1/prompt-templates/{id}/labels/{label}", () => {
  it("points a label at a revision and WRITES the edge pointer", async () => {
    const res = await put(KEY_A, "tpl_shared", "production", { revision: 7 });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      object: "prompt_template_label",
      prompt_template_label: {
        template_id: "tpl_shared",
        label: "production",
        revision: 7,
        tenant_id: TENANT_A,
      },
    });

    // The half a 200 alone does not prove.
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({
      tenant_id: TENANT_A,
      template_id: "tpl_shared",
      label: "production",
      revision: 7,
    });
  });

  it("MOVES a label — the second call replaces the pointer, it does not append", async () => {
    await put(KEY_A, "tpl_shared", "production", { revision: 1 });
    await put(KEY_A, "tpl_shared", "production", { revision: 2 });
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({ revision: 2 });
  });

  it("normalizes the label so `Production` and `production` are ONE label", async () => {
    await put(KEY_A, "tpl_shared", "Production", { revision: 4 });
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({ revision: 4 });
  });

  it("400s a label name that is not a legal label", async () => {
    const res = await put(KEY_A, "tpl_shared", "not%20a%20label", { revision: 1 });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_prompt_label",
    );
  });

  it("400s a revision that is not a positive integer", async () => {
    for (const revision of [0, -1, 1.5, "2"]) {
      const res = await put(KEY_A, "tpl_shared", "staging", { revision });
      expect(res.status).toBe(400);
      expect(await pointer(TENANT_A, "tpl_shared", "staging")).toBeNull();
    }
  });

  it("404s a template the caller cannot see, and writes NOTHING", async () => {
    const res = await put(KEY_A, "tpl_missing", "production", { revision: 1 });
    expect(res.status).toBe(404);
    expect(await pointer(TENANT_A, "tpl_missing", "production")).toBeNull();
  });

  it("409s an ARCHIVED template — a retired prompt cannot be re-deployed by label", async () => {
    const res = await put(KEY_A, "tpl_archived", "production", { revision: 1 });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "prompt_template_inactive",
    );
    expect(await pointer(TENANT_A, "tpl_archived", "production")).toBeNull();
  });

  it("403s a credential without admin.write", async () => {
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey("readonly-secret", TENANT_A, ["admin.read"])],
      seed: SEED,
    });
    const res = await put("readonly-secret", "tpl_shared", "production", { revision: 1 });
    expect(res.status).toBe(403);
  });
});

describe("THE TENANT FENCE", () => {
  it("keeps two tenants' identically-named labels on the same template id apart", async () => {
    expect((await put(KEY_A, "tpl_shared", "production", { revision: 11 })).status).toBe(200);
    expect((await put(KEY_B, "tpl_shared", "production", { revision: 22 })).status).toBe(200);

    // Same template id, same label name, two different revisions — which is
    // only possible because the SCOPE is part of the key.
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({ revision: 11 });
    expect(await pointer(TENANT_B, "tpl_shared", "production")).toMatchObject({ revision: 22 });
  });

  it("does not let tenant B's DELETE remove tenant A's pointer", async () => {
    await put(KEY_A, "tpl_shared", "production", { revision: 11 });
    await put(KEY_B, "tpl_shared", "production", { revision: 22 });

    const res = await SELF.fetch(
      `${BASE}/admin/v1/prompt-templates/tpl_shared/labels/production`,
      { method: "DELETE", headers: bearer(KEY_B) },
    );
    expect(res.status).toBe(200);

    expect(await pointer(TENANT_B, "tpl_shared", "production")).toBeNull();
    // The assertion that matters: B's delete touched only B's key space.
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({ revision: 11 });
  });

  it("does not let a tenant read another tenant's labels through the listing", async () => {
    await put(KEY_A, "tpl_shared", "production", { revision: 11 });
    await put(KEY_B, "tpl_shared", "staging", { revision: 22 });

    const res = await SELF.fetch(`${BASE}/admin/v1/prompt-templates/tpl_shared/labels`, {
      headers: bearer(KEY_A),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { label: string; revision: number }[] };
    expect(body.data.map((entry) => entry.label)).toEqual(["production"]);
    expect(body.data[0]?.revision).toBe(11);
  });

  it("keeps the PLATFORM-OPERATOR label space separate from every tenant's", async () => {
    // The operator's own space is reached with a platform-operator credential;
    // it is not a wildcard over the tenants, and this is the case that says so.
    await put(KEY_A, "tpl_shared", "production", { revision: 11 });
    const operator = await put(operatorKey.secret, "tpl_shared", "production", { revision: 99 });
    expect(operator.status).toBe(404);

    expect(await pointer(null, "tpl_shared", "production")).toBeNull();
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toMatchObject({ revision: 11 });
  });
});

describe("DELETE /admin/v1/prompt-templates/{id}/labels/{label}", () => {
  it("removes the pointer so the edge stops resolving it", async () => {
    await put(KEY_A, "tpl_shared", "production", { revision: 3 });
    const res = await SELF.fetch(
      `${BASE}/admin/v1/prompt-templates/tpl_shared/labels/production`,
      { method: "DELETE", headers: bearer(KEY_A) },
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      object: "prompt_template_label",
      id: "production",
      deleted: true,
    });
    expect(await pointer(TENANT_A, "tpl_shared", "production")).toBeNull();
  });

  it("404s a label that was never defined", async () => {
    const res = await SELF.fetch(`${BASE}/admin/v1/prompt-templates/tpl_shared/labels/nope`, {
      method: "DELETE",
      headers: bearer(KEY_A),
    });
    expect(res.status).toBe(404);
  });
});
