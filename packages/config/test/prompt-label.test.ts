/**
 * The `label -> revision` pointer: key derivation, and the two refusals.
 *
 * These are the ADVERSARIAL cases for the shared primitive. Both Workers depend
 * on it — `apps/control-plane` writes, `apps/gateway` reads — so a key-space
 * confusion here is a cross-tenant prompt swap that neither app's own tests
 * would attribute to this module.
 */
import { describe, expect, test } from "vitest";
import {
  PROMPT_LABEL_KEY_PREFIX,
  PromptLabelError,
  type PromptLabelKv,
  normalizePromptLabel,
  promptLabelPointerKey,
  promptLabelPointerSchema,
  promptLabelTemplatePrefix,
  readPromptLabelPointer,
} from "../src/prompt-label.js";

/** An in-memory KV double with exactly the four methods the module uses. */
function fakeKv(seed: Record<string, string> = {}): PromptLabelKv & { store: Map<string, string> } {
  const store = new Map(Object.entries(seed));
  return {
    store,
    get: (key) => Promise.resolve(store.get(key) ?? null),
    put: (key, value) => {
      store.set(key, value);
      return Promise.resolve();
    },
    delete: (key) => {
      store.delete(key);
      return Promise.resolve();
    },
    list: ({ prefix }) =>
      Promise.resolve({
        keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })),
      }),
  };
}

function pointer(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    tenant_id: "acme",
    template_id: "tpl",
    label: "production",
    revision: 3,
    updated_at_unix: 1_700_000_000,
    updated_by: null,
    ...over,
  });
}

describe("normalizePromptLabel", () => {
  test("trims and lowercases, so `  Production ` and `production` are one label", () => {
    expect(normalizePromptLabel("  Production ")).toBe("production");
    expect(normalizePromptLabel("STAGING")).toBe("staging");
  });

  test("accepts operator-chosen names with dots, dashes and underscores", () => {
    for (const name of ["eu-west", "v2.1", "canary_10", "a"]) {
      expect(normalizePromptLabel(name)).toBe(name);
    }
  });

  test("THROWS rather than returning null for an illegal name", () => {
    // The throw is the point: a normalizer that answered `null` would let an
    // illegal name flow onward as an empty string and match a key nobody wrote.
    for (const bad of [
      "",
      "   ",
      "-leading",
      ".dot",
      "has space",
      "sla/sh",
      "co:lon",
      "a".repeat(65),
    ]) {
      expect(() => normalizePromptLabel(bad)).toThrow(PromptLabelError);
    }
  });
});

describe("promptLabelPointerKey — the scope is part of the KEY", () => {
  test("two tenants naming the same template and label get different keys", () => {
    const a = promptLabelPointerKey({ tenantId: "a", templateId: "tpl", label: "production" });
    const b = promptLabelPointerKey({ tenantId: "b", templateId: "tpl", label: "production" });
    expect(a).not.toBe(b);
    expect(a.startsWith(PROMPT_LABEL_KEY_PREFIX)).toBe(true);
  });

  test("the platform-operator space is not reachable from any tenant id", () => {
    const operator = promptLabelPointerKey({
      tenantId: null,
      templateId: "tpl",
      label: "production",
    });
    // Including the literal id `operator`, which is the obvious collision to
    // try: it escapes to the same text but sits behind the `tenant` segment.
    for (const tenantId of ["operator", "", "/operator", "..", "%2Foperator"]) {
      expect(promptLabelPointerKey({ tenantId, templateId: "tpl", label: "production" })).not.toBe(
        operator,
      );
    }
  });

  test("a separator inside a component cannot climb into another key space", () => {
    // Without escaping, tenant `a` + template `x/tenant/b/y` would produce the
    // same string as tenant `a/x` + template `tenant/b/y`. It must not.
    const crafted = promptLabelPointerKey({
      tenantId: "a",
      templateId: "x/tenant/b/y",
      label: "production",
    });
    const honest = promptLabelPointerKey({
      tenantId: "b",
      templateId: "y",
      label: "production",
    });
    expect(crafted).not.toBe(honest);
    expect(crafted).not.toContain("x/tenant/b/y");
  });

  test("the template prefix enumerates one template within one scope", () => {
    const prefix = promptLabelTemplatePrefix("acme", "tpl");
    expect(
      promptLabelPointerKey({ tenantId: "acme", templateId: "tpl", label: "production" }),
    ).toContain(prefix);
    expect(
      promptLabelPointerKey({ tenantId: "other", templateId: "tpl", label: "production" }),
    ).not.toContain(prefix);
  });
});

describe("promptLabelPointerSchema", () => {
  test("refuses an unknown member rather than guessing at a newer format", () => {
    expect(promptLabelPointerSchema.safeParse(JSON.parse(pointer({ mystery: 1 }))).success).toBe(
      false,
    );
  });

  test("refuses a non-positive or fractional revision", () => {
    for (const revision of [0, -1, 2.5]) {
      expect(promptLabelPointerSchema.safeParse(JSON.parse(pointer({ revision }))).success).toBe(
        false,
      );
    }
  });
});

describe("readPromptLabelPointer — every failure is LOUD", () => {
  const ref = { tenantId: "acme", templateId: "tpl", label: "production" };

  test("returns the pointer when the scope, template and label all agree", async () => {
    const kv = fakeKv({ [promptLabelPointerKey(ref)]: pointer() });
    expect((await readPromptLabelPointer(kv, ref)).revision).toBe(3);
  });

  test("`unavailable` when no namespace is bound — never a silent 'no label'", async () => {
    await expect(readPromptLabelPointer(null, ref)).rejects.toMatchObject({
      reason: "unavailable",
    });
  });

  test("`unavailable` when the KV read itself throws", async () => {
    const broken: PromptLabelKv = {
      ...fakeKv(),
      get: () => Promise.reject(new Error("kv down")),
    };
    // A KV outage must NOT degrade into "this label does not exist", which the
    // caller would render as the un-labelled path.
    await expect(readPromptLabelPointer(broken, ref)).rejects.toMatchObject({
      reason: "unavailable",
    });
  });

  test("`not_found` for a label nobody has written", async () => {
    await expect(readPromptLabelPointer(fakeKv(), ref)).rejects.toMatchObject({
      reason: "not_found",
    });
  });

  test("`malformed` for a value that is not a readable pointer", async () => {
    for (const raw of ["not json", "[]", '{"revision":1}']) {
      const kv = fakeKv({ [promptLabelPointerKey(ref)]: raw });
      await expect(readPromptLabelPointer(kv, ref)).rejects.toMatchObject({
        reason: "malformed",
      });
    }
  });

  test("`scope_mismatch` when a stored pointer describes ANOTHER scope", async () => {
    // Unreachable while the key derivation is the only writer — which is why it
    // is checked. If a future key-format change ever collided two scopes, this
    // is the assertion that turns a cross-tenant prompt swap into a failure.
    for (const wrong of [
      { tenant_id: "other" },
      { template_id: "elsewhere" },
      { label: "staging" },
    ]) {
      const kv = fakeKv({ [promptLabelPointerKey(ref)]: pointer(wrong) });
      await expect(readPromptLabelPointer(kv, ref)).rejects.toMatchObject({
        reason: "scope_mismatch",
      });
    }
  });
});
