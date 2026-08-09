import { describe, expect, it } from "vitest";

import {
  SECRET_SHAPED_KEY_FRAGMENTS,
  hasSecretShapedKey,
  isSecretShapedKey,
  redactSecretShapedKeys,
  secretShapedKeyPaths,
} from "../src/index";

describe("SECRET_SHAPED_KEY_FRAGMENTS", () => {
  it("is exactly the 10 shared fragments in order", () => {
    expect([...SECRET_SHAPED_KEY_FRAGMENTS]).toEqual([
      "secret",
      "signer",
      "signature",
      "private",
      "keypair",
      "mnemonic",
      "seed",
      "credential",
      "password",
      "token",
    ]);
  });

  // Guards against the #351 regression where a copy silently dropped a fragment.
  it("flags every fragment individually, case-insensitively", () => {
    for (const fragment of SECRET_SHAPED_KEY_FRAGMENTS) {
      expect(isSecretShapedKey(fragment.toUpperCase())).toBe(true);
    }
  });
});

describe("isSecretShapedKey", () => {
  it("matches as a case-insensitive substring", () => {
    expect(isSecretShapedKey("API_TOKEN")).toBe(true);
    expect(isSecretShapedKey("Mnemonic_phrase")).toBe(true);
    expect(isSecretShapedKey("aws_secret_access_key")).toBe(true);
    expect(isSecretShapedKey("username")).toBe(false);
    expect(isSecretShapedKey("region")).toBe(false);
  });
});

describe("redactSecretShapedKeys", () => {
  it("recursively redacts values under secret-shaped keys without mutating input", () => {
    const input = {
      user: "alice",
      api_token: "sk-123",
      nested: { private_key: "xyz", ok: 1 },
      list: [{ password: "p" }, { fine: true }],
    };
    const redacted = redactSecretShapedKeys(input);
    expect(redacted).toEqual({
      user: "alice",
      api_token: "<redacted>",
      nested: { private_key: "<redacted>", ok: 1 },
      list: [{ password: "<redacted>" }, { fine: true }],
    });
    // input untouched (deep copy)
    expect(input.api_token).toBe("sk-123");
    expect(input.nested.private_key).toBe("xyz");
  });

  it("hides the ENTIRE subtree under a secret-shaped key (does not descend)", () => {
    const redacted = redactSecretShapedKeys({
      credential: { password: "p", other: 1 },
    } as unknown);
    expect(redacted).toEqual({ credential: "<redacted>" });
  });

  it("honours a custom placeholder (edge case)", () => {
    const redacted = redactSecretShapedKeys({ secret: "x", ok: 1 } as unknown, "***");
    expect(redacted).toEqual({ secret: "***", ok: 1 });
  });
});

describe("secretShapedKeyPaths / hasSecretShapedKey", () => {
  it("reports the dotted/indexed paths of every offending key", () => {
    const input = {
      user: "alice",
      api_token: "sk-123",
      nested: { private_key: "xyz" },
      list: [{ password: "p" }, { fine: true }],
    };
    expect(secretShapedKeyPaths(input).sort()).toEqual(
      ["api_token", "list[0].password", "nested.private_key"].sort(),
    );
    expect(hasSecretShapedKey(input)).toBe(true);
    expect(hasSecretShapedKey({ ok: 1, region: "us" })).toBe(false);
  });
});
