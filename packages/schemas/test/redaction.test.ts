import {
  REDACTED_PLACEHOLDER,
  SECRET_SHAPED_KEY_FRAGMENTS,
  hasSecretShapedKey,
  isSecretShapedKey,
  redactSecretShapedKeys,
  secretShapedKeyPaths,
} from "@ferrogate/schemas";
import { describe, expect, test } from "vitest";

describe("SECRET_SHAPED_KEY_FRAGMENTS", () => {
  // Guard against the #351 drift: the two fragments a weaker copy had lost.
  test("contains the full canonical fragment list", () => {
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
});

describe("isSecretShapedKey", () => {
  test("matches case-insensitively as a substring", () => {
    expect(isSecretShapedKey("api_token")).toBe(true);
    expect(isSecretShapedKey("MY_SECRET")).toBe(true);
    expect(isSecretShapedKey("SignerAddress")).toBe(true);
    expect(isSecretShapedKey("wallet_mnemonic")).toBe(true);
  });

  // Edge: benign key names never trip the filter.
  test("does not match benign keys", () => {
    expect(isSecretShapedKey("organization_id")).toBe(false);
    expect(isSecretShapedKey("workspace")).toBe(false);
    expect(isSecretShapedKey("")).toBe(false);
  });
});

describe("redactSecretShapedKeys", () => {
  test("replaces a secret-shaped subtree and does not descend into it", () => {
    const input = {
      user: "alice",
      credential: { access_token: "abc", nested: { deep: 1 } },
      items: [{ private_key: "x" }, { ok: true }],
    };
    const out = redactSecretShapedKeys(input) as {
      user: string;
      credential: unknown;
      items: Array<Record<string, unknown>>;
    };
    expect(out.user).toBe("alice");
    expect(out.credential).toBe(REDACTED_PLACEHOLDER); // whole subtree replaced
    expect(out.items[0]?.private_key).toBe(REDACTED_PLACEHOLDER);
    expect(out.items[1]?.ok).toBe(true);
  });

  // Edge: the input is never mutated (deep copy semantics).
  test("does not mutate the input", () => {
    const input = { password: "hunter2", keep: 1 };
    const out = redactSecretShapedKeys(input);
    expect(input.password).toBe("hunter2");
    expect(out.password).toBe(REDACTED_PLACEHOLDER);
  });
});

describe("secretShapedKeyPaths / hasSecretShapedKey", () => {
  test("collects dotted/indexed paths of every secret-shaped key", () => {
    const value = { config: { api_token: "x" }, items: [{ private: 1 }] };
    expect(secretShapedKeyPaths(value).sort()).toEqual(
      ["config.api_token", "items[0].private"].sort(),
    );
    expect(hasSecretShapedKey(value)).toBe(true);
  });

  test("returns empty for a safe value", () => {
    const safe = { organization_id: "org", items: [{ ok: true }] };
    expect(secretShapedKeyPaths(safe)).toEqual([]);
    expect(hasSecretShapedKey(safe)).toBe(false);
  });
});
