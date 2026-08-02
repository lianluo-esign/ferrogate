import { describe, expect, it } from "vitest";
import { isSecretRef, parseSecretRef } from "../src/index.js";

describe("parseSecretRef", () => {
  it("parses an env:// reference", () => {
    expect(parseSecretRef("env://OPENAI_API_KEY")).toEqual({
      kind: "env",
      name: "OPENAI_API_KEY",
    });
  });

  it("rejects an empty env:// reference", () => {
    expect(() => parseSecretRef("env://")).toThrow(/variable name/);
  });

  it("parses a vault:// reference", () => {
    expect(parseSecretRef("vault://secret/data/openai#api_key")).toEqual({
      kind: "vault",
      mount: "secret",
      path: "data/openai",
      field: "api_key",
    });
  });

  it("rejects a vault:// reference missing the #field", () => {
    expect(() => parseSecretRef("vault://secret/data/openai")).toThrow(
      /#field/,
    );
  });

  it("rejects a vault:// reference missing the path", () => {
    expect(() => parseSecretRef("vault://secret#api_key")).toThrow(
      /<mount>\/<path>/,
    );
  });

  it("rejects an empty vault mount or path", () => {
    expect(() => parseSecretRef("vault:///data#api_key")).toThrow(
      /non-empty mount and path/,
    );
  });

  it("parses a cf:// reference", () => {
    expect(parseSecretRef("cf://provider-keys/openai-api-key")).toEqual({
      kind: "cfSecret",
      store: "provider-keys",
      name: "openai-api-key",
    });
  });

  it("keeps extra slashes in the cf:// secret name segment", () => {
    // split_once('/') → only the first slash separates store from name.
    expect(parseSecretRef("cf://store/a/b")).toEqual({
      kind: "cfSecret",
      store: "store",
      name: "a/b",
    });
  });

  it("rejects a cf:// reference missing the name", () => {
    expect(() => parseSecretRef("cf://provider-keys")).toThrow(
      /<store>\/<name>/,
    );
  });

  // DELIBERATELY CHANGED by issue #682, which added a FOURTH scheme (`byok://`).
  // The old assertion read `/env:\/\/, vault:\/\/, or cf:\/\//` and was pinning
  // the enumeration itself, so it had to move with the enumeration; the property
  // it exists to hold — an unknown scheme is refused, and the refusal names
  // every scheme that IS supported — is unchanged and is asserted below on all
  // four, so this is a widening, not a weakening.
  it("rejects an unsupported scheme, naming the four supported schemes", () => {
    expect(() => parseSecretRef("aws-sm://foo")).toThrow(
      /env:\/\/, vault:\/\/, cf:\/\/, or byok:\/\//,
    );
  });

  it("trims surrounding whitespace before parsing", () => {
    expect(parseSecretRef("  env://X  ")).toEqual({ kind: "env", name: "X" });
  });

  it("isSecretRef narrows valid vs invalid references", () => {
    expect(isSecretRef("env://X")).toBe(true);
    expect(isSecretRef("nope")).toBe(false);
  });
});
