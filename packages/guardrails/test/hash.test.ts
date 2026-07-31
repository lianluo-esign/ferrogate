import { describe, expect, test } from "vitest";
import { hmacSha256, sha256, toHex } from "../src/hash.js";

const enc = (s: string) => new TextEncoder().encode(s);

describe("sha256", () => {
  test("known vector: 'abc'", () => {
    expect(toHex(sha256(enc("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  test("empty input", () => {
    expect(toHex(sha256(enc("")))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  test("multi-block input (> 55 bytes) hashes correctly", () => {
    const msg = "a".repeat(1000);
    // Reference sha256 of 1000 'a' characters.
    expect(toHex(sha256(enc(msg)))).toBe(
      "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
    );
  });
});

describe("hmacSha256", () => {
  test("known RFC-style vector", () => {
    const digest = hmacSha256(enc("key"), enc("The quick brown fox jumps over the lazy dog"));
    expect(toHex(digest)).toBe("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  });

  test("long key (> block size) is hashed first", () => {
    const digest = hmacSha256(enc("x".repeat(100)), enc("hi"));
    expect(toHex(digest)).toHaveLength(64);
  });
});
