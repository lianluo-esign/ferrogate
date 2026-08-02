/**
 * The key-material construction: prefix, hash, last4, verification.
 *
 * Runs in real `workerd` (so `crypto.subtle` is the runtime's own SHA-256), but
 * touches no binding — it is pure logic and needs none.
 *
 * The BLAKE2b block is what earns this file its keep. `verifyStoredKeyHash`
 * accepts `blake2b:` because the Rust does, and WebCrypto has no BLAKE2b, so
 * the digest is hand-implemented in `src/keys/blake2b.ts`. A hand-implemented
 * digest that is only ever tested against ITSELF is worthless — a transposed
 * SIGMA row or an off-by-one rotation would round-trip perfectly and still
 * reject every real stored row. So it is pinned against externally-published
 * vectors: the RFC 7693 values for `""` and `"abc"`, plus multi-block,
 * abbreviated-output and non-ASCII cases.
 */
import { describe, expect, test } from "vitest";
import {
  VIRTUAL_API_KEY_PREFIX_CHARS,
  blake2b,
  blake2b512Hex,
  constantTimeEqualBytes,
  encodeHex,
  hashVirtualApiKeySecret,
  sha256Hex,
  verifyStoredKeyHash,
  virtualApiKeyLast4,
  virtualApiKeyMaterial,
  virtualApiKeyPrefix,
} from "../../src/keys/index.js";

const SECRET = "fg_0123456789abcdef0123456789abcdef0123456789abcdef";

describe("encodeHex", () => {
  test("is lowercase, two chars per byte, no separator (Rust encode_hex)", () => {
    expect(encodeHex(new Uint8Array([0x00, 0x0f, 0xa5, 0xff]))).toBe("000fa5ff");
    expect(encodeHex(new Uint8Array())).toBe("");
  });
});

describe("BLAKE2b-512 against published vectors", () => {
  // RFC 7693 / the reference implementation's own test set.
  const VECTORS: readonly (readonly [string, string])[] = [
    [
      "",
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ],
    [
      "abc",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ],
    [
      "The quick brown fox jumps over the lazy dog",
      "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673" +
        "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
    ],
  ];

  for (const [input, expected] of VECTORS) {
    test(`blake2b512(${JSON.stringify(input.slice(0, 24))}) matches the published digest`, () => {
      expect(blake2b512Hex(input)).toBe(expected);
    });
  }

  test("exactly one block (128 bytes) is finalized, not double-compressed", () => {
    // The classic boundary bug: a 128-byte message must be compressed ONCE,
    // with last=true. Compressing a full block early and then an empty final
    // block gives a different, wrong digest.
    expect(blake2b512Hex("a".repeat(128))).toBe(
      "fc6c71f688f43ea7d60817478808f3cac753e61571865c95adbc2d9122c943a7" +
        "6b92c2cb1047ef3fe7bf6e436ec1d0a99a9e5b216780bf7fed9d7ca91d3a8f3b",
    );
  });

  test("multi-block inputs chain correctly (129 and 255 bytes)", () => {
    expect(blake2b512Hex("a".repeat(129))).toBe(
      "55e6e0eb418149a8af92fd9ddc99254781b2f522a131b4f4d984404b71a00e11" +
        "67b8124d5dcddd4c6977b299392335d6edd303da6d344d74bbef2d38101b232b",
    );
    expect(blake2b512Hex("x".repeat(255))).toBe(
      "e3e955c92e4a9b125402a5a57840f4ee07381174ca40daf2e8f49a0b5b9903c3" +
        "64c06b8669e3792608113f70d98891d1cb5a6860e388e9df497343d7ae0556f6",
    );
  });

  test("non-ASCII input is hashed as UTF-8, like Rust's as_bytes()", () => {
    expect(blake2b512Hex("ünïcödé-ключ-🔑")).toBe(
      "05ae8fe4233bc1bad735ab6978cd3c033a05b4ce2a3ba80f719a942f69616814" +
        "accd52d7bd88c4f31dd2580a9cf8738814825b5a4c625ad0eaf231cc717d4984",
    );
  });

  test("the parameter block encodes the output length (abbreviated digests)", () => {
    // A truncated BLAKE2b-512 would give the SAME leading bytes; a correctly
    // parameterised BLAKE2b-256 gives entirely different ones. This is what
    // proves `h[0] ^= 0x01010000 ^ outputBytes` rather than a slice.
    expect(encodeHex(blake2b(new TextEncoder().encode("abc"), 32))).toBe(
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    );
    expect(encodeHex(blake2b(new TextEncoder().encode("abc"), 1))).toBe("6b");
  });

  test("rejects an out-of-range output length rather than silently clamping", () => {
    expect(() => blake2b(new Uint8Array(), 0)).toThrow(RangeError);
    expect(() => blake2b(new Uint8Array(), 65)).toThrow(RangeError);
  });
});

describe("sha256Hex", () => {
  test('matches the published SHA-256 of "abc"', async () => {
    await expect(sha256Hex("abc")).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("virtual key material (Rust virtual_api_key_material)", () => {
  test("key_prefix is the first 16 characters", async () => {
    expect(VIRTUAL_API_KEY_PREFIX_CHARS).toBe(16);
    expect(virtualApiKeyPrefix(SECRET)).toBe("fg_0123456789abc");
    expect(virtualApiKeyPrefix(SECRET)).toHaveLength(16);
  });

  test("last4 is the final 4 characters", () => {
    expect(virtualApiKeyLast4(SECRET)).toBe("cdef");
  });

  test("both slice by Unicode scalar value, not UTF-16 code unit", () => {
    // Four astral code points: `.slice(0, 16)` would cut a surrogate pair in
    // half and produce a lone surrogate; Rust's `.chars().take(16)` does not.
    const astral = `${"🔑".repeat(20)}end`;
    expect([...(virtualApiKeyPrefix(astral) ?? "")]).toHaveLength(16);
    expect(virtualApiKeyPrefix(astral)).toBe("🔑".repeat(16));
    expect(virtualApiKeyLast4(astral)).toBe("🔑end");
  });

  test("the secret is trimmed before every derivation", async () => {
    const material = await virtualApiKeyMaterial(`  ${SECRET}\n`);
    const clean = await virtualApiKeyMaterial(SECRET);
    expect(material).toEqual(clean);
  });

  test("a blank secret yields no material at all (Rust None)", async () => {
    await expect(virtualApiKeyMaterial("   ")).resolves.toBeNull();
    expect(virtualApiKeyPrefix("")).toBeNull();
  });

  test("key_hash is `sha256:` + hex, and is NOT the plaintext", async () => {
    const material = await virtualApiKeyMaterial(SECRET);
    expect(material?.keyHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(material?.keyHash).not.toContain(SECRET);
    await expect(hashVirtualApiKeySecret(SECRET)).resolves.toBe(material?.keyHash);
  });
});

describe("verifyStoredKeyHash", () => {
  test("accepts the sha256: construction FerroGate mints", async () => {
    const stored = await hashVirtualApiKeySecret(SECRET);
    await expect(verifyStoredKeyHash(SECRET, stored)).resolves.toBe(true);
  });

  test("accepts a legacy blake2b: row", async () => {
    const stored = `blake2b:${blake2b512Hex(SECRET)}`;
    await expect(verifyStoredKeyHash(SECRET, stored)).resolves.toBe(true);
  });

  test("rejects a near-miss secret under both algorithms", async () => {
    const wrong = `${SECRET.slice(0, -1)}0`;
    await expect(verifyStoredKeyHash(wrong, await hashVirtualApiKeySecret(SECRET))).resolves.toBe(
      false,
    );
    await expect(verifyStoredKeyHash(wrong, `blake2b:${blake2b512Hex(SECRET)}`)).resolves.toBe(
      false,
    );
  });

  test("fails closed on an untagged, unknown-algorithm or PLAINTEXT key_hash", async () => {
    // A row whose `key_hash` column somehow holds the secret itself must never
    // authenticate — otherwise a bad migration turns the store into plaintext
    // credentials that still work.
    await expect(verifyStoredKeyHash(SECRET, SECRET)).resolves.toBe(false);
    await expect(verifyStoredKeyHash(SECRET, await sha256Hex(SECRET))).resolves.toBe(false);
    await expect(verifyStoredKeyHash(SECRET, `md5:${await sha256Hex(SECRET)}`)).resolves.toBe(
      false,
    );
    await expect(verifyStoredKeyHash(SECRET, "")).resolves.toBe(false);
  });

  test("an empty stored digest does not authenticate an empty secret", async () => {
    await expect(verifyStoredKeyHash("", "sha256:")).resolves.toBe(false);
  });
});

describe("constantTimeEqualBytes", () => {
  test("equal, differing-content and differing-length inputs", () => {
    const a = new TextEncoder().encode("abcd");
    expect(constantTimeEqualBytes(a, new TextEncoder().encode("abcd"))).toBe(true);
    expect(constantTimeEqualBytes(a, new TextEncoder().encode("abce"))).toBe(false);
    expect(constantTimeEqualBytes(a, new TextEncoder().encode("abc"))).toBe(false);
    expect(constantTimeEqualBytes(new Uint8Array(), new Uint8Array())).toBe(true);
  });

  test("a shared prefix is not enough", () => {
    expect(
      constantTimeEqualBytes(
        new TextEncoder().encode("aaaaaaaaaa"),
        new TextEncoder().encode("aaaaaaaaab"),
      ),
    ).toBe(false);
  });
});
