/**
 * XChaCha20-Poly1305 against the PUBLISHED test vectors.
 *
 * This is the whole basis of the interoperability claim. There is no Rust
 * process to diff against in an offline harness, so what stands in for it is
 * the standard the Rust crate implements: an implementation that reproduces RFC
 * 8439's and draft-irtf-cfrg-xchacha's vectors byte for byte agrees with every
 * conforming implementation, `chacha20poly1305` included.
 *
 * Every expected value below is quoted from the specification, NOT captured
 * from this implementation's output — a self-captured expectation would pass
 * for any wrong-but-stable implementation, which is exactly the vacuous shape
 * this project keeps getting bitten by.
 */
import { describe, expect, it } from "vitest";

import {
  CHACHA20_BLOCK_BYTES,
  POLY1305_TAG_BYTES,
  XCHACHA20_NONCE_BYTES,
  chacha20Block,
  chacha20Xor,
  chacha20poly1305Open,
  chacha20poly1305Seal,
  constantTimeEqual,
  hchacha20,
  poly1305,
  xchacha20poly1305Open,
  xchacha20poly1305Seal,
} from "../src/workers/xchacha20poly1305.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1)
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** RFC 8439 §2.3.2 / §2.4.2 key: the bytes 0x00..0x1f in order. */
const SEQUENTIAL_KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

/** RFC 8439 §2.4.2 and §2.8.2 plaintext. */
const SUNSCREEN = utf8(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);

describe("ChaCha20 — RFC 8439", () => {
  it("§2.3.2: the block function, key 00..1f, nonce 000000090000004a00000000, counter 1", () => {
    const block = chacha20Block(SEQUENTIAL_KEY, 1, unhex("000000090000004a00000000"));
    expect(block.length).toBe(CHACHA20_BLOCK_BYTES);
    expect(hex(block)).toBe(
      "10f1e7e4d13b5915500fdd1fa32071c4" +
        "c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2" +
        "b5129cd1de164eb9cbd083e8a2503c4e",
    );
  });

  it("§2.4.2: encrypts the sunscreen plaintext, counter 1, nonce 000000000000004a00000000", () => {
    const ciphertext = chacha20Xor(SEQUENTIAL_KEY, 1, unhex("000000000000004a00000000"), SUNSCREEN);
    expect(hex(ciphertext)).toBe(
      "6e2e359a2568f98041ba0728dd0d6981" +
        "e97e7aec1d4360c20a27afccfd9fae0b" +
        "f91b65c5524733ab8f593dabcd62b357" +
        "1639d624e65152ab8f530c359f0861d8" +
        "07ca0dbf500d6a6156a38e088a22b65e" +
        "52bc514d16ccf806818ce91ab7793736" +
        "5af90bbf74a35be6b40b8eedf2785e42" +
        "874d",
    );
  });

  it("is its own inverse — the keystream XOR round trips", () => {
    const nonce = unhex("000000000000004a00000000");
    const ciphertext = chacha20Xor(SEQUENTIAL_KEY, 1, nonce, SUNSCREEN);
    expect(hex(chacha20Xor(SEQUENTIAL_KEY, 1, nonce, ciphertext))).toBe(hex(SUNSCREEN));
  });

  it("advances the block counter across a 64-byte boundary", () => {
    // A plaintext spanning three blocks must equal the three blocks' keystream
    // concatenated. An implementation that reused counter 1 for every block
    // would pass a single-block test and fail this one.
    const nonce = unhex("000000000000004a00000000");
    const data = new Uint8Array(CHACHA20_BLOCK_BYTES * 3);
    const streamed = chacha20Xor(SEQUENTIAL_KEY, 1, nonce, data);
    const expected = new Uint8Array(CHACHA20_BLOCK_BYTES * 3);
    for (let i = 0; i < 3; i += 1) {
      expected.set(chacha20Block(SEQUENTIAL_KEY, 1 + i, nonce), i * CHACHA20_BLOCK_BYTES);
    }
    expect(hex(streamed)).toBe(hex(expected));
  });
});

describe("Poly1305 — RFC 8439 §2.5.2", () => {
  it('tags "Cryptographic Forum Research Group" with the published one-time key', () => {
    const tag = poly1305(
      utf8("Cryptographic Forum Research Group"),
      unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
    );
    expect(tag.length).toBe(POLY1305_TAG_BYTES);
    expect(hex(tag)).toBe("a8061dc1305136c6c22b8baf0c0127a9");
  });

  it("is not length-blind — the same message truncated tags differently", () => {
    const key = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    const full = poly1305(utf8("Cryptographic Forum Research Group"), key);
    const short = poly1305(utf8("Cryptographic Forum Research Grou"), key);
    expect(hex(full)).not.toBe(hex(short));
  });
});

describe("HChaCha20 — draft-irtf-cfrg-xchacha §2.2.1", () => {
  it("derives the published subkey from key 00..1f and nonce 000000090000004a0000000031415927", () => {
    expect(hex(hchacha20(SEQUENTIAL_KEY, unhex("000000090000004a0000000031415927")))).toBe(
      "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
    );
  });

  it("is NOT the ChaCha20 block function — the feed-forward addition is absent", () => {
    // If the feed-forward were (incorrectly) applied, words 0..3 would differ
    // from the published subkey by the sigma constants. Asserting the two
    // constructions disagree is what pins that the difference is real.
    const nonce16 = unhex("000000090000004a0000000031415927");
    const block = chacha20Block(SEQUENTIAL_KEY, 0x09000000, nonce16.subarray(4, 16));
    expect(hex(hchacha20(SEQUENTIAL_KEY, nonce16)).slice(0, 32)).not.toBe(hex(block).slice(0, 32));
  });
});

describe("AEAD_CHACHA20_POLY1305 — RFC 8439 §2.8.2", () => {
  const KEY = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
  const NONCE = unhex("070000004041424344454647");
  const AAD = unhex("50515253c0c1c2c3c4c5c6c7");

  const CIPHERTEXT =
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116";
  const TAG = "1ae10b594f09e26a7e902ecbd0600691";

  it("produces the published ciphertext and tag", () => {
    expect(hex(chacha20poly1305Seal(KEY, NONCE, SUNSCREEN, AAD))).toBe(CIPHERTEXT + TAG);
  });

  it("opens the published ciphertext back to the plaintext", () => {
    const opened = chacha20poly1305Open(KEY, NONCE, unhex(CIPHERTEXT + TAG), AAD);
    expect(opened).toBeDefined();
    expect(new TextDecoder().decode(opened)).toBe(new TextDecoder().decode(SUNSCREEN));
  });

  it("REFUSES a flipped AAD byte — the AAD really is authenticated", () => {
    const badAad = Uint8Array.from(AAD);
    (badAad[0] as NonNullable<(typeof badAad)[0]>) ^= 0x01;
    expect(chacha20poly1305Open(KEY, NONCE, unhex(CIPHERTEXT + TAG), badAad)).toBeUndefined();
  });

  it("REFUSES a flipped ciphertext byte, returning NO plaintext at all", () => {
    const sealed = unhex(CIPHERTEXT + TAG);
    sealed[3] = sealed[3]! ^ 0x01;
    expect(chacha20poly1305Open(KEY, NONCE, sealed, AAD)).toBeUndefined();
  });

  it("REFUSES a flipped tag byte", () => {
    const sealed = unhex(CIPHERTEXT + TAG);
    sealed[sealed.length - 1] = sealed[sealed.length - 1]! ^ 0x01;
    expect(chacha20poly1305Open(KEY, NONCE, sealed, AAD)).toBeUndefined();
  });

  it("REFUSES a frame shorter than the tag rather than reading out of bounds", () => {
    expect(chacha20poly1305Open(KEY, NONCE, new Uint8Array(4), AAD)).toBeUndefined();
  });
});

describe("XChaCha20-Poly1305 — draft-irtf-cfrg-xchacha §A.3", () => {
  const KEY = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
  const NONCE24 = Uint8Array.from({ length: 24 }, (_, i) => 0x40 + i);
  const AAD = unhex("50515253c0c1c2c3c4c5c6c7");

  const CIPHERTEXT =
    "bd6d179d3e83d43b9576579493c0e939" +
    "572a1700252bfaccbed2902c21396cbb" +
    "731c7f1b0b4aa6440bf3a82f4eda7e39" +
    "ae64c6708c54c216cb96b72e1213b452" +
    "2f8c9ba40db5d945b11b69b982c1bb9e" +
    "3f3fac2bc369488f76b2383565d3fff9" +
    "21f9664c97637da9768812f615c68b13" +
    "b52e";
  const TAG = "c0875924c1c7987947deafd8780acf49";

  it("produces the published ciphertext and tag", () => {
    expect(hex(xchacha20poly1305Seal(KEY, NONCE24, SUNSCREEN, AAD))).toBe(
      (CIPHERTEXT + TAG).replace(/\s+/g, ""),
    );
  });

  it("opens the published ciphertext", () => {
    const opened = xchacha20poly1305Open(KEY, NONCE24, unhex(CIPHERTEXT + TAG), AAD);
    expect(new TextDecoder().decode(opened)).toBe(new TextDecoder().decode(SUNSCREEN));
  });

  it("REFUSES the same ciphertext under a one-bit-different 192-bit nonce", () => {
    const nonce = Uint8Array.from(NONCE24);
    (nonce[0] as NonNullable<(typeof nonce)[0]>) ^= 0x01;
    expect(xchacha20poly1305Open(KEY, nonce, unhex(CIPHERTEXT + TAG), AAD)).toBeUndefined();
  });

  it("REFUSES a wrong key", () => {
    const key = Uint8Array.from(KEY);
    (key[31] as NonNullable<(typeof key)[31]>) ^= 0x01;
    expect(xchacha20poly1305Open(key, NONCE24, unhex(CIPHERTEXT + TAG), AAD)).toBeUndefined();
  });

  it("rejects a nonce that is not 192 bits rather than padding it", () => {
    expect(() => xchacha20poly1305Seal(KEY, new Uint8Array(12), SUNSCREEN, AAD)).toThrow(
      /24 bytes/,
    );
    expect(XCHACHA20_NONCE_BYTES).toBe(24);
  });

  it("round trips an empty plaintext and an empty AAD", () => {
    const sealed = xchacha20poly1305Seal(KEY, NONCE24, new Uint8Array(), new Uint8Array());
    expect(sealed.length).toBe(POLY1305_TAG_BYTES);
    expect(xchacha20poly1305Open(KEY, NONCE24, sealed, new Uint8Array())?.length).toBe(0);
  });

  it("round trips a payload spanning many keystream blocks", () => {
    const plaintext = Uint8Array.from({ length: 4096 }, (_, i) => (i * 31) & 0xff);
    const sealed = xchacha20poly1305Seal(KEY, NONCE24, plaintext, AAD);
    expect(hex(xchacha20poly1305Open(KEY, NONCE24, sealed, AAD)!)).toBe(hex(plaintext));
  });
});

describe("constantTimeEqual", () => {
  it("is true only for identical byte strings", () => {
    expect(constantTimeEqual(unhex("00ff10"), unhex("00ff10"))).toBe(true);
    expect(constantTimeEqual(unhex("00ff10"), unhex("00ff11"))).toBe(false);
    // A differing FIRST byte and a differing LAST byte must both be false —
    // an early-return compare would still pass this, but a compare that only
    // looked at a prefix or a suffix would not.
    expect(constantTimeEqual(unhex("01ff10"), unhex("00ff10"))).toBe(false);
    expect(constantTimeEqual(unhex("00ff10"), unhex("00ff1000"))).toBe(false);
  });
});
