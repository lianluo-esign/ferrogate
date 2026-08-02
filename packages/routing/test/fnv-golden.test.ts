/**
 * GOLDEN BUCKET TABLE for `rolloutBucket` — the Rust-anchored specification.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `rolloutBucket` is the deterministic FNV-1a-64 bucketing behind canary and
 * shadow rollout. Determinism is the whole product promise: the SAME sticky key
 * must land in the SAME bucket on every Worker, every isolate, and across a
 * redeploy — otherwise a canary silently reshuffles traffic and an operator's
 * 5% experiment becomes noise.
 *
 * Every other test in this package proves the TS is SELF-CONSISTENT, which is
 * exactly what a wrong-but-stable hash also achieves. This table is the only
 * gate that proves the TS agrees with the ORIGINAL Rust implementation
 * (`crates/ferrogate-routing/src/rollout.rs`). Once `crates/**` is deleted the
 * table can never be regenerated, so THIS FILE IS THE SPECIFICATION. Do not
 * "fix" a value here to make a test pass: a disagreement means the TS
 * implementation diverged and the implementation is what must change.
 *
 * PROVENANCE
 * ----------
 * Each `raw` / `bucket` pair was produced by an independent transcription of
 * the Rust source into a third language (never by running the TS, and never by
 * running cargo — the clean-room rule holds), following `rollout.rs` verbatim:
 *
 *     const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
 *     const FNV_PRIME: u64        = 0x0000_0100_0000_01b3;
 *     fn fnv1a64(bytes: &[u8]) -> u64 {
 *         let mut hash = FNV_OFFSET_BASIS;
 *         for byte in bytes { hash ^= u64::from(*byte);
 *                             hash = hash.wrapping_mul(FNV_PRIME); }
 *         hash
 *     }
 *     pub fn rollout_bucket(salt: &str, sticky_key: &str) -> u8 {
 *         // salt.as_bytes() ++ [0u8] ++ sticky_key.as_bytes()   (UTF-8)
 *         (fnv1a64(&input) % 100) as u8
 *     }
 *
 * That transcription was itself anchored against the canonical FNV-1a-64
 * reference vectors before generating anything, so it cannot silently repeat a
 * mistake made in the TS port:
 *
 *     ""       -> 0xcbf29ce484222325      "d"      -> 0xaf63d94c8601e773
 *     "a"      -> 0xaf63dc4c8601ec8c      "fo"     -> 0x08985907b541d342
 *     "b"      -> 0xaf63df4c8601f1a5      "foo"    -> 0xdcb27518fed9d577
 *     "c"      -> 0xaf63de4c8601eff2      "foobar" -> 0x85944171f73967e8
 *
 * WHAT THE VECTORS ARE CHOSEN TO CATCH
 * ------------------------------------
 * The table is built so that every divergence that stays SELF-CONSISTENT is
 * still caught:
 *   - wrong offset basis / wrong prime ........ every row
 *   - FNV-1 (multiply-then-xor) instead of 1a . every row
 *   - hashing UTF-16 code units, latin1 bytes,
 *     or code points instead of UTF-8 bytes ... the multi-byte + astral rows
 *   - a changed modulo (100 -> 101/128/...) ... 163 of 165 rows disagree under
 *                                               `% 101`, 160 under `% 128`
 *   - a signed (i64) fold of the hash ......... 87 rows have bit 63 set
 *   - a dropped/moved NUL separator ........... the salt/key framing rows
 *   - case folding or trailing-byte loss ...... the case-only and last-byte-only pairs
 */
import { describe, expect, test } from "vitest";
import { canarySelected, fnv1a64, rolloutBucket, shadowSampled } from "@ferrogate/routing";

/** 1000 ASCII bytes. */
const LONG_ASCII = "0123456789".repeat(100);
/** 600 CJK code points = 1800 UTF-8 bytes. */
const LONG_CJK = "\u65e5\u672c\u8a9e".repeat(200);

interface GoldenRow {
  /** `salt` argument to `rolloutBucket`. */
  readonly salt: string;
  /** `stickyKey` argument to `rolloutBucket`. */
  readonly key: string;
  /** Rust `fnv1a64(salt_bytes ++ 0x00 ++ key_bytes)`, full 64 bits. */
  readonly raw: bigint;
  /** Rust `rollout_bucket(salt, key)` — `raw % 100`. */
  readonly bucket: number;
  /** Why this vector is in the table. */
  readonly why: string;
}

// prettier-ignore
const GOLDEN: readonly GoldenRow[] = [
  // ---- salt "canary" (production canary salt) ----
  { salt: "canary", key: "", raw: 0x6e0c1b4c2a0d53bbn, bucket: 55, why: "empty string" },
  { salt: "canary", key: "a", raw: 0x0be63c6b74a57b6en, bucket: 2, why: "single ASCII byte" },
  { salt: "canary", key: "A", raw: 0x0be65c6b74a5b1cen, bucket: 54, why: "case-flipped vs 'a'" },
  { salt: "canary", key: "z", raw: 0x0be6236b74a550f3n, bucket: 27, why: "single ASCII letter, high" },
  { salt: "canary", key: "0", raw: 0x0be5ed6b74a4f531n, bucket: 33, why: "single ASCII digit" },
  { salt: "canary", key: " ", raw: 0x0be5fd6b74a51061n, bucket: 9, why: "single space" },
  { salt: "canary", key: "  ", raw: 0xdcddde97347a9e73n, bucket: 51, why: "two spaces (length sensitivity)" },
  { salt: "canary", key: "tenant-alpha", raw: 0xa95582926a936032n, bucket: 54, why: "plain ASCII tenant id" },
  { salt: "canary", key: "Tenant-Alpha", raw: 0x2f0ee6c1bc3fcb72n, bucket: 42, why: "case-only difference vs tenant-alpha" },
  { salt: "canary", key: "TENANT-ALPHA", raw: 0xee8a1590af3158d2n, bucket: 18, why: "all-caps, case-only difference" },
  { salt: "canary", key: "sk-live-000000000000000000000000000a", raw: 0xdc82e21865df63den, bucket: 90, why: "api-key shaped" },
  { salt: "canary", key: "sk-live-000000000000000000000000000b", raw: 0xdc82e11865df622bn, bucket: 79, why: "differs in LAST byte only" },
  { salt: "canary", key: "key-1000", raw: 0x9058a2d7b27291fcn, bucket: 88, why: "sequential key" },
  { salt: "canary", key: "key-1001", raw: 0x9058a3d7b27293afn, bucket: 99, why: "differs in last byte only" },
  { salt: "canary", key: "key-1002", raw: 0x9058a4d7b2729562n, bucket: 10, why: "differs in last byte only" },
  { salt: "canary", key: "caf\u00e9", raw: 0x75a08981fed6192fn, bucket: 83, why: "2-byte UTF-8 U+00E9; latin1 truncation diverges" },
  { salt: "canary", key: "caf\u00c9", raw: 0x75a0a981fed64f8fn, bucket: 35, why: "2-byte UTF-8, case-only difference" },
  { salt: "canary", key: "\u65e5\u672c\u8a9e", raw: 0xd7c32615a9844c65n, bucket: 77, why: "3-byte UTF-8 CJK" },
  { salt: "canary", key: "\u65e5\u672c\u8a9f", raw: 0xd7c32515a9844ab2n, bucket: 66, why: "3-byte UTF-8, last codepoint +1" },
  { salt: "canary", key: "\u{1f680}", raw: 0xe2f3851d7207a8f0n, bucket: 60, why: "4-byte UTF-8 U+1F680, surrogate pair in UTF-16" },
  { salt: "canary", key: "\u{1f680}\u{1f680}", raw: 0xfd4c54740b5aeecfn, bucket: 35, why: "two astral codepoints" },
  { salt: "canary", key: "a\u0000b", raw: 0xe9c150ef61cea818n, bucket: 20, why: "embedded NUL (framing edge)" },
  { salt: "canary", key: "\u0000", raw: 0x0be61d6b74a546c1n, bucket: 61, why: "lone NUL key (framing edge)" },
  { salt: "canary", key: "\u007f", raw: 0x0be6266b74a5560cn, bucket: 60, why: "U+007F, last 1-byte UTF-8" },
  { salt: "canary", key: "\u0080", raw: 0xdc69f2973417cfe1n, bucket: 65, why: "U+0080, first 2-byte UTF-8" },
  { salt: "canary", key: "\u07ff", raw: 0xdc227b9733db0309n, bucket: 45, why: "U+07FF, last 2-byte UTF-8" },
  { salt: "canary", key: "\u0800", raw: 0x9b8d6decf0e924a9n, bucket: 29, why: "U+0800, first 3-byte UTF-8" },
  { salt: "canary", key: "\uffff", raw: 0x5e9727ecce4ac812n, bucket: 38, why: "U+FFFF, last BMP 3-byte UTF-8" },
  { salt: "canary", key: "\u{10000}", raw: 0x7243e21d322e674bn, bucket: 15, why: "U+10000, first 4-byte UTF-8" },
  { salt: "canary", key: "\u{10ffff}", raw: 0x1ce5343ea30baa5cn, bucket: 52, why: "U+10FFFF, last codepoint" },
  { salt: "canary", key: LONG_ASCII, raw: 0x16d20cd920c409abn, bucket: 39, why: "very long: 1000 ASCII bytes" },
  { salt: "canary", key: LONG_ASCII + "0", raw: 0x8af56ff2ad1c5261n, bucket: 21, why: "very long, one byte longer" },
  { salt: "canary", key: LONG_CJK, raw: 0x1030cb769e14888bn, bucket: 23, why: "very long: 1800 UTF-8 bytes of CJK" },

  // ---- salt "shadow" (production shadow salt) ----
  { salt: "shadow", key: "", raw: 0x874279bb4948b613n, bucket: 75, why: "empty string" },
  { salt: "shadow", key: "a", raw: 0x1eab4b3d868e03b6n, bucket: 18, why: "single ASCII byte" },
  { salt: "shadow", key: "A", raw: 0x1eab2b3d868dcd56n, bucket: 66, why: "case-flipped vs 'a'" },
  { salt: "shadow", key: "z", raw: 0x1eab423d868df46bn, bucket: 19, why: "single ASCII letter, high" },
  { salt: "shadow", key: "0", raw: 0x1eaafc3d868d7d79n, bucket: 49, why: "single ASCII digit" },
  { salt: "shadow", key: " ", raw: 0x1eab0c3d868d98a9n, bucket: 25, why: "single space" },
  { salt: "shadow", key: "  ", raw: 0xaa3e558ba29a30cbn, bucket: 23, why: "two spaces (length sensitivity)" },
  { salt: "shadow", key: "tenant-alpha", raw: 0xb5fcb5842af2737an, bucket: 2, why: "plain ASCII tenant id" },
  { salt: "shadow", key: "Tenant-Alpha", raw: 0x0c90144834aea9fan, bucket: 38, why: "case-only difference vs tenant-alpha" },
  { salt: "shadow", key: "TENANT-ALPHA", raw: 0x099326538c4184dan, bucket: 2, why: "all-caps, case-only difference" },
  { salt: "shadow", key: "sk-live-000000000000000000000000000a", raw: 0x8bff8f6307dbea46n, bucket: 26, why: "api-key shaped" },
  { salt: "shadow", key: "sk-live-000000000000000000000000000b", raw: 0x8bff8e6307dbe893n, bucket: 15, why: "differs in LAST byte only" },
  { salt: "shadow", key: "key-1000", raw: 0xcf4bd05480e949a4n, bucket: 12, why: "sequential key" },
  { salt: "shadow", key: "key-1001", raw: 0xcf4bd15480e94b57n, bucket: 23, why: "differs in last byte only" },
  { salt: "shadow", key: "key-1002", raw: 0xcf4bd25480e94d0an, bucket: 34, why: "differs in last byte only" },
  { salt: "shadow", key: "caf\u00e9", raw: 0x32b5b4a76953a3a7n, bucket: 11, why: "2-byte UTF-8 U+00E9; latin1 truncation diverges" },
  { salt: "shadow", key: "caf\u00c9", raw: 0x32b594a769536d47n, bucket: 59, why: "2-byte UTF-8, case-only difference" },
  { salt: "shadow", key: "\u65e5\u672c\u8a9e", raw: 0x9f5cf0f29a6fdbbdn, bucket: 61, why: "3-byte UTF-8 CJK" },
  { salt: "shadow", key: "\u65e5\u672c\u8a9f", raw: 0x9f5ceff29a6fda0an, bucket: 50, why: "3-byte UTF-8, last codepoint +1" },
  { salt: "shadow", key: "\u{1f680}", raw: 0x4d1e347934b6c0c8n, bucket: 56, why: "4-byte UTF-8 U+1F680, surrogate pair in UTF-16" },
  { salt: "shadow", key: "\u{1f680}\u{1f680}", raw: 0x33e17c8868578047n, bucket: 51, why: "two astral codepoints" },
  { salt: "shadow", key: "a\u0000b", raw: 0x043e0a468174c060n, bucket: 84, why: "embedded NUL (framing edge)" },
  { salt: "shadow", key: "\u0000", raw: 0x1eaaec3d868d6249n, bucket: 73, why: "lone NUL key (framing edge)" },
  { salt: "shadow", key: "\u007f", raw: 0x1eab453d868df984n, bucket: 52, why: "U+007F, last 1-byte UTF-8" },
  { salt: "shadow", key: "\u0080", raw: 0xac57e98ba46373f9n, bucket: 93, why: "U+0080, first 2-byte UTF-8" },
  { salt: "shadow", key: "\u07ff", raw: 0xac45e28ba45341e1n, bucket: 53, why: "U+07FF, last 2-byte UTF-8" },
  { salt: "shadow", key: "\u0800", raw: 0x5f85e748f88f2e31n, bucket: 77, why: "U+0800, first 3-byte UTF-8" },
  { salt: "shadow", key: "\uffff", raw: 0xb0c281492780134an, bucket: 82, why: "U+FFFF, last BMP 3-byte UTF-8" },
  { salt: "shadow", key: "\u{10000}", raw: 0x673da179438d4f63n, bucket: 47, why: "U+10000, first 4-byte UTF-8" },
  { salt: "shadow", key: "\u{10ffff}", raw: 0x9c3ff39b02bbc2a4n, bucket: 84, why: "U+10FFFF, last codepoint" },
  { salt: "shadow", key: LONG_ASCII, raw: 0xe68d26956de81e83n, bucket: 75, why: "very long: 1000 ASCII bytes" },
  { salt: "shadow", key: LONG_ASCII + "0", raw: 0xa9f742e9c16c2a29n, bucket: 69, why: "very long, one byte longer" },
  { salt: "shadow", key: LONG_CJK, raw: 0x097a38a2237bf523n, bucket: 7, why: "very long: 1800 UTF-8 bytes of CJK" },

  // ---- salt "" (empty salt) ----
  { salt: "", key: "", raw: 0xaf63bd4c8601b7dfn, bucket: 55, why: "empty string" },
  { salt: "", key: "a", raw: 0x08326707b4eb37dan, bucket: 26, why: "single ASCII byte" },
  { salt: "", key: "A", raw: 0x08324707b4eb017an, bucket: 74, why: "case-flipped vs 'a'" },
  { salt: "", key: "z", raw: 0x08324e07b4eb0d5fn, bucket: 51, why: "single ASCII letter, high" },
  { salt: "", key: "0", raw: 0x08329807b4eb8b1dn, bucket: 65, why: "single ASCII digit" },
  { salt: "", key: " ", raw: 0x0832a807b4eba64dn, bucket: 41, why: "single space" },
  { salt: "", key: "  ", raw: 0xd9b9f2186c6bcb37n, bucket: 71, why: "two spaces (length sensitivity)" },
  { salt: "", key: "tenant-alpha", raw: 0x5c48d093115fd71en, bucket: 26, why: "plain ASCII tenant id" },
  { salt: "", key: "Tenant-Alpha", raw: 0xb2dc2f571b1c0d9en, bucket: 78, why: "case-only difference vs tenant-alpha" },
  { salt: "", key: "TENANT-ALPHA", raw: 0x5be1a44bb133a9fen, bucket: 26, why: "all-caps, case-only difference" },
  { salt: "", key: "sk-live-000000000000000000000000000a", raw: 0xe531cd75839c023an, bucket: 82, why: "api-key shaped" },
  { salt: "", key: "sk-live-000000000000000000000000000b", raw: 0xe531cc75839c0087n, bucket: 71, why: "differs in LAST byte only" },
  { salt: "", key: "key-1000", raw: 0x43de2a15fe29fb90n, bucket: 92, why: "sequential key" },
  { salt: "", key: "key-1001", raw: 0x43de2b15fe29fd43n, bucket: 3, why: "differs in last byte only" },
  { salt: "", key: "key-1002", raw: 0x43de2c15fe29fef6n, bucket: 14, why: "differs in last byte only" },
  { salt: "", key: "caf\u00e9", raw: 0x9e497c1388a05983n, bucket: 75, why: "2-byte UTF-8 U+00E9; latin1 truncation diverges" },
  { salt: "", key: "caf\u00c9", raw: 0x9e495c1388a02323n, bucket: 23, why: "2-byte UTF-8, case-only difference" },
  { salt: "", key: "\u65e5\u672c\u8a9e", raw: 0x9e4ddcf33f63a809n, bucket: 37, why: "3-byte UTF-8 CJK" },
  { salt: "", key: "\u65e5\u672c\u8a9f", raw: 0x9e4ddbf33f63a656n, bucket: 26, why: "3-byte UTF-8, last codepoint +1" },
  { salt: "", key: "\u{1f680}", raw: 0xabc6d51ae975079cn, bucket: 16, why: "4-byte UTF-8 U+1F680, surrogate pair in UTF-16" },
  { salt: "", key: "\u{1f680}\u{1f680}", raw: 0x2a5d51c6f9cb6733n, bucket: 95, why: "two astral codepoints" },
  { salt: "", key: "a\u0000b", raw: 0x2f4c397efbe59964n, bucket: 4, why: "embedded NUL (framing edge)" },
  { salt: "", key: "\u0000", raw: 0x08328807b4eb6fedn, bucket: 89, why: "lone NUL key (framing edge)" },
  { salt: "", key: "\u007f", raw: 0x08324907b4eb04e0n, bucket: 96, why: "U+007F, last 1-byte UTF-8" },
  { salt: "", key: "\u0080", raw: 0xd6ba461869dfe425n, bucket: 57, why: "U+0080, first 2-byte UTF-8" },
  { salt: "", key: "\u07ff", raw: 0xd657f718698c938dn, bucket: 45, why: "U+07FF, last 2-byte UTF-8" },
  { salt: "", key: "\u0800", raw: 0xe557d67c8e9c0935n, bucket: 29, why: "U+0800, first 3-byte UTF-8" },
  { salt: "", key: "\uffff", raw: 0x6000407c421e1986n, bucket: 94, why: "U+FFFF, last BMP 3-byte UTF-8" },
  { salt: "", key: "\u{10000}", raw: 0x075d5a1b1c48976fn, bucket: 99, why: "U+10000, first 4-byte UTF-8" },
  { salt: "", key: "\u{10ffff}", raw: 0x2ed23bff3c01e000n, bucket: 20, why: "U+10FFFF, last codepoint" },
  { salt: "", key: LONG_ASCII, raw: 0x558a10de978d36afn, bucket: 7, why: "very long: 1000 ASCII bytes" },
  { salt: "", key: LONG_ASCII + "0", raw: 0xe6d1493b84f3d02dn, bucket: 49, why: "very long, one byte longer" },
  { salt: "", key: LONG_CJK, raw: 0xcd7284dd9503dcafn, bucket: 99, why: "very long: 1800 UTF-8 bytes of CJK" },

  // ---- salt "\u65e5" (multi-byte salt) ----
  { salt: "\u65e5", key: "", raw: 0x018198a712dc4307n, bucket: 11, why: "empty string" },
  { salt: "\u65e5", key: "a", raw: 0x6b79c9e50c468652n, bucket: 86, why: "single ASCII byte" },
  { salt: "\u65e5", key: "A", raw: 0x6b79a9e50c464ff2n, bucket: 34, why: "case-flipped vs 'a'" },
  { salt: "\u65e5", key: "z", raw: 0x6b79e0e50c46ad67n, bucket: 39, why: "single ASCII letter, high" },
  { salt: "\u65e5", key: "0", raw: 0x6b799ae50c463675n, bucket: 69, why: "single ASCII digit" },
  { salt: "\u65e5", key: " ", raw: 0x6b798ae50c461b45n, bucket: 93, why: "single space" },
  { salt: "\u65e5", key: "  ", raw: 0xe5a26833db208c9fn, bucket: 71, why: "two spaces (length sensitivity)" },
  { salt: "\u65e5", key: "tenant-alpha", raw: 0xf5ae7950153ca036n, bucket: 50, why: "plain ASCII tenant id" },
  { salt: "\u65e5", key: "Tenant-Alpha", raw: 0x373caecfb9147d76n, bucket: 34, why: "case-only difference vs tenant-alpha" },
  { salt: "\u65e5", key: "TENANT-ALPHA", raw: 0xae120eb52350b616n, bucket: 66, why: "all-caps, case-only difference" },
  { salt: "\u65e5", key: "sk-live-000000000000000000000000000a", raw: 0xdcddf1abcaa1db72n, bucket: 34, why: "api-key shaped" },
  { salt: "\u65e5", key: "sk-live-000000000000000000000000000b", raw: 0xdcddf0abcaa1d9bfn, bucket: 23, why: "differs in LAST byte only" },
  { salt: "\u65e5", key: "key-1000", raw: 0x79506d155b34d6e8n, bucket: 80, why: "sequential key" },
  { salt: "\u65e5", key: "key-1001", raw: 0x79506e155b34d89bn, bucket: 91, why: "differs in last byte only" },
  { salt: "\u65e5", key: "key-1002", raw: 0x79506f155b34da4en, bucket: 2, why: "differs in last byte only" },
  { salt: "\u65e5", key: "caf\u00e9", raw: 0x809fad9dd9cdfe6bn, bucket: 15, why: "2-byte UTF-8 U+00E9; latin1 truncation diverges" },
  { salt: "\u65e5", key: "caf\u00c9", raw: 0x809f8d9dd9cdc80bn, bucket: 63, why: "2-byte UTF-8, case-only difference" },
  { salt: "\u65e5", key: "\u65e5\u672c\u8a9e", raw: 0xc0d8b981f35a70d1n, bucket: 61, why: "3-byte UTF-8 CJK" },
  { salt: "\u65e5", key: "\u65e5\u672c\u8a9f", raw: 0xc0d8b881f35a6f1en, bucket: 50, why: "3-byte UTF-8, last codepoint +1" },
  { salt: "\u65e5", key: "\u{1f680}", raw: 0x6b867d9fd3fef7e4n, bucket: 0, why: "4-byte UTF-8 U+1F680, surrogate pair in UTF-16" },
  { salt: "\u65e5", key: "\u{1f680}\u{1f680}", raw: 0xd65b739d428aa39bn, bucket: 19, why: "two astral codepoints" },
  { salt: "\u65e5", key: "a\u0000b", raw: 0x74cc121e8d09ff5cn, bucket: 0, why: "embedded NUL (framing edge)" },
  { salt: "\u65e5", key: "\u0000", raw: 0x6b796ae50c45e4e5n, bucket: 41, why: "lone NUL key (framing edge)" },
  { salt: "\u65e5", key: "\u007f", raw: 0x6b79dbe50c46a4e8n, bucket: 84, why: "U+007F, last 1-byte UTF-8" },
  { salt: "\u65e5", key: "\u0080", raw: 0xe7babc33dce7b00dn, bucket: 21, why: "U+0080, first 2-byte UTF-8" },
  { salt: "\u65e5", key: "\u07ff", raw: 0xe7fc7d33dd208ef5n, bucket: 9, why: "U+07FF, last 2-byte UTF-8" },
  { salt: "\u65e5", key: "\u0800", raw: 0xd0ec6f2104db846dn, bucket: 57, why: "U+0800, first 3-byte UTF-8" },
  { salt: "\u65e5", key: "\uffff", raw: 0xdbe999210bbe6c6en, bucket: 2, why: "U+FFFF, last BMP 3-byte UTF-8" },
  { salt: "\u65e5", key: "\u{10000}", raw: 0x3d29729fb8dee7b7n, bucket: 75, why: "U+10000, first 4-byte UTF-8" },
  { salt: "\u65e5", key: "\u{10ffff}", raw: 0x319a947ea2feff98n, bucket: 0, why: "U+10FFFF, last codepoint" },
  { salt: "\u65e5", key: LONG_ASCII, raw: 0x42564f9badcee657n, bucket: 27, why: "very long: 1000 ASCII bytes" },
  { salt: "\u65e5", key: LONG_ASCII + "0", raw: 0x878fac8856918105n, bucket: 21, why: "very long, one byte longer" },
  { salt: "\u65e5", key: LONG_CJK, raw: 0x38ace1d9c894fe17n, bucket: 55, why: "very long: 1800 UTF-8 bytes of CJK" },

  // ---- salt "canary " (salt with trailing space) ----
  { salt: "canary ", key: "", raw: 0x0c52dd6b7501abe1n, bucket: 1, why: "empty string" },
  { salt: "canary ", key: "a", raw: 0xf279bd97d1d66a80n, bucket: 60, why: "single ASCII byte" },
  { salt: "canary ", key: "A", raw: 0xf279dd97d1d6a0e0n, bucket: 12, why: "case-flipped vs 'a'" },
  { salt: "canary ", key: "z", raw: 0xf279d897d1d69861n, bucket: 57, why: "single ASCII letter, high" },
  { salt: "canary ", key: "0", raw: 0xf27a0e97d1d6f423n, bucket: 51, why: "single ASCII digit" },
  { salt: "canary ", key: " ", raw: 0xf279fe97d1d6d8f3n, bucket: 75, why: "single space" },
  { salt: "canary ", key: "  ", raw: 0xdc246ef990126e89n, bucket: 49, why: "two spaces (length sensitivity)" },
  { salt: "canary ", key: "tenant-alpha", raw: 0x0bb5c25d219b4be0n, bucket: 36, why: "plain ASCII tenant id" },
  { salt: "canary ", key: "Tenant-Alpha", raw: 0x62a6d947440c3a60n, bucket: 96, why: "case-only difference vs tenant-alpha" },
  { salt: "canary ", key: "TENANT-ALPHA", raw: 0xb16925c0c521a500n, bucket: 76, why: "all-caps, case-only difference" },
  { salt: "canary ", key: "sk-live-000000000000000000000000000a", raw: 0xb89f0b242305a260n, bucket: 28, why: "api-key shaped" },
  { salt: "canary ", key: "sk-live-000000000000000000000000000b", raw: 0xb89f0e242305a779n, bucket: 61, why: "differs in LAST byte only" },
  { salt: "canary ", key: "key-1000", raw: 0x9da86d128c3d9aben, bucket: 22, why: "sequential key" },
  { salt: "canary ", key: "key-1001", raw: 0x9da86e128c3d9c71n, bucket: 33, why: "differs in last byte only" },
  { salt: "canary ", key: "key-1002", raw: 0x9da86b128c3d9758n, bucket: 0, why: "differs in last byte only" },
  { salt: "canary ", key: "caf\u00e9", raw: 0x8b64c67d7b348925n, bucket: 1, why: "2-byte UTF-8 U+00E9; latin1 truncation diverges" },
  { salt: "canary ", key: "caf\u00c9", raw: 0x8b64e67d7b34bf85n, bucket: 53, why: "2-byte UTF-8, case-only difference" },
  { salt: "canary ", key: "\u65e5\u672c\u8a9e", raw: 0x5d46efc592704683n, bucket: 63, why: "3-byte UTF-8 CJK" },
  { salt: "canary ", key: "\u65e5\u672c\u8a9f", raw: 0x5d46eec5927044d0n, bucket: 52, why: "3-byte UTF-8, last codepoint +1" },
  { salt: "canary ", key: "\u{1f680}", raw: 0xacb78020a53ddbden, bucket: 62, why: "4-byte UTF-8 U+1F680, surrogate pair in UTF-16" },
  { salt: "canary ", key: "\u{1f680}\u{1f680}", raw: 0x1cd0f7b9821b18ddn, bucket: 5, why: "two astral codepoints" },
  { salt: "canary ", key: "a\u0000b", raw: 0xf1bc020e90c73506n, bucket: 42, why: "embedded NUL (framing edge)" },
  { salt: "canary ", key: "\u0000", raw: 0xf27a1e97d1d70f53n, bucket: 27, why: "lone NUL key (framing edge)" },
  { salt: "canary ", key: "\u007f", raw: 0xf279db97d1d69d7an, bucket: 90, why: "U+007F, last 1-byte UTF-8" },
  { salt: "canary ", key: "\u0080", raw: 0xda0c1af98e4b4b1bn, bucket: 99, why: "U+0080, first 2-byte UTF-8" },
  { salt: "canary ", key: "\u07ff", raw: 0xda67e7f98e99531fn, bucket: 35, why: "U+07FF, last 2-byte UTF-8" },
  { salt: "canary ", key: "\u0800", raw: 0xa3885b0c1fe2178bn, bucket: 11, why: "U+0800, first 3-byte UTF-8" },
  { salt: "canary ", key: "\uffff", raw: 0x15219d0c60811850n, bucket: 92, why: "U+FFFF, last BMP 3-byte UTF-8" },
  { salt: "canary ", key: "\u{10000}", raw: 0x623b91207c08b0d1n, bucket: 61, why: "U+10000, first 4-byte UTF-8" },
  { salt: "canary ", key: "\u{10ffff}", raw: 0xd59cdb413cc4bb56n, bucket: 62, why: "U+10FFFF, last codepoint" },
  { salt: "canary ", key: LONG_ASCII, raw: 0x7aa52ca0f896f471n, bucket: 81, why: "very long: 1000 ASCII bytes" },
  { salt: "canary ", key: LONG_ASCII + "0", raw: 0xfd9f168668810a73n, bucket: 31, why: "very long, one byte longer" },
  { salt: "canary ", key: LONG_CJK, raw: 0xc56364a64e65dbf1n, bucket: 61, why: "very long: 1800 UTF-8 bytes of CJK" },
];

/**
 * The framing the Rust builds before hashing: `salt` UTF-8 bytes, one `0x00`
 * separator, then `stickyKey` UTF-8 bytes. Written out longhand HERE rather
 * than imported, so that the `raw` column gates the production framing instead
 * of agreeing with whatever the production framing happens to be.
 */
function rustFraming(salt: string, stickyKey: string): Uint8Array {
  const enc = new TextEncoder();
  const s = enc.encode(salt);
  const k = enc.encode(stickyKey);
  const out = new Uint8Array(s.length + 1 + k.length);
  out.set(s, 0);
  out[s.length] = 0x00;
  out.set(k, s.length + 1);
  return out;
}

/** Compact, greppable label for a vector (keys may be 1800 bytes long). */
function label(row: GoldenRow, index: number): string {
  const key = row.key.length > 24 ? `${row.key.slice(0, 24)}...(${row.key.length} chars)` : row.key;
  return `#${index} salt=${JSON.stringify(row.salt)} key=${JSON.stringify(key)} [${row.why}]`;
}

describe("rolloutBucket golden table (anchored to the Rust implementation)", () => {
  test("every vector lands in the bucket the Rust computes", () => {
    const diverged: string[] = [];
    GOLDEN.forEach((row, index) => {
      const actual = rolloutBucket(row.salt, row.key);
      if (actual !== row.bucket) {
        diverged.push(`${label(row, index)}: rust=${row.bucket} ts=${actual}`);
      }
    });
    // A non-empty list is a CLASS A regression: the TS bucketing disagrees with
    // the Rust and a live canary would reshuffle. Fix the implementation.
    expect(diverged).toEqual([]);
  });

  test("every vector hashes to the full 64-bit value the Rust computes", () => {
    // Pins the hash itself, not just its residue mod 100: a mutation that only
    // perturbs high bits survives the bucket check on most keys but dies here.
    const diverged: string[] = [];
    GOLDEN.forEach((row, index) => {
      const actual = fnv1a64(rustFraming(row.salt, row.key));
      if (actual !== row.raw) {
        diverged.push(
          `${label(row, index)}: rust=0x${row.raw.toString(16).padStart(16, "0")} ts=0x${actual
            .toString(16)
            .padStart(16, "0")}`,
        );
      }
    });
    expect(diverged).toEqual([]);
  });

  test("rolloutBucket frames its input as salt + 0x00 + key, exactly as the Rust does", () => {
    // Cross-checks the production framing against the longhand one above; with
    // the previous test this makes the framing Rust-anchored, not merely
    // self-consistent.
    const diverged: string[] = [];
    GOLDEN.forEach((row, index) => {
      const viaFraming = Number(fnv1a64(rustFraming(row.salt, row.key)) % 100n);
      const viaProduct = rolloutBucket(row.salt, row.key);
      if (viaFraming !== viaProduct) {
        diverged.push(`${label(row, index)}: framing=${viaFraming} rolloutBucket=${viaProduct}`);
      }
    });
    expect(diverged).toEqual([]);
  });

  test("canary/shadow selection flips at exactly the Rust bucket boundary", () => {
    // Behavioural, not source-text: for a key whose Rust bucket is b, a canary
    // at b% must EXCLUDE it and a canary at (b+1)% must INCLUDE it. That pins
    // the salt, the bucket value and the strict `<` all at once. Rows with
    // bucket 0 or 99 are skipped because the percent<=0 / percent>=100
    // short-circuits would answer without consulting the bucket.
    const failures: string[] = [];
    let exercised = 0;
    GOLDEN.forEach((row, index) => {
      if (row.salt !== "canary" && row.salt !== "shadow") return;
      if (row.bucket < 1 || row.bucket > 98) return;
      const select = row.salt === "canary" ? canarySelected : shadowSampled;
      exercised += 1;
      if (select(row.key, row.bucket)) {
        failures.push(`${label(row, index)}: selected at percent=${row.bucket}, must be excluded`);
      }
      if (!select(row.key, row.bucket + 1)) {
        failures.push(
          `${label(row, index)}: not selected at percent=${row.bucket + 1}, must be included`,
        );
      }
    });
    expect(failures).toEqual([]);
    // Guards the guard: if the skip conditions ever swallow the whole table the
    // assertion above would pass vacuously.
    expect(exercised).toBeGreaterThan(50);
  });

  test("the table itself is non-degenerate", () => {
    // A golden table that has been quietly trimmed to a handful of ASCII keys
    // stops catching the mutations it exists to catch. These bounds are the
    // discrimination measured when the table was generated.
    expect(GOLDEN.length).toBe(165);
    expect(new Set(GOLDEN.map((r) => r.bucket)).size).toBeGreaterThanOrEqual(60);
    // Rows whose hash has bit 63 set — these are what kill a signed (i64) fold.
    const topBit = GOLDEN.filter((r) => (r.raw >> 63n) === 1n).length;
    expect(topBit).toBeGreaterThanOrEqual(40);
    // Rows whose key is not pure ASCII — these are what kill UTF-16/latin1 hashing.
    const multiByte = GOLDEN.filter((r) => new TextEncoder().encode(r.key).length > r.key.length);
    expect(multiByte.length).toBeGreaterThanOrEqual(30);
    // Rows that disagree with the golden bucket under a changed modulo.
    const modSensitive = GOLDEN.filter((r) => Number(r.raw % 101n) !== r.bucket).length;
    expect(modSensitive).toBeGreaterThanOrEqual(150);
    // Every bucket is a Rust `u8` in 0..=99.
    for (const row of GOLDEN) {
      expect(Number.isInteger(row.bucket)).toBe(true);
      expect(row.bucket).toBeGreaterThanOrEqual(0);
      expect(row.bucket).toBeLessThanOrEqual(99);
      expect(row.raw).toBeGreaterThanOrEqual(0n);
      expect(row.raw).toBeLessThanOrEqual(0xffff_ffff_ffff_ffffn);
    }
  });
});
