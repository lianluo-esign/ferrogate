/**
 * SigV4 GOLDEN VECTORS — the pin that outlives `crates/**` (item **L11**).
 *
 * WHY THIS FILE EXISTS, stated so it cannot be deleted by accident.
 *
 * A structurally wrong AWS SigV4 canonical request produces a signature that is
 * *self-consistently wrong*: every property test written against the signer's
 * own output still passes (it is deterministic, it is 64 lowercase hex chars, a
 * different body still yields a different signature), and every real
 * AWS/Bedrock call fails with an opaque `403 SignatureDoesNotMatch`. Before this
 * file, `test/crypto-sigv4.test.ts` asserted only that shape, and
 * `cert3-controlplane-libs.md §7.11` demonstrated the consequence: deleting the
 * mandatory blank line between the canonical headers and the signed-header list
 * left `packages/providers` **75 / 75 GREEN** while breaking every Bedrock and
 * every S3-compatible asset request the product makes. That result was
 * REPRODUCED on this tree before this file was written (see the ledger below).
 *
 * The only defence against a self-consistently wrong signer is a vector derived
 * from an INDEPENDENT implementation. Three independent derivations agree on
 * every literal below:
 *
 *   1. `crates/ferrogate-providers/src/sigv4.rs:225-233` (`sign_canonical`) —
 *      the crate this package is a port of, whose canonical-request `format!`
 *      is character-for-character the layout pinned here. **This reference is
 *      deleted when `crates/**` is deleted, which is exactly why the vectors
 *      are transcribed into assertions now.**
 *   2. A from-scratch Python implementation (`hashlib`/`hmac`) written against
 *      AWS's published algorithm text, not against this code — run by cert-3
 *      (§7.11) and re-run independently when this file was authored.
 *   3. The literals in this file, which rebuild the canonical request and the
 *      string-to-sign as SPEC TEXT and re-derive the signature through the
 *      primitives alone (`hmacSha256`/`hexHmac`/`hexSha256`), never calling
 *      `sigv4.ts`'s own canonicalisation or key derivation.
 *
 * Derivation 3 is the load-bearing one. Each test states the canonical request
 * AWS must reproduce byte for byte, hashes it, builds the string-to-sign,
 * derives the signing key by the published `AWS4` → date → region → service →
 * `aws4_request` chain, and only then requires the production entry point to
 * agree. So a structural change inside `sigv4.ts` — header order, the `\n`
 * framing, path canonicalisation, the payload-hash line, the credential-scope
 * date — moves the implementation away from a literal that did not move, and
 * the test fails. It is not a typo detector.
 *
 * MUTATION LEDGER — every recipe below was applied to `src/sigv4.ts`, read back
 * OFF DISK with the ORIGINAL TEXT REQUIRED ABSENT and the file's `sha256`
 * required to have changed, run, then restored and re-hashed byte-identical.
 * Seven for seven. The "pre-L11 gate" column was measured against a verbatim
 * reconstruction of `crypto-sigv4.test.ts` as it stood before this work
 * (23 assertions), so it is a measurement and not a recollection.
 *
 * | # | structural error the mutation introduces | pre-L11 gate | this file |
 * |---|---|---|---|
 * | A | drop the blank line before the signed-header list | **SURVIVED 23/23** | RED, 6 failed |
 * | B | reorder canonical headers (`x-amz-date` before `x-amz-content-sha256`), leaving the signed-header LIST correct | **SURVIVED 23/23** | RED, 3 failed |
 * | C | double-hash the payload line (`hexSha256(hexSha256(body))`) | RED, 1 failed | RED, 5 failed |
 * | D | credential scope built from `amzDate` instead of `dateStamp` | RED, 1 failed | RED, 7 failed |
 * | E | drop the trailing `\n` closing the last canonical header | **SURVIVED 23/23** | RED, 3 failed |
 * | F | `canonicalUri` returns the path unencoded | **SURVIVED 23/23** | RED, 2 failed |
 * | G | presign signs `""` instead of `UNSIGNED-PAYLOAD` | **SURVIVED 23/23** | RED, 1 failed |
 *
 * Five of the seven — including every purely structural one — were invisible to
 * the pre-L11 suite. F is the sharpest: an unencoded canonical path breaks every
 * asset object key containing a space, and NOTHING in the tree failed. The two
 * that the old gate did catch (C, D) it caught incidentally, through the
 * streamed-vs-buffered equality and a `Credential=` substring, not through any
 * assertion about the signature itself.
 *
 * IF A LITERAL IN THIS FILE IS EVER DISPUTED: it is re-derivable from AWS's
 * published algorithm with ~40 lines of `hashlib`/`hmac`, and — until the tag
 * `legacy-rs` is unreachable — from `sigv4.rs` directly. Do not "fix" a failure
 * here by editing a vector. A disagreement between `sigv4.ts` and these
 * literals means the signer is wrong and every live AWS call is failing.
 */
import { describe, expect, test } from "vitest";

import { hexHmac, hexSha256, hmacSha256, utf8 } from "../src/crypto.js";
import type { AwsCredentials, SigningRequest } from "../src/index.js";
import {
  canonicalQueryString,
  canonicalUri,
  presignQuery,
  presignQueryBound,
  sign,
  signStreamedWithContentHashHeader,
  signWithContentHashHeader,
  signWithContentHashHeaderAndQuery,
} from "../src/sigv4.js";

/** The AWS documentation example credentials — never valid against real AWS. */
const CREDENTIALS: AwsCredentials = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

/** 2015-08-30T12:36:00Z — the instant used throughout AWS's own SigV4 suite. */
const TIMESTAMP_UNIX = 1_440_938_160;
const AMZ_DATE = "20150830T123600Z";
const DATE_STAMP = "20150830";

const BEDROCK_HOST = "bedrock-runtime.us-east-1.amazonaws.com";
const BEDROCK_BODY = '{"messages":[]}';
/** SHA-256 of `BEDROCK_BODY` — the canonical request's final line. */
const BEDROCK_PAYLOAD_SHA256 = "5e4ce7b36ba37b78a5d5f9fd08e6b7b54ba6879d651aa46ec9e1d6fa24ebe30a";
/** SHA-256 of the empty payload (RFC/NIST vector), used by the query vector. */
const EMPTY_PAYLOAD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const bedrockRequest: SigningRequest = {
  method: "POST",
  path: "/model/test-model/converse",
  host: BEDROCK_HOST,
  region: "us-east-1",
  service: "bedrock",
  body: utf8(BEDROCK_BODY),
  timestampUnix: TIMESTAMP_UNIX,
};

/**
 * The published `AWS4` → date → region → service → `aws4_request` HMAC chain,
 * written here from the algorithm text. Deliberately NOT importing
 * `sigv4.ts`'s `deriveSigningKey` (which is private anyway): if the two ever
 * disagree, this file must be the one that is right.
 */
function specSigningKey(region: string, service: string): Uint8Array {
  const kDate = hmacSha256(utf8(`AWS4${CREDENTIALS.secretAccessKey}`), utf8(DATE_STAMP));
  const kRegion = hmacSha256(kDate, utf8(region));
  const kService = hmacSha256(kRegion, utf8(service));
  return hmacSha256(kService, utf8("aws4_request"));
}

/** `AWS4-HMAC-SHA256\n<amzDate>\n<scope>\n<sha256(canonicalRequest)>`, per spec. */
function specStringToSign(canonicalRequest: string, region: string, service: string): string {
  const scope = `${DATE_STAMP}/${region}/${service}/aws4_request`;
  return `AWS4-HMAC-SHA256\n${AMZ_DATE}\n${scope}\n${hexSha256(utf8(canonicalRequest))}`;
}

/** The signature AWS itself would compute for `canonicalRequest`. */
function specSignature(canonicalRequest: string, region: string, service: string): string {
  return hexHmac(
    specSigningKey(region, service),
    utf8(specStringToSign(canonicalRequest, region, service)),
  );
}

/** Pulls the `Signature=` field out of an `Authorization` header. */
function signatureOf(authorization: string): string {
  const signature = authorization.split("Signature=")[1];
  expect(signature).toBeDefined();
  return signature as NonNullable<typeof signature>;
}

// ---------------------------------------------------------------------------
// VECTOR 1 — `sign` (Bedrock Converse; minimal `host;x-amz-date` header set)
// ---------------------------------------------------------------------------

describe("GOLDEN VECTOR 1 — sign() over a Bedrock Converse POST", () => {
  /**
   * The exact bytes AWS reconstructs on its side. Note the THREE structural
   * features that a wrong implementation gets wrong and no shape assertion can
   * see: the empty third line (no query string), the trailing `\n` that closes
   * the last canonical header, and the BLANK LINE that separates the header
   * block from the signed-header list.
   */
  const CANONICAL_REQUEST = `POST\n/model/test-model/converse\n\nhost:${BEDROCK_HOST}\nx-amz-date:${AMZ_DATE}\n\nhost;x-amz-date\n${BEDROCK_PAYLOAD_SHA256}`;

  const CANONICAL_REQUEST_SHA256 =
    "c653759c4d070cc74876b2e59e03a74ee4b8b74ba2864992db3bb5660b2cfddc";

  const STRING_TO_SIGN = `AWS4-HMAC-SHA256\n${AMZ_DATE}\n20150830/us-east-1/bedrock/aws4_request\n${CANONICAL_REQUEST_SHA256}`;

  /** cert3-controlplane-libs.md §7.11, re-derived independently. */
  const GOLDEN_SIGNATURE = "ee11e0386b7d4282de4b9d27205cb9633a5f30dcde4a5013991445a3093e6803";

  test("the payload hash is the SHA-256 of the body, not the body", () => {
    expect(hexSha256(utf8(BEDROCK_BODY))).toBe(BEDROCK_PAYLOAD_SHA256);
  });

  test("the canonical request hashes to the pinned digest", () => {
    expect(hexSha256(utf8(CANONICAL_REQUEST))).toBe(CANONICAL_REQUEST_SHA256);
  });

  test("the string-to-sign is the pinned four-line document", () => {
    expect(specStringToSign(CANONICAL_REQUEST, "us-east-1", "bedrock")).toBe(STRING_TO_SIGN);
  });

  test("the spec-derived signature is the golden signature", () => {
    expect(specSignature(CANONICAL_REQUEST, "us-east-1", "bedrock")).toBe(GOLDEN_SIGNATURE);
  });

  test("sign() produces the golden signature", () => {
    expect(signatureOf(sign(bedrockRequest, CREDENTIALS).authorization)).toBe(GOLDEN_SIGNATURE);
  });

  test("sign() produces the exact Authorization header, field for field", () => {
    expect(sign(bedrockRequest, CREDENTIALS).authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=${GOLDEN_SIGNATURE}`,
    );
  });

  test("the X-Amz-Date header is the pinned instant", () => {
    expect(sign(bedrockRequest, CREDENTIALS).xAmzDate).toBe(AMZ_DATE);
  });

  /**
   * The credential SCOPE date is `YYYYMMDD`; the `x-amz-date` HEADER is the
   * full `YYYYMMDDTHHMMSSZ`. Confusing the two is the classic SigV4 error and
   * it produces a well-formed 64-hex signature AWS always rejects.
   */
  test("the credential scope carries the date stamp, not the timestamp", () => {
    const authorization = sign(bedrockRequest, CREDENTIALS).authorization;
    expect(authorization).toContain(`Credential=AKIDEXAMPLE/${DATE_STAMP}/us-east-1/bedrock/`);
    expect(authorization).not.toContain(`Credential=AKIDEXAMPLE/${AMZ_DATE}/`);
  });
});

// ---------------------------------------------------------------------------
// VECTOR 2 — `signWithContentHashHeader` (S3-compatible; three signed headers)
// ---------------------------------------------------------------------------

describe("GOLDEN VECTOR 2 — signWithContentHashHeader() over the same request", () => {
  /**
   * Same request, one extra signed header. The header block MUST stay sorted by
   * lowercase name (`host` < `x-amz-content-sha256` < `x-amz-date`) and the
   * signed-header list MUST list them in that same order.
   */
  const CANONICAL_REQUEST = `POST\n/model/test-model/converse\n\nhost:${BEDROCK_HOST}\nx-amz-content-sha256:${BEDROCK_PAYLOAD_SHA256}\nx-amz-date:${AMZ_DATE}\n\nhost;x-amz-content-sha256;x-amz-date\n${BEDROCK_PAYLOAD_SHA256}`;

  const CANONICAL_REQUEST_SHA256 =
    "2a698d80a6d646dd730b97071d10702bd97c1ed171aab9187db736457559d67f";

  const STRING_TO_SIGN = `AWS4-HMAC-SHA256\n${AMZ_DATE}\n20150830/us-east-1/bedrock/aws4_request\n${CANONICAL_REQUEST_SHA256}`;

  /** cert3-controlplane-libs.md §7.11, re-derived independently. */
  const GOLDEN_SIGNATURE = "398afec746a079f98e63bf0ead0a2c56e516490f56f0192c848c5a1ae7013c13";

  test("the canonical request hashes to the pinned digest", () => {
    expect(hexSha256(utf8(CANONICAL_REQUEST))).toBe(CANONICAL_REQUEST_SHA256);
  });

  test("the string-to-sign is the pinned four-line document", () => {
    expect(specStringToSign(CANONICAL_REQUEST, "us-east-1", "bedrock")).toBe(STRING_TO_SIGN);
  });

  test("the spec-derived signature is the golden signature", () => {
    expect(specSignature(CANONICAL_REQUEST, "us-east-1", "bedrock")).toBe(GOLDEN_SIGNATURE);
  });

  test("signWithContentHashHeader() produces the exact Authorization header", () => {
    const signed = signWithContentHashHeader(bedrockRequest, CREDENTIALS);
    expect(signed.authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${GOLDEN_SIGNATURE}`,
    );
    expect(signed.xAmzContentSha256).toBe(BEDROCK_PAYLOAD_SHA256);
  });

  test("the streamed variant reaches the same golden signature", () => {
    const streamed = signStreamedWithContentHashHeader(
      {
        method: bedrockRequest.method,
        path: bedrockRequest.path,
        host: bedrockRequest.host,
        region: bedrockRequest.region,
        service: bedrockRequest.service,
        payloadSha256Hex: BEDROCK_PAYLOAD_SHA256,
        timestampUnix: TIMESTAMP_UNIX,
      },
      CREDENTIALS,
    );
    expect(signatureOf(streamed.authorization)).toBe(GOLDEN_SIGNATURE);
  });

  test("the two vectors are distinguishable — the header set changes the signature", () => {
    expect(signatureOf(sign(bedrockRequest, CREDENTIALS).authorization)).not.toBe(
      signatureOf(signWithContentHashHeader(bedrockRequest, CREDENTIALS).authorization),
    );
  });
});

// ---------------------------------------------------------------------------
// VECTOR 3 — `presignQuery` (S3 query-string presigned URL, UNSIGNED-PAYLOAD)
// ---------------------------------------------------------------------------

describe("GOLDEN VECTOR 3 — presignQuery() for an S3-compatible PUT", () => {
  const CANONICAL_QUERY =
    "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
    "&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request" +
    "&X-Amz-Date=20150830T123600Z" +
    "&X-Amz-Expires=900" +
    "&X-Amz-SignedHeaders=host";

  /** A presigned request signs the literal `UNSIGNED-PAYLOAD`, not a digest. */
  const CANONICAL_REQUEST = `PUT\n/bucket/key\n${CANONICAL_QUERY}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD`;

  const GOLDEN_SIGNATURE = "6751d6cb0aa4fb962fdb322beeb16da030ba004d4f92670a65d4bf5108d2c1b9";

  const presignRequest = {
    method: "PUT",
    path: "/bucket/key",
    host: "s3.example.com",
    region: "us-east-1",
    service: "s3",
    expiresSecs: 900,
    timestampUnix: TIMESTAMP_UNIX,
  };

  test("the canonical request hashes to the pinned digest", () => {
    expect(hexSha256(utf8(CANONICAL_REQUEST))).toBe(
      "cda2935b5836d4c12413ea90b56ca99fc0892e31e33a8a4c82a4041cd59b6f86",
    );
  });

  test("the spec-derived signature is the golden signature", () => {
    expect(specSignature(CANONICAL_REQUEST, "us-east-1", "s3")).toBe(GOLDEN_SIGNATURE);
  });

  test("presignQuery() returns the exact query string", () => {
    expect(presignQuery(presignRequest, CREDENTIALS)).toBe(
      `${CANONICAL_QUERY}&X-Amz-Signature=${GOLDEN_SIGNATURE}`,
    );
  });
});

// ---------------------------------------------------------------------------
// VECTOR 4 — `presignQueryBound` (issue #368: size + checksum are SIGNED)
// ---------------------------------------------------------------------------

describe("GOLDEN VECTOR 4 — presignQueryBound() binds size and checksum", () => {
  const CANONICAL_QUERY =
    "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
    "&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request" +
    "&X-Amz-Date=20150830T123600Z" +
    "&X-Amz-Expires=900" +
    "&X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256";

  const CANONICAL_REQUEST = `PUT\n/bucket/key\n${CANONICAL_QUERY}\ncontent-length:1024\nhost:s3.example.com\nx-amz-content-sha256:${BEDROCK_PAYLOAD_SHA256}\n\ncontent-length;host;x-amz-content-sha256\nUNSIGNED-PAYLOAD`;

  const GOLDEN_SIGNATURE = "3793b48f921ec59b3c0bbb1d07944db2a1c3e57c497cc6e9004a76af4bc10620";

  const presignRequest = {
    method: "PUT",
    path: "/bucket/key",
    host: "s3.example.com",
    region: "us-east-1",
    service: "s3",
    expiresSecs: 900,
    timestampUnix: TIMESTAMP_UNIX,
  };
  const payload = { contentLength: 1024, contentSha256Hex: BEDROCK_PAYLOAD_SHA256 };

  test("the canonical request hashes to the pinned digest", () => {
    expect(hexSha256(utf8(CANONICAL_REQUEST))).toBe(
      "25b1b28b025e6d7672110119cec5ae0ff82ad719554e13806f6d1c46262b0ba6",
    );
  });

  test("the spec-derived signature is the golden signature", () => {
    expect(specSignature(CANONICAL_REQUEST, "us-east-1", "s3")).toBe(GOLDEN_SIGNATURE);
  });

  test("presignQueryBound() returns the exact query string and required headers", () => {
    const bound = presignQueryBound(presignRequest, CREDENTIALS, payload);
    expect(bound.query).toBe(`${CANONICAL_QUERY}&X-Amz-Signature=${GOLDEN_SIGNATURE}`);
    expect(bound.requiredHeaders).toEqual([
      ["content-length", "1024"],
      ["x-amz-content-sha256", BEDROCK_PAYLOAD_SHA256],
    ]);
  });

  /**
   * The whole point of #368: the URL is worthless for a different size. This is
   * a golden test rather than a `not.toBe`, so a signer that silently stopped
   * signing `content-length` fails HERE and not only at the bucket.
   */
  test("a different declared size yields a different signature", () => {
    const other = presignQueryBound(presignRequest, CREDENTIALS, {
      ...payload,
      contentLength: 1025,
    });
    expect(other.query).not.toContain(GOLDEN_SIGNATURE);
    expect(other.query).toContain(
      "X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256",
    );
  });
});

// ---------------------------------------------------------------------------
// VECTOR 5 — canonicalisation of the pieces, pinned to spec text
// ---------------------------------------------------------------------------

describe("GOLDEN VECTOR 5 — path and query canonicalisation", () => {
  /**
   * `canonicalUri` encodes PER SEGMENT and preserves `/`. A space becomes
   * `%20` (not `+`), `+` becomes `%2B`, multi-byte characters are UTF-8 then
   * percent-encoded, and `~` `-` `_` `.` are unreserved and pass through.
   */
  test("canonicalUri percent-encodes per segment and preserves the separators", () => {
    expect(canonicalUri("/bucket/a b/ünï+code/x~y.z")).toBe(
      "/bucket/a%20b/%C3%BCn%C3%AF%2Bcode/x~y.z",
    );
  });

  test("canonicalUri maps the empty path to the mandatory single slash", () => {
    expect(canonicalUri("")).toBe("/");
  });

  /** An already-well-formed escape passes through instead of double-encoding. */
  test("canonicalUri does not double-encode an existing %XY escape", () => {
    expect(canonicalUri("/bucket/a%20b")).toBe("/bucket/a%20b");
  });

  /** The canonical query encodes `/` in a VALUE — RFC 3986, no `safe` chars. */
  test("canonicalQueryString sorts by encoded key and encodes the slash", () => {
    expect(
      canonicalQueryString([
        ["prefix", "a/b"],
        ["list-type", "2"],
      ]),
    ).toBe("list-type=2&prefix=a%2Fb");
  });

  /**
   * A full signature over an encoded path AND a canonical query, so the two
   * canonicalisers are pinned where they actually meet the signer rather than
   * only in isolation.
   */
  test("GOLDEN VECTOR 6 — signWithContentHashHeaderAndQuery over an encoded path", () => {
    const canonicalQuery = canonicalQueryString([
      ["list-type", "2"],
      ["prefix", "a/b"],
    ]);
    const CANONICAL_REQUEST = `GET\n/bucket/a%20b\n${canonicalQuery}\nhost:s3.example.com\nx-amz-content-sha256:${EMPTY_PAYLOAD_SHA256}\nx-amz-date:${AMZ_DATE}\n\nhost;x-amz-content-sha256;x-amz-date\n${EMPTY_PAYLOAD_SHA256}`;
    const GOLDEN_SIGNATURE = "292efecef5c54fb96b2d357009c6c5777e9de566fe06769c25243202d9064804";

    expect(hexSha256(utf8(CANONICAL_REQUEST))).toBe(
      "ebb7aac9d12b6024ee6985ab07e04bdaeb60ae25ea95cb48c484f2950a0a5c6f",
    );
    expect(specSignature(CANONICAL_REQUEST, "us-east-1", "s3")).toBe(GOLDEN_SIGNATURE);

    const signed = signWithContentHashHeaderAndQuery(
      {
        method: "GET",
        path: "/bucket/a b",
        host: "s3.example.com",
        region: "us-east-1",
        service: "s3",
        body: utf8(""),
        timestampUnix: TIMESTAMP_UNIX,
      },
      CREDENTIALS,
      canonicalQuery,
    );
    expect(signatureOf(signed.authorization)).toBe(GOLDEN_SIGNATURE);
  });
});

// ---------------------------------------------------------------------------
// The session-token posture, pinned as CURRENT BEHAVIOUR and flagged
// ---------------------------------------------------------------------------

/**
 * READ THIS BEFORE CHANGING THE VECTOR BELOW.
 *
 * `sigv4.rs:214-224` signs `host;x-amz-date` (or the three-header set) and
 * returns `x_amz_security_token` as an UNSIGNED pass-through header. This port
 * reproduces that byte for byte, which is what a port is required to do — so
 * the vector below is the SAME signature as VECTOR 1, and adding a session
 * token changes only the returned header.
 *
 * That is faithful, and it is also a KNOWN DIVERGENCE FROM AWS'S GUIDANCE,
 * which requires `x-amz-security-token` to be part of the canonical headers and
 * the signed-header list when temporary credentials are used. It is recorded
 * here rather than silently "fixed": correcting it changes the wire signature,
 * so it is a deliberate product decision with a golden vector attached, not a
 * drive-by edit. If the signer is later corrected, THIS test must fail first
 * and be updated with a newly derived vector — that failure is the feature.
 */
describe("temporary credentials — Rust-faithful, and flagged", () => {
  const GOLDEN_SIGNATURE_WITHOUT_TOKEN_SIGNED =
    "ee11e0386b7d4282de4b9d27205cb9633a5f30dcde4a5013991445a3093e6803";

  test("the session token is returned but NOT folded into the signature", () => {
    const signed = sign(bedrockRequest, {
      ...CREDENTIALS,
      sessionToken: "temporary-session-token",
    });
    expect(signed.xAmzSecurityToken).toBe("temporary-session-token");
    expect(signed.authorization).toContain("SignedHeaders=host;x-amz-date,");
    expect(signatureOf(signed.authorization)).toBe(GOLDEN_SIGNATURE_WITHOUT_TOKEN_SIGNED);
  });
});
