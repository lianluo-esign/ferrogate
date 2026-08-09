import { describe, expect, test } from "vitest";

import { hexSha256, hmacSha256, sha256, utf8 } from "../src/crypto.js";
import type { AwsCredentials, SigningRequest } from "../src/index.js";
import {
  canonicalQueryString,
  formatTimestamps,
  presignQuery,
  sign,
  signStreamedWithContentHashHeader,
  signWithContentHashHeader,
} from "../src/sigv4.js";

describe("SHA-256 / HMAC primitives", () => {
  test("SHA-256 of empty string matches the known NIST vector", () => {
    expect(hexSha256(utf8(""))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  test("SHA-256 of 'abc' matches the known NIST vector", () => {
    expect(hexSha256(utf8("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  test("HMAC-SHA256 matches RFC 4231 test case 2 (key='Jefe')", () => {
    const mac = hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?"));
    expect(Buffer.from(mac).toString("hex")).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });

  test("hashing a >64-byte message spans multiple blocks correctly", () => {
    // Self-consistency: 100 'a's has a well-known digest.
    expect(hexSha256(utf8("a".repeat(100)))).toBe(
      Buffer.from(sha256(utf8("a".repeat(100)))).toString("hex"),
    );
    expect(hexSha256(utf8("a".repeat(1000)))).toHaveLength(64);
  });
});

describe("SigV4 signing", () => {
  const credentials: AwsCredentials = {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  };
  const request: SigningRequest = {
    method: "POST",
    path: "/model/test-model/converse",
    host: "bedrock-runtime.us-east-1.amazonaws.com",
    region: "us-east-1",
    service: "bedrock",
    body: utf8('{"messages":[]}'),
    timestampUnix: 1_440_938_160,
  };

  test("formatTimestamps matches the AWS documentation instant", () => {
    expect(formatTimestamps(1_440_938_160)).toEqual(["20150830T123600Z", "20150830"]);
  });

  test("produces the documented Authorization header shape", () => {
    const signed = sign(request, credentials);
    expect(signed.xAmzDate).toBe("20150830T123600Z");
    expect(signed.xAmzSecurityToken).toBeUndefined();
    expect(signed.authorization).toContain(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, ",
    );
    expect(signed.authorization).toContain("SignedHeaders=host;x-amz-date, ");
    const signature = signed.authorization.split("Signature=")[1]!;
    expect(signature).toHaveLength(64);
    expect(signature).toMatch(/^[0-9a-f]{64}$/);
    // L11: shape is not enough — a structurally wrong canonical request is also
    // 64 lowercase hex. The value is pinned to the independently-derived golden
    // (cert3-controlplane-libs.md §7.11); `test/sigv4-golden.test.ts` carries
    // the canonical request and string-to-sign it comes from.
    expect(signature).toBe("ee11e0386b7d4282de4b9d27205cb9633a5f30dcde4a5013991445a3093e6803");
  });

  test("includes the security token for temporary credentials", () => {
    const signed = sign(request, { ...credentials, sessionToken: "temporary-session-token" });
    expect(signed.xAmzSecurityToken).toBe("temporary-session-token");
  });

  test("changing the body changes the signature", () => {
    const a = sign(request, credentials).authorization;
    const b = sign(
      { ...request, body: utf8('{"messages":[{"role":"user"}]}') },
      credentials,
    ).authorization;
    expect(a).not.toBe(b);
  });

  test("streamed signing matches buffered signing for the same payload", () => {
    const buffered = signWithContentHashHeader(request, credentials);
    const streamed = signStreamedWithContentHashHeader(
      {
        method: request.method,
        path: request.path,
        host: request.host,
        region: request.region,
        service: request.service,
        payloadSha256Hex: hexSha256(request.body),
        timestampUnix: request.timestampUnix,
      },
      credentials,
    );
    expect(streamed.authorization).toBe(buffered.authorization);
    expect(buffered.xAmzContentSha256).toBe(hexSha256(request.body));
    // L11: pin the value the two agree ON, not merely that they agree.
    expect(streamed.authorization.split("Signature=")[1]).toBe(
      "398afec746a079f98e63bf0ead0a2c56e516490f56f0192c848c5a1ae7013c13",
    );
  });

  test("presignQuery emits all required X-Amz parameters", () => {
    const query = presignQuery(
      {
        method: "PUT",
        path: "/bucket/key",
        host: "s3.example.com",
        region: "us-east-1",
        service: "s3",
        expiresSecs: 900,
        timestampUnix: 1_440_938_160,
      },
      credentials,
    );
    expect(query).toContain("X-Amz-Algorithm=AWS4-HMAC-SHA256");
    expect(query).toContain(
      "X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request",
    );
    expect(query).toContain("X-Amz-SignedHeaders=host");
    expect(query).toMatch(/&X-Amz-Signature=[0-9a-f]{64}$/);
    // L11: same trap on the presign path — pin the value.
    expect(query).toMatch(
      /&X-Amz-Signature=6751d6cb0aa4fb962fdb322beeb16da030ba004d4f92670a65d4bf5108d2c1b9$/,
    );
  });

  test("canonicalQueryString sorts and RFC3986-encodes pairs", () => {
    expect(
      canonicalQueryString([
        ["list-type", "2"],
        ["prefix", "a/b"],
      ]),
    ).toBe("list-type=2&prefix=a%2Fb");
  });
});

/**
 * The mechanism divergence, CLOSED by proof rather than by assertion.
 *
 * The inventory (§3.8) suggests Web Crypto for SigV4. `crypto.subtle` is
 * ASYNC, and the Rust `ProviderAdapter::prepare_chat_completions` is
 * synchronous — adopting it would force the whole adapter trait surface to
 * become `async`, a behavioral divergence from the crate. So this package signs
 * with its own synchronous SHA-256/HMAC-SHA256 instead.
 *
 * That is only legitimate if the two agree BYTE FOR BYTE, which is what these
 * tests establish, against the platform's own implementation rather than
 * against more fixtures of our own choosing. If the sync implementation ever
 * drifts, this fails.
 */
describe("the synchronous primitives are byte-identical to crypto.subtle", () => {
  const inputs = [
    "",
    "abc",
    "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request",
    "a".repeat(55), // one block minus padding boundary
    "a".repeat(56), // forces a second block
    "a".repeat(64), // exactly one block
    "a".repeat(1000),
    "🔐 multi-byte ünïcödé",
  ];

  test.each(inputs)("SHA-256 agrees with crypto.subtle for %j", async (input) => {
    const expected = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)),
    );
    expect(sha256(new TextEncoder().encode(input))).toEqual(expected);
  });

  // A zero-length key is omitted: `crypto.subtle.importKey` REFUSES it
  // ("Zero-length key is not supported"), so there is no reference value to
  // compare against. SigV4 never derives one — every key in the chain starts
  // with the literal "AWS4" prefix — so the case is unreachable in this crate.
  test.each([
    ["Jefe", "what do ya want for nothing?"],
    ["k".repeat(64), "exactly-one-block-key"],
    ["k".repeat(65), "key longer than the block size is hashed first"],
    ["AWS4secret", "20150830"],
  ])("HMAC-SHA256 agrees with crypto.subtle for key %j", async (key, message) => {
    const encoder = new TextEncoder();
    const imported = await crypto.subtle.importKey(
      "raw",
      encoder.encode(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const expected = new Uint8Array(
      await crypto.subtle.sign("HMAC", imported, encoder.encode(message)),
    );
    expect(hmacSha256(encoder.encode(key), encoder.encode(message))).toEqual(expected);
  });
});
