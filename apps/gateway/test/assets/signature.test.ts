/**
 * Detached publisher-signature verification — the port of
 * `crates/ferrogate-gateway/src/asset_signature.rs` (issue #261).
 *
 * ## Where the fixtures come from, and why it matters
 *
 * Every signature below was produced by **OpenSSL 3** (`openssl pkeyutl -sign
 * -rawin` against an `openssl genpkey -algorithm ed25519` key), not by this
 * code and not by `workerd`. That is the point: if the port both signed and
 * verified, a wrong message construction (say, prehashing when it should not)
 * would verify against itself and every test would pass. Signing with an
 * INDEPENDENT implementation is what makes a green assertion mean "this is
 * really Ed25519 over really those bytes".
 *
 * The BLAKE2b-512 digest the prehashed minisign variant signs was likewise
 * produced by Python's `hashlib.blake2b` and is pinned below as a literal, so
 * the digest and the signature constrain each other.
 *
 * The minisign PUBLIC KEY fixture base64-encodes to `RWQBAgMEBQYHCAVU…` — the
 * `RW` prefix real minisign keys carry — which is the cheapest available
 * evidence that the 42-byte `algo || key_id || pubkey` layout is the tool's and
 * not this file's invention.
 */
import { describe, expect, it } from "vitest";

import { assetDepsFromEnv, assetRouteModule } from "../../src/assets/index.js";
import {
  type AssetScreeningRequest,
  type AssetScreeningVerdict,
  BuiltinEicarScreener,
  isScreeningRejection,
} from "../../src/assets/ports.js";
import {
  SignatureVerifyingScreener,
  withSignatureVerification,
} from "../../src/assets/signature-screener.js";
import {
  PublisherKeyRegistry,
  hexLower,
  parseMinisignPublicKey,
  parseMinisignSignature,
  parseSignatureFormat,
  signatureIsVerified,
  verifyAssetSignature,
} from "../../src/assets/signature.js";
import { blake2b } from "../../src/keys/blake2b.js";
import { createGatewayApp } from "../../src/routes/index.js";

// --- OpenSSL-generated fixtures --------------------------------------------

/** The raw 32-byte Ed25519 public key, base64. */
const PUBLIC_KEY_B64 = "BVQdBdbOBidk+0ca24JMR5EOIiSrOPhgCkH8s0QDOQw=";
/** The exact bytes every signature below covers. */
const CONTENT = new TextEncoder().encode("ferrogate asset bytes v1");
/** `openssl pkeyutl -sign -rawin` over CONTENT. */
const BARE_SIGNATURE_B64 =
  "IM/BeFcu+GCpkPzWW+Mhm5Ub5NcJtwrHeVcwaAXddZgHHHB9XO1uxCiZTIhfGUimrA+LLRlnC4SZhfhNUlZfDA==";
/** `Ed` || key_id 0102030405060708 || the 32-byte public key. */
const MINISIGN_PUBLIC_KEY = "RWQBAgMEBQYHCAVUHQXWzgYnZPtHGtuCTEeRDiIkqzj4YApB/LNEAzkM";
const MINISIGN_KEY_ID = "0102030405060708";
/** `Ed` (legacy): the signature is over the RAW file. */
const MINISIGN_SIG_LEGACY =
  "RWQBAgMEBQYHCCDPwXhXLvhgqZD81lvjIZuVG+TXCbcKx3lXMGgF3XWYBxxwfVztbsQomUyIXxlIpqwPiy0ZZwuEmYX4TVJWXww=";
/** `ED` (modern default): the signature is over BLAKE2b-512(file). */
const MINISIGN_SIG_PREHASHED =
  "RUQBAgMEBQYHCHKJQpILMp52vnLLttBARyD5XV5ovY8NL4f5acsVTPrq3skQTg7RH3CLIAofbiqACmc9e6qikWAMoKG0Zi8THgM=";
/** Python `hashlib.blake2b(CONTENT, digest_size=64).hexdigest()`. */
const CONTENT_BLAKE2B_HEX =
  "0f6b29435f01c8d3f32ff5ff7699e54044a8ab12e4ce89e3ed3e40c020b058d6" +
  "1447840944f15ee7520022d620cd4f10cf65262c3d3077f42250fa1099c2d5c0";

const MINISIG_FILE = [
  "untrusted comment: signature from minisign secret key",
  MINISIGN_SIG_PREHASHED,
  "trusted comment: timestamp:1753000000\tfile:asset.bin",
  "AAAA",
].join("\n");

async function registryWithMinisign(): Promise<PublisherKeyRegistry> {
  const registry = new PublisherKeyRegistry();
  const result = await registry.registerMinisign(MINISIGN_PUBLIC_KEY);
  expect(result).toBe(MINISIGN_KEY_ID);
  return registry;
}

async function registryWithBare(label = "publisher-a"): Promise<PublisherKeyRegistry> {
  const registry = new PublisherKeyRegistry();
  expect(await registry.registerEd25519(label, PUBLIC_KEY_B64)).toBeNull();
  return registry;
}

// ---------------------------------------------------------------------------

describe("the BLAKE2b-512 the prehashed variant depends on", () => {
  it("matches the Python golden digest of the fixture content", () => {
    // WebCrypto has no BLAKE2b (probed: `crypto.subtle.digest("BLAKE2b-512")`
    // rejects in workerd), so this reuses `src/keys/blake2b.ts`. If that digest
    // is wrong the `ED` signature below cannot verify — the two constrain each
    // other, which is why the literal is here rather than recomputed.
    expect(hexLower(blake2b(CONTENT))).toBe(CONTENT_BLAKE2B_HEX);
  });
});

describe("parseSignatureFormat", () => {
  it.each([
    ["minisign", "minisign"],
    ["MiniSign", "minisign"],
    ["  ed25519 ", "ed25519"],
    ["cosign", "ed25519"],
  ])("%s ⇒ %s", (raw, expected) => {
    expect(parseSignatureFormat(raw)).toBe(expected);
  });

  it("is undefined for anything else — never a silent 'skip verification'", () => {
    expect(parseSignatureFormat("rsa")).toBeUndefined();
    expect(parseSignatureFormat("")).toBeUndefined();
  });
});

describe("minisign container parsing", () => {
  it("reads the 42-byte public key and its embedded key id", () => {
    const parsed = parseMinisignPublicKey(`untrusted comment: x\n${MINISIGN_PUBLIC_KEY}`);
    expect("error" in parsed).toBe(false);
    expect((parsed as { keyIdHex: string }).keyIdHex).toBe(MINISIGN_KEY_ID);
    expect((parsed as { publicKey: Uint8Array }).publicKey).toHaveLength(32);
  });

  it.each([
    ["", "minisign public key is empty"],
    ["untrusted comment: only", "minisign public key is empty"],
    ["not base64 ***", "minisign public key is not valid base64"],
    ["AAAA", "expected a 42-byte minisign public key, got 3 bytes"],
  ])("rejects %j", (text, reason) => {
    expect(parseMinisignPublicKey(text)).toEqual({ error: reason });
  });

  it("skips the comment lines AND the trailing global-signature blob", () => {
    // A real `.minisig` has FOUR lines; only one of them is the 74-byte
    // signature this reads. Picking the wrong one is the classic bug.
    const parsed = parseMinisignSignature(MINISIG_FILE);
    expect("error" in parsed).toBe(false);
    expect(parsed).toMatchObject({ algorithm: "ED", keyIdHex: MINISIGN_KEY_ID });
    expect((parsed as { signature: Uint8Array }).signature).toHaveLength(64);
  });

  it("reports a file with no 74-byte line", () => {
    expect(parseMinisignSignature("untrusted comment: x\nAAAA")).toEqual({
      error: "no 74-byte minisign signature line found",
    });
  });
});

describe("verifyAssetSignature — minisign", () => {
  it("verifies the modern PREHASHED (`ED`) signature over the real file", async () => {
    const status = await verifyAssetSignature(
      CONTENT,
      { format: "minisign", material: MINISIG_FILE },
      await registryWithMinisign(),
    );
    expect(status).toEqual({
      status: "verified",
      key_id: MINISIGN_KEY_ID,
      format: "minisign",
    });
    expect(signatureIsVerified(status)).toBe(true);
  });

  it("verifies the legacy raw-message (`Ed`) signature too", async () => {
    const status = await verifyAssetSignature(
      CONTENT,
      { format: "minisign", material: MINISIGN_SIG_LEGACY },
      await registryWithMinisign(),
    );
    expect(status).toMatchObject({ status: "verified", format: "minisign" });
  });

  it("the two algorithms are NOT interchangeable — a prehash mix-up is caught", async () => {
    // The `Ed` signature relabelled `ED` must fail: it covers the raw file, and
    // `ED` says to verify against the BLAKE2b digest. If this passed, the
    // implementation would be ignoring the algorithm byte.
    const relabelled = MINISIGN_SIG_LEGACY.replace(/^RWQ/, "RUQ");
    expect(relabelled).not.toBe(MINISIGN_SIG_LEGACY);
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "minisign", material: relabelled },
        await registryWithMinisign(),
      ),
    ).toEqual({
      status: "invalid",
      reason: "minisign signature did not verify against the registered key",
    });
  });

  it("ONE flipped content byte invalidates it", async () => {
    const tampered = new Uint8Array(CONTENT);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    expect(
      await verifyAssetSignature(
        tampered,
        { format: "minisign", material: MINISIG_FILE },
        await registryWithMinisign(),
      ),
    ).toMatchObject({ status: "invalid" });
  });

  it("an UNREGISTERED key id is `unverified`, not `invalid`", async () => {
    // The distinction is load-bearing: "I do not know this key" is an operator
    // configuration problem; "these bytes do not match" is a supply-chain one.
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "minisign", material: MINISIG_FILE },
        new PublisherKeyRegistry(),
      ),
    ).toEqual({
      status: "unverified",
      reason: `no registered minisign key for id ${MINISIGN_KEY_ID}`,
    });
  });

  it("an unsupported algorithm byte is refused by name", async () => {
    const bytes = new Uint8Array(74);
    bytes.set(new TextEncoder().encode("XY"), 0);
    bytes.set([1, 2, 3, 4, 5, 6, 7, 8], 2);
    const material = btoa(String.fromCharCode(...bytes));
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "minisign", material },
        await registryWithMinisign(),
      ),
    ).toEqual({ status: "invalid", reason: "unsupported minisign algorithm XY" });
  });
});

describe("verifyAssetSignature — bare Ed25519 / cosign", () => {
  it("verifies against the key the hint names", async () => {
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "ed25519", material: BARE_SIGNATURE_B64, keyId: "publisher-a" },
        await registryWithBare(),
      ),
    ).toEqual({ status: "verified", key_id: "publisher-a", format: "ed25519" });
  });

  it("with NO hint, accepts if any registered key verifies", async () => {
    const registry = await registryWithBare("second");
    // A decoy key that cannot verify, registered first alphabetically.
    await registry.registerEd25519("first", btoa(String.fromCharCode(...new Uint8Array(32))));
    const status = await verifyAssetSignature(
      CONTENT,
      { format: "ed25519", material: BARE_SIGNATURE_B64 },
      registry,
    );
    expect(status).toEqual({ status: "verified", key_id: "second", format: "ed25519" });
  });

  it("a NAMED key that does not verify is `invalid`, never retried against others", async () => {
    const registry = await registryWithBare("real");
    await registry.registerEd25519("decoy", btoa(String.fromCharCode(...new Uint8Array(32))));
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "ed25519", material: BARE_SIGNATURE_B64, keyId: "decoy" },
        registry,
      ),
    ).toEqual({
      status: "invalid",
      reason: "ed25519 signature did not verify against the named key",
    });
  });

  it("distinguishes an unknown hint, an empty registry, and a real mismatch", async () => {
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "ed25519", material: BARE_SIGNATURE_B64, keyId: "ghost" },
        await registryWithBare(),
      ),
    ).toEqual({ status: "unverified", reason: "no registered ed25519 key with id ghost" });

    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "ed25519", material: BARE_SIGNATURE_B64 },
        new PublisherKeyRegistry(),
      ),
    ).toEqual({ status: "unverified", reason: "no publisher ed25519 keys are registered" });

    const tampered = new Uint8Array(CONTENT);
    tampered[3] = (tampered[3] ?? 0) ^ 0xff;
    expect(
      await verifyAssetSignature(
        tampered,
        { format: "ed25519", material: BARE_SIGNATURE_B64 },
        await registryWithBare(),
      ),
    ).toEqual({
      status: "invalid",
      reason: "ed25519 signature did not verify against any registered key",
    });
  });

  it.each([
    ["not base64 ***", "signature is not valid base64"],
    ["AAAA", "expected a 64-byte ed25519 signature, got 3 bytes"],
  ])("malformed material %j is data, not a throw", async (material, reason) => {
    expect(
      await verifyAssetSignature(
        CONTENT,
        { format: "ed25519", material },
        await registryWithBare(),
      ),
    ).toEqual({ status: "invalid", reason });
  });
});

describe("PublisherKeyRegistry.fromEnv", () => {
  it("reads both Rust env names", async () => {
    const registry = await PublisherKeyRegistry.fromEnv({
      FERROGATE_ASSET_PUBLISHER_ED25519_KEYS: `publisher-a=${PUBLIC_KEY_B64}`,
      FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: MINISIGN_PUBLIC_KEY,
    });
    expect(registry.ed25519KeyIds).toEqual(["publisher-a"]);
    expect(registry.minisignKeyIds).toEqual([MINISIGN_KEY_ID]);
    expect(registry.isEmpty).toBe(false);
  });

  it("a malformed entry is skipped, and does not take the good ones down", async () => {
    const registry = await PublisherKeyRegistry.fromEnv({
      FERROGATE_ASSET_PUBLISHER_ED25519_KEYS: `broken=zzz,publisher-a=${PUBLIC_KEY_B64},noequals`,
      FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: `AAAA\n${MINISIGN_PUBLIC_KEY}`,
    });
    expect(registry.ed25519KeyIds).toEqual(["publisher-a"]);
    expect(registry.minisignKeyIds).toEqual([MINISIGN_KEY_ID]);
  });

  it("an unset env yields an EMPTY registry, so every signature is `unverified`", async () => {
    const registry = await PublisherKeyRegistry.fromEnv({});
    expect(registry.isEmpty).toBe(true);
    expect(
      await verifyAssetSignature(CONTENT, { format: "minisign", material: MINISIG_FILE }, registry),
    ).toMatchObject({ status: "unverified" });
  });
});

// ---------------------------------------------------------------------------
// The screening stage
// ---------------------------------------------------------------------------

function screeningRequest(
  content: Uint8Array,
  signature?: AssetScreeningRequest["signature"],
): AssetScreeningRequest {
  return {
    assetId: "asset_1",
    tenantId: "tenant_a",
    assetType: "skill",
    contentType: "application/octet-stream",
    content,
    contentSha256: "0".repeat(64),
    nowUnix: 1_753_000_000,
    ...(signature !== undefined ? { signature } : {}),
  };
}

describe("SignatureVerifyingScreener", () => {
  it("records the verified status on the audit line and in the manifest", async () => {
    const screener = new SignatureVerifyingScreener(
      new BuiltinEicarScreener(),
      registryWithMinisign(),
    );
    const verdict = (await screener.screen(
      screeningRequest(CONTENT, { format: "minisign", material: MINISIG_FILE }),
    )) as AssetScreeningVerdict;

    expect(verdict.visibility).toBe("visible");
    // The inner screener writes `signature=absent`; only that token changes.
    expect(verdict.auditDetail).toBe("scan=clean signature=verified approval=not_required");
    expect(verdict.manifest.signature).toEqual({
      status: "verified",
      key_id: MINISIGN_KEY_ID,
      format: "minisign",
    });
  });

  it("labels an unsigned push `unsigned` and still admits it", async () => {
    const screener = new SignatureVerifyingScreener(
      new BuiltinEicarScreener(),
      registryWithMinisign(),
    );
    const verdict = (await screener.screen(screeningRequest(CONTENT))) as AssetScreeningVerdict;
    expect(verdict.auditDetail).toContain("signature=unsigned");
    expect(verdict.manifest.signature).toEqual({ status: "unsigned" });
  });

  it("NEVER relaxes the inner verdict — an EICAR quarantine survives a good signature", async () => {
    // The failure this forbids: a valid publisher signature persuading the
    // screener that malware is fine. Signature and scan are independent gates.
    const eicar = new TextEncoder().encode(
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    );
    const registry = await registryWithBare();
    const screener = new SignatureVerifyingScreener(new BuiltinEicarScreener(), registry);
    const verdict = (await screener.screen(screeningRequest(eicar))) as AssetScreeningVerdict;
    expect(verdict.visibility).toBe("quarantined");
  });

  it("requireSignature refuses an unsigned push with the Rust code and status", async () => {
    const screener = new SignatureVerifyingScreener(
      new BuiltinEicarScreener(),
      registryWithMinisign(),
      { requireSignature: true },
    );
    const outcome = await screener.screen(screeningRequest(CONTENT));
    expect(isScreeningRejection(outcome)).toBe(true);
    expect(outcome).toEqual({
      status: 422,
      code: "asset_signature_required",
      message: "this tenant requires signed assets but no signature was presented",
    });
  });

  it("requireSignature refuses an UNVERIFIABLE push, and says which", async () => {
    const screener = new SignatureVerifyingScreener(
      new BuiltinEicarScreener(),
      new PublisherKeyRegistry(),
      { requireSignature: true },
    );
    const outcome = await screener.screen(
      screeningRequest(CONTENT, { format: "minisign", material: MINISIG_FILE }),
    );
    expect(outcome).toMatchObject({
      status: 422,
      code: "asset_signature_required",
      message: `this tenant requires signed assets: no registered minisign key for id ${MINISIGN_KEY_ID}`,
    });
  });

  it("requireSignature ADMITS a verified push", async () => {
    const screener = new SignatureVerifyingScreener(
      new BuiltinEicarScreener(),
      registryWithMinisign(),
      { requireSignature: true },
    );
    const outcome = await screener.screen(
      screeningRequest(CONTENT, { format: "minisign", material: MINISIG_FILE }),
    );
    expect(isScreeningRejection(outcome)).toBe(false);
  });

  it("the signature refusal happens BEFORE the scanner is consulted", async () => {
    // Rust ordering: stage (2) is signature, stage (4) is the scan. A screener
    // that ran the scan first would report the EICAR quarantine here instead.
    let innerCalls = 0;
    const screener = new SignatureVerifyingScreener(
      {
        async screen() {
          innerCalls += 1;
          return {
            visibility: "quarantined" as const,
            auditDetail: "scan=infected(eicar) signature=absent approval=not_required",
            manifest: {},
          };
        },
      },
      new PublisherKeyRegistry(),
      { requireSignature: true },
    );
    const outcome = await screener.screen(screeningRequest(CONTENT));
    expect(outcome).toMatchObject({ code: "asset_signature_required" });
    expect(innerCalls).toBe(0);
  });
});

describe("withSignatureVerification composes only when asked", () => {
  const inner = new BuiltinEicarScreener();

  it("returns its argument BY IDENTITY with neither keys nor requirement", () => {
    expect(withSignatureVerification(inner, {})).toBe(inner);
    expect(withSignatureVerification(inner, { FERROGATE_ASSET_REQUIRE_SIGNATURE: "0" })).toBe(
      inner,
    );
  });

  it("composes when publisher keys are configured", () => {
    expect(
      withSignatureVerification(inner, {
        FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: MINISIGN_PUBLIC_KEY,
      }),
    ).not.toBe(inner);
  });

  it("composes — fail CLOSED — when the requirement is on but NO keys are set", async () => {
    // The dangerous shape: an operator who demands signed assets and forgets
    // the keys must get every push refused, not every push admitted unsigned.
    const composed = withSignatureVerification(inner, {
      FERROGATE_ASSET_REQUIRE_SIGNATURE: "true",
    });
    expect(composed).not.toBe(inner);
    expect(await composed.screen(screeningRequest(CONTENT))).toMatchObject({
      status: 422,
      code: "asset_signature_required",
    });
  });
});

// ---------------------------------------------------------------------------
// The MOUNT — headers → assetDepsFromEnv → the deployed push path
// ---------------------------------------------------------------------------

/**
 * Everything above proves the verifier. None of it proves the gateway ever
 * reads `x-asset-signature`, which is the defect class this repo keeps
 * shipping: a module implemented, tested, and never reached.
 *
 * These drive `createGatewayApp({ modules: [assetRouteModule({ depsFromEnv:
 * assetDepsFromEnv })] })` — the composition-root shape verbatim from
 * `src/index.ts` — over real HTTP with the three real headers, and each one
 * fails if EITHER the header parse in `handlers.ts` or the
 * `withSignatureVerification` line in `assetDepsFromEnv` is removed.
 */
describe("the signature stage is MOUNTED on the push path", () => {
  const KEYS = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify([
      {
        key: "fg_sig_rw",
        id: "key_sig",
        tenant_id: "tenant_sig",
        scopes: ["assets.read", "assets.write"],
      },
    ]),
    ASSET_ENTITLEMENTS: JSON.stringify({ tenant_sig: { asset_hosting_enabled: true } }),
    FG_DEV_IN_MEMORY_PORTS: "1",
  };

  function push(
    env: Record<string, unknown>,
    headers: Record<string, string> = {},
    body: BodyInit = CONTENT,
  ): Promise<Response> {
    const { app } = createGatewayApp({
      modules: [assetRouteModule({ depsFromEnv: assetDepsFromEnv })],
    });
    return Promise.resolve(
      app.request(
        "https://gw.test/v1/assets/skill/signed/1.0.0",
        {
          method: "PUT",
          headers: new Headers({
            authorization: "Bearer fg_sig_rw",
            "content-type": "application/octet-stream",
            ...headers,
          }),
          body,
        },
        { ...KEYS, ...env },
      ),
    );
  }

  it("an UNSIGNED push is refused when the deployment requires signatures", async () => {
    const response = await push({
      FERROGATE_ASSET_REQUIRE_SIGNATURE: "1",
      FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: MINISIGN_PUBLIC_KEY,
    });
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      error: { code: "asset_signature_required" },
    });
  });

  it("the SAME push WITH the real minisign header is accepted", async () => {
    // This is the arm that proves the header is read: identical env, identical
    // bytes, and the only difference is `x-asset-signature`.
    const response = await push(
      {
        FERROGATE_ASSET_REQUIRE_SIGNATURE: "1",
        FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: MINISIGN_PUBLIC_KEY,
      },
      { "x-asset-signature": MINISIGN_SIG_PREHASHED },
    );
    expect(response.status).toBe(200);
  });

  it("a signature over DIFFERENT bytes is refused at the same seam", async () => {
    const response = await push(
      {
        FERROGATE_ASSET_REQUIRE_SIGNATURE: "1",
        FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS: MINISIGN_PUBLIC_KEY,
      },
      { "x-asset-signature": MINISIGN_SIG_PREHASHED },
      "these are not the signed bytes",
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      error: {
        code: "asset_signature_required",
        message: expect.stringContaining("did not verify"),
      },
    });
  });

  it("the bare-ed25519 format and the key-id hint header are both read", async () => {
    const response = await push(
      {
        FERROGATE_ASSET_REQUIRE_SIGNATURE: "1",
        FERROGATE_ASSET_PUBLISHER_ED25519_KEYS: `publisher-a=${PUBLIC_KEY_B64}`,
      },
      {
        "x-asset-signature": BARE_SIGNATURE_B64,
        "x-asset-signature-format": "cosign",
        "x-asset-signature-key-id": "publisher-a",
      },
    );
    expect(response.status).toBe(200);
  });

  it("an unrecognised format header falls back to minisign, NOT to 'skip'", async () => {
    // A bare ed25519 signature declared with a typo'd format is read as
    // minisign and fails the 74-byte container parse — a refusal. The shape
    // this forbids is a typo silently disabling verification.
    const response = await push(
      {
        FERROGATE_ASSET_REQUIRE_SIGNATURE: "1",
        FERROGATE_ASSET_PUBLISHER_ED25519_KEYS: `publisher-a=${PUBLIC_KEY_B64}`,
      },
      { "x-asset-signature": BARE_SIGNATURE_B64, "x-asset-signature-format": "rsa" },
    );
    expect(response.status).toBe(422);
  });

  it("CONTROL: with no publisher config the same push is accepted unsigned", async () => {
    // Without this arm the 422s above would prove only that this app refuses
    // pushes. The default posture is unchanged for every existing deployment.
    expect((await push({})).status).toBe(200);
  });
});
