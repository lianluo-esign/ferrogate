import { describe, expect, test } from "vitest";
import {
  buildSnapshotCrypto,
  isSmallOrderOrNonCanonicalPoint,
  parseSigningKey,
  parseVerifyingKey,
  signSnapshot,
  SignedSnapshotStore,
  SIGNED_SNAPSHOT_SCHEMA_VERSION,
  verifySnapshot,
  type SignedSnapshotEnvelope,
  type SignedSnapshotPayload,
} from "../src/signed-snapshot.js";
import { clusterConfigSchema } from "../src/schema/sections.js";

// A deterministic 32-byte Ed25519 seed and its public key are derived at runtime
// via WebCrypto so the test is self-contained.
async function freshKeypair(): Promise<{ seedB64: string; publicB64: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const seed = pkcs8.slice(pkcs8.length - 32); // last 32 bytes of the PKCS8 DER
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
  return { seedB64: b64(seed), publicB64: b64(raw) };
}

const payload: SignedSnapshotPayload = { version: 1, api_keys: [], policies: [] };

describe("sign / verify round trip", () => {
  test("a freshly signed envelope verifies and rejects tampering", async () => {
    const { seedB64, publicB64 } = await freshKeypair();
    const signingKey = await parseSigningKey(seedB64, "cluster.snapshot_signing_key");
    const verifyingKey = await parseVerifyingKey(publicB64, "cluster.snapshot_trusted_keys.public_key");
    const trusted = new Map([["k1", verifyingKey]]);

    const envelope = await signSnapshot(payload, "t1", "d1", 5, 10_000, signingKey, "k1");
    expect(envelope.schema_version).toBe(SIGNED_SNAPSHOT_SCHEMA_VERSION);

    const ok = await verifySnapshot(envelope, trusted, "t1", "d1", 4, 9_000);
    expect(ok.ok).toBe(true);

    const tampered: SignedSnapshotEnvelope = { ...envelope, payload: { version: 2, api_keys: [], policies: [] } };
    const bad = await verifySnapshot(tampered, trusted, "t1", "d1", 4, 9_000);
    expect(bad).toEqual({ ok: false, reason: "bad_signature" });
  });

  test("fail-closed rejections: identity, revision, expiry, unknown key", async () => {
    const { seedB64, publicB64 } = await freshKeypair();
    const signingKey = await parseSigningKey(seedB64, "f");
    const verifyingKey = await parseVerifyingKey(publicB64, "f");
    const trusted = new Map([["k1", verifyingKey]]);
    const envelope = await signSnapshot(payload, "t1", "d1", 5, 10_000, signingKey, "k1");

    expect((await verifySnapshot(envelope, trusted, "other", "d1", 4, 9_000)).ok).toBe(false);
    expect((await verifySnapshot(envelope, trusted, "t1", "d1", 5, 9_000)).ok).toBe(false); // revision not strictly newer
    expect((await verifySnapshot(envelope, trusted, "t1", "d1", 4, 20_000)).ok).toBe(false); // expired
    expect(await verifySnapshot(envelope, new Map(), "t1", "d1", 4, 9_000)).toEqual({
      ok: false,
      reason: "unknown_key_id",
    });
    expect(await verifySnapshot({ ...envelope, signature: "" }, trusted, "t1", "d1", 4, 9_000)).toEqual({
      ok: false,
      reason: "missing_signature",
    });
  });
});

describe("SignedSnapshotStore", () => {
  test("adopts strictly-newer authentic snapshots and fails closed on expiry", async () => {
    const { seedB64, publicB64 } = await freshKeypair();
    const signingKey = await parseSigningKey(seedB64, "f");
    const verifyingKey = await parseVerifyingKey(publicB64, "f");
    const store = new SignedSnapshotStore(new Map([["k1", verifyingKey]]), "t1", "d1");
    expect(store.status(0)).toEqual({ type: "no_snapshot" });

    const first = await signSnapshot(payload, "t1", "d1", 1, 1_000, signingKey, "k1");
    expect(await store.ingest(first, 500)).toEqual({ type: "activated", revision: 1 });
    expect(store.activeRevision()).toBe(1);

    // A replay (same revision) is rejected; last-known-good is retained.
    expect((await store.ingest(first, 600)).type).toBe("rejected");

    // Past expiry -> fail closed (no payload served).
    expect(store.status(2_000).type).toBe("expired_fail_closed");
    expect(store.activePayload(2_000)).toBeNull();
    expect(store.activePayload(500)).toEqual(payload);
  });
});

describe("buildSnapshotCrypto", () => {
  test("both disabled -> legacy unsigned (null signer + verifier)", async () => {
    const crypto = await buildSnapshotCrypto(clusterConfigSchema.parse({}));
    expect(crypto).toEqual({ signer: null, verifier: null });
  });

  test("signing without an identity is rejected", async () => {
    const cluster = clusterConfigSchema.parse({ snapshot_signing_key: "AAAA" });
    await expect(buildSnapshotCrypto(cluster)).rejects.toThrow(/snapshot_tenant_id/);
  });

  test("builds a signer + verifier from a valid cluster config", async () => {
    const { seedB64, publicB64 } = await freshKeypair();
    const cluster = clusterConfigSchema.parse({
      snapshot_signing_key: seedB64,
      snapshot_signing_key_id: "k1",
      snapshot_tenant_id: "t1",
      snapshot_deployment_id: "d1",
      snapshot_trusted_keys: [{ key_id: "k1", public_key: publicB64 }],
    });
    const built = await buildSnapshotCrypto(cluster);
    expect(built.signer).not.toBeNull();
    expect(built.verifier).not.toBeNull();
  });
});

/**
 * `ed25519-dalek::verify_strict` parity — the leg the module header used to
 * carry as an unclosed residual gap. WebCrypto's `verify` is the RFC 8032
 * baseline only; `verify_strict` additionally refuses non-canonical encodings
 * and small-order `A`/`R`. Both halves are now enforced in `verifySnapshot`.
 */
describe("verify_strict parity: small-order / non-canonical points", () => {
  const hex = (value: string) => Uint8Array.from(value.match(/../g)!.map((b) => parseInt(b, 16)));
  const leBytes = (value: bigint) => {
    const out = new Uint8Array(32);
    let rest = value;
    for (let index = 0; index < 32; index += 1) {
      out[index] = Number(rest & 0xffn);
      rest >>= 8n;
    }
    return out;
  };
  const P = (1n << 255n) - 19n;

  // libsodium's published small-order blocklist (`ed25519_ref10`'s `has_small_order`).
  const smallOrder: [string, Uint8Array][] = [
    ["y = 0 (order 4, the all-zero encoding)", new Uint8Array(32)],
    ["y = 1 (the identity, order 1)", leBytes(1n)],
    ["y = p-1 (order 2)", leBytes(P - 1n)],
    ["y = p (non-canonical, order 4)", leBytes(P)],
    ["y = p+1 (non-canonical, order 1)", leBytes(P + 1n)],
    ["order-8 representative #1", hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")],
    ["order-8 representative #2", hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")],
  ];
  test.each(smallOrder)("flags %s", (_name, bytes) => {
    expect(isSmallOrderOrNonCanonicalPoint(bytes)).toBe(true);
  });

  test("does NOT flag the ed25519 basepoint", () => {
    expect(
      isSmallOrderOrNonCanonicalPoint(
        hex("5866666666666666666666666666666666666666666666666666666666666666"),
      ),
    ).toBe(false);
  });

  test("does NOT flag freshly generated real public keys", async () => {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
      expect(isSmallOrderOrNonCanonicalPoint(raw)).toBe(false);
    }
  });

  /**
   * The forgery WebCrypto alone would admit: with the order-4 all-zero public
   * key, `crypto.subtle.verify` returns TRUE for an all-zero signature over
   * ARBITRARY content. This test first proves the raw platform primitive does
   * that, then proves `verifySnapshot` refuses the envelope anyway.
   */
  test("an all-zero trusted key cannot authenticate an arbitrary envelope", async () => {
    const zeroKeyB64 = btoa(String.fromCharCode(...new Uint8Array(32)));
    const zeroSigB64 = btoa(String.fromCharCode(...new Uint8Array(64)));
    const verifyingKey = await parseVerifyingKey(zeroKeyB64, "cluster.snapshot_trusted_keys");

    // The platform primitive really is this permissive. Whether the all-zero
    // signature closes depends on `k = H(R || A || M) mod L` landing in the
    // right residue class, so ~1 message in 4 forges; these four are fixed
    // witnesses found by enumeration, and every one of them must verify.
    for (const message of ["forge-4", "forge-14", "forge-15", "forge-18"]) {
      expect(
        await crypto.subtle.verify(
          "Ed25519",
          verifyingKey,
          new Uint8Array(64),
          new TextEncoder().encode(message),
        ),
      ).toBe(true);
    }

    const forged: SignedSnapshotEnvelope = {
      schema_version: SIGNED_SNAPSHOT_SCHEMA_VERSION,
      tenant_id: "t1",
      deployment_id: "d1",
      key_id: "k1",
      revision: 9,
      not_after_unix: 10_000,
      payload,
      signature: zeroSigB64,
    };
    expect(
      await verifySnapshot(forged, new Map([["k1", verifyingKey]]), "t1", "d1", 0, 9_000),
    ).toEqual({ ok: false, reason: "bad_signature" });
  });

  test("a small-order R in an otherwise well-formed signature is refused", async () => {
    const { seedB64, publicB64 } = await freshKeypair();
    const signingKey = await parseSigningKey(seedB64, "f");
    const verifyingKey = await parseVerifyingKey(publicB64, "f");
    const envelope = await signSnapshot(payload, "t1", "d1", 5, 10_000, signingKey, "k1");

    const signature = Uint8Array.from(atob(envelope.signature), (c) => c.charCodeAt(0));
    signature.set(new Uint8Array(32), 0); // R := the order-4 all-zero point
    const tampered: SignedSnapshotEnvelope = {
      ...envelope,
      signature: btoa(String.fromCharCode(...signature)),
    };
    expect(
      await verifySnapshot(tampered, new Map([["k1", verifyingKey]]), "t1", "d1", 4, 9_000),
    ).toEqual({ ok: false, reason: "bad_signature" });
  });
});
