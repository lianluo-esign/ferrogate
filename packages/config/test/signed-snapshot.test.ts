import { describe, expect, test } from "vitest";
import {
  buildSnapshotCrypto,
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
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32); // last 32 bytes of the PKCS8 DER
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
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
