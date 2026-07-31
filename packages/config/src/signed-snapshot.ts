/**
 * Port of `ferrogate-config`'s `config/signed_snapshot.rs` (inventory §5.4,
 * "Signed snapshots", issue #206): Ed25519 sign/verify of a cluster config
 * snapshot, the config-driven crypto builder, and the offline last-known-good
 * store.
 *
 * PORT-TODO(inventory §5.8): Rust used `ed25519-dalek` synchronously; this port
 * uses WebCrypto (`crypto.subtle`, Ed25519 is supported in workerd and Node 20+),
 * which is async — so `signSnapshot`/`verifySnapshot`/`buildSnapshotCrypto` and
 * the store's `ingest` return Promises. WebCrypto's verify enforces RFC 8032
 * canonicality; dalek's `verify_strict` additionally rejects small-order keys —
 * the residual gap is noted rather than re-implemented. The snapshot store maps
 * to KV/D1 at the call site; this is the pure decision core.
 */
import type { ApiKey, PolicyRule } from "./schema/index.js";
import type { ClusterConfig } from "./schema/index.js";

/** Schema version this build knows how to verify. */
export const SIGNED_SNAPSHOT_SCHEMA_VERSION = 1;

/** The signable payload: `version` + `api_keys` + `policies`. */
export interface SignedSnapshotPayload {
  version: number;
  api_keys: ApiKey[];
  policies: PolicyRule[];
}

/** A signed, self-describing snapshot envelope. */
export interface SignedSnapshotEnvelope {
  schema_version: number;
  tenant_id: string;
  deployment_id: string;
  key_id: string;
  revision: number;
  not_after_unix: number;
  payload: SignedSnapshotPayload;
  /** base64 (standard, padded) of the 64-byte Ed25519 signature over the other fields. */
  signature: string;
}

/** A snapshot whose signature + metadata passed every check. */
export interface VerifiedSnapshot {
  key_id: string;
  tenant_id: string;
  deployment_id: string;
  revision: number;
  not_after_unix: number;
  payload: SignedSnapshotPayload;
}

/** Typed, exhaustive reasons `verifySnapshot` can reject an envelope. */
export type RejectReason =
  | "missing_signature"
  | "unknown_key_id"
  | "bad_signature"
  | "identity_mismatch"
  | "schema_unsupported"
  | "stale_or_replayed_revision"
  | "expired"
  | "malformed_field";

/** Human text for a {@link RejectReason} (Rust `Display`). */
export function describeRejectReason(reason: RejectReason): string {
  switch (reason) {
    case "missing_signature":
      return "signature is missing or empty";
    case "unknown_key_id":
      return "no trusted key for the supplied key_id";
    case "bad_signature":
      return "signature failed verification";
    case "identity_mismatch":
      return "tenant/deployment identity mismatch";
    case "schema_unsupported":
      return "unsupported schema_version";
    case "stale_or_replayed_revision":
      return "revision is stale or replayed";
    case "expired":
      return "snapshot has expired";
    case "malformed_field":
      return "a field was malformed or unparseable";
  }
}

/** Result of a verification attempt. */
export type VerifyResult =
  | { ok: true; snapshot: VerifiedSnapshot }
  | { ok: false; reason: RejectReason };

const ED25519_KEY_LEN = 32;

/** A configured snapshot key/identity that is unusable. */
export class SnapshotConfigError extends Error {
  override readonly name = "SnapshotConfigError";
  readonly kind: string;
  readonly field?: string;
  constructor(kind: string, message: string, field?: string) {
    super(message);
    this.kind = kind;
    this.field = field;
  }
}

// --- base64 (standard alphabet) --------------------------------------------

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const binary = atob(b64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function decodeEd25519Bytes(b64: string, field: string): Uint8Array {
  const bytes = base64ToBytes(b64);
  if (bytes === null) {
    throw new SnapshotConfigError("invalid_base64", `field ${field}: must be valid base64`, field);
  }
  if (bytes.length !== ED25519_KEY_LEN) {
    throw new SnapshotConfigError(
      "wrong_key_length",
      `field ${field}: expected a 32-byte ed25519 key, got ${bytes.length} bytes`,
      field,
    );
  }
  return bytes;
}

// PKCS8 DER prefix for an Ed25519 private key (seed follows).
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Parse a base64 32-byte Ed25519 seed into a signing `CryptoKey`. */
export async function parseSigningKey(b64Seed: string, field: string): Promise<CryptoKey> {
  const seed = decodeEd25519Bytes(b64Seed, field);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  try {
    return await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  } catch {
    throw new SnapshotConfigError("wrong_key_length", `field ${field}: invalid ed25519 signing key`, field);
  }
}

/** Parse a base64 32-byte Ed25519 public key into a verifying `CryptoKey`. */
export async function parseVerifyingKey(b64Public: string, field: string): Promise<CryptoKey> {
  const bytes = decodeEd25519Bytes(b64Public, field);
  try {
    return await crypto.subtle.importKey("raw", bytes, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw new SnapshotConfigError(
      "wrong_key_length",
      `field ${field}: expected a 32-byte ed25519 key, got ${ED25519_KEY_LEN} bytes`,
      field,
    );
  }
}

// --- canonical encoding -----------------------------------------------------

/**
 * Deterministic canonical byte encoding of every envelope field except the
 * signature: object keys sorted lexicographically at every level, arrays in
 * order. Both sign and verify call this, so identical logical content yields
 * identical bytes.
 */
function canonicalSigningBytes(
  schemaVersion: number,
  tenantId: string,
  deploymentId: string,
  keyId: string,
  revision: number,
  notAfterUnix: number,
  payload: SignedSnapshotPayload,
): Uint8Array {
  const input = {
    schema_version: schemaVersion,
    tenant_id: tenantId,
    deployment_id: deploymentId,
    key_id: keyId,
    revision,
    not_after_unix: notAfterUnix,
    payload,
  };
  const value = JSON.parse(JSON.stringify(input));
  return new TextEncoder().encode(writeCanonical(value));
}

function writeCanonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(writeCanonical).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${writeCanonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// --- sign / verify ----------------------------------------------------------

/** Produce a signed envelope for `payload` (producer / control plane). */
export async function signSnapshot(
  payload: SignedSnapshotPayload,
  tenantId: string,
  deploymentId: string,
  revision: number,
  notAfterUnix: number,
  signingKey: CryptoKey,
  keyId: string,
): Promise<SignedSnapshotEnvelope> {
  const schemaVersion = SIGNED_SNAPSHOT_SCHEMA_VERSION;
  const canonical = canonicalSigningBytes(
    schemaVersion,
    tenantId,
    deploymentId,
    keyId,
    revision,
    notAfterUnix,
    payload,
  );
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", signingKey, canonical));
  return {
    schema_version: schemaVersion,
    tenant_id: tenantId,
    deployment_id: deploymentId,
    key_id: keyId,
    revision,
    not_after_unix: notAfterUnix,
    payload,
    signature: bytesToBase64(signature),
  };
}

/**
 * Verify a signed envelope against a trust map, fail-closed and in the same
 * order as the Rust source (signature/key_id guard → canonical bytes → key
 * lookup → crypto verify → identity → schema → revision → expiry). A rejection
 * is NEVER turned into `ok: true`.
 */
export async function verifySnapshot(
  envelope: SignedSnapshotEnvelope,
  trustedKeys: Map<string, CryptoKey>,
  expectedTenant: string,
  expectedDeployment: string,
  activeRevision: number,
  nowUnix: number,
): Promise<VerifyResult> {
  if (envelope.signature.trim().length === 0) return { ok: false, reason: "missing_signature" };
  if (envelope.key_id.length === 0) return { ok: false, reason: "unknown_key_id" };

  const canonical = canonicalSigningBytes(
    envelope.schema_version,
    envelope.tenant_id,
    envelope.deployment_id,
    envelope.key_id,
    envelope.revision,
    envelope.not_after_unix,
    envelope.payload,
  );

  const verifyingKey = trustedKeys.get(envelope.key_id);
  if (verifyingKey === undefined) return { ok: false, reason: "unknown_key_id" };

  const signatureBytes = base64ToBytes(envelope.signature);
  if (signatureBytes === null || signatureBytes.length !== 64) {
    return { ok: false, reason: "malformed_field" };
  }
  let valid: boolean;
  try {
    valid = await crypto.subtle.verify("Ed25519", verifyingKey, signatureBytes, canonical);
  } catch {
    return { ok: false, reason: "malformed_field" };
  }
  if (!valid) return { ok: false, reason: "bad_signature" };

  if (envelope.tenant_id !== expectedTenant || envelope.deployment_id !== expectedDeployment) {
    return { ok: false, reason: "identity_mismatch" };
  }
  if (envelope.schema_version !== SIGNED_SNAPSHOT_SCHEMA_VERSION) {
    return { ok: false, reason: "schema_unsupported" };
  }
  if (envelope.revision <= activeRevision) {
    return { ok: false, reason: "stale_or_replayed_revision" };
  }
  if (nowUnix > envelope.not_after_unix) {
    return { ok: false, reason: "expired" };
  }

  return {
    ok: true,
    snapshot: {
      key_id: envelope.key_id,
      tenant_id: envelope.tenant_id,
      deployment_id: envelope.deployment_id,
      revision: envelope.revision,
      not_after_unix: envelope.not_after_unix,
      payload: envelope.payload,
    },
  };
}

// --- config-driven crypto ---------------------------------------------------

/** Producer-side signing material for file-backed control-plane snapshots. */
export class SnapshotSigner {
  constructor(
    private readonly signingKey: CryptoKey,
    readonly keyId: string,
    readonly tenantId: string,
    readonly deploymentId: string,
    private readonly maxAgeSecs: number,
  ) {}

  /** Sign `payload` for `revision`, stamping expiry `nowUnix + maxAgeSecs`. */
  sign(payload: SignedSnapshotPayload, revision: number, nowUnix: number): Promise<SignedSnapshotEnvelope> {
    const notAfterUnix = nowUnix + this.maxAgeSecs;
    return signSnapshot(
      payload,
      this.tenantId,
      this.deploymentId,
      revision,
      notAfterUnix,
      this.signingKey,
      this.keyId,
    );
  }
}

/** Consumer-side verification material. */
export class SnapshotVerifier {
  constructor(
    readonly trustedKeys: Map<string, CryptoKey>,
    readonly expectedTenant: string,
    readonly expectedDeployment: string,
  ) {}

  verify(envelope: SignedSnapshotEnvelope, activeRevision: number, nowUnix: number): Promise<VerifyResult> {
    return verifySnapshot(
      envelope,
      this.trustedKeys,
      this.expectedTenant,
      this.expectedDeployment,
      activeRevision,
      nowUnix,
    );
  }
}

/** The signing/verification material derived from a node's cluster config. */
export interface SnapshotCrypto {
  signer: SnapshotSigner | null;
  verifier: SnapshotVerifier | null;
}

/** The `(tenant, deployment)` identity a crypto signs/verifies for, or `null`. */
export function snapshotCryptoIdentity(crypto: SnapshotCrypto): [string, string] | null {
  if (crypto.verifier !== null) {
    return [crypto.verifier.expectedTenant, crypto.verifier.expectedDeployment];
  }
  if (crypto.signer !== null) return [crypto.signer.tenantId, crypto.signer.deploymentId];
  return null;
}

/**
 * Build the snapshot signing/verification material from cluster config, or
 * throw the first {@link SnapshotConfigError}. Called both by `validateConfig`
 * (result discarded) and at runtime, so a config that validates is one that
 * builds. Both fields `null` = legacy unsigned behavior.
 */
export async function buildSnapshotCrypto(cluster: ClusterConfig): Promise<SnapshotCrypto> {
  const signingEnabled =
    typeof cluster.snapshot_signing_key === "string" && cluster.snapshot_signing_key.trim().length > 0;
  const verificationEnabled = cluster.snapshot_trusted_keys.length > 0;

  if (!signingEnabled && !verificationEnabled) return { signer: null, verifier: null };

  const tenantId = requireIdentity(cluster.snapshot_tenant_id, "cluster.snapshot_tenant_id");
  const deploymentId = requireIdentity(cluster.snapshot_deployment_id, "cluster.snapshot_deployment_id");

  let signer: SnapshotSigner | null = null;
  if (signingEnabled) {
    if (cluster.snapshot_max_age_secs === 0) {
      throw new SnapshotConfigError(
        "zero_max_age",
        "field cluster.snapshot_max_age_secs: must be greater than zero when signing is enabled",
      );
    }
    const keyId = cluster.snapshot_signing_key_id?.trim();
    if (keyId === undefined || keyId.length === 0) {
      throw new SnapshotConfigError(
        "missing_signing_key_id",
        "field cluster.snapshot_signing_key_id: required when cluster.snapshot_signing_key is set",
      );
    }
    const signingKey = await parseSigningKey(cluster.snapshot_signing_key ?? "", "cluster.snapshot_signing_key");
    signer = new SnapshotSigner(signingKey, keyId, tenantId, deploymentId, cluster.snapshot_max_age_secs);
  }

  let verifier: SnapshotVerifier | null = null;
  if (verificationEnabled) {
    const trustedKeys = new Map<string, CryptoKey>();
    for (const entry of cluster.snapshot_trusted_keys) {
      const keyId = entry.key_id.trim();
      if (keyId.length === 0) {
        throw new SnapshotConfigError(
          "empty_trusted_key_id",
          "field cluster.snapshot_trusted_keys: key_id cannot be empty",
        );
      }
      const verifyingKey = await parseVerifyingKey(entry.public_key, "cluster.snapshot_trusted_keys.public_key");
      if (trustedKeys.has(keyId)) {
        throw new SnapshotConfigError(
          "duplicate_trusted_key_id",
          `field cluster.snapshot_trusted_keys: duplicate key_id "${keyId}"`,
        );
      }
      trustedKeys.set(keyId, verifyingKey);
    }
    verifier = new SnapshotVerifier(trustedKeys, tenantId, deploymentId);
  }

  return { signer, verifier };
}

function requireIdentity(value: string | null | undefined, field: string): string {
  const trimmed = value?.trim();
  if (trimmed === undefined || trimmed.length === 0) {
    throw new SnapshotConfigError(
      "missing_identity",
      `field ${field}: required when snapshot signing or verification is enabled`,
      field,
    );
  }
  return trimmed;
}

// --- offline store ----------------------------------------------------------

/** Outcome of feeding an envelope to a {@link SignedSnapshotStore}. */
export type SnapshotIngestOutcome =
  | { type: "activated"; revision: number }
  | { type: "rejected"; reason: RejectReason };

/** The data plane's offline serving status. */
export type OfflineStatus =
  | { type: "no_snapshot" }
  | { type: "active"; revision: number; not_after_unix: number; seconds_until_expiry: number }
  | { type: "expired_fail_closed"; revision: number; not_after_unix: number };

/**
 * The data-plane side of the offline policy loop (issue #206): holds the last
 * verified snapshot, accepts only strictly-newer authentic snapshots, and
 * decides what may be served during a control-plane outage (last-known-good
 * until expiry, then fail closed).
 */
export class SignedSnapshotStore {
  private lastKnownGood: VerifiedSnapshot | null = null;

  constructor(
    private readonly trustedKeys: Map<string, CryptoKey>,
    private readonly expectedTenant: string,
    private readonly expectedDeployment: string,
  ) {}

  /** The active revision (0 when none accepted) — the replay/downgrade floor. */
  activeRevision(): number {
    return this.lastKnownGood?.revision ?? 0;
  }

  /** Verify + (only if it passes) adopt `envelope` as the new last-known-good. */
  async ingest(envelope: SignedSnapshotEnvelope, nowUnix: number): Promise<SnapshotIngestOutcome> {
    const result = await verifySnapshot(
      envelope,
      this.trustedKeys,
      this.expectedTenant,
      this.expectedDeployment,
      this.activeRevision(),
      nowUnix,
    );
    if (result.ok) {
      this.lastKnownGood = result.snapshot;
      return { type: "activated", revision: result.snapshot.revision };
    }
    return { type: "rejected", reason: result.reason };
  }

  /** The offline serving status at `nowUnix`. */
  status(nowUnix: number): OfflineStatus {
    const snapshot = this.lastKnownGood;
    if (snapshot === null) return { type: "no_snapshot" };
    if (nowUnix <= snapshot.not_after_unix) {
      return {
        type: "active",
        revision: snapshot.revision,
        not_after_unix: snapshot.not_after_unix,
        seconds_until_expiry: snapshot.not_after_unix - nowUnix,
      };
    }
    return { type: "expired_fail_closed", revision: snapshot.revision, not_after_unix: snapshot.not_after_unix };
  }

  /** The payload safe to serve at `nowUnix`, or `null` once expired / never set. */
  activePayload(nowUnix: number): SignedSnapshotPayload | null {
    const snapshot = this.lastKnownGood;
    if (snapshot !== null && nowUnix <= snapshot.not_after_unix) return snapshot.payload;
    return null;
  }
}
