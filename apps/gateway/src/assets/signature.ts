/**
 * Detached publisher-signature verification for hosted assets — the port of
 * `crates/ferrogate-gateway/src/asset_signature.rs` (issue #261, slice 2).
 *
 * This closes ONE of the three detectors the `AssetScreener` marker in
 * `./ports.ts` classified as unported. That marker said the primitive was
 * available and the CONTAINER FORMAT was what was unwritten; this file is the
 * container format, and it is written from the minisign byte layout the Rust
 * encodes rather than translated from `ed25519-dalek`/`minisign`.
 *
 * ## What runs on Workers, checked rather than assumed
 *
 *  - **Ed25519 verify: supported.** `crypto.subtle.importKey("raw", …,
 *    { name: "Ed25519" })` + `crypto.subtle.verify` both work in `workerd`
 *    (probed under `@cloudflare/vitest-pool-workers` before this file existed,
 *    not read off a compatibility table). So the signature primitive is the
 *    PLATFORM's, not a hand-rolled curve.
 *  - **BLAKE2b-512: NOT in WebCrypto** — `crypto.subtle.digest("BLAKE2b-512")`
 *    rejects. Modern minisign PREHASHES with it (the `ED` algorithm; `Ed` is
 *    the legacy raw-message form), so without it this port would reject the
 *    default output of the actual `minisign` tool while claiming to support it.
 *    It is therefore taken from `../keys/blake2b.ts`, which already exists in
 *    this app, is written from RFC 7693, and is pinned to the RFC's own
 *    vectors. That digest is `BigInt`-based — ~125 ms per MiB, so ~1.2 s of CPU
 *    at the 10 MiB inline push cap. Stated rather than hidden: it is bounded by
 *    `INLINE_ASSET_MAX_BYTES`, and only the `ED` variant pays it.
 *
 * ## The one deliberate departure
 *
 * Rust calls `verify_strict`, which additionally rejects small-order public
 * keys. WebCrypto exposes no such switch: `crypto.subtle.verify` is RFC 8032
 * verification as the runtime implements it. The gap is not reachable from the
 * threat this gate addresses — a small-order key is one a PUBLISHER would have
 * to register against itself, and registration is an operator action — but it
 * is a difference, so it is named here rather than left to be discovered.
 *
 * ECDSA-keyed cosign stays out of scope exactly as it is in the Rust: the
 * acceptance bar is met by the Ed25519 path.
 */
import { blake2b } from "../keys/blake2b.js";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/** Which detached-signature encoding a push carries — Rust `SignatureFormat`. */
export type SignatureFormat = "minisign" | "ed25519";

/**
 * Parse the `x-asset-signature-format` header value.
 *
 * `cosign` is an alias for `ed25519`: `cosign sign-blob` with an Ed25519 key
 * emits exactly a bare base64 detached signature. `undefined` for anything
 * else — the caller defaults to `minisign`, which is the Rust default, and
 * NEVER to "skip verification".
 */
export function parseSignatureFormat(raw: string): SignatureFormat | undefined {
  switch (raw.trim().toLowerCase()) {
    case "minisign":
      return "minisign";
    case "ed25519":
    case "cosign":
      return "ed25519";
    default:
      return undefined;
  }
}

/** The detached signature material presented at push time. */
export interface AssetSignatureInput {
  readonly format: SignatureFormat;
  /** The signature FILE text (minisign) or bare base64 signature (ed25519). */
  readonly material: string;
  /** Optional publisher key-id hint, for the bare-Ed25519 path. */
  readonly keyId?: string | undefined;
}

/**
 * The outcome, serialized into the verification manifest so a consuming agent
 * can decide whether to trust the blob before executing it — Rust
 * `SignatureStatus`, including its `#[serde(tag = "status")]` wire shape.
 *
 * `unverified` and `invalid` are deliberately DISTINCT: "I do not know this
 * key" is an operator-configuration problem, "these bytes do not match this
 * signature" is a supply-chain one, and collapsing them would hide the second
 * behind the first.
 */
export type SignatureStatus =
  | { readonly status: "unsigned" }
  | { readonly status: "verified"; readonly key_id: string; readonly format: SignatureFormat }
  | { readonly status: "unverified"; readonly reason: string }
  | { readonly status: "invalid"; readonly reason: string };

/** Rust `SignatureStatus::is_verified`. */
export function signatureIsVerified(status: SignatureStatus): boolean {
  return status.status === "verified";
}

/** Rust `SignatureStatus::label` — the token the audit line carries. */
export function signatureStatusLabel(status: SignatureStatus): string {
  return status.status;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/** Standard base64 → bytes, or `null`. Never throws: a bad line is DATA. */
function decodeBase64(raw: string): Uint8Array | null {
  const text = raw.trim();
  if (text === "" || /[^A-Za-z0-9+/=\s]/.test(text)) return null;
  try {
    const binary = atob(text.replace(/\s+/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

/** Rust `hex_lower`. */
export function hexLower(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function bufferOf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Import a raw 32-byte Ed25519 public key, or `null` if the runtime refuses. */
async function importEd25519(publicKey: Uint8Array): Promise<CryptoKey | null> {
  if (publicKey.byteLength !== 32) return null;
  try {
    return await crypto.subtle.importKey("raw", bufferOf(publicKey), { name: "Ed25519" }, false, [
      "verify",
    ]);
  } catch {
    return null;
  }
}

async function ed25519Verify(
  key: CryptoKey,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      bufferOf(signature),
      bufferOf(message),
    );
  } catch {
    // A malformed signature makes `verify` REJECT in some runtimes rather than
    // resolve `false`. Both mean "did not verify"; neither may propagate as a
    // 500 out of a content gate.
    return false;
  }
}

// ---------------------------------------------------------------------------
// minisign container parsing
// ---------------------------------------------------------------------------

/** A parsed minisign public key: `algo(2) || key_id(8) || pubkey(32)` = 42 bytes. */
export interface MinisignPublicKey {
  /** Lowercase hex of the embedded 8-byte key id. */
  readonly keyIdHex: string;
  readonly publicKey: Uint8Array;
}

/**
 * Rust `parse_minisign_public_key`.
 *
 * The LAST non-empty, non-`untrusted comment:` line wins (Rust `rfind`), which
 * is what makes a key file with a comment header parse the same as a bare key.
 */
export function parseMinisignPublicKey(text: string): MinisignPublicKey | { error: string } {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("untrusted comment:"));
  const line = lines[lines.length - 1];
  if (line === undefined) return { error: "minisign public key is empty" };
  const bytes = decodeBase64(line);
  if (bytes === null) return { error: "minisign public key is not valid base64" };
  if (bytes.byteLength !== 42) {
    return { error: `expected a 42-byte minisign public key, got ${bytes.byteLength} bytes` };
  }
  return {
    keyIdHex: hexLower(bytes.subarray(2, 10)),
    publicKey: bytes.subarray(10, 42),
  };
}

interface MinisignSignature {
  /** `"Ed"` (raw message) or `"ED"` (BLAKE2b-512 prehashed). */
  readonly algorithm: string;
  readonly keyIdHex: string;
  readonly signature: Uint8Array;
}

/**
 * Rust `parse_minisign_signature`: the first base64 line that decodes to
 * `algo(2) || key_id(8) || signature(64)` = 74 bytes.
 *
 * Lines that are comments, or that decode to anything else, are SKIPPED rather
 * than rejected — a minisign `.minisig` carries a `trusted comment:` line and a
 * second, shorter base64 blob (the global signature over that comment) after
 * the one this reads.
 */
export function parseMinisignSignature(text: string): MinisignSignature | { error: string } {
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (
      line === "" ||
      line.startsWith("untrusted comment:") ||
      line.startsWith("trusted comment:")
    ) {
      continue;
    }
    const bytes = decodeBase64(line);
    if (bytes === null || bytes.byteLength !== 74) continue;
    return {
      algorithm: String.fromCharCode(bytes[0] as number, bytes[1] as number),
      keyIdHex: hexLower(bytes.subarray(2, 10)),
      signature: bytes.subarray(10, 74),
    };
  }
  return { error: "no 74-byte minisign signature line found" };
}

// ---------------------------------------------------------------------------
// Publisher key registry
// ---------------------------------------------------------------------------

/** Worker vars the registry reads — the Rust `from_env` names, verbatim. */
export interface PublisherKeyBindings {
  /** Newline/comma-separated `label=<base64 32-byte key>` entries. */
  readonly FERROGATE_ASSET_PUBLISHER_ED25519_KEYS?: string;
  /** Newline-separated minisign public keys (`RW…`, comment header optional). */
  readonly FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS?: string;
}

/**
 * Publisher-registered verification keys — Rust `PublisherKeyRegistry`.
 *
 * Minisign keys are indexed by their EMBEDDED key id (so a signature names its
 * own key); bare Ed25519 keys by an operator-chosen label (so `cosign` output,
 * which carries no key id, can name one).
 *
 * Registration is `async` where Rust's is not, and only because
 * `crypto.subtle.importKey` is: the platform owns the key parse, so a byte
 * string that is not a point on the curve is rejected by the RUNTIME rather
 * than by a length check here.
 */
export class PublisherKeyRegistry {
  readonly #minisign = new Map<string, CryptoKey>();
  readonly #ed25519 = new Map<string, CryptoKey>();

  /** Registered minisign key ids (hex), for diagnostics and tests. */
  get minisignKeyIds(): readonly string[] {
    return [...this.#minisign.keys()].sort();
  }

  /** Registered bare-Ed25519 labels, sorted — Rust's `BTreeMap` order. */
  get ed25519KeyIds(): readonly string[] {
    return [...this.#ed25519.keys()].sort();
  }

  get isEmpty(): boolean {
    return this.#minisign.size === 0 && this.#ed25519.size === 0;
  }

  /** Register a minisign public key; resolves to its hex key id, or an error. */
  async registerMinisign(publicKey: string): Promise<string | { error: string }> {
    const parsed = parseMinisignPublicKey(publicKey);
    if ("error" in parsed) return parsed;
    const key = await importEd25519(parsed.publicKey);
    if (key === null) {
      return { error: "minisign public key is not a valid ed25519 key" };
    }
    this.#minisign.set(parsed.keyIdHex, key);
    return parsed.keyIdHex;
  }

  /** Register a bare base64 32-byte Ed25519 public key under `keyId`. */
  async registerEd25519(keyId: string, publicKeyBase64: string): Promise<null | { error: string }> {
    const bytes = decodeBase64(publicKeyBase64);
    if (bytes === null) return { error: "public key is not valid base64" };
    if (bytes.byteLength !== 32) {
      return { error: `expected a 32-byte ed25519 key, got ${bytes.byteLength} bytes` };
    }
    const key = await importEd25519(bytes);
    if (key === null) return { error: "not a valid ed25519 key" };
    this.#ed25519.set(keyId, key);
    return null;
  }

  /**
   * Rust `PublisherKeyRegistry::from_env`, reading Worker vars instead of
   * process env.
   *
   * A malformed entry is SKIPPED, exactly as Rust's `let _ = register…`
   * discards the error: one bad line must not take the other publishers'
   * keys down with it. The consequence — a signature that then fails to
   * verify — is `unverified`, which is a labeled refusal, not a silent pass.
   */
  static async fromEnv(env: PublisherKeyBindings): Promise<PublisherKeyRegistry> {
    const registry = new PublisherKeyRegistry();
    for (const entry of (env.FERROGATE_ASSET_PUBLISHER_ED25519_KEYS ?? "")
      .split(/[,\n]/)
      .map((value) => value.trim())
      .filter((value) => value !== "")) {
      const separator = entry.indexOf("=");
      if (separator <= 0) continue;
      await registry.registerEd25519(
        entry.slice(0, separator).trim(),
        entry.slice(separator + 1).trim(),
      );
    }
    for (const entry of (env.FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS ?? "")
      .split("\n")
      .map((value) => value.trim())
      .filter((value) => value !== "")) {
      await registry.registerMinisign(entry);
    }
    return registry;
  }

  minisignKey(keyIdHex: string): CryptoKey | undefined {
    return this.#minisign.get(keyIdHex);
  }

  ed25519Key(keyId: string): CryptoKey | undefined {
    return this.#ed25519.get(keyId);
  }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Rust `verify_asset_signature`. */
export async function verifyAssetSignature(
  content: Uint8Array,
  signature: AssetSignatureInput,
  keys: PublisherKeyRegistry,
): Promise<SignatureStatus> {
  return signature.format === "minisign"
    ? verifyMinisign(content, signature.material, keys)
    : verifyBareEd25519(content, signature.material, signature.keyId, keys);
}

/** Rust `verify_minisign`. */
async function verifyMinisign(
  content: Uint8Array,
  text: string,
  keys: PublisherKeyRegistry,
): Promise<SignatureStatus> {
  const parsed = parseMinisignSignature(text);
  if ("error" in parsed) return { status: "invalid", reason: parsed.error };

  const key = keys.minisignKey(parsed.keyIdHex);
  if (key === undefined) {
    return {
      status: "unverified",
      reason: `no registered minisign key for id ${parsed.keyIdHex}`,
    };
  }

  // minisign signs the raw file (`Ed`) or its BLAKE2b-512 hash (`ED`,
  // prehashed) as an ordinary Ed25519 message.
  let message: Uint8Array;
  if (parsed.algorithm === "ED") {
    message = blake2b(content);
  } else if (parsed.algorithm === "Ed") {
    message = content;
  } else {
    return {
      status: "invalid",
      reason: `unsupported minisign algorithm ${parsed.algorithm}`,
    };
  }

  return (await ed25519Verify(key, parsed.signature, message))
    ? { status: "verified", key_id: parsed.keyIdHex, format: "minisign" }
    : {
        status: "invalid",
        reason: "minisign signature did not verify against the registered key",
      };
}

/** Rust `verify_bare_ed25519`. */
async function verifyBareEd25519(
  content: Uint8Array,
  material: string,
  keyIdHint: string | undefined,
  keys: PublisherKeyRegistry,
): Promise<SignatureStatus> {
  const signature = decodeBase64(material);
  if (signature === null) {
    return { status: "invalid", reason: "signature is not valid base64" };
  }
  if (signature.byteLength !== 64) {
    return {
      status: "invalid",
      reason: `expected a 64-byte ed25519 signature, got ${signature.byteLength} bytes`,
    };
  }

  if (keyIdHint !== undefined && keyIdHint !== "") {
    const key = keys.ed25519Key(keyIdHint);
    if (key === undefined) {
      return { status: "unverified", reason: `no registered ed25519 key with id ${keyIdHint}` };
    }
    return (await ed25519Verify(key, signature, content))
      ? { status: "verified", key_id: keyIdHint, format: "ed25519" }
      : {
          status: "invalid",
          reason: "ed25519 signature did not verify against the named key",
        };
  }

  // No hint: accept if ANY registered key verifies it. Sorted, so the reported
  // `key_id` is deterministic — Rust iterates a `BTreeMap`.
  for (const keyId of keys.ed25519KeyIds) {
    const key = keys.ed25519Key(keyId);
    if (key !== undefined && (await ed25519Verify(key, signature, content))) {
      return { status: "verified", key_id: keyId, format: "ed25519" };
    }
  }
  return keys.ed25519KeyIds.length === 0
    ? { status: "unverified", reason: "no publisher ed25519 keys are registered" }
    : {
        status: "invalid",
        reason: "ed25519 signature did not verify against any registered key",
      };
}
