/**
 * The self-hosted worker transport FRAME — `SelfHostedWorkerTransportFrame`.
 *
 * Clean-room port of the sealed envelope in
 * `crates/ferrogate-runtime/src/self_hosted_worker.rs` (`encrypt_json` /
 * `decode_json`). A worker on the `symmetric_aead` channel does not put its
 * `{token_id, token_secret}` envelope on the wire in the clear: it seals the
 * document under a key derived from its transport secret, with the routing
 * header — `{protocol_version, tenant_id, workspace_id, worker_id, token_id}` —
 * as ASSOCIATED DATA. The header must stay readable (the gateway needs it to
 * find which key to try) but must not be forgeable, which is exactly what AAD
 * gives.
 *
 * ## What the frame is and is not
 *
 * The frame adds CONFIDENTIALITY and header integrity. It is NOT the
 * authorization decision — that stays the constant-time `token_secret`
 * comparison in `WorkerIdentityPort.validate`, which runs on the plaintext
 * identity after the frame is opened. Opening a frame proves the sender knew
 * the derived key; admission still requires the registered secret to match.
 *
 * ## The one deliberate divergence from Rust, and why it is unavoidable
 *
 * // PORT-TODO(inventory-edge-control §agent-worker §8.3): Rust seals with
 * // **XChaCha20-Poly1305** (24-byte extended nonce). WebCrypto in workerd
 * // exposes no ChaCha20 family at all — `crypto.subtle` supports AES-GCM,
 * // AES-CBC, AES-CTR, AES-KW, HMAC, RSA-*, ECDSA, ECDH, Ed25519, X25519,
 * // PBKDF2 and HKDF, and nothing else — so the exact Rust wire format cannot
 * // be produced or consumed on this platform without shipping a JS/WASM
 * // ChaCha implementation, which the clean-room rule forbids sourcing from the
 * // Rust tree. Implemented instead, and fully: AES-256-GCM (the same AEAD
 * // construction and the same security goal) with a 96-bit random nonce, the
 * // same associated data, and an HKDF-SHA256 key derivation domain-separated
 * // by {@link FRAME_KEY_INFO}. CONSEQUENCE, stated plainly: a Rust
 * // self-hosted-worker binary emitting XChaCha20 frames does NOT interoperate
 * // with this gateway — such a worker must either use the cleartext
 * // `mutual_tls` marker path (which IS byte-compatible) or be rebuilt against
 * // {@link sealWorkerFrame}. The nonce LENGTH difference is the observable
 * // symptom and {@link openWorkerFrame} rejects a 24-byte nonce explicitly
 * // rather than silently truncating it into an AES-GCM IV.
 */

/** Rust's extended-nonce length. Present ONLY so we can refuse it loudly. */
export const XCHACHA20_NONCE_BYTES = 24;

/** AES-GCM's nonce length. */
export const AES_GCM_NONCE_BYTES = 12;

/** HKDF domain separation for the frame key. Never reused for another purpose. */
export const FRAME_KEY_INFO = "ferrogate:self-hosted-worker:transport-frame:v1";

/** HKDF salt. Fixed and public — the entropy is in the transport secret. */
export const FRAME_KEY_SALT = "ferrogate:self-hosted-worker:transport-frame:v1:salt";

/**
 * The cleartext routing header. It is the AEAD associated data, so any change
 * to it invalidates the frame — a header cannot be swapped onto another
 * worker's ciphertext.
 */
export interface WorkerFrameHeader {
  readonly protocol_version: number;
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly token_id: string;
}

/** The on-the-wire sealed frame. */
export interface SealedWorkerFrame {
  readonly header: WorkerFrameHeader;
  /** base64, 12 bytes. */
  readonly nonce: string;
  /** base64 — AES-GCM ciphertext with the 16-byte tag appended. */
  readonly ciphertext: string;
}

export type FrameOpenFailure =
  | { readonly reason: "invalid_shape"; readonly detail: string }
  | { readonly reason: "unopenable"; readonly detail: string };

export type FrameOpenResult =
  | { readonly outcome: "opened"; readonly envelope: Record<string, unknown> }
  | { readonly outcome: "rejected"; readonly failure: FrameOpenFailure };

// ---------------------------------------------------------------------------
// Canonical associated data
// ---------------------------------------------------------------------------

/**
 * The exact bytes bound as AEAD associated data.
 *
 * A fixed-order pipe-joined string rather than `JSON.stringify(header)`: JSON
 * key order is an encoder detail, so two peers that agree on the header but
 * disagree on key order would compute different AAD and every frame would fail
 * to open for a reason that looks like a wrong key. Each field is
 * length-prefixed so a value containing the separator cannot be re-parsed as
 * two fields (`tenant_id: "a|b"` + `workspace_id: "c"` must not collide with
 * `tenant_id: "a"` + `workspace_id: "b|c"`).
 */
export function frameAssociatedData(header: WorkerFrameHeader): Uint8Array {
  const parts = [
    String(header.protocol_version),
    header.tenant_id,
    header.workspace_id,
    header.worker_id,
    header.token_id,
  ];
  const canonical = parts.map((part) => `${part.length}:${part}`).join("|");
  return new TextEncoder().encode(`${FRAME_KEY_INFO}|${canonical}`);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * Derive the AES-256-GCM frame key from the worker's transport secret.
 *
 * HKDF-SHA256 rather than using the secret's bytes directly: the secret is a
 * printable token, not uniformly random key material, and HKDF is what turns
 * one into the other. The domain-separated `info` also means this key can never
 * collide with any other use of the same secret.
 */
export async function deriveFrameKey(tokenSecret: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(tokenSecret) as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(FRAME_KEY_SALT) as BufferSource,
      info: new TextEncoder().encode(FRAME_KEY_INFO) as BufferSource,
    },
    ikm,
    256,
  );
  return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  try {
    const binary = atob(text);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return undefined;
  }
}

/**
 * Recognize a sealed frame on a parsed body.
 *
 * Deliberately structural and strict: a body is only treated as sealed when it
 * carries a well-formed `sealed` object. Anything else is the cleartext
 * `mutual_tls` marker document, which stays supported because Rust supports it
 * too — this must never "helpfully" reinterpret a cleartext body as a
 * half-decoded frame.
 */
export function readSealedFrame(body: Record<string, unknown>): SealedWorkerFrame | undefined {
  const sealed = body.sealed;
  if (typeof sealed !== "object" || sealed === null || Array.isArray(sealed)) return undefined;
  const candidate = sealed as Record<string, unknown>;
  const header = candidate.header;
  if (typeof header !== "object" || header === null || Array.isArray(header)) return undefined;
  const fields = header as Record<string, unknown>;
  if (typeof fields.protocol_version !== "number" || !Number.isInteger(fields.protocol_version)) {
    return undefined;
  }
  for (const name of ["tenant_id", "workspace_id", "worker_id", "token_id"] as const) {
    if (typeof fields[name] !== "string" || (fields[name] as string).trim() === "") return undefined;
  }
  if (typeof candidate.nonce !== "string" || typeof candidate.ciphertext !== "string") {
    return undefined;
  }
  return {
    header: {
      protocol_version: fields.protocol_version,
      tenant_id: fields.tenant_id as string,
      workspace_id: fields.workspace_id as string,
      worker_id: fields.worker_id as string,
      token_id: fields.token_id as string,
    },
    nonce: candidate.nonce,
    ciphertext: candidate.ciphertext,
  };
}

/**
 * Seal a document. Used by tests and by any first-party client this repo ships;
 * a self-hosted worker binary implements the same construction.
 */
export async function sealWorkerFrame(
  header: WorkerFrameHeader,
  tokenSecret: string,
  document: unknown,
): Promise<SealedWorkerFrame> {
  const nonce = new Uint8Array(AES_GCM_NONCE_BYTES);
  crypto.getRandomValues(nonce);
  const key = await deriveFrameKey(tokenSecret);
  const sealed = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce as BufferSource,
      additionalData: frameAssociatedData(header) as BufferSource,
    },
    key,
    new TextEncoder().encode(JSON.stringify(document)) as BufferSource,
  );
  return {
    header,
    nonce: toBase64(nonce),
    ciphertext: toBase64(new Uint8Array(sealed)),
  };
}

/**
 * Open a sealed frame with the registered worker's transport secret.
 *
 * Every failure collapses onto ONE opaque `unopenable` detail. An attacker
 * probing the frame must not learn whether the tag failed, the key was wrong,
 * or the plaintext was not JSON — those all mean "you did not hold the secret".
 * The two shape failures reported distinctly (bad base64, wrong nonce length)
 * are decided BEFORE any key is touched and disclose nothing about the secret.
 */
export async function openWorkerFrame(
  frame: SealedWorkerFrame,
  tokenSecret: string,
): Promise<FrameOpenResult> {
  const nonce = fromBase64(frame.nonce);
  const ciphertext = fromBase64(frame.ciphertext);
  if (nonce === undefined || ciphertext === undefined) {
    return {
      outcome: "rejected",
      failure: { reason: "invalid_shape", detail: "frame nonce and ciphertext must be base64" },
    };
  }
  if (nonce.length === XCHACHA20_NONCE_BYTES) {
    return {
      outcome: "rejected",
      failure: {
        reason: "invalid_shape",
        detail:
          "frame carries a 24-byte XChaCha20-Poly1305 nonce; this gateway seals with AES-256-GCM (12-byte nonce) because workerd's WebCrypto has no ChaCha20 family",
      },
    };
  }
  if (nonce.length !== AES_GCM_NONCE_BYTES) {
    return {
      outcome: "rejected",
      failure: {
        reason: "invalid_shape",
        detail: `frame nonce must be ${AES_GCM_NONCE_BYTES} bytes`,
      },
    };
  }
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce as BufferSource,
        additionalData: frameAssociatedData(frame.header) as BufferSource,
      },
      await deriveFrameKey(tokenSecret),
      ciphertext as BufferSource,
    );
  } catch {
    return {
      outcome: "rejected",
      failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
    };
  }
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return {
      outcome: "rejected",
      failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
    };
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return {
      outcome: "rejected",
      failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
    };
  }
  return { outcome: "opened", envelope: document as Record<string, unknown> };
}
