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
 * ## Two accepted wire formats, and why
 *
 * `openWorkerFrame` opens BOTH, dispatching on {@link SealedWorkerFrame.format}:
 *
 * | format | wire shape | AEAD | nonce | who emits it |
 * |---|---|---|---|---|
 * | `xchacha20poly1305` | Rust `SelfHostedWorkerTransportFrame` (top-level routing header + `encoding` + `encrypted_payload`) | XChaCha20-Poly1305 | 24 B | a Rust/host self-hosted-worker binary |
 * | `aes_gcm` | `{ sealed: { header, nonce, ciphertext } }` | AES-256-GCM | 12 B | this repo's own clients |
 *
 * The Rust format is the PARITY one and it is implemented byte-for-byte: same
 * `xchacha20poly1305` algorithm tag, same `\n`-joined associated data, same
 * HKDF-SHA256(salt=`ferrogate/self-hosted-worker/transport-aead`,
 * info=`ferrogate-self-hosted-worker-transport-v1`) key schedule, same 32-char
 * minimum transport secret. workerd's `crypto.subtle` has no ChaCha20 family,
 * but that is a limit on WebCrypto, not on the platform — the cipher is
 * implemented from RFC 8439 + draft-irtf-cfrg-xchacha in
 * `xchacha20poly1305.ts` and pinned to the published test vectors, so an
 * unmodified Rust worker binary interoperates with this gateway.
 *
 * The AES-GCM format is this port's own addition, kept because it is what the
 * repo's TS clients already seal with and because `crypto.subtle` runs it
 * natively. Neither format is a weaker door: both derive their key from the
 * registered `token_secret`, both bind the routing header as associated data,
 * and both still have to hand the opened identity to
 * {@link WorkerIdentityPort.validate} to be admitted.
 */

import {
  XCHACHA20_NONCE_BYTES,
  xchacha20poly1305Open,
  xchacha20poly1305Seal,
} from "./xchacha20poly1305.js";

export { XCHACHA20_NONCE_BYTES };

/** AES-GCM's nonce length. */
export const AES_GCM_NONCE_BYTES = 12;

/** HKDF domain separation for the frame key. Never reused for another purpose. */
export const FRAME_KEY_INFO = "ferrogate:self-hosted-worker:transport-frame:v1";

/** HKDF salt. Fixed and public — the entropy is in the transport secret. */
export const FRAME_KEY_SALT = "ferrogate:self-hosted-worker:transport-frame:v1:salt";

// ---------------------------------------------------------------------------
// Rust wire-format constants — `crates/ferrogate-runtime/src/self_hosted_worker.rs`
// ---------------------------------------------------------------------------

/** Rust `SELF_HOSTED_WORKER_SYMMETRIC_AEAD_ALGORITHM`, verbatim. */
export const RUST_FRAME_ALGORITHM = "xchacha20poly1305";

/** Rust `SelfHostedWorkerTransportFrameEncoding::EncryptedJson`, serde snake_case. */
export const RUST_FRAME_ENCODING = "encrypted_json";

/** Rust `SELF_HOSTED_WORKER_TRANSPORT_HKDF_SALT`, byte for byte. */
export const RUST_FRAME_HKDF_SALT = "ferrogate/self-hosted-worker/transport-aead";

/** Rust `SELF_HOSTED_WORKER_TRANSPORT_HKDF_INFO`, byte for byte. */
export const RUST_FRAME_HKDF_INFO = "ferrogate-self-hosted-worker-transport-v1";

/**
 * Rust `SELF_HOSTED_WORKER_TRANSPORT_SECRET_MIN_LEN`.
 *
 * Ported because it FAILS CLOSED, not for symmetry: a worker registered before
 * the provisioned-secret migration carries an empty `token_secret`, and HKDF
 * would happily derive a perfectly-shaped key from it. Refusing below the floor
 * is what stops a legacy row from keying the cipher at all.
 */
export const RUST_FRAME_SECRET_MIN_LEN = 32;

/** Rust `SELF_HOSTED_WORKER_HTTP_MAX_MESSAGE_BYTES`. */
export const RUST_FRAME_MAX_MESSAGE_BYTES = 1024 * 1024;

/** Which AEAD a frame is sealed under. Absent ⇒ this port's native AES-256-GCM. */
export type FrameFormat = "aes_gcm" | "xchacha20poly1305";

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

/**
 * The on-the-wire sealed frame, normalized across both accepted formats.
 *
 * `format` is absent on frames this port seals itself, which keeps every
 * existing caller and every stored fixture valid; absent means `aes_gcm`.
 */
export interface SealedWorkerFrame {
  readonly header: WorkerFrameHeader;
  /** base64 — 12 bytes for `aes_gcm`, 24 for `xchacha20poly1305`. */
  readonly nonce: string;
  /** base64 — ciphertext with the 16-byte AEAD tag appended. */
  readonly ciphertext: string;
  /** Which AEAD opens it. Absent ⇒ `aes_gcm`. */
  readonly format?: FrameFormat;
}

/**
 * Rust `SelfHostedWorkerTransportFrame::validate_identity`.
 *
 * After a frame opens, the identity INSIDE it must be the identity the
 * cleartext header claimed. Rust refuses the mismatch as a transport error and
 * so does this port: the header is what selected the registry row and therefore
 * the key, so letting the enclosed document name a different worker would mean
 * the row that authorized the open is not the row the request is attributed to.
 *
 * Returns the offending field name, or `null` when the two agree.
 */
export function frameIdentityMismatch(
  header: WorkerFrameHeader,
  identity: Record<string, unknown>,
): string | null {
  for (const field of ["tenant_id", "workspace_id", "worker_id", "token_id"] as const) {
    if (identity[field] !== header[field]) return field;
  }
  return null;
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

/**
 * Rust `SelfHostedWorkerTransportFrame::associated_data`, byte for byte:
 * the five routing fields joined with `\n`, nothing else.
 *
 * Deliberately NOT {@link frameAssociatedData}. That one is this port's own
 * (length-prefixed, domain-tagged) construction and it is strictly better —
 * but "better" is not the goal for a wire format. One byte of difference here
 * and every frame a Rust worker emits fails its tag check, which is exactly the
 * silent non-interoperability this port exists to remove. Rust's field values
 * are all UUID/slug-shaped and its own AAD is unprefixed, so the theoretical
 * separator ambiguity is not reachable through the registry.
 */
export function rustFrameAssociatedData(header: WorkerFrameHeader): Uint8Array {
  return new TextEncoder().encode(
    [
      String(header.protocol_version),
      header.tenant_id,
      header.workspace_id,
      header.worker_id,
      header.token_id,
    ].join("\n"),
  );
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

/**
 * Rust `self_hosted_transport_aead_cipher`: HKDF-SHA256 over the transport
 * secret with Rust's salt and info, expanded to the 32-byte XChaCha20 key.
 *
 * `crypto.subtle.deriveBits` (HKDF is one of the algorithms workerd DOES
 * expose) produces the key material; only the cipher itself is software. So
 * the key schedule is platform-native and byte-identical to Rust's `hkdf`
 * crate call, and a wrong salt or info yields a key that opens nothing —
 * which is why both constants are asserted directly in the suite.
 */
export async function deriveRustFrameKey(tokenSecret: string): Promise<Uint8Array> {
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
      salt: new TextEncoder().encode(RUST_FRAME_HKDF_SALT) as BufferSource,
      info: new TextEncoder().encode(RUST_FRAME_HKDF_INFO) as BufferSource,
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
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
function readFrameHeaderFields(fields: Record<string, unknown>): WorkerFrameHeader | undefined {
  if (typeof fields.protocol_version !== "number" || !Number.isInteger(fields.protocol_version)) {
    return undefined;
  }
  for (const name of ["tenant_id", "workspace_id", "worker_id", "token_id"] as const) {
    if (typeof fields[name] !== "string" || (fields[name] as string).trim() === "") return undefined;
  }
  return {
    protocol_version: fields.protocol_version,
    tenant_id: fields.tenant_id as string,
    workspace_id: fields.workspace_id as string,
    worker_id: fields.worker_id as string,
    token_id: fields.token_id as string,
  };
}

/**
 * Recognize Rust's `SelfHostedWorkerTransportFrame` on a parsed body.
 *
 * The Rust document carries its routing header at the TOP level alongside
 * `encoding` and `encrypted_payload`, which is what distinguishes it from both
 * this port's `{sealed: …}` wrapper and from a cleartext identity envelope.
 * Recognition requires `encrypted_payload` to be present and well-formed, so a
 * cleartext body — which has an `identity` and no `encrypted_payload` — can
 * never be mistaken for a half-decoded frame.
 *
 * An unknown `encoding` or `algorithm` is `undefined` (not a frame) rather than
 * a guess: Rust refuses both, and treating an unrecognised algorithm tag as
 * "probably xchacha" is how a downgrade gets accepted.
 */
export function readRustTransportFrame(
  body: Record<string, unknown>,
): SealedWorkerFrame | undefined {
  const payload = body.encrypted_payload;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  if (body.encoding !== RUST_FRAME_ENCODING) return undefined;
  const header = readFrameHeaderFields(body);
  if (header === undefined) return undefined;
  const fields = payload as Record<string, unknown>;
  if (fields.algorithm !== RUST_FRAME_ALGORITHM) return undefined;
  if (typeof fields.nonce !== "string" || typeof fields.ciphertext !== "string") return undefined;
  return {
    header,
    nonce: fields.nonce,
    ciphertext: fields.ciphertext,
    format: "xchacha20poly1305",
  };
}

/**
 * Render a {@link SealedWorkerFrame} back into Rust's wire document.
 *
 * Exported so the suite can prove the shape this gateway ACCEPTS is the shape
 * Rust EMITS, rather than asserting against a JSON literal a test author typed
 * from the same misreading twice.
 */
export function toRustTransportFrame(frame: SealedWorkerFrame): Record<string, unknown> {
  return {
    protocol_version: frame.header.protocol_version,
    tenant_id: frame.header.tenant_id,
    workspace_id: frame.header.workspace_id,
    worker_id: frame.header.worker_id,
    token_id: frame.header.token_id,
    encoding: RUST_FRAME_ENCODING,
    encrypted_payload: {
      algorithm: RUST_FRAME_ALGORITHM,
      nonce: frame.nonce,
      ciphertext: frame.ciphertext,
    },
  };
}

export function readSealedFrame(body: Record<string, unknown>): SealedWorkerFrame | undefined {
  const rust = readRustTransportFrame(body);
  if (rust !== undefined) return rust;
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
 * Rust `validate_self_hosted_transport_shared_secret`: a non-blank secret of at
 * least {@link RUST_FRAME_SECRET_MIN_LEN} characters, or no cipher at all.
 */
function rustSecretRefusal(tokenSecret: string): string | null {
  if (tokenSecret.trim() === "") {
    return "self-hosted worker symmetric AEAD transport requires a non-empty shared secret";
  }
  if (tokenSecret.length < RUST_FRAME_SECRET_MIN_LEN) {
    return `self-hosted worker symmetric AEAD transport secret must be at least ${RUST_FRAME_SECRET_MIN_LEN} characters`;
  }
  return null;
}

/**
 * Seal a document in RUST's wire format — `encrypt_json`, byte for byte.
 *
 * This is the emitter side of the parity claim. It exists so the suite can
 * produce a frame the way a Rust worker binary would (same AEAD, same AAD, same
 * key schedule, same base64 payload) and drive it through the real Worker; a
 * gate written against a TS-only sealer would only ever prove the port agrees
 * with itself.
 */
export async function sealRustWorkerFrame(
  header: WorkerFrameHeader,
  tokenSecret: string,
  document: unknown,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(XCHACHA20_NONCE_BYTES)),
): Promise<SealedWorkerFrame> {
  const refusal = rustSecretRefusal(tokenSecret);
  if (refusal !== null) throw new Error(refusal);
  if (nonce.length !== XCHACHA20_NONCE_BYTES) {
    throw new Error(`xchacha20poly1305 nonce must be ${XCHACHA20_NONCE_BYTES} bytes`);
  }
  const plaintext = new TextEncoder().encode(JSON.stringify(document));
  if (plaintext.length > RUST_FRAME_MAX_MESSAGE_BYTES) {
    throw new Error("self-hosted worker encrypted transport plaintext exceeds maximum size");
  }
  const sealed = xchacha20poly1305Seal(
    await deriveRustFrameKey(tokenSecret),
    nonce,
    plaintext,
    rustFrameAssociatedData(header),
  );
  return {
    header,
    nonce: toBase64(nonce),
    ciphertext: toBase64(sealed),
    format: "xchacha20poly1305",
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

/** The single opaque refusal every key-dependent failure collapses onto. */
const UNOPENABLE: FrameOpenResult = {
  outcome: "rejected",
  failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
};

/** Decode the opened plaintext, or the same opaque refusal. */
function envelopeFromPlaintext(plaintext: Uint8Array): FrameOpenResult {
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return UNOPENABLE;
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return UNOPENABLE;
  }
  return { outcome: "opened", envelope: document as Record<string, unknown> };
}

/**
 * Open a sealed frame with the registered worker's transport secret.
 *
 * The AEAD is chosen by {@link SealedWorkerFrame.format}, which is set by the
 * READER from the wire shape — never by anything inside the ciphertext — so a
 * caller cannot talk the gateway into a different cipher than the document it
 * actually sent.
 *
 * Every key-dependent failure collapses onto ONE opaque `unopenable` detail. An
 * attacker probing the frame must not learn whether the tag failed, the key was
 * wrong, or the plaintext was not JSON — those all mean "you did not hold the
 * secret". The shape failures reported distinctly (bad base64, wrong nonce
 * length) are decided BEFORE any key is touched and disclose nothing about it.
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

  if (frame.format === "xchacha20poly1305") {
    if (nonce.length !== XCHACHA20_NONCE_BYTES) {
      return {
        outcome: "rejected",
        failure: {
          reason: "invalid_shape",
          detail: `self-hosted worker encrypted frame nonce must be ${XCHACHA20_NONCE_BYTES} bytes`,
        },
      };
    }
    // Rust checks this ceiling on the decode path too; a frame is refused on
    // SIZE before a megabyte of attacker-chosen bytes is run through the MAC.
    if (ciphertext.length > RUST_FRAME_MAX_MESSAGE_BYTES) {
      return {
        outcome: "rejected",
        failure: {
          reason: "invalid_shape",
          detail: "self-hosted worker encrypted frame exceeds maximum size",
        },
      };
    }
    // A too-short registered secret refuses the frame rather than keying the
    // cipher with it — and it refuses OPAQUELY, because the secret's length is
    // a property of the registry row, which the caller must not learn.
    if (rustSecretRefusal(tokenSecret) !== null) return UNOPENABLE;
    const plaintext = xchacha20poly1305Open(
      await deriveRustFrameKey(tokenSecret),
      nonce,
      ciphertext,
      rustFrameAssociatedData(frame.header),
    );
    if (plaintext === undefined) return UNOPENABLE;
    return envelopeFromPlaintext(plaintext);
  }

  if (nonce.length === XCHACHA20_NONCE_BYTES) {
    return {
      outcome: "rejected",
      failure: {
        reason: "invalid_shape",
        detail:
          "frame nonce is 24 bytes (XChaCha20-Poly1305) but the frame is declared AES-256-GCM, which takes a 12-byte nonce; present Rust's encrypted_payload frame to seal with XChaCha20-Poly1305",
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
    return UNOPENABLE;
  }
  return envelopeFromPlaintext(new Uint8Array(plaintext));
}
