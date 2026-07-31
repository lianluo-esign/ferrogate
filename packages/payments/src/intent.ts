/**
 * The immutable payment intent (issue #351). Faithful port of the Rust `intent`
 * module.
 *
 * A {@link SelectedPayment} says what a merchant is asking to be paid; it does
 * not say which request of ours is paying. A {@link PaymentIntent} closes that
 * gap: it pins the HTTP method and a hash of the request body alongside the
 * payment terms, so a spend decision is attributable to exactly one request and
 * a replay against a different one (e.g. a `POST` of a different body to the
 * same URL as an authorized `GET`) is detectable.
 *
 * # Immutability
 *
 * Every field is a private class field with no setter, and the only
 * deserialization path ({@link PaymentIntent.fromWire}) runs the exact same
 * validation as construction — so a persisted-then-reloaded intent can never be
 * weaker than a freshly built one.
 *
 * # Money
 *
 * `atomicAmount` is the on-chain integer amount, carried as `bigint` for full
 * `u64` fidelity. There is no float anywhere in this module.
 */

import { z } from "zod";

import { sha256, hexLower, Sha256Builder } from "./hash.js";
import {
  challengeHashHex,
  caip2ForNetwork,
  MAX_TIMEOUT_SECONDS,
  SCHEME_EXACT,
  type SelectedPayment,
  type SolanaNetwork,
  solanaNetworkFromCaip2,
  validateSolanaAddress,
  X402_VERSION,
} from "./wire.js";

/** Domain-separation tag mixed into {@link PaymentIntent.intentHashHex}. */
export const PAYMENT_INTENT_HASH_DOMAIN = "ferrogate.x402.payment-intent.v1";

const MAX_METHOD_BYTES = 32;
const MAX_IDENTITY_BYTES = 256;
const MAX_RESOURCE_URL_BYTES = 2_048;
/** Largest `u64` — the ceiling on a wire-supplied atomic amount. */
const U64_MAX = 18_446_744_073_709_551_615n;

const encoder = new TextEncoder();
function byteLen(s: string): number {
  return encoder.encode(s).length;
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

export type PaymentIntentErrorKind =
  | "unsupported_version"
  | "unsupported_scheme"
  | "unknown_network"
  | "invalid_address"
  | "zero_amount"
  | "invalid_resource_url"
  | "invalid_http_method"
  | "invalid_body_hash"
  | "invalid_challenge_hash"
  | "timeout_out_of_range"
  | "invalid_identity";

function dbg(s: string): string {
  return JSON.stringify(s);
}

/** Why a {@link PaymentIntentDraft} is not a valid intent. */
export class PaymentIntentError extends Error {
  readonly kind: PaymentIntentErrorKind;
  readonly field?: string;

  constructor(kind: PaymentIntentErrorKind, message: string, field?: string) {
    super(message);
    this.name = "PaymentIntentError";
    this.kind = kind;
    this.field = field;
  }

  static unsupportedVersion(value: number | bigint): PaymentIntentError {
    return new PaymentIntentError(
      "unsupported_version",
      `unsupported x402 version ${value} (expected ${X402_VERSION})`,
    );
  }
  static unsupportedScheme(value: string): PaymentIntentError {
    return new PaymentIntentError(
      "unsupported_scheme",
      `unsupported payment scheme ${dbg(value)} (expected ${dbg(SCHEME_EXACT)})`,
    );
  }
  static unknownNetwork(value: string): PaymentIntentError {
    return new PaymentIntentError("unknown_network", `unrecognised CAIP-2 network ${dbg(value)}`);
  }
  static invalidAddress(field: string, value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_address",
      `${field} ${dbg(value)} is not a valid base58 Solana address`,
      field,
    );
  }
  static zeroAmount(): PaymentIntentError {
    return new PaymentIntentError("zero_amount", "payment intent atomic amount is zero");
  }
  static invalidResourceUrl(value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_resource_url",
      `authorized resource url ${dbg(value)} is not an absolute http(s) URL`,
    );
  }
  static invalidHttpMethod(value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_http_method",
      `http method ${dbg(value)} is not a valid method token`,
    );
  }
  static invalidBodyHash(value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_body_hash",
      `request body hash ${dbg(value)} is not 32 bytes of lowercase hex`,
    );
  }
  static invalidChallengeHash(value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_challenge_hash",
      `challenge hash ${dbg(value)} is not 32 bytes of lowercase hex`,
    );
  }
  static timeoutOutOfRange(value: number | bigint): PaymentIntentError {
    return new PaymentIntentError(
      "timeout_out_of_range",
      `merchant timeout ${value}s is outside 1..=${MAX_TIMEOUT_SECONDS}`,
    );
  }
  static invalidIdentity(field: string, value: string): PaymentIntentError {
    return new PaymentIntentError(
      "invalid_identity",
      `identity component ${field} ${dbg(value)} is not usable`,
      field,
    );
  }
}

// ---------------------------------------------------------------------------
// Request body hash
// ---------------------------------------------------------------------------

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

/**
 * SHA-256 of the request body an authorized egress request carries. A bodyless
 * request hashes the empty byte string, so "no body" is a concrete, checkable
 * value. Deliberately a PLAIN SHA-256 with no domain tag, interoperable with
 * every other request-body hash in the codebase.
 */
export class RequestBodyHash {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /** Hash a request body. An empty slice is the canonical "no body" value. */
  static of(body: Uint8Array): RequestBodyHash {
    return new RequestBodyHash(sha256(body));
  }

  /** The canonical hash of a bodyless request (`GET`, `HEAD`, …). */
  static empty(): RequestBodyHash {
    return RequestBodyHash.of(new Uint8Array(0));
  }

  /**
   * Parse a lowercase-hex body hash. Throws unless it is exactly 32 bytes of
   * lowercase hex, so a truncated or upper-cased value can never silently
   * compare unequal to the same logical hash.
   */
  static fromHex(value: string): RequestBodyHash {
    if (!LOWER_HEX_64.test(value)) throw PaymentIntentError.invalidBodyHash(value);
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    return new RequestBodyHash(bytes);
  }

  /** Lowercase hex form — the wire/audit representation. */
  asHex(): string {
    return hexLower(this.#bytes);
  }

  toString(): string {
    return this.asHex();
  }

  equals(other: RequestBodyHash): boolean {
    return this.asHex() === other.asHex();
  }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** Who the payment is being made on behalf of. */
export interface PaymentIntentIdentity {
  tenantId: string;
  projectId?: string | null;
  workspaceId?: string | null;
  keyId?: string | null;
  runId?: string | null;
  workerId?: string | null;
  requestId: string;
}

// ---------------------------------------------------------------------------
// Draft
// ---------------------------------------------------------------------------

/** The unvalidated shape of a {@link PaymentIntent}. */
export interface PaymentIntentDraft {
  x402Version: number;
  scheme: string;
  networkCaip2: string;
  mint: string;
  atomicAmount: bigint;
  recipient: string;
  authorizedResourceUrl: string;
  httpMethod: string;
  requestBodyHash: RequestBodyHash;
  challengeHashHex: string;
  maxTimeoutSeconds: number;
  identity: PaymentIntentIdentity;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const METHOD_TOKEN = /^[A-Za-z0-9_-]+$/;

function normalizeHttpMethod(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0 || byteLen(trimmed) > MAX_METHOD_BYTES) {
    throw PaymentIntentError.invalidHttpMethod(value);
  }
  if (!METHOD_TOKEN.test(trimmed)) throw PaymentIntentError.invalidHttpMethod(value);
  return trimmed.toUpperCase();
}

function requireAbsoluteUrl(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0 || byteLen(trimmed) > MAX_RESOURCE_URL_BYTES) {
    throw PaymentIntentError.invalidResourceUrl(value);
  }
  const idx = trimmed.indexOf("://");
  if (idx < 0) throw PaymentIntentError.invalidResourceUrl(value);
  const scheme = trimmed.slice(0, idx).toLowerCase();
  const rest = trimmed.slice(idx + 3);
  if ((scheme !== "https" && scheme !== "http") || rest.length === 0) {
    throw PaymentIntentError.invalidResourceUrl(value);
  }
  return trimmed;
}

function requiredIdentity(field: string, value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0 || byteLen(trimmed) > MAX_IDENTITY_BYTES) {
    throw PaymentIntentError.invalidIdentity(field, value);
  }
  return trimmed;
}

function optionalIdentity(field: string, value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  // An id present but blank is a caller bug, not "absent".
  if (trimmed.length === 0 || byteLen(trimmed) > MAX_IDENTITY_BYTES) {
    throw PaymentIntentError.invalidIdentity(field, value);
  }
  return trimmed;
}

function validateIdentity(identity: PaymentIntentIdentity): PaymentIntentIdentity {
  return {
    tenantId: requiredIdentity("tenant_id", identity.tenantId),
    projectId: optionalIdentity("project_id", identity.projectId),
    workspaceId: optionalIdentity("workspace_id", identity.workspaceId),
    keyId: optionalIdentity("key_id", identity.keyId),
    runId: optionalIdentity("run_id", identity.runId),
    workerId: optionalIdentity("worker_id", identity.workerId),
    requestId: requiredIdentity("request_id", identity.requestId),
  };
}

// ---------------------------------------------------------------------------
// Wire (serde) schema — Zod-validated snake_case shape
// ---------------------------------------------------------------------------

const IdentityWireSchema = z.object({
  tenant_id: z.string(),
  project_id: z.string().nullish(),
  workspace_id: z.string().nullish(),
  key_id: z.string().nullish(),
  run_id: z.string().nullish(),
  worker_id: z.string().nullish(),
  request_id: z.string(),
});

const PaymentIntentWireSchema = z.object({
  x402_version: z.number().int().nonnegative(),
  scheme: z.string(),
  network_caip2: z.string(),
  mint: z.string(),
  // PORT-TODO(inventory §3.2 "intent") — LANGUAGE LIMIT, NOT CLOSED, and NOT
  // closable at this layer.
  //
  // The exact limitation: **the precision is already gone before this schema
  // runs.** `atomic_amount` is a `u64` in Rust serde — a bare JSON integer that
  // `serde_json` parses exactly. `fromWire` takes an ALREADY-PARSED `unknown`,
  // i.e. the caller has run `JSON.parse`, and `JSON.parse` materialises every
  // number as an IEEE-754 double. `18446744073709551615` has become
  // `18446744073709552000` by the time it reaches this line; no validator here
  // can recover the original digits. Widening the type to `bigint` would move
  // the corruption, not fix it.
  //
  // A faithful fix has to happen at the JSON TEXT boundary — a bigint-aware
  // reviver, or the field carried as a decimal string — which changes the
  // signature of `fromWire`/`toWire` and the on-the-wire shape shared with the
  // Rust producer. That is a wire-contract change, and x402/Solana is
  // DEPRIORITIZED per project directive, so it is deliberately not made here.
  //
  // What holds today, and is pinned in `test/intent.test.ts`: the in-memory
  // domain type is `bigint` end to end (`PaymentIntent.atomicAmount()`,
  // `SelectedPayment.atomicAmount`, every cap and conversion in
  // `@ferrogate/policy`), so nothing in the money path is a float once
  // construction succeeds. Only this serde hop is number-domain, and every
  // frozen fixture and tested amount is orders of magnitude below 2^53.
  atomic_amount: z.number().int().nonnegative(),
  recipient: z.string(),
  authorized_resource_url: z.string(),
  http_method: z.string(),
  request_body_hash: z.string(),
  challenge_hash_hex: z.string(),
  max_timeout_seconds: z.number().int().nonnegative(),
  identity: IdentityWireSchema,
});

/** The JSON-serializable wire form of a {@link PaymentIntent}. */
export type PaymentIntentWire = z.infer<typeof PaymentIntentWireSchema>;

// ---------------------------------------------------------------------------
// The sealed intent
// ---------------------------------------------------------------------------

/**
 * The immutable payment-intent contract (issue #351). Binds one
 * already-authorized egress request to one merchant challenge at one caller
 * identity. Build with {@link PaymentIntent.new_}, {@link PaymentIntent.fromSelected},
 * or {@link PaymentIntent.fromWire}.
 */
export class PaymentIntent {
  readonly #x402Version: number;
  readonly #scheme: string;
  readonly #network: SolanaNetwork;
  readonly #mint: string;
  readonly #atomicAmount: bigint;
  readonly #recipient: string;
  readonly #authorizedResourceUrl: string;
  readonly #httpMethod: string;
  readonly #requestBodyHash: RequestBodyHash;
  readonly #challengeHashHex: string;
  readonly #maxTimeoutSeconds: number;
  readonly #identity: PaymentIntentIdentity;

  private constructor(fields: {
    x402Version: number;
    scheme: string;
    network: SolanaNetwork;
    mint: string;
    atomicAmount: bigint;
    recipient: string;
    authorizedResourceUrl: string;
    httpMethod: string;
    requestBodyHash: RequestBodyHash;
    challengeHashHex: string;
    maxTimeoutSeconds: number;
    identity: PaymentIntentIdentity;
  }) {
    this.#x402Version = fields.x402Version;
    this.#scheme = fields.scheme;
    this.#network = fields.network;
    this.#mint = fields.mint;
    this.#atomicAmount = fields.atomicAmount;
    this.#recipient = fields.recipient;
    this.#authorizedResourceUrl = fields.authorizedResourceUrl;
    this.#httpMethod = fields.httpMethod;
    this.#requestBodyHash = fields.requestBodyHash;
    this.#challengeHashHex = fields.challengeHashHex;
    this.#maxTimeoutSeconds = fields.maxTimeoutSeconds;
    this.#identity = fields.identity;
  }

  /**
   * Validate a draft into an immutable intent. Fails closed on every field the
   * decision later depends on. (Named `new_` because `new` is reserved.)
   */
  static new_(draft: PaymentIntentDraft): PaymentIntent {
    if (draft.x402Version !== X402_VERSION) {
      throw PaymentIntentError.unsupportedVersion(draft.x402Version);
    }
    if (draft.scheme !== SCHEME_EXACT) throw PaymentIntentError.unsupportedScheme(draft.scheme);
    const network = solanaNetworkFromCaip2(draft.networkCaip2);
    if (network === undefined) throw PaymentIntentError.unknownNetwork(draft.networkCaip2);
    try {
      validateSolanaAddress("mint", draft.mint);
    } catch {
      throw PaymentIntentError.invalidAddress("mint", draft.mint);
    }
    try {
      validateSolanaAddress("recipient", draft.recipient);
    } catch {
      throw PaymentIntentError.invalidAddress("recipient", draft.recipient);
    }
    if (draft.atomicAmount === 0n) throw PaymentIntentError.zeroAmount();
    const authorizedResourceUrl = requireAbsoluteUrl(draft.authorizedResourceUrl);
    const httpMethod = normalizeHttpMethod(draft.httpMethod);
    if (!LOWER_HEX_64.test(draft.challengeHashHex)) {
      throw PaymentIntentError.invalidChallengeHash(draft.challengeHashHex);
    }
    if (draft.maxTimeoutSeconds === 0 || draft.maxTimeoutSeconds > MAX_TIMEOUT_SECONDS) {
      throw PaymentIntentError.timeoutOutOfRange(draft.maxTimeoutSeconds);
    }
    const identity = validateIdentity(draft.identity);

    return new PaymentIntent({
      x402Version: draft.x402Version,
      scheme: draft.scheme,
      network,
      mint: draft.mint,
      atomicAmount: draft.atomicAmount,
      recipient: draft.recipient,
      authorizedResourceUrl,
      httpMethod,
      requestBodyHash: draft.requestBodyHash,
      challengeHashHex: draft.challengeHashHex,
      maxTimeoutSeconds: draft.maxTimeoutSeconds,
      identity,
    });
  }

  /**
   * Build an intent from a wire-validated challenge plus the request the gateway
   * already authorized. Copies the payment terms straight off
   * {@link SelectedPayment} so a transcription slip cannot silently change what
   * is being paid. `body` is the authorized request body (`new Uint8Array(0)`
   * for a bodyless method).
   */
  static fromSelected(
    selected: SelectedPayment,
    httpMethod: string,
    authorizedResourceUrl: string,
    body: Uint8Array,
    identity: PaymentIntentIdentity,
  ): PaymentIntent {
    return PaymentIntent.new_({
      x402Version: X402_VERSION,
      scheme: SCHEME_EXACT,
      networkCaip2: caip2ForNetwork(selected.network),
      mint: selected.mint,
      atomicAmount: selected.atomicAmount,
      recipient: selected.recipient,
      authorizedResourceUrl,
      httpMethod,
      requestBodyHash: RequestBodyHash.of(body),
      challengeHashHex: challengeHashHex(selected),
      maxTimeoutSeconds: selected.maxTimeoutSeconds,
      identity,
    });
  }

  /**
   * Deserialize from the wire (serde) form, running the SAME validation as
   * construction. Throws on any invalid field.
   */
  static fromWire(value: unknown): PaymentIntent {
    const parsed = PaymentIntentWireSchema.safeParse(value);
    if (!parsed.success) {
      throw new PaymentIntentError("invalid_identity", `malformed payment intent: ${parsed.error.message}`);
    }
    const w = parsed.data;
    const identity: PaymentIntentIdentity = {
      tenantId: w.identity.tenant_id,
      projectId: w.identity.project_id ?? null,
      workspaceId: w.identity.workspace_id ?? null,
      keyId: w.identity.key_id ?? null,
      runId: w.identity.run_id ?? null,
      workerId: w.identity.worker_id ?? null,
      requestId: w.identity.request_id,
    };
    return PaymentIntent.new_({
      x402Version: w.x402_version,
      scheme: w.scheme,
      networkCaip2: w.network_caip2,
      mint: w.mint,
      atomicAmount: BigInt(w.atomic_amount),
      recipient: w.recipient,
      authorizedResourceUrl: w.authorized_resource_url,
      httpMethod: w.http_method,
      requestBodyHash: RequestBodyHash.fromHex(w.request_body_hash),
      challengeHashHex: w.challenge_hash_hex,
      maxTimeoutSeconds: w.max_timeout_seconds,
      identity,
    });
  }

  // -- accessors ------------------------------------------------------------

  x402Version(): number {
    return this.#x402Version;
  }
  scheme(): string {
    return this.#scheme;
  }
  network(): SolanaNetwork {
    return this.#network;
  }
  networkCaip2(): string {
    return caip2ForNetwork(this.#network);
  }
  mint(): string {
    return this.#mint;
  }
  atomicAmount(): bigint {
    return this.#atomicAmount;
  }
  recipient(): string {
    return this.#recipient;
  }
  authorizedResourceUrl(): string {
    return this.#authorizedResourceUrl;
  }
  httpMethod(): string {
    return this.#httpMethod;
  }
  requestBodyHash(): RequestBodyHash {
    return this.#requestBodyHash;
  }
  challengeHashHex(): string {
    return this.#challengeHashHex;
  }
  maxTimeoutSeconds(): number {
    return this.#maxTimeoutSeconds;
  }
  identity(): PaymentIntentIdentity {
    return this.#identity;
  }

  /**
   * Deterministic SHA-256 over the whole intent, lowercase hex. Domain-tagged
   * and NUL-separated so no two distinct intents collide through field
   * concatenation; optional identity components encode presence separately from
   * content so an absent `run_id` and an empty-string `run_id` never hash alike.
   */
  intentHashHex(): string {
    const b = new Sha256Builder();
    for (const part of [
      PAYMENT_INTENT_HASH_DOMAIN,
      this.#x402Version.toString(),
      this.#scheme,
      caip2ForNetwork(this.#network),
      this.#mint,
      this.#atomicAmount.toString(),
      this.#recipient,
      this.#authorizedResourceUrl,
      this.#httpMethod,
      this.#requestBodyHash.asHex(),
      this.#challengeHashHex,
      this.#maxTimeoutSeconds.toString(),
      this.#identity.tenantId,
      this.#identity.requestId,
    ]) {
      b.pushStr(part).pushByte(0);
    }
    for (const optional of [
      this.#identity.projectId,
      this.#identity.workspaceId,
      this.#identity.keyId,
      this.#identity.runId,
      this.#identity.workerId,
    ]) {
      if (optional !== null && optional !== undefined) {
        b.pushByte(1).pushStr(optional);
      } else {
        b.pushByte(0);
      }
      b.pushByte(0);
    }
    return b.digestHex();
  }

  /**
   * Does this intent describe exactly the payment `selected` demands? Returns
   * the first field that disagrees (so the caller can emit a specific reason),
   * or `null` when they match.
   */
  bindingMismatch(selected: SelectedPayment): string | null {
    if (this.#challengeHashHex !== challengeHashHex(selected)) return "challenge_hash";
    if (this.#network !== selected.network) return "network";
    if (this.#mint !== selected.mint) return "mint";
    if (this.#recipient !== selected.recipient) return "recipient";
    if (this.#atomicAmount !== selected.atomicAmount) return "atomic_amount";
    if (this.#maxTimeoutSeconds !== selected.maxTimeoutSeconds) return "max_timeout_seconds";
    return null;
  }

  /** The JSON-serializable wire (serde) form. */
  toWire(): PaymentIntentWire {
    return {
      x402_version: this.#x402Version,
      scheme: this.#scheme,
      network_caip2: caip2ForNetwork(this.#network),
      mint: this.#mint,
      atomic_amount: Number(this.#atomicAmount),
      recipient: this.#recipient,
      authorized_resource_url: this.#authorizedResourceUrl,
      http_method: this.#httpMethod,
      request_body_hash: this.#requestBodyHash.asHex(),
      challenge_hash_hex: this.#challengeHashHex,
      max_timeout_seconds: this.#maxTimeoutSeconds,
      identity: {
        tenant_id: this.#identity.tenantId,
        project_id: this.#identity.projectId ?? null,
        workspace_id: this.#identity.workspaceId ?? null,
        key_id: this.#identity.keyId ?? null,
        run_id: this.#identity.runId ?? null,
        worker_id: this.#identity.workerId ?? null,
        request_id: this.#identity.requestId,
      },
    };
  }

  toJSON(): PaymentIntentWire {
    return this.toWire();
  }

  /** Structural equality (mirrors the derived Rust `PartialEq`). */
  equals(other: PaymentIntent): boolean {
    return JSON.stringify(this.toWire()) === JSON.stringify(other.toWire());
  }
}
