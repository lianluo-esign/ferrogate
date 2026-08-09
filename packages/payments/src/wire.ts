/**
 * Frozen x402 V2 wire contract for the HTTP transport + Solana SVM `exact`
 * scheme (client role). Faithful port of the Rust `wire` module.
 *
 * - `PAYMENT-REQUIRED` (server → client): base64 of a `PaymentRequired` object.
 * - `PAYMENT-SIGNATURE` (client → server): base64 of a `PaymentPayload` object.
 * - `PAYMENT-RESPONSE` (server → client): base64 of a `SettlementResponse`.
 *
 * Parsing is strict: unknown top-level fields are tolerated (forward
 * compatibility) but every recognised field is validated, and nothing invalid
 * is ever coerced to a default. Money is integer-only: atomic amounts and block
 * heights are `bigint` to preserve full `u64` fidelity with no float drift.
 */

import { decodeBase64Std, encodeBase64Std } from "./base64.js";
import { PaymentError } from "./error.js";
import { Sha256Builder } from "./hash.js";

/** x402 protocol version this adapter speaks. */
export const X402_VERSION = 2;

/** HTTP header carrying the base64 `PaymentRequired` object (server→client). */
export const HEADER_PAYMENT_REQUIRED = "PAYMENT-REQUIRED";
/** HTTP header carrying the base64 `PaymentPayload` object (client→server). */
export const HEADER_PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE";
/** HTTP header carrying the base64 `SettlementResponse` object (server→client). */
export const HEADER_PAYMENT_RESPONSE = "PAYMENT-RESPONSE";

/** Hard cap on the pre-decode (base64 text) size of any x402 header. */
export const MAX_HEADER_BYTES = 16 * 1024;
/** Hard cap on the number of entries in `accepts` before rejection. */
export const MAX_ACCEPTS_ENTRIES = 16;
/** Safety cap on `maxTimeoutSeconds`; anything above is treated as unsafe. */
export const MAX_TIMEOUT_SECONDS = 86_400;
/** Maximum length of `extra.memo` in bytes, per the SVM `exact` scheme spec. */
export const MAX_MEMO_BYTES = 256;
/** Domain-separation tag mixed into {@link SelectedPayment.challengeHash}. */
export const CHALLENGE_HASH_DOMAIN = "ferrogate-x402-challenge-v1";
/** Solana wire packet limit; a serialized proof transaction can never exceed this. */
export const MAX_SVM_TRANSACTION_BYTES = 1232;

/** CAIP-2 network identifier for Solana mainnet-beta. */
export const CAIP2_SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
/** CAIP-2 network identifier for Solana devnet. */
export const CAIP2_SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/** The `exact` payment scheme identifier. */
export const SCHEME_EXACT = "exact";

/** Largest `u64` — the ceiling for a strictly-parsed atomic amount. */
const U64_MAX = 18_446_744_073_709_551_615n;

// ---------------------------------------------------------------------------
// Solana network (recognised CAIP-2 identifiers)
// ---------------------------------------------------------------------------

/** Recognised Solana networks, keyed by their CAIP-2 identifiers. */
export const SolanaNetwork = {
  Mainnet: "mainnet",
  Devnet: "devnet",
} as const;
export type SolanaNetwork = (typeof SolanaNetwork)[keyof typeof SolanaNetwork];

/** Recognise a CAIP-2 network identifier. Purely local — no RPC. */
export function solanaNetworkFromCaip2(id: string): SolanaNetwork | undefined {
  if (id === CAIP2_SOLANA_MAINNET) return SolanaNetwork.Mainnet;
  if (id === CAIP2_SOLANA_DEVNET) return SolanaNetwork.Devnet;
  return undefined;
}

/** The CAIP-2 identifier for a network. */
export function caip2ForNetwork(network: SolanaNetwork): string {
  return network === SolanaNetwork.Mainnet ? CAIP2_SOLANA_MAINNET : CAIP2_SOLANA_DEVNET;
}

// ---------------------------------------------------------------------------
// Parsed shapes
// ---------------------------------------------------------------------------

/** Parsed, validated `PaymentRequired` object (the decoded `PAYMENT-REQUIRED`). */
export interface PaymentRequired {
  error: string | null;
  resourceUrl: string;
  resourceDescription: string | null;
  resourceMimeType: string | null;
  /** Raw, order-preserved `accepts` entries (validated lazily during selection). */
  accepts: unknown[];
  /** Server-advertised protocol `extensions` object, verbatim. */
  extensions: unknown | null;
}

/** One fully validated, selected SVM `exact` requirement. */
export interface SelectedPayment {
  network: SolanaNetwork;
  mint: string;
  /** Atomic token amount. Parsed strictly; never coerced. */
  atomicAmount: bigint;
  recipient: string;
  /** Facilitator fee payer from `extra.feePayer`. */
  feePayer: string;
  memo: string | null;
  /** Optional server-supplied blockhash from `extra.recentBlockhash`. */
  recentBlockhash: string | null;
  /** Optional `extra.lastValidBlockHeight`; only ever set alongside `recentBlockhash`. */
  lastValidBlockHeight: bigint | null;
  resourceUrl: string;
  maxTimeoutSeconds: number;
  extensions: unknown | null;
  /** Deterministic SHA-256 (32 bytes) over the canonical payment-terms tuple. */
  challengeHash: Uint8Array;
  /** The requirement entry exactly as received, echoed verbatim into `accepted`. */
  rawRequirement: unknown;
}

/** Lowercase hex form of a {@link SelectedPayment} challenge hash. */
export function challengeHashHex(selected: SelectedPayment): string {
  let out = "";
  for (const b of selected.challengeHash) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Caller-supplied constraints for requirement selection. */
export interface RequirementFilter {
  /** Networks the caller will pay on. Empty/absent ⇒ any recognised network. */
  networks?: readonly SolanaNetwork[];
  /** Optional mint allowlist (base58). Absent ⇒ any valid mint. */
  allowedMints?: readonly string[];
}

/** Decoded settlement evidence from a `PAYMENT-RESPONSE` header. */
export interface SettlementEvidence {
  success: boolean;
  transactionSignature: string | null;
  network: SolanaNetwork;
  payer: string | null;
  errorReason: string | null;
  settledAmount: bigint | null;
}

// ---------------------------------------------------------------------------
// JSON accessors (a small `serde_json::Value` twin)
// ---------------------------------------------------------------------------

function asObject(v: unknown): Record<string, unknown> | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}
function asArray(v: unknown): unknown[] | undefined {
  return Array.isArray(v) ? v : undefined;
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}
/** `serde_json::Value::as_u64` twin: a non-negative integer JSON number. */
function asU64(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : undefined;
}
function isNullish(v: unknown): boolean {
  return v === undefined || v === null;
}

// ---------------------------------------------------------------------------
// Header decode / JSON parse
// ---------------------------------------------------------------------------

const byteLengthEncoder = new TextEncoder();

function malformed(header: string, reason: string): PaymentError {
  return PaymentError.malformedHeader(header, reason);
}

/** Base64-decode an x402 header value, enforcing the size cap BEFORE decoding. */
function decodeHeader(header: string, value: string): Uint8Array {
  const byteLen = byteLengthEncoder.encode(value).length;
  if (byteLen > MAX_HEADER_BYTES) {
    throw PaymentError.oversizedHeader(header, MAX_HEADER_BYTES, byteLen);
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) throw malformed(header, "empty header value");
  const bytes = decodeBase64Std(trimmed);
  if (bytes === null) throw malformed(header, "invalid base64");
  return bytes;
}

function parseJson(header: string, bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw malformed(header, "invalid JSON: not valid UTF-8");
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw malformed(header, `invalid JSON: ${(e as Error).message}`);
  }
}

/** Validate the `x402Version` field: must exist and be the integer 2. */
function requireVersion(header: string, obj: Record<string, unknown>): void {
  if (!("x402Version" in obj)) throw malformed(header, "missing x402Version");
  const v = obj.x402Version;
  if (asU64(v) !== X402_VERSION) {
    throw PaymentError.unsupportedVersion(JSON.stringify(v ?? null));
  }
}

function requireStr(header: string, obj: Record<string, unknown>, field: string): string {
  const s = asString(obj[field]);
  if (s === undefined) throw malformed(header, `missing or non-string ${field}`);
  return s;
}

// ---------------------------------------------------------------------------
// parse_payment_required
// ---------------------------------------------------------------------------

/** Parse a `PAYMENT-REQUIRED` header value into a validated {@link PaymentRequired}. */
export function parsePaymentRequired(headerValue: string): PaymentRequired {
  const H = HEADER_PAYMENT_REQUIRED;
  const bytes = decodeHeader(H, headerValue);
  const root = parseJson(H, bytes);
  const rootObj = asObject(root);
  if (rootObj === undefined) throw malformed(H, "top-level value is not a JSON object");
  requireVersion(H, rootObj);

  const resource = asObject(rootObj.resource);
  if (resource === undefined) throw malformed(H, "missing or non-object resource");
  const url = asString(resource.url);
  if (url === undefined || url.length === 0 || url.length > 2048) {
    throw malformed(H, "resource.url missing, empty, or oversized");
  }

  const accepts = asArray(rootObj.accepts);
  if (accepts === undefined) throw malformed(H, "missing or non-array accepts");
  if (accepts.length === 0) throw malformed(H, "accepts is empty");
  if (accepts.length > MAX_ACCEPTS_ENTRIES) {
    throw malformed(H, `accepts has ${accepts.length} entries, cap is ${MAX_ACCEPTS_ENTRIES}`);
  }
  if (!accepts.every((e) => asObject(e) !== undefined)) {
    throw malformed(H, "accepts contains a non-object entry");
  }

  let extensions: unknown | null;
  const extRaw = rootObj.extensions;
  if (isNullish(extRaw)) {
    extensions = null;
  } else if (asObject(extRaw) !== undefined) {
    extensions = extRaw;
  } else {
    throw malformed(H, "extensions is not a JSON object");
  }

  return {
    error: asString(rootObj.error) ?? null,
    resourceUrl: url,
    resourceDescription: asString(resource.description) ?? null,
    resourceMimeType: asString(resource.mimeType) ?? null,
    accepts,
    extensions,
  };
}

// ---------------------------------------------------------------------------
// Amount / address / timeout / block-height parsing
// ---------------------------------------------------------------------------

function truncateForError(s: string): string {
  const CAP = 64;
  if (s.length <= CAP) return s;
  // Split on a UTF-16 code-unit boundary; good enough for an error string.
  return `${s.slice(0, CAP)}…`;
}

/**
 * Strict atomic-amount parser: ASCII digits only, canonical (no leading zeros),
 * non-zero, fits `u64`. Invalid input is a hard error — NEVER zero.
 */
export function parseAtomicAmount(raw: string): bigint {
  const err = (reason: string): PaymentError =>
    PaymentError.invalidAmount(truncateForError(raw), reason);
  if (raw.length === 0) throw err("empty");
  if (!/^[0-9]+$/.test(raw)) throw err("must contain only ASCII digits");
  if (raw.length > 1 && raw.startsWith("0")) throw err("non-canonical leading zero");
  const value = BigInt(raw);
  if (value > U64_MAX) throw err("overflows u64");
  if (value === 0n) throw err("zero amount");
  return value;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Minimal base58 decoder (Bitcoin alphabet) — enough to validate Solana
 * addresses (32 bytes) and transaction signatures (64 bytes). Returns
 * `undefined` on an out-of-alphabet character or bounds violation.
 */
export function base58Decode(input: string): Uint8Array | undefined {
  if (input.length === 0 || input.length > 128) return undefined;
  const digits: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const d = BASE58_ALPHABET.indexOf(input[i] as string);
    if (d < 0) return undefined;
    digits.push(d);
  }
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros++;
  const out: number[] = [];
  for (const d of digits) {
    let carry = d;
    for (let i = 0; i < out.length; i++) {
      carry += (out[i] as number) * 58;
      out[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      out.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < zeros; i++) out.push(0);
  out.reverse();
  return Uint8Array.from(out);
}

/** Validate a base58 Solana address (must decode to exactly 32 bytes). */
export function validateSolanaAddress(field: string, value: string): void {
  const bytes = base58Decode(value);
  if (bytes === undefined || bytes.length !== 32) {
    throw PaymentError.invalidRecipient(field, truncateForError(value));
  }
}

function requireTimeout(entry: Record<string, unknown>): number {
  if (!("maxTimeoutSeconds" in entry)) throw PaymentError.invalidTimeout("missing");
  const v = entry.maxTimeoutSeconds;
  const secs = asU64(v);
  if (secs === undefined) {
    throw PaymentError.invalidTimeout(`not a non-negative integer: ${JSON.stringify(v ?? null)}`);
  }
  if (secs === 0) throw PaymentError.invalidTimeout("zero (already expired)");
  if (secs > MAX_TIMEOUT_SECONDS) {
    throw PaymentError.invalidTimeout(`${secs}s exceeds safety cap of ${MAX_TIMEOUT_SECONDS}s`);
  }
  return secs;
}

/**
 * Strict decimal parser for `extra.lastValidBlockHeight` (a decimal string).
 * Tolerates leading zeros (advisory bound, not money) but is never coerced: a
 * non-numeric, zero, or overflowing value is an error.
 */
function parseBlockHeight(raw: string): bigint {
  const bad = (): PaymentError =>
    malformed(
      HEADER_PAYMENT_REQUIRED,
      `extra.lastValidBlockHeight ${JSON.stringify(truncateForError(raw))} is not a positive decimal u64`,
    );
  if (raw.length === 0 || raw.length > 20 || !/^[0-9]+$/.test(raw)) throw bad();
  const v = BigInt(raw);
  if (v <= 0n || v > U64_MAX) throw bad();
  return v;
}

// ---------------------------------------------------------------------------
// challenge_hash
// ---------------------------------------------------------------------------

interface ChallengeTerms {
  network: SolanaNetwork;
  mint: string;
  recipient: string;
  feePayer: string;
  memo: string | null;
  atomicAmount: bigint;
  maxTimeoutSeconds: number;
  resourceUrl: string;
}

/**
 * Deterministic SHA-256 over the canonical payment-terms tuple. FerroGate-local
 * (not part of the wire contract); NUL-separated with a versioned domain tag so
 * field concatenation cannot collide. Memo presence is encoded separately from
 * memo content so an absent memo and an empty-string memo cannot hash alike.
 */
function computeChallengeHash(terms: ChallengeTerms): Uint8Array {
  const h = new Sha256Builder();
  for (const part of [
    CHALLENGE_HASH_DOMAIN,
    SCHEME_EXACT,
    caip2ForNetwork(terms.network),
    terms.mint,
    terms.recipient,
    terms.feePayer,
    terms.atomicAmount.toString(),
    terms.maxTimeoutSeconds.toString(),
    terms.resourceUrl,
  ]) {
    h.pushStr(part).pushByte(0);
  }
  if (terms.memo !== null) {
    h.pushByte(1).pushStr(terms.memo);
  } else {
    h.pushByte(0);
  }
  h.pushByte(0);
  return h.digest();
}

// ---------------------------------------------------------------------------
// select_requirement
// ---------------------------------------------------------------------------

/**
 * Select exactly one supported requirement from a parsed {@link PaymentRequired},
 * validating every field of the chosen entry.
 *
 * Entries whose scheme or network this adapter does not support are skipped; if
 * a supported entry is present but corrupt, that is a hard error rather than a
 * silent skip. Duplicate/conflicting entries (same scheme/network/asset/payTo)
 * are rejected.
 */
export function selectRequirement(
  required: PaymentRequired,
  filter: RequirementFilter = {},
): SelectedPayment {
  const H = HEADER_PAYMENT_REQUIRED;
  const networks = filter.networks ?? [];
  const allowedMints = filter.allowedMints;

  // Reject duplicate / conflicting accepts entries up front.
  const seen = new Set<string>();
  for (const entryRaw of required.accepts) {
    const entry = asObject(entryRaw) ?? {};
    const key = JSON.stringify([
      asString(entry.scheme) ?? "",
      asString(entry.network) ?? "",
      asString(entry.asset) ?? "",
      asString(entry.payTo) ?? "",
    ]);
    if (seen.has(key)) {
      throw malformed(
        H,
        "duplicate or conflicting accepts entries for the same scheme/network/asset/payTo",
      );
    }
    seen.add(key);
  }

  let lastUnsupported: PaymentError | undefined;
  for (const entryRaw of required.accepts) {
    const entry = asObject(entryRaw) as Record<string, unknown>;
    const scheme = requireStr(H, entry, "scheme");
    if (scheme !== SCHEME_EXACT) {
      lastUnsupported = PaymentError.unsupportedScheme(truncateForError(scheme));
      continue;
    }
    const networkId = requireStr(H, entry, "network");
    const network = solanaNetworkFromCaip2(networkId);
    if (network === undefined) {
      lastUnsupported = PaymentError.unsupportedNetwork(truncateForError(networkId));
      continue;
    }
    if (networks.length > 0 && !networks.includes(network)) {
      lastUnsupported = PaymentError.unsupportedNetwork(networkId);
      continue;
    }

    // This entry claims a scheme+network we support: any invalid field is now a
    // hard error, never a silent skip.
    const mint = requireStr(H, entry, "asset");
    validateSolanaAddress("asset", mint);
    if (allowedMints !== undefined && !allowedMints.includes(mint)) {
      lastUnsupported = PaymentError.unsupportedMint(mint);
      continue;
    }
    const amountRaw = requireStr(H, entry, "amount");
    const atomicAmount = parseAtomicAmount(amountRaw);
    const recipient = requireStr(H, entry, "payTo");
    validateSolanaAddress("payTo", recipient);
    const maxTimeoutSeconds = requireTimeout(entry);

    const extra = asObject(entry.extra);
    if (extra === undefined) throw malformed(H, "SVM exact requirement missing extra object");
    const feePayer = asString(extra.feePayer);
    if (feePayer === undefined) throw malformed(H, "extra.feePayer missing or non-string");
    validateSolanaAddress("extra.feePayer", feePayer);

    let memo: string | null;
    const memoRaw = extra.memo;
    if (memoRaw === undefined) {
      memo = null;
    } else if (typeof memoRaw === "string") {
      if (byteLengthEncoder.encode(memoRaw).length > MAX_MEMO_BYTES) {
        throw malformed(H, `extra.memo exceeds ${MAX_MEMO_BYTES} bytes`);
      }
      memo = memoRaw;
    } else {
      throw malformed(H, "extra.memo is not a string");
    }

    let recentBlockhash: string | null;
    const bhRaw = extra.recentBlockhash;
    if (isNullish(bhRaw)) {
      recentBlockhash = null;
    } else if (typeof bhRaw === "string") {
      const decoded = base58Decode(bhRaw);
      if (decoded === undefined || decoded.length !== 32) {
        throw malformed(H, "extra.recentBlockhash is not a base58 32-byte blockhash");
      }
      recentBlockhash = bhRaw;
    } else {
      throw malformed(H, "extra.recentBlockhash is not a string");
    }

    // Spec: lastValidBlockHeight is ignored when recentBlockhash is absent.
    let lastValidBlockHeight: bigint | null = null;
    if (recentBlockhash !== null) {
      const heightRaw = extra.lastValidBlockHeight;
      if (isNullish(heightRaw)) {
        lastValidBlockHeight = null;
      } else if (typeof heightRaw === "string") {
        lastValidBlockHeight = parseBlockHeight(heightRaw);
      } else {
        throw malformed(H, "extra.lastValidBlockHeight is not a decimal string");
      }
    }

    const challengeHash = computeChallengeHash({
      network,
      mint,
      recipient,
      feePayer,
      memo,
      atomicAmount,
      maxTimeoutSeconds,
      resourceUrl: required.resourceUrl,
    });

    return {
      network,
      mint,
      atomicAmount,
      recipient,
      feePayer,
      memo,
      recentBlockhash,
      lastValidBlockHeight,
      resourceUrl: required.resourceUrl,
      maxTimeoutSeconds,
      extensions: required.extensions,
      challengeHash,
      rawRequirement: entryRaw,
    };
  }

  if (lastUnsupported !== undefined) {
    if (lastUnsupported.kind === "unsupported_mint") throw lastUnsupported;
    if (lastUnsupported.kind === "unsupported_network" && required.accepts.length === 1) {
      throw lastUnsupported;
    }
    if (lastUnsupported.kind === "unsupported_scheme" && required.accepts.length === 1) {
      throw lastUnsupported;
    }
  }
  throw PaymentError.noAcceptableRequirement();
}

// ---------------------------------------------------------------------------
// parse_payment_response
// ---------------------------------------------------------------------------

/**
 * Parse and validate a `PAYMENT-RESPONSE` settlement header. `expectedNetwork`
 * pins the evidence to the network of the payment that was actually proposed; a
 * mismatch is malformed settlement evidence.
 */
export function parsePaymentResponse(
  headerValue: string,
  expectedNetwork: SolanaNetwork,
): SettlementEvidence {
  const H = HEADER_PAYMENT_RESPONSE;
  const settle = (reason: string): PaymentError => PaymentError.malformedSettlement(reason);

  let bytes: Uint8Array;
  try {
    bytes = decodeHeader(H, headerValue);
  } catch (e) {
    if (e instanceof PaymentError && e.kind === "oversized_header") throw e;
    throw settle(e instanceof Error ? e.message : String(e));
  }

  let root: unknown;
  try {
    root = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch (e) {
    throw settle(`invalid JSON: ${(e as Error).message}`);
  }
  const obj = asObject(root);
  if (obj === undefined) throw settle("top-level value is not a JSON object");

  const success = asBool(obj.success);
  if (success === undefined) throw settle("missing or non-boolean success");

  const networkId = asString(obj.network);
  if (networkId === undefined) throw settle("missing or non-string network");
  const network = solanaNetworkFromCaip2(networkId);
  if (network === undefined) throw PaymentError.unsupportedNetwork(truncateForError(networkId));
  if (network !== expectedNetwork) {
    throw settle(
      `settlement network ${caip2ForNetwork(network)} does not match expected ${caip2ForNetwork(expectedNetwork)}`,
    );
  }

  const transaction = asString(obj.transaction);
  if (transaction === undefined) throw settle("missing or non-string transaction");
  let transactionSignature: string | null = null;
  if (success) {
    const sig = base58Decode(transaction);
    if (sig === undefined || sig.length !== 64) {
      throw settle("successful settlement carries an invalid base58 transaction signature");
    }
    transactionSignature = transaction;
  }

  let settledAmount: bigint | null = null;
  const amountRaw = obj.amount;
  if (isNullish(amountRaw)) {
    settledAmount = null;
  } else if (typeof amountRaw === "string") {
    settledAmount = parseAtomicAmount(amountRaw);
  } else {
    throw settle("amount is not a string");
  }

  return {
    success,
    transactionSignature,
    network,
    payer: asString(obj.payer) ?? null,
    errorReason: asString(obj.errorReason) ?? null,
    settledAmount,
  };
}

/** Encode arbitrary bytes as a base64 header value (standard alphabet, padded). */
export function encodeHeaderBytes(bytes: Uint8Array): string {
  return encodeBase64Std(bytes);
}
