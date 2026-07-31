/**
 * x402 / Solana SVM wire primitives the spend policy binds against.
 *
 * PORT-TODO(inventory §2.1 "x402_spend (deprioritized)"): the authoritative home
 * for these is the `ferrogate-payments` crate → `@ferrogate/payments`, which is a
 * deprioritized wave-2 stub (x402/Solana deferred per project directive). They
 * are re-implemented here so the policy decision (`authorize_x402_payment`) is
 * behaviorally complete and testable. When `@ferrogate/payments` ports the frozen
 * wire contract (`SelectedPayment`, `PaymentIntent`, `SolanaNetwork`,
 * `validate_solana_address`, intent hashing), this module should re-export from
 * there. Faithful to the crate: integer-only money (bigint for u64), no floats.
 */
import { Sha256Builder, hexLower, sha256 } from "./sha256.js";

/** x402 protocol version this contract implements. */
export const X402_VERSION = 2n;
/** The `exact` payment scheme identifier. */
export const SCHEME_EXACT = "exact";
/** Safety cap on `maxTimeoutSeconds`. */
export const MAX_TIMEOUT_SECONDS = 86_400n;

/** CAIP-2 network identifier for Solana mainnet-beta. */
export const CAIP2_SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
/** CAIP-2 network identifier for Solana devnet. */
export const CAIP2_SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/** Domain-separation tag for the payment-intent seal. */
export const PAYMENT_INTENT_HASH_DOMAIN = "ferrogate.x402.payment-intent.v1";

/** Recognised Solana networks, keyed by their CAIP-2 identifiers. */
export type SolanaNetwork = "mainnet" | "devnet";

/** Recognise a CAIP-2 network identifier (purely local; no RPC). */
export function networkFromCaip2(id: string): SolanaNetwork | undefined {
  if (id === CAIP2_SOLANA_MAINNET) return "mainnet";
  if (id === CAIP2_SOLANA_DEVNET) return "devnet";
  return undefined;
}

/** The CAIP-2 identifier for a network. */
export function networkCaip2(network: SolanaNetwork): string {
  return network === "mainnet" ? CAIP2_SOLANA_MAINNET : CAIP2_SOLANA_DEVNET;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Base58-decode, or `undefined` on an invalid character / bounds. */
export function base58Decode(input: string): Uint8Array | undefined {
  if (input.length === 0 || input.length > 128) return undefined;
  const digits: number[] = [];
  for (const ch of input) {
    const d = BASE58_ALPHABET.indexOf(ch);
    if (d < 0) return undefined;
    digits.push(d);
  }
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros++;
  const out: number[] = [];
  for (const d of digits) {
    let carry = d;
    for (let i = 0; i < out.length; i++) {
      carry += out[i]! * 58;
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

/** True iff `value` is a canonical base58 address decoding to exactly 32 bytes. */
export function isValidSolanaAddress(value: string): boolean {
  const bytes = base58Decode(value);
  return bytes !== undefined && bytes.length === 32;
}

/**
 * One wire-validated, selected SVM `exact` requirement handed to policy. Money
 * is integer-only (`atomicAmount` is a `bigint`). `challengeHash` is the frozen
 * wire contract's deterministic 32-byte terms hash.
 */
export interface SelectedPayment {
  network: SolanaNetwork;
  mint: string;
  atomicAmount: bigint;
  recipient: string;
  resourceUrl: string;
  maxTimeoutSeconds: bigint;
  /** 32-byte deterministic challenge/terms hash from the wire contract. */
  challengeHash: Uint8Array;
}

/** Lowercase hex of a {@link SelectedPayment}'s challenge hash. */
export function challengeHashHex(selected: SelectedPayment): string {
  return hexLower(selected.challengeHash);
}

/** SHA-256 of an authorized request body; empty slice ⇒ the canonical "no body". */
export function requestBodyHashHex(body: Uint8Array): string {
  return hexLower(sha256(body));
}

/** Who a payment is made on behalf of (mandatory tenant + request id). */
export interface PaymentIntentIdentity {
  tenantId: string;
  projectId?: string;
  workspaceId?: string;
  keyId?: string;
  runId?: string;
  workerId?: string;
  requestId: string;
}

/**
 * The immutable payment-intent contract (issue #351): binds one already-authorized
 * egress request (method + body hash + canonical URL) to one merchant challenge
 * at one caller identity. Every field is private; there is no mutating API, so an
 * intent cannot be edited into describing a different payment.
 *
 * PORT-TODO(inventory §2.1): full draft validation (`PaymentIntentError` taxonomy)
 * lives in `@ferrogate/payments`; `fromSelected` here copies the already
 * wire-validated terms verbatim, which is the only path the policy decision uses.
 */
export class PaymentIntent {
  private constructor(
    private readonly _network: SolanaNetwork,
    private readonly _mint: string,
    private readonly _atomicAmount: bigint,
    private readonly _recipient: string,
    private readonly _authorizedResourceUrl: string,
    private readonly _httpMethod: string,
    private readonly _requestBodyHashHex: string,
    private readonly _challengeHashHex: string,
    private readonly _maxTimeoutSeconds: bigint,
    private readonly _identity: PaymentIntentIdentity,
  ) {}

  /**
   * Build an intent from a wire-validated challenge plus the request the gateway
   * already authorized. `body` is the authorized request body; pass an empty
   * slice for a bodyless method. The HTTP method is upper-cased so `get` and
   * `GET` cannot produce two different intent hashes for the same request.
   */
  static fromSelected(
    selected: SelectedPayment,
    httpMethod: string,
    authorizedResourceUrl: string,
    body: Uint8Array,
    identity: PaymentIntentIdentity,
  ): PaymentIntent {
    return new PaymentIntent(
      selected.network,
      selected.mint,
      selected.atomicAmount,
      selected.recipient,
      authorizedResourceUrl,
      httpMethod.trim().toUpperCase(),
      requestBodyHashHex(body),
      challengeHashHex(selected),
      selected.maxTimeoutSeconds,
      identity,
    );
  }

  authorizedResourceUrl(): string {
    return this._authorizedResourceUrl;
  }
  httpMethod(): string {
    return this._httpMethod;
  }
  requestBodyHashHex(): string {
    return this._requestBodyHashHex;
  }
  challengeHashHex(): string {
    return this._challengeHashHex;
  }
  identity(): PaymentIntentIdentity {
    return this._identity;
  }

  /**
   * Deterministic SHA-256 over the whole intent, lowercase hex. Domain-tagged and
   * NUL-separated; optional identity components encode their presence separately
   * from their content so an absent id and an empty-string id never hash alike.
   */
  intentHashHex(): string {
    const h = new Sha256Builder();
    for (const part of [
      PAYMENT_INTENT_HASH_DOMAIN,
      X402_VERSION.toString(),
      SCHEME_EXACT,
      networkCaip2(this._network),
      this._mint,
      this._atomicAmount.toString(),
      this._recipient,
      this._authorizedResourceUrl,
      this._httpMethod,
      this._requestBodyHashHex,
      this._challengeHashHex,
      this._maxTimeoutSeconds.toString(),
      this._identity.tenantId,
      this._identity.requestId,
    ]) {
      h.pushStr(part).pushByte(0);
    }
    for (const optional of [
      this._identity.projectId,
      this._identity.workspaceId,
      this._identity.keyId,
      this._identity.runId,
      this._identity.workerId,
    ]) {
      if (optional !== undefined) {
        h.pushByte(1).pushStr(optional);
      } else {
        h.pushByte(0);
      }
      h.pushByte(0);
    }
    return h.digestHex();
  }

  /**
   * Does this intent describe exactly the payment `selected` demands? Returns the
   * first field that disagrees so the caller can emit a specific reason code.
   */
  bindingMismatch(selected: SelectedPayment): string | undefined {
    if (this._challengeHashHex !== challengeHashHex(selected)) return "challenge_hash";
    if (this._network !== selected.network) return "network";
    if (this._mint !== selected.mint) return "mint";
    if (this._recipient !== selected.recipient) return "recipient";
    if (this._atomicAmount !== selected.atomicAmount) return "atomic_amount";
    if (this._maxTimeoutSeconds !== selected.maxTimeoutSeconds) return "max_timeout_seconds";
    return undefined;
  }
}
