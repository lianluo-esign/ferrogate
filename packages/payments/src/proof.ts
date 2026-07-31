/**
 * Proof construction for the SVM `exact` scheme (client role). Faithful port of
 * the Rust `proof` module.
 *
 * The adapter never touches key material: transaction construction and signing
 * happen behind the injected {@link SvmTransferSigner}. This module only turns
 * the signer's partially-signed transaction bytes into the x402 V2
 * `PAYMENT-SIGNATURE` wire artifact, echoing the server's `extensions`
 * verbatim as the spec requires of clients.
 */

import { PaymentError } from "./error.js";
import {
  caip2ForNetwork,
  encodeHeaderBytes,
  MAX_SVM_TRANSACTION_BYTES,
  type SelectedPayment,
  type SolanaNetwork,
  X402_VERSION,
} from "./wire.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/**
 * Opaque signer secret material. `toString`, `inspect`, and `toJSON` output
 * never contain the underlying bytes.
 */
export class SecretBytes {
  readonly #bytes: Uint8Array;

  // PORT-TODO(inventory §3.2 "proof"): the Rust `SecretBytes` scrubs its buffer
  // to zero in `Drop`. JS is garbage-collected with no deterministic destructor,
  // so a best-effort scrub-on-drop cannot be replicated; the redaction of
  // Debug/serde output (the observable guarantee the tests assert) is preserved.
  constructor(bytes: Uint8Array) {
    this.#bytes = Uint8Array.from(bytes);
  }

  /** Expose the secret to a signer implementation. Narrowly scoped. */
  expose(): Uint8Array {
    return this.#bytes;
  }

  /** Length of the secret, safe to log. */
  len(): number {
    return this.#bytes.length;
  }

  /** Whether the secret is empty. */
  isEmpty(): boolean {
    return this.#bytes.length === 0;
  }

  toString(): string {
    return `SecretBytes([REDACTED; ${this.#bytes.length} bytes])`;
  }

  [INSPECT](): string {
    return this.toString();
  }

  /** Secrets must never round-trip through serialized output. */
  toJSON(): string {
    return "[REDACTED]";
  }
}

/**
 * Everything a signer needs to build and partially sign the SVM `exact`
 * transfer transaction. Derived from a validated {@link SelectedPayment}.
 */
export interface SvmTransferIntent {
  network: SolanaNetwork;
  mint: string;
  atomicAmount: bigint;
  recipient: string;
  feePayer: string;
  memo: string | null;
  /** Server-supplied blockhash; when `null` the signer MUST fetch one. */
  recentBlockhash: string | null;
  lastValidBlockHeight: bigint | null;
  challengeHash: Uint8Array;
}

/** Build the signer-facing intent from a validated selection. */
export function svmTransferIntentFromSelected(selected: SelectedPayment): SvmTransferIntent {
  return {
    network: selected.network,
    mint: selected.mint,
    atomicAmount: selected.atomicAmount,
    recipient: selected.recipient,
    feePayer: selected.feePayer,
    memo: selected.memo,
    recentBlockhash: selected.recentBlockhash,
    lastValidBlockHeight: selected.lastValidBlockHeight,
    challengeHash: selected.challengeHash,
  };
}

/**
 * Injected signing boundary. Implementations hold the wallet/key material and
 * return the serialized, partially-signed versioned Solana transaction for the
 * given transfer intent.
 *
 * Contract: the returned bytes are a complete wire-format transaction in which
 * the client's signature is present and the fee payer's slot is unsigned; they
 * must not exceed {@link MAX_SVM_TRANSACTION_BYTES}. A refusal (policy veto,
 * user denial, locked key) is reported by throwing; the adapter maps the thrown
 * reason to {@link PaymentError} `signer_rejected`.
 */
export interface SvmTransferSigner {
  /** The signer's public key (base58), i.e. the paying wallet. */
  payerAddress(): string;
  /** Build and partially sign the transfer, or throw a refusal reason. */
  signTransfer(intent: SvmTransferIntent): Uint8Array;
}

/**
 * Build the `PAYMENT-SIGNATURE` header value for a selected requirement,
 * routing all signing through the injected `signer`.
 *
 * Returns the base64 header value; the decoded JSON is the x402 V2
 * `PaymentPayload` with the original requirement echoed in `accepted` and the
 * partially-signed transaction in `payload.transaction`.
 */
export function buildPaymentSignature(
  selected: SelectedPayment,
  signer: SvmTransferSigner,
): string {
  const intent = svmTransferIntentFromSelected(selected);
  let txBytes: Uint8Array;
  try {
    txBytes = signer.signTransfer(intent);
  } catch (e) {
    throw PaymentError.signerRejected(e instanceof Error ? e.message : String(e));
  }
  if (txBytes.length === 0) {
    throw PaymentError.proofBuildFailed("signer returned an empty transaction");
  }
  if (txBytes.length > MAX_SVM_TRANSACTION_BYTES) {
    throw PaymentError.proofBuildFailed(
      `signer returned ${txBytes.length} bytes, exceeding the ${MAX_SVM_TRANSACTION_BYTES}-byte Solana packet limit`,
    );
  }

  // Insertion order mirrors the golden fixtures; consumers compare parsed
  // objects, so key order is not load-bearing.
  const payload: Record<string, unknown> = {
    x402Version: X402_VERSION,
    resource: { url: selected.resourceUrl },
    accepted: selected.rawRequirement,
    payload: { transaction: encodeHeaderBytes(txBytes) },
  };
  // x402 V2 §5.1.2: clients echo the server's extensions verbatim — never
  // delete or overwrite what the server advertised, and never invent an empty
  // object when the server sent none.
  if (selected.extensions !== null && selected.extensions !== undefined) {
    payload["extensions"] = selected.extensions;
  }

  const json = JSON.stringify(payload);
  return encodeHeaderBytes(new TextEncoder().encode(json));
}

// Re-export for callers that build intents against a network directly.
export { caip2ForNetwork };
