/**
 * Typed error surface for the x402/SVM payment adapter.
 *
 * Faithful port of the Rust `PaymentError` enum. Every rejection is a distinct
 * variant so callers (policy, billing, observability) can branch on the failure
 * class without string matching. Invalid input is NEVER coerced into a default
 * value — in particular an invalid atomic amount is a hard error, never `0`.
 *
 * In TS the enum is modeled as an `Error` subclass carrying a discriminated
 * `kind` plus the variant payload; the wire functions throw it. The `message`
 * mirrors the Rust `Display` output so the "Failure contract" variants each
 * render a distinct, non-empty string.
 */

/** Discriminant matching the Rust `PaymentError` variants (snake_case). */
export type PaymentErrorKind =
  | "malformed_header"
  | "oversized_header"
  | "unsupported_version"
  | "no_acceptable_requirement"
  | "unsupported_network"
  | "unsupported_scheme"
  | "unsupported_mint"
  | "invalid_amount"
  | "invalid_recipient"
  | "invalid_timeout"
  | "signer_rejected"
  | "proof_build_failed"
  | "malformed_settlement"
  | "sdk_incompatible";

/** Structured payload carried alongside a {@link PaymentError}. */
export interface PaymentErrorData {
  /** Which wire artifact was being parsed, for header-scoped variants. */
  header?: string;
  reason?: string;
  limit?: number;
  actual?: number;
  found?: string;
  network?: string;
  scheme?: string;
  mint?: string;
  amount?: string;
  field?: string;
  value?: string;
  detail?: string;
}

/** Debug-style quoting mirroring Rust's `{:?}` for strings. */
function dbg(s: string): string {
  return JSON.stringify(s);
}

export class PaymentError extends Error {
  readonly kind: PaymentErrorKind;
  readonly data: PaymentErrorData;

  constructor(kind: PaymentErrorKind, data: PaymentErrorData, message: string) {
    super(message);
    this.name = "PaymentError";
    this.kind = kind;
    this.data = data;
  }

  static malformedHeader(header: string, reason: string): PaymentError {
    return new PaymentError(
      "malformed_header",
      { header, reason },
      `malformed ${header} header: ${reason}`,
    );
  }

  static oversizedHeader(header: string, limit: number, actual: number): PaymentError {
    return new PaymentError(
      "oversized_header",
      { header, limit, actual },
      `oversized ${header} header: ${actual} bytes exceeds cap of ${limit}`,
    );
  }

  static unsupportedVersion(found: string): PaymentError {
    return new PaymentError(
      "unsupported_version",
      { found },
      `unsupported x402 version ${found} (supported: 2)`,
    );
  }

  static noAcceptableRequirement(): PaymentError {
    return new PaymentError(
      "no_acceptable_requirement",
      {},
      "no acceptable payment requirement in accepts",
    );
  }

  static unsupportedNetwork(network: string): PaymentError {
    return new PaymentError("unsupported_network", { network }, `unsupported network ${network}`);
  }

  static unsupportedScheme(scheme: string): PaymentError {
    return new PaymentError(
      "unsupported_scheme",
      { scheme },
      `unsupported payment scheme ${scheme}`,
    );
  }

  static unsupportedMint(mint: string): PaymentError {
    return new PaymentError("unsupported_mint", { mint }, `unsupported token mint ${mint}`);
  }

  static invalidAmount(amount: string, reason: string): PaymentError {
    return new PaymentError(
      "invalid_amount",
      { amount, reason },
      `invalid atomic amount ${dbg(amount)}: ${reason}`,
    );
  }

  static invalidRecipient(field: string, value: string): PaymentError {
    return new PaymentError(
      "invalid_recipient",
      { field, value },
      `invalid recipient in ${field}: ${dbg(value)}`,
    );
  }

  static invalidTimeout(reason: string): PaymentError {
    return new PaymentError("invalid_timeout", { reason }, `invalid maxTimeoutSeconds: ${reason}`);
  }

  static signerRejected(reason: string): PaymentError {
    return new PaymentError("signer_rejected", { reason }, `signer rejected payment: ${reason}`);
  }

  static proofBuildFailed(reason: string): PaymentError {
    return new PaymentError("proof_build_failed", { reason }, `proof build failed: ${reason}`);
  }

  static malformedSettlement(reason: string): PaymentError {
    return new PaymentError(
      "malformed_settlement",
      { reason },
      `malformed PAYMENT-RESPONSE settlement header: ${reason}`,
    );
  }

  static sdkIncompatible(detail: string): PaymentError {
    return new PaymentError(
      "sdk_incompatible",
      { detail },
      `payment SDK incompatible with this build: ${detail}`,
    );
  }
}

/** Type guard for a thrown {@link PaymentError}. */
export function isPaymentError(e: unknown): e is PaymentError {
  return e instanceof PaymentError;
}
