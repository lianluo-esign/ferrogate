/**
 * Boundary error — port of `ferrogate-core`'s `GatewayError` and `Result<T>`.
 *
 * Rust: `struct GatewayError { code: String, message: String }` with a
 * `GatewayError::new(code, message)` constructor, and
 * `type Result<T> = std::result::Result<T, GatewayError>`.
 *
 * The wire shape is `{ code, message }`. We render it as a throwable `Error`
 * subclass (idiomatic TS) that still serializes to exactly `{ code, message }`
 * via `toJSON`, plus a Zod validator for the wire form. The `GatewayResult<T>`
 * alias lives in `index.ts` (it reuses the package-level `Result` envelope).
 */
import { z } from "zod";

/** Zod validator for the wire shape of a `GatewayError`. */
export const gatewayErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
});
/** The plain `{ code, message }` data shape of a `GatewayError`. */
export type GatewayErrorData = z.infer<typeof gatewayErrorSchema>;

/**
 * Boundary error carrying a stable machine-readable `code` and a `message`.
 * Throwable, and serializes to `{ code, message }`.
 */
export class GatewayError extends Error implements GatewayErrorData {
  override readonly name = "GatewayError";
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }

  /** Mirrors Rust `GatewayError::new(code, message)`. */
  static new(code: string, message: string): GatewayError {
    return new GatewayError(code, message);
  }

  /** Rebuild a `GatewayError` from its wire shape. */
  static fromData(data: GatewayErrorData): GatewayError {
    return new GatewayError(data.code, data.message);
  }

  toJSON(): GatewayErrorData {
    return { code: this.code, message: this.message };
  }
}

/** Functional constructor mirroring Rust `GatewayError::new`. */
export function newGatewayError(code: string, message: string): GatewayError {
  return new GatewayError(code, message);
}
