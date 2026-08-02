import { samlError } from "./errors.js";

/**
 * RAW DEFLATE (RFC 1951, no zlib wrapper) — the encoding the SAML 2.0
 * HTTP-Redirect binding mandates (§3.4.4.1: the DEFLATE encoding "without the
 * zlib header and checksum"). `flate2::read::DeflateDecoder`, which the Rust
 * port used, is likewise the RAW variant; `DecompressionStream("deflate")`
 * would be the zlib-wrapped one and is NOT interchangeable — `response.test.ts`
 * pins that a zlib-wrapped payload is refused.
 *
 * ## The size caps have no Rust twin, deliberately
 *
 * The Rust port called `read_to_end` on the decoder with no bound, so a small
 * compressed payload that inflates to gigabytes would have been materialised in
 * full. That is a decompression-bomb DoS the Rust service carried, reachable
 * before authentication. It is not behaviour worth porting, and on Workers it
 * is worse than expensive: a Worker isolate has a hard memory ceiling, so one
 * crafted unauthenticated request would kill the isolate.
 *
 * Two caps, in this order:
 *
 *  1. **`MAX_SAML_RESPONSE_B64_CHARS`, checked before ANY decoding.** This is
 *     the cap that actually bounds worst-case memory, because it bounds the
 *     input to the decompressor. DEFLATE's maximum expansion ratio is 1032:1,
 *     so the true worst case is `32 KiB × 3/4 × 1032 ≈ 24.8 MiB` — a fraction
 *     of the isolate budget, and `caps_bound_worst_case_memory` in
 *     `response.test.ts` asserts that arithmetic so nobody raises one cap
 *     without re-deriving the other.
 *  2. **`MAX_INFLATED_SAML_RESPONSE_BYTES`, checked on the result.** A real
 *     `samlp:Response` is a few KB; 1 MiB is already absurd, and refusing at
 *     1 MiB means a bomb never reaches the XML scanner.
 *
 * ### Why the second cap is not enforced mid-stream
 *
 * The obvious implementation — read the decompressed stream chunk by chunk and
 * stop early — cannot be written on workerd without leaking an unhandled
 * promise rejection. Every shape was measured (`getReader()` on the transform's
 * readable; `getReader()` on a `Response` body; `pipeTo` into a limiting
 * `WritableStream`; a limiting `TransformStream` using `controller.error()`;
 * one using `controller.terminate()`): when the decompressor errors, the pipe's
 * INTERNAL promise rejects, and only `new Response(readable).arrayBuffer()`
 * observes it. Every other shape reported "Decompression failed." as an
 * uncaught error even though the failure was fully handled — which in
 * production is a spurious error on a correctly-refused request, and in the
 * suite is a hard failure.
 *
 * So the code uses the one observant shape and pays for it with a coarser
 * bound: `input_cap × 1032` rather than `output_cap`. That is a real and stated
 * limit, not an oversight. It is still strictly better than the Rust port's
 * unbounded read.
 */

/** A real `samlp:Response` is a few KB; 1 MiB is already absurdly generous. */
export const MAX_INFLATED_SAML_RESPONSE_BYTES = 1024 * 1024;

/**
 * The base64 payload cap, checked before anything is decoded at all. 32 KiB of
 * base64 is 24 KiB of DEFLATE — roughly ten times a large real assertion (one
 * carrying a few hundred group memberships).
 */
export const MAX_SAML_RESPONSE_B64_CHARS = 32 * 1024;

/** DEFLATE's maximum expansion ratio, used to state the worst-case bound. */
export const MAX_DEFLATE_EXPANSION_RATIO = 1032;

/**
 * A one-chunk source stream.
 *
 * It MUST be `new Blob([bytes]).stream()` and not a hand-built
 * `ReadableStream`. Measured on workerd: when the decompressor errors, a
 * hand-built source leaves the pipe's internal rejection unobserved (two
 * "Decompression failed." uncaught errors on the malformed/truncated payload
 * tests) while a Blob-backed source does not. Same consumer, same caps, same
 * assertions — only the source differs.
 */
function singleChunkStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new Blob([bytes]).stream() as ReadableStream<Uint8Array>;
}

export class InflateError extends Error {}
export class InflateTooLargeError extends Error {}

/**
 * Inflates raw-DEFLATE bytes, refusing a result larger than `limit`.
 *
 * `compressed` MUST already have been bounded by the caller (see
 * `MAX_SAML_RESPONSE_B64_CHARS`) — this function's memory use is proportional
 * to the DECOMPRESSED size, which it can only report after the fact.
 */
export async function inflateRawBounded(
  compressed: Uint8Array,
  limit: number = MAX_INFLATED_SAML_RESPONSE_BYTES,
): Promise<Uint8Array> {
  const stream = singleChunkStream(compressed).pipeThrough(new DecompressionStream("deflate-raw"));
  let inflated: Uint8Array;
  try {
    // `new Response(...).arrayBuffer()` — the ONE consumer shape on workerd
    // that observes the pipe's internal rejection. See the note above.
    inflated = new Uint8Array(await new Response(stream).arrayBuffer());
  } catch (error) {
    throw new InflateError(error instanceof Error ? error.message : String(error));
  }
  if (inflated.byteLength > limit) {
    throw new InflateTooLargeError(`inflated SAMLResponse exceeds ${limit} bytes`);
  }
  return inflated;
}

/** Compresses with raw DEFLATE — used for the outbound `AuthnRequest`. */
export async function deflateRaw(input: Uint8Array): Promise<Uint8Array> {
  const stream = singleChunkStream(input).pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Maps the two inflate failures onto their SAML refusal codes. */
export function inflateFailure(error: unknown): never {
  if (error instanceof InflateTooLargeError) {
    throw samlError("saml_response_too_large", error.message);
  }
  const detail = error instanceof Error ? error.message : String(error);
  throw samlError("saml_response_inflate_failed", `SAMLResponse could not be inflated: ${detail}`);
}
