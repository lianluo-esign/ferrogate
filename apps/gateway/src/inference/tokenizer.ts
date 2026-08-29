/**
 * The local BPE tokenizer, used to recover a token count when an upstream
 * returns a valid success body with NO usage object (#976 Phase B1).
 *
 * ## Why this exists, and what it is NOT
 *
 * `./estimate.ts` documents the OPEN port-TODO: the pre-dispatch reservation is
 * a `chars/4` approximation because no tokenizer was vendored. This module is
 * the tokenizer, added for the SETTLEMENT-side fallback first (buffered
 * responses with no usage), not the pre-dispatch estimate. The estimate keeps
 * its `chars/4` leg until a later slice moves it here too — landing the sharper
 * count on the money path where a missing usage object was previously metered at
 * $0 is the higher-value half.
 *
 * ## Encoding choice: `o200k_base` only, deliberately
 *
 * `gpt-tokenizer` ships one embedded BPE rank table per encoding, each a ~1 MB
 * (gzipped) array literal parsed at module load — so every encoding imported is
 * paid for in Worker bundle size AND cold-start parse. Measured on this repo:
 * `o200k_base` adds ~1.11 MB gzip, `cl100k_base` a further ~0.44 MB.
 *
 * `o200k_base` is EXACT for every current OpenAI model (gpt-4o, gpt-5, the
 * o-series, gpt-4.1) and a close approximation for everything else. The fallback
 * population is dominated by upstreams that emit no usage at all — native
 * Anthropic streams that drop it, OAuth/subscription providers — and for those
 * `gpt-tokenizer` is an approximation regardless of which OpenAI encoding is
 * chosen. `cl100k_base` would only sharpen legacy gpt-4 / gpt-3.5-turbo, a
 * shrinking slice seen only within the fallback subset, and it is not worth
 * doubling the cold-start parse for. `o200k_base` for everything is already far
 * closer than the `chars/4` it replaces.
 *
 * Adding `cl100k_base` later is a one-line change here plus its import — hence
 * {@link encodingForModel} exists rather than a bare `countTokens`.
 */
import { countTokens as countO200k } from "gpt-tokenizer/encoding/o200k_base";

/** The BPE encodings this module can count with. B1 ships exactly one. */
export type TokenizerEncoding = "o200k_base";

/**
 * The encoding to count `model` with.
 *
 * B1 always answers `o200k_base` (see the module header). The `model` argument
 * is the selection key a later slice keys `cl100k_base` off — keeping it in the
 * signature means adding that encoding is a change to this one function and to
 * nothing that calls it.
 */
export function encodingForModel(_model: string): TokenizerEncoding {
  return "o200k_base";
}

/**
 * Count the BPE tokens in `text` for `model`. Synchronous — it runs on the same
 * buffered record path as the usage extractor, which has no async seam.
 */
export function countTokens(text: string, model: string): number {
  switch (encodingForModel(model)) {
    case "o200k_base":
      return countO200k(text);
  }
}
