/**
 * Strict standard-alphabet base64, matching `base64::engine::general_purpose::
 * STANDARD` (the engine the Rust port used).
 *
 * `atob` alone is not enough: it accepts unpadded input and (in some runtimes)
 * ignores stray whitespace, so a payload the Rust port would have REFUSED
 * would decode here. The alphabet/padding check below restores the refusal.
 * Everything downstream is a signature check, so a decoder that is more
 * permissive than the signer's is a place where two parties can disagree about
 * what the bytes were.
 */

const STANDARD_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

export class Base64Error extends Error {}

export function decodeBase64Strict(value: string): Uint8Array {
  if (value.length % 4 !== 0) {
    throw new Base64Error(`Invalid input length: ${value.length}`);
  }
  if (!STANDARD_BASE64.test(value)) {
    throw new Base64Error("Invalid symbol, offset unknown.");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch (error) {
    throw new Base64Error(error instanceof Error ? error.message : String(error));
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  // Chunked so a large buffer cannot blow the argument limit of `String.fromCharCode`.
  const CHUNK = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + CHUNK));
  }
  return btoa(binary);
}
