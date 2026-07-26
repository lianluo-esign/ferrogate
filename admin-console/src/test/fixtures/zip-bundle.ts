// Byte fixtures for the static-site publish flow (#345).
//
// WHY THESE LIVE OUTSIDE THE SPEC THAT USES THEM: the console's publish form
// gates on `readsAsZipArchive`, which requires the first four bytes to be the
// ZIP local-file-header magic. When that gate replaced the old filename/MIME
// check, `e2e/static-sites.spec.ts` was still uploading `Buffer.alloc(4096, 1)`
// and `Buffer.alloc(2048, 9)` — buffers shaped to pass the OLD gate. The Publish
// button was therefore permanently `disabled` in the two publish specs, yet
// `playwright --list` still discovered all 18 cases and `typecheck:e2e` was
// clean, because neither of those EXECUTES a validation. The break was invisible
// until a browser ran.
//
// So the bytes are declared here, in a module `src/lib/zip-archive.test.ts` can
// import, and that test runs the REAL predicate over them. Tighten the gate
// again and the guard goes red in `vitest` — seconds, no browser — instead of
// in the gate's chromium run.
//
// The general rule this encodes: tightening an input gate invalidates every
// fixture that was shaped to pass the old one, and neither a type-checker nor a
// test lister can see it.

/**
 * `byteLength` bytes that the gateway's `is_zip_archive` (and therefore the
 * console's `readsAsZipArchive`) accepts: the four-byte `PK\x03\x04` local-file
 * header followed by `fill` padding. Not a parseable archive — the gateway's
 * branch condition is the magic alone (sites.rs:203-205), and every consumer of
 * these bytes is a mock — but it is a real ZIP as far as every validation in the
 * publish path is concerned.
 */
export function zipBundleBytes(byteLength: number, fill = 0): Uint8Array {
  const magic = [0x50, 0x4b, 0x03, 0x04];
  if (byteLength < magic.length) {
    throw new Error(`a ZIP bundle fixture needs at least ${magic.length} bytes`);
  }
  const bytes = new Uint8Array(byteLength).fill(fill);
  bytes.set(magic, 0);
  return bytes;
}

/** The bundle `e2e/static-sites.spec.ts` publishes to the new `landing` site. */
export const E2E_PUBLISH_BUNDLE = zipBundleBytes(4096, 1);

/** The bundle `e2e/static-sites.spec.ts` republishes to `marketing`. */
export const E2E_REPUBLISH_BUNDLE = zipBundleBytes(2048, 9);
