// The console's client-side "is this actually a ZIP?" predicate (#345).
//
// Extracted from src/pages/static-sites.tsx so the exact function the publish
// form gates on can be exercised by tests OTHER than that page's — in
// particular src/lib/zip-archive.test.ts runs it over the byte fixtures the
// Playwright specs upload. A predicate that only its own page can reach is a
// predicate whose fixtures drift silently: tightening it invalidated the e2e
// upload buffers while `playwright --list` and `typecheck:e2e` both stayed
// green, because neither executes a validation. Keeping the predicate reachable
// is what makes that guard possible at all.

/** The ZIP local-file-header magic, byte-for-byte the gateway's `is_zip_archive`
 * predicate (`data.starts_with(&[0x50, 0x4b, 0x03, 0x04])`, sites.rs:203-205). */
export const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04];

/** Whether these leading bytes are what the gateway's `is_zip_archive` reads as
 * a ZIP archive. Split from the `File` reader so a fixture held as plain bytes
 * can be checked without constructing a DOM `File`. */
export function hasZipMagic(bytes: Uint8Array): boolean {
  return (
    bytes.length >= ZIP_MAGIC.length && ZIP_MAGIC.every((byte, index) => bytes[index] === byte)
  );
}

/**
 * Reads the bundle's first bytes and reports whether the gateway will see a ZIP
 * archive — the SAME predicate `is_zip_archive` applies, so the client-side
 * check cannot disagree with the branch it is predicting.
 *
 * This used to trust the FILENAME (`.zip`) or the browser-declared MIME type,
 * which is not evidence about the bytes at all: `head -c 400 /dev/urandom >
 * site.zip` sailed straight through to a publish that the gateway then stored as
 * an opaque blob. The filename is the operator's claim; the magic is the fact.
 * Still fast feedback rather than the gate — the gateway remains authoritative,
 * and the envelope check on the publish response is the real guarantee (see
 * `PublishEnvelope` in pages/static-sites.tsx) — but it now fails the case it
 * was meant to catch.
 */
export async function readsAsZipArchive(file: File): Promise<boolean> {
  const head = new Uint8Array(await file.slice(0, ZIP_MAGIC.length).arrayBuffer());
  return hasZipMagic(head);
}
