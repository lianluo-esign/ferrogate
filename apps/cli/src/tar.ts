/**
 * A minimal, DETERMINISTIC ustar writer — the client half of issue #736.
 *
 * `ferrogate site push ./dist` has to hand the gateway one archive, and the
 * gateway's expander (`apps/gateway/src/assets/bundle.ts`) reads ustar. Writing
 * ~90 lines here rather than shelling out to `tar` buys three things the shell
 * cannot:
 *
 *  - **Determinism.** Every mtime is 0, every mode is 0644, uid/gid are 0, and
 *    entries are emitted in sorted path order. The same `dist/` therefore
 *    produces byte-identical archive bytes and therefore an identical sha256,
 *    so republishing an unchanged site is visibly a no-op instead of a new
 *    content hash every time. `tar` bakes in mtimes and directory order.
 *  - **No shell.** The CLI ships as one binary and `tar` is not on every host
 *    it runs on (nor is it the same `tar` — bsdtar writes pax records where GNU
 *    writes ustar).
 *  - **Only what we mean to send.** Nothing here can emit a symlink, a device
 *    node, or a `..` path, because there is no code that writes one. The walk
 *    in `commands/site.ts` refuses symlinks before they reach this file, so a
 *    symlinked secret in `dist/` is a refusal rather than an upload of whatever
 *    it pointed at.
 */

const BLOCK = 512;

/** One regular file destined for the archive. */
export interface TarFile {
  /** Bundle-relative, `/`-separated, already validated by the caller. */
  readonly path: string;
  readonly content: Uint8Array;
}

function writeAscii(into: Uint8Array, offset: number, text: string, width: number): void {
  const encoded = new TextEncoder().encode(text);
  if (encoded.length > width) {
    throw new Error(`tar field at offset ${offset} overflows (${encoded.length} > ${width})`);
  }
  into.set(encoded, offset);
}

/** ustar numeric fields are NUL-terminated, zero-padded octal. */
function writeOctal(into: Uint8Array, offset: number, value: number, width: number): void {
  writeAscii(into, offset, value.toString(8).padStart(width - 1, "0"), width - 1);
}

function headerBlock(file: TarFile): Uint8Array {
  const header = new Uint8Array(BLOCK);
  writeAscii(header, 0, file.path, 100);
  writeOctal(header, 100, 0o644, 8);
  writeOctal(header, 108, 0, 8); // uid
  writeOctal(header, 116, 0, 8); // gid
  writeOctal(header, 124, file.content.length, 12);
  writeOctal(header, 136, 0, 12); // mtime — fixed, see the determinism note
  // The checksum is defined over the header with its own field read as spaces.
  header.fill(0x20, 148, 156);
  writeAscii(header, 156, "0", 1); // typeflag: regular file, always
  writeAscii(header, 257, "ustar", 6);
  writeAscii(header, 263, "00", 2);
  let sum = 0;
  for (const byte of header) sum += byte;
  writeAscii(header, 148, `${sum.toString(8).padStart(6, "0")}\0 `, 8);
  return header;
}

/**
 * The longest path this writer can express. ustar's `name` field is 100 bytes,
 * and rather than reach for the `prefix` split or a GNU long-name record — both
 * of which are extra parsing surface on the RECEIVING side — an over-long path
 * is refused by the caller with a message naming it.
 */
export const TAR_MAX_PATH_BYTES = 100;

/** Serialize `files` into a ustar archive, terminated by two zero blocks. */
export function buildTar(files: readonly TarFile[]): Uint8Array {
  const sorted = [...files].sort((left, right) => (left.path < right.path ? -1 : 1));
  const records = sorted.map((file) => {
    const padded = Math.ceil(file.content.length / BLOCK) * BLOCK;
    const record = new Uint8Array(BLOCK + padded);
    record.set(headerBlock(file), 0);
    record.set(file.content, BLOCK);
    return record;
  });
  const total = records.reduce((sum, record) => sum + record.length, 0) + 2 * BLOCK;
  const archive = new Uint8Array(total);
  let offset = 0;
  for (const record of records) {
    archive.set(record, offset);
    offset += record.length;
  }
  return archive;
}
