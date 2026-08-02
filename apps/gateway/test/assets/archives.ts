/**
 * REAL archive bytes, built here in the test tree.
 *
 * The point of building them by hand rather than reaching for a library is the
 * hostile half: a symlink entry, a `..` component, an absolute path, a pax
 * header that overrides the following entry's name, a zip whose central
 * directory disagrees with its local header. None of those can be produced by
 * asking `tar` politely, and unit-testing a path-validation helper in isolation
 * proves nothing about whether the expansion loop calls it — so every guard in
 * `src/assets/bundle.ts` is driven through an archive an attacker could really
 * upload.
 *
 * Both writers are deliberately minimal (ustar; zip with STORE or DEFLATE) and
 * are only ever used as INPUT to the production expander.
 */

const BLOCK = 512;

function ascii(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function writeAscii(into: Uint8Array, offset: number, text: string, width: number): void {
  const encoded = ascii(text);
  if (encoded.length > width) throw new Error(`field overflow at ${offset}`);
  into.set(encoded, offset);
}

/** `size`/`mode`/`mtime` are NUL-terminated octal, right-aligned with zeros. */
function writeOctal(into: Uint8Array, offset: number, value: number, width: number): void {
  const text = value.toString(8).padStart(width - 1, "0");
  writeAscii(into, offset, text, width - 1);
}

export interface TarEntry {
  readonly name: string;
  readonly body?: Uint8Array | string;
  /** ustar typeflag: `0` regular, `5` directory, `2` symlink, `x` pax header. */
  readonly typeflag?: string;
  readonly linkname?: string;
  readonly mode?: number;
}

/** One 512-byte ustar header + its NUL-padded body blocks. */
function tarRecord(entry: TarEntry): Uint8Array {
  const body =
    typeof entry.body === "string" ? ascii(entry.body) : (entry.body ?? new Uint8Array(0));
  const header = new Uint8Array(BLOCK);
  writeAscii(header, 0, entry.name, 100);
  writeOctal(header, 100, entry.mode ?? 0o644, 8);
  writeOctal(header, 108, 0, 8);
  writeOctal(header, 116, 0, 8);
  writeOctal(header, 124, body.length, 12);
  writeOctal(header, 136, 0, 12);
  // Checksum is computed with the checksum field itself read as spaces.
  header.fill(0x20, 148, 156);
  writeAscii(header, 156, entry.typeflag ?? "0", 1);
  if (entry.linkname !== undefined) writeAscii(header, 157, entry.linkname, 100);
  writeAscii(header, 257, "ustar", 6);
  writeAscii(header, 263, "00", 2);
  let sum = 0;
  for (const byte of header) sum += byte;
  writeAscii(header, 148, `${sum.toString(8).padStart(6, "0")}\0 `, 8);

  const padded = Math.ceil(body.length / BLOCK) * BLOCK;
  const out = new Uint8Array(BLOCK + padded);
  out.set(header, 0);
  out.set(body, BLOCK);
  return out;
}

/** A ustar archive, terminated by the two zero blocks a real `tar` writes. */
export function buildTar(entries: readonly TarEntry[]): Uint8Array {
  const records = entries.map(tarRecord);
  const total = records.reduce((sum, record) => sum + record.length, 0) + 2 * BLOCK;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const record of records) {
    out.set(record, offset);
    offset += record.length;
  }
  return out;
}

/** A pax extended header record body: `"<len> key=value\n"`, self-sizing. */
export function paxRecord(key: string, value: string): string {
  // The length prefix counts itself, so it is solved by iteration.
  let length = key.length + value.length + 3;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const candidate = `${length + String(length).length} ${key}=${value}\n`;
    if (candidate.length === length + String(length).length) return candidate;
    length = candidate.length;
  }
  throw new Error("pax record length did not converge");
}

/** gzip the bytes with the platform's own compressor (workerd has one). */
export async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  return compress(bytes, "gzip");
}

/** raw-DEFLATE the bytes, the compression method a real zip uses. */
async function deflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  return compress(bytes, "deflate-raw");
}

/** `new Response(bytes).body` is the ambient-typed byte stream in workerd. */
async function compress(bytes: Uint8Array, format: "gzip" | "deflate-raw"): Promise<Uint8Array> {
  const copy = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const body = new Response(copy).body;
  if (body === null) return new Uint8Array(0);
  const stream = body.pipeThrough(new CompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (CRC_TABLE[(crc ^ byte) & 0xff] as number) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export interface ZipEntry {
  readonly name: string;
  readonly body?: Uint8Array | string;
  /** `true` writes the entry raw-DEFLATEd rather than STOREd. */
  readonly deflate?: boolean;
  /** Unix mode placed in the high 16 bits of `external_file_attributes`. */
  readonly unixMode?: number;
  /** Overstate the uncompressed size — the declared-vs-real zip-bomb lie. */
  readonly declaredSize?: number;
}

/** A single-disk zip with a real central directory. */
export async function buildZip(entries: readonly ZipEntry[]): Promise<Uint8Array> {
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;

  for (const entry of entries) {
    const raw =
      typeof entry.body === "string" ? ascii(entry.body) : (entry.body ?? new Uint8Array(0));
    const stored = entry.deflate === true ? await deflateRaw(raw) : raw;
    const name = ascii(entry.name);
    const crc = crc32(raw);
    const method = entry.deflate === true ? 8 : 0;
    const uncompressed = entry.declaredSize ?? raw.length;

    const local = new Uint8Array(30 + name.length + stored.length);
    const localView = new DataView(local.buffer);
    localView.setUint32(0, 0x04034b50, true);
    localView.setUint16(4, 20, true);
    localView.setUint16(6, 0, true);
    localView.setUint16(8, method, true);
    localView.setUint32(14, crc, true);
    localView.setUint32(18, stored.length, true);
    localView.setUint32(22, uncompressed, true);
    localView.setUint16(26, name.length, true);
    local.set(name, 30);
    local.set(stored, 30 + name.length);
    locals.push(local);

    const central = new Uint8Array(46 + name.length);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x02014b50, true);
    centralView.setUint16(4, 0x031e, true); // made by unix
    centralView.setUint16(6, 20, true);
    centralView.setUint16(10, method, true);
    centralView.setUint32(16, crc, true);
    centralView.setUint32(20, stored.length, true);
    centralView.setUint32(24, uncompressed, true);
    centralView.setUint16(28, name.length, true);
    centralView.setUint32(38, (entry.unixMode ?? 0o100644) << 16, true);
    centralView.setUint32(42, offset, true);
    central.set(name, 46);
    centrals.push(central);

    offset += local.length;
  }

  const centralSize = centrals.reduce((sum, part) => sum + part.length, 0);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, 0x06054b50, true);
  endView.setUint16(8, entries.length, true);
  endView.setUint16(10, entries.length, true);
  endView.setUint32(12, centralSize, true);
  endView.setUint32(16, offset, true);

  const parts = [...locals, ...centrals, end];
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
}
