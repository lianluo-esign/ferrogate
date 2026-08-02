/**
 * Multi-file `static_site` bundles (issue #736): archive → per-file entries.
 *
 * ## What this file is for
 *
 * A static website is a directory tree, but the publish path stores exactly one
 * object with one content type. `static_site` existed only as an entry in the
 * content-type allowlist (`content-gate.ts`), which admits `application/zip` /
 * `application/gzip` / `application/x-tar` — so a tenant could publish an
 * archive and FerroGate would vouch for it without ever looking inside. The
 * archive's own content type says nothing at all about its contents; an allowed
 * archive can contain anything.
 *
 * So expansion happens at PUBLISH time, in the gateway, and every rule the
 * single-object path applies to one blob is applied here to every file:
 *
 *  - the content-type allowlist, derived per file from its path extension and
 *    checked against {@link STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES};
 *  - a path grammar that refuses traversal (`..`), absolute paths, drive
 *    letters, backslashes, NUL and control bytes, and over-long names;
 *  - a refusal of every archive member that is not a plain file — symlinks and
 *    hardlinks above all, because a symlink is how an archive smuggles a
 *    reference to something it does not contain;
 *  - hard ceilings on DECOMPRESSED bytes and on file count, enforced *while*
 *    decompressing rather than after, which is the only ordering that bounds a
 *    zip bomb (a bomb's damage is done by the time you can measure it).
 *
 * ## Why the expander returns a list instead of writing objects
 *
 * Expansion is a pure function of the archive bytes. It has no bucket, no
 * store, no clock. That keeps the whole security surface assertable without
 * storage, and it lets the SERVICE own the ordering that makes a publish
 * atomic — reserve the version as `pending_scan`, write every file, then CAS
 * the row to `visible`. A partial expansion therefore cannot reach `visible`,
 * because the promotion is the last step and it never runs.
 *
 * ## Formats
 *
 * ustar tar (with the GNU `L` long-name and pax `x` extended-header records
 * that real tars emit), gzip-wrapped tar, and single-disk zip with STORE or
 * DEFLATE members. gzip and DEFLATE are done by the platform's own
 * `DecompressionStream`, which exists in workerd; no dependency is added.
 */

import { sha256Hex } from "./hash.js";

/** A standalone `ArrayBuffer` copy of a view — `Response` wants a BufferSource. */
function bufferOf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// ---------------------------------------------------------------------------
// Ceilings
// ---------------------------------------------------------------------------

/**
 * The DECOMPRESSED-byte ceiling for one bundle. This is the zip-bomb bound and
 * it is checked incrementally as bytes leave the decompressor, so a 10 MiB
 * archive that would inflate to 10 GiB is abandoned after 32 MiB rather than
 * after it has exhausted the isolate.
 */
export const BUNDLE_MAX_TOTAL_BYTES = 32 * 1024 * 1024;

/**
 * The file-count ceiling. Separate from the byte ceiling because the two bombs
 * are different: a million empty files costs nothing in bytes and everything in
 * R2 writes, index rows, and request time.
 */
export const BUNDLE_MAX_FILES = 2048;

/** Per-file ceiling. A single member may not be the whole budget. */
export const BUNDLE_MAX_FILE_BYTES = 8 * 1024 * 1024;

/** Longest member path, in UTF-8 bytes. */
export const BUNDLE_MAX_PATH_BYTES = 512;

/** The knobs a caller may tighten (never loosen — see {@link resolveLimits}). */
export interface BundleLimits {
  readonly maxTotalBytes?: number | undefined;
  readonly maxFiles?: number | undefined;
  readonly maxFileBytes?: number | undefined;
}

interface ResolvedBundleLimits {
  readonly maxTotalBytes: number;
  readonly maxFiles: number;
  readonly maxFileBytes: number;
}

/**
 * Caller limits are TIGHTENED into the constants, never substituted for them.
 * A caller that passes a larger ceiling gets the constant, so no call site —
 * present or future, including a config-driven one — can widen the zip-bomb
 * bound by supplying a bigger number.
 */
function resolveLimits(limits: BundleLimits | undefined): ResolvedBundleLimits {
  return {
    maxTotalBytes: Math.min(
      BUNDLE_MAX_TOTAL_BYTES,
      limits?.maxTotalBytes ?? Number.MAX_SAFE_INTEGER,
    ),
    maxFiles: Math.min(BUNDLE_MAX_FILES, limits?.maxFiles ?? Number.MAX_SAFE_INTEGER),
    maxFileBytes: Math.min(BUNDLE_MAX_FILE_BYTES, limits?.maxFileBytes ?? Number.MAX_SAFE_INTEGER),
  };
}

// ---------------------------------------------------------------------------
// Per-file content types
// ---------------------------------------------------------------------------

/**
 * What a file inside a `static_site` bundle is allowed to BE.
 *
 * Deliberately NOT `ASSET_CONTENT_TYPE_ALLOWLIST.static_site`. That list must
 * contain the archive container types (`application/zip`, `application/gzip`,
 * `application/x-tar`) because the bundle itself is uploaded as one — and if it
 * were reused here, a bundle could carry a nested archive of arbitrary bytes
 * and the per-file gate would be a no-op for exactly the payload it exists to
 * stop. It also does NOT contain `application/octet-stream`: a catch-all in a
 * per-file allowlist is the same as no allowlist, since every unrecognized
 * extension would land there.
 *
 * The additions over the single-object list (`font/woff*`, `image/webp`,
 * `image/gif`, `text/javascript`, XML, web-app manifests) are the inert,
 * browser-rendered types a real `dist/` contains; each is served as a static
 * response and none is executable outside the browser sandbox.
 */
export const STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES: readonly string[] = [
  "text/html",
  "text/css",
  "text/plain",
  "text/markdown",
  "text/javascript",
  "application/javascript",
  "application/json",
  "application/manifest+json",
  "application/xml",
  "text/xml",
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/svg+xml",
  "image/x-icon",
  "font/woff",
  "font/woff2",
  "font/ttf",
];

/**
 * Extension → content type. The map is CLOSED: a path whose extension is absent
 * has no content type and is refused, rather than degrading to
 * `application/octet-stream` — degrading is how an allowlist stops being one.
 */
const EXTENSION_CONTENT_TYPES: Readonly<Record<string, string>> = {
  html: "text/html",
  htm: "text/html",
  css: "text/css",
  js: "text/javascript",
  mjs: "text/javascript",
  cjs: "text/javascript",
  json: "application/json",
  webmanifest: "application/manifest+json",
  map: "application/json",
  txt: "text/plain",
  md: "text/markdown",
  xml: "application/xml",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  ico: "image/x-icon",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
};

/** The content type a bundle file is published under, or `undefined`. */
export function bundleFileContentType(path: string): string | undefined {
  const base = path.slice(path.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return undefined;
  const extension = base.slice(dot + 1).toLowerCase();
  const contentType = EXTENSION_CONTENT_TYPES[extension];
  if (contentType === undefined) return undefined;
  return STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES.includes(contentType) ? contentType : undefined;
}

// ---------------------------------------------------------------------------
// Path grammar
// ---------------------------------------------------------------------------

/**
 * The refusal reason for `path`, or `undefined` when it is a legal bundle path.
 *
 * Everything here is a REFUSAL, never a repair. Normalizing `a/../b` to `b`
 * would mean the published tree no longer matches the archive the publisher
 * signed and inspected, and normalization bugs are the classic source of
 * traversal escapes. The one exception is a leading `./`, which carries no
 * meaning and which every tar writer emits.
 */
export function bundlePathRejection(path: string): string | undefined {
  const cleaned = path.startsWith("./") ? path.slice(2) : path;
  if (cleaned === "") return "empty path";
  if (new TextEncoder().encode(cleaned).length > BUNDLE_MAX_PATH_BYTES) {
    return `path longer than ${BUNDLE_MAX_PATH_BYTES} bytes`;
  }
  if (cleaned.startsWith("/")) return "absolute path";
  if (cleaned.includes("\\")) return "backslash in path";
  if (/^[A-Za-z]:/.test(cleaned)) return "drive-letter path";
  for (const code of cleaned) {
    const point = code.codePointAt(0) ?? 0;
    if (point < 0x20 || point === 0x7f) return "control character in path";
  }
  for (const segment of cleaned.split("/")) {
    if (segment === "") return "empty path segment";
    if (segment === "." || segment === "..") return "path traversal segment";
  }
  return undefined;
}

/** The canonical form of a legal path (leading `./` dropped). */
export function normalizeBundlePath(path: string): string {
  return path.startsWith("./") ? path.slice(2) : path;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** One file the expander is prepared to publish. */
export interface BundleFile {
  readonly path: string;
  readonly contentType: string;
  readonly content: Uint8Array;
  readonly sha256: string;
}

export type BundleExpansion =
  | { readonly ok: true; readonly files: readonly BundleFile[]; readonly totalBytes: number }
  | { readonly ok: false; readonly message: string };

function refuse(message: string): BundleExpansion {
  return { ok: false, message };
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

export type BundleArchiveFormat = "tar" | "tar.gz" | "zip";

/**
 * The container content types that mark a `static_site` push as a BUNDLE.
 * A subset of the `static_site` allowlist, so nothing here widens what the
 * content gate already admits.
 */
export const BUNDLE_ARCHIVE_CONTENT_TYPES: readonly string[] = [
  "application/zip",
  "application/gzip",
  "application/x-gzip",
  "application/x-tar",
  "application/x-gtar",
  "application/tar+gzip",
  "application/x-compressed-tar",
];

/** True when this `(asset_type, content_type)` pair is a bundle publish. */
export function isBundlePush(assetType: string, contentType: string): boolean {
  if (assetType !== "static_site") return false;
  const base = (contentType.split(";")[0] ?? contentType).trim().toLowerCase();
  return BUNDLE_ARCHIVE_CONTENT_TYPES.includes(base);
}

/**
 * The archive's real format, read from its MAGIC BYTES rather than from the
 * client's declared content type. The declared type decides only *that* this is
 * a bundle; what it actually is has to come from the bytes, or a `.zip` label
 * on a tar would pick the wrong parser — and picking a parser from an
 * attacker-controlled string is how parser-confusion bugs start.
 */
export function detectArchiveFormat(bytes: Uint8Array): BundleArchiveFormat | undefined {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return "tar.gz";
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    const third = bytes[2];
    const fourth = bytes[3];
    // Local file header, central directory, or an empty archive's EOCD.
    if ((third === 0x03 && fourth === 0x04) || (third === 0x05 && fourth === 0x06)) return "zip";
  }
  if (bytes.length >= 263) {
    const magic = new TextDecoder().decode(bytes.subarray(257, 262));
    if (magic === "ustar") return "tar";
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// The expander
// ---------------------------------------------------------------------------

/**
 * Expand `archive` into the files a `static_site` version publishes.
 *
 * Never throws for a hostile archive: every refusal is a message the service
 * renders as `422 asset_rejected`, so the caller cannot accidentally treat a
 * rejection as a server fault (or vice versa).
 */
export async function expandBundle(
  archive: Uint8Array,
  limits?: BundleLimits,
): Promise<BundleExpansion> {
  const resolved = resolveLimits(limits);
  const format = detectArchiveFormat(archive);
  if (format === undefined) {
    return refuse(
      "the uploaded static_site bundle is not a recognizable tar, tar.gz or zip archive",
    );
  }
  try {
    if (format === "zip") return await expandZip(archive, resolved);
    const tar =
      format === "tar" ? archive : await inflateBounded(archive, "gzip", resolved.maxTotalBytes);
    if (tar === null) {
      // Deliberately WORDED differently from the accumulator's identical-looking
      // ceiling refusal below. Only this arm can be reached by the incremental
      // guard inside `inflateBounded`, i.e. only this wording proves the bomb
      // was abandoned mid-stream rather than measured after it had already been
      // materialized — and a test can therefore pin the difference.
      return refuse(
        `the static_site bundle expands beyond the ${resolved.maxTotalBytes}-byte decompressed ceiling: abandoned while decompressing`,
      );
    }
    return await expandTar(tar, resolved);
  } catch (error) {
    // A malformed stream is the publisher's problem, not a 500: a truncated
    // gzip member or a corrupt deflate stream throws out of the platform
    // decompressor and must still read as "your archive is bad".
    return refuse(
      `the static_site bundle could not be read as an archive: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Decompress with a hard output ceiling, checked as chunks arrive.
 *
 * `null` means the ceiling was hit. The reader is cancelled at that moment, so
 * the remaining gigabytes of a bomb are never produced — which is the whole
 * difference between a bound and a comment claiming one.
 */
async function inflateBounded(
  input: Uint8Array,
  format: "gzip" | "deflate-raw",
  maxBytes: number,
): Promise<Uint8Array | null> {
  // `new Response(bytes).body` is the dependency-free way to get a byte stream
  // in workerd; `Blob` would work too but its typings are not in the Workers
  // ambient set.
  const body = new Response(bufferOf(input)).body;
  if (body === null) return new Uint8Array(0);
  const reader = body.pipeThrough(new DecompressionStream(format)).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Accumulates accepted files while enforcing the count/byte ceilings. */
class BundleAccumulator {
  readonly files: BundleFile[] = [];
  #totalBytes = 0;

  constructor(private readonly limits: ResolvedBundleLimits) {}

  get totalBytes(): number {
    return this.#totalBytes;
  }

  /** `undefined` on success, else the refusal message. */
  async add(rawPath: string, content: Uint8Array): Promise<string | undefined> {
    const pathRejection = bundlePathRejection(rawPath);
    if (pathRejection !== undefined) {
      return `bundle entry ${JSON.stringify(rawPath)} is refused: ${pathRejection}`;
    }
    const path = normalizeBundlePath(rawPath);
    if (this.files.some((file) => file.path === path)) {
      // Two members with one path is the classic "which one wins" ambiguity —
      // and a zip whose second entry quietly replaces the first is a real
      // smuggling technique against scanners that read only the first.
      return `bundle entry ${JSON.stringify(path)} is refused: duplicate path in archive`;
    }
    const contentType = bundleFileContentType(path);
    if (contentType === undefined) {
      return (
        `bundle entry ${JSON.stringify(path)} is refused: its file type is not allowed inside a ` +
        `static_site bundle (allowed: ${STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES.join(", ")})`
      );
    }
    if (content.byteLength > this.limits.maxFileBytes) {
      return `bundle entry ${JSON.stringify(path)} is refused: ${content.byteLength} bytes exceeds the ${this.limits.maxFileBytes}-byte per-file ceiling`;
    }
    if (this.files.length >= this.limits.maxFiles) {
      return `the static_site bundle contains more than the ${this.limits.maxFiles}-file ceiling`;
    }
    this.#totalBytes += content.byteLength;
    if (this.#totalBytes > this.limits.maxTotalBytes) {
      return `the static_site bundle expands beyond the ${this.limits.maxTotalBytes}-byte decompressed ceiling`;
    }
    this.files.push({ path, contentType, content, sha256: await sha256Hex(content) });
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------

const TAR_BLOCK = 512;

/** ustar octal field → number. Tolerates the space/NUL terminators tars emit. */
function readOctal(block: Uint8Array, offset: number, length: number): number {
  let text = "";
  for (let index = offset; index < offset + length; index += 1) {
    const byte = block[index];
    if (byte === undefined || byte === 0 || byte === 0x20) break;
    text += String.fromCharCode(byte);
  }
  if (text === "") return 0;
  const value = Number.parseInt(text, 8);
  return Number.isFinite(value) && value >= 0 ? value : Number.NaN;
}

function readString(block: Uint8Array, offset: number, length: number): string {
  const slice = block.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}

/**
 * Read the `path=` attribute out of a pax extended header record body.
 *
 * pax headers are the reason a name check on the ustar `name` field alone is
 * not enough: a conforming reader takes the pax `path` in preference, so an
 * archive can present an innocuous `index.html` in the header block and the
 * real, traversing path in the extended record. Whatever we honour is what must
 * be validated, so the override is returned and run through the SAME grammar.
 */
function paxPath(body: Uint8Array): string | undefined {
  const text = new TextDecoder().decode(body);
  let cursor = 0;
  while (cursor < text.length) {
    const space = text.indexOf(" ", cursor);
    if (space < 0) return undefined;
    const length = Number.parseInt(text.slice(cursor, space), 10);
    if (!Number.isFinite(length) || length <= 0) return undefined;
    const record = text.slice(cursor, cursor + length);
    const equals = record.indexOf("=");
    if (equals > 0) {
      const key = record.slice(record.indexOf(" ") + 1, equals);
      if (key === "path") return record.slice(equals + 1).replace(/\n$/, "");
    }
    cursor += length;
  }
  return undefined;
}

async function expandTar(tar: Uint8Array, limits: ResolvedBundleLimits): Promise<BundleExpansion> {
  const accumulator = new BundleAccumulator(limits);
  let offset = 0;
  /** A pending pax/GNU long-name override for the NEXT ustar record. */
  let overridePath: string | undefined;
  let sawEntry = false;

  while (offset + TAR_BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK);
    if (header.every((byte) => byte === 0)) break; // the terminating blocks
    const size = readOctal(header, 124, 12);
    if (!Number.isFinite(size)) return refuse("the static_site bundle has a malformed tar header");
    const typeflag = readString(header, 156, 1) || "0";
    const bodyStart = offset + TAR_BLOCK;
    const bodyEnd = bodyStart + size;
    if (bodyEnd > tar.length) return refuse("the static_site bundle has a truncated tar entry");
    const body = tar.subarray(bodyStart, bodyEnd);
    const advance = TAR_BLOCK + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;

    if (typeflag === "x" || typeflag === "X") {
      // A pax extended header. Its `path` binds the NEXT record.
      if (size > TAR_BLOCK * 64)
        return refuse("the static_site bundle has an oversized pax header");
      overridePath = paxPath(body) ?? overridePath;
      offset += advance;
      continue;
    }
    if (typeflag === "L") {
      // GNU long name: the body IS the next record's name.
      if (size > BUNDLE_MAX_PATH_BYTES * 4) {
        return refuse("the static_site bundle has an oversized long-name record");
      }
      overridePath = new TextDecoder().decode(body).replace(/\0+$/, "");
      offset += advance;
      continue;
    }
    if (typeflag === "g" || typeflag === "K") {
      // A pax GLOBAL header / long link name: carries nothing we honour.
      offset += advance;
      continue;
    }

    // ustar splits a long name across `prefix` + `name`; a pax/GNU override,
    // when one preceded this record, replaces both.
    const headerName = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const name = overridePath ?? (prefix === "" ? headerName : `${prefix}/${headerName}`);
    overridePath = undefined;
    sawEntry = true;

    if (typeflag === "1" || typeflag === "2") {
      // A hardlink or symlink. Refused unconditionally: the member names bytes
      // it does not carry, which is precisely how an archive reaches outside
      // itself, and there is no sane meaning for one in an R2 key space.
      const link = readString(header, 157, 100);
      return refuse(
        `bundle entry ${JSON.stringify(name)} is refused: symlink and hardlink entries are not allowed in a static_site bundle (points at ${JSON.stringify(link)})`,
      );
    }
    if (typeflag === "5" || name.endsWith("/")) {
      // A directory. R2 has no directories; the per-file keys carry the shape.
      // Its name is still validated, so `../` cannot ride in on a dir entry.
      const rejection = bundlePathRejection(name.replace(/\/+$/, ""));
      if (rejection !== undefined) {
        return refuse(`bundle entry ${JSON.stringify(name)} is refused: ${rejection}`);
      }
      offset += advance;
      continue;
    }
    if (typeflag !== "0" && typeflag !== "\0" && typeflag !== "") {
      // Character/block devices, FIFOs, and every vendor extension. A bundle is
      // a set of files; anything else is refused rather than skipped, so an
      // unknown type can never be silently dropped from what we vouch for.
      return refuse(
        `bundle entry ${JSON.stringify(name)} is refused: unsupported tar entry type ${JSON.stringify(typeflag)}`,
      );
    }

    const rejection = await accumulator.add(name, body.slice());
    if (rejection !== undefined) return refuse(rejection);
    offset += advance;
  }

  // `sawEntry` distinguishes "an archive of nothing but directories" from "an
  // archive we could not parse at all"; both refuse, but only the second is a
  // sign the format detection picked the wrong parser.
  if (accumulator.files.length === 0) {
    return refuse(
      sawEntry
        ? "the static_site bundle contains no publishable files"
        : "the static_site bundle contains no files",
    );
  }
  return { ok: true, files: accumulator.files, totalBytes: accumulator.totalBytes };
}

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

async function expandZip(zip: Uint8Array, limits: ResolvedBundleLimits): Promise<BundleExpansion> {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  // The EOCD is at the end, after a comment of unknown length, so it is found
  // by scanning backwards over the maximum comment size.
  let eocd = -1;
  for (let index = zip.length - 22; index >= 0 && index >= zip.length - 22 - 0xffff; index -= 1) {
    if (view.getUint32(index, true) === EOCD_SIGNATURE) {
      eocd = index;
      break;
    }
  }
  if (eocd < 0) return refuse("the static_site bundle has no zip end-of-central-directory record");

  const entryCount = view.getUint16(eocd + 10, true);
  if (entryCount === 0) return refuse("the static_site bundle contains no files");
  if (entryCount > limits.maxFiles) {
    return refuse(`the static_site bundle contains more than the ${limits.maxFiles}-file ceiling`);
  }
  let cursor = view.getUint32(eocd + 16, true);
  const accumulator = new BundleAccumulator(limits);

  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > zip.length || view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      return refuse("the static_site bundle has a malformed zip central directory");
    }
    const method = view.getUint16(cursor + 10, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const declaredSize = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const externalAttributes = view.getUint32(cursor + 38, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const name = new TextDecoder().decode(zip.subarray(cursor + 46, cursor + 46 + nameLength));
    cursor += 46 + nameLength + extraLength + commentLength;

    // The unix mode lives in the high 16 bits of `external_file_attributes`;
    // `S_IFLNK` (0xA000) is how a zip stores a symlink, with the target as the
    // member's own body. Refused for the same reason tar symlinks are.
    const unixMode = externalAttributes >>> 16;
    if ((unixMode & 0xf000) === 0xa000) {
      return refuse(
        `bundle entry ${JSON.stringify(name)} is refused: symlink entries are not allowed in a static_site bundle`,
      );
    }
    if (name.endsWith("/")) {
      const rejection = bundlePathRejection(name.replace(/\/+$/, ""));
      if (rejection !== undefined) {
        return refuse(`bundle entry ${JSON.stringify(name)} is refused: ${rejection}`);
      }
      continue;
    }
    // The DECLARED size is checked first because it is free, and a bomb that
    // declares itself honestly is stopped before a byte is inflated. It is not
    // trusted: the real, incrementally-counted length is checked below, so a
    // header that lies about its size gains nothing.
    if (declaredSize > limits.maxFileBytes) {
      return refuse(
        `bundle entry ${JSON.stringify(name)} is refused: declared ${declaredSize} bytes exceeds the ${limits.maxFileBytes}-byte per-file ceiling`,
      );
    }
    if (localOffset + 30 > zip.length || view.getUint32(localOffset, true) !== LOCAL_SIGNATURE) {
      return refuse("the static_site bundle has a malformed zip local header");
    }
    const localNameLength = view.getUint16(localOffset + 26, true);
    const localExtraLength = view.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > zip.length) return refuse("the static_site bundle has a truncated zip entry");
    const stored = zip.subarray(dataStart, dataEnd);

    let content: Uint8Array;
    if (method === 0) {
      content = stored.slice();
    } else if (method === 8) {
      const inflated = await inflateBounded(stored, "deflate-raw", limits.maxFileBytes);
      if (inflated === null) {
        return refuse(
          `bundle entry ${JSON.stringify(name)} is refused: it inflates beyond the ${limits.maxFileBytes}-byte per-file ceiling`,
        );
      }
      content = inflated;
    } else {
      return refuse(
        `bundle entry ${JSON.stringify(name)} is refused: unsupported zip compression method ${method}`,
      );
    }

    const rejection = await accumulator.add(name, content);
    if (rejection !== undefined) return refuse(rejection);
  }

  if (accumulator.files.length === 0) return refuse("the static_site bundle contains no files");
  return { ok: true, files: accumulator.files, totalBytes: accumulator.totalBytes };
}
