/**
 * A minimal, dependency-free Apache Parquet writer — enough of the format, and
 * no more, to emit the chargeback export (#677).
 *
 * ============================================================================
 * WHY THIS EXISTS RATHER THAN A DEPENDENCY
 * ============================================================================
 *
 * The issue's "Done when" says CSV *or* Parquet, and the difference is not
 * cosmetic: a finance analyst opens the CSV, and a data team lands the Parquet
 * in a warehouse and joins it against their own cost model. Parquet is the
 * format that makes an export a DATA ASSET rather than an attachment, because
 * it carries types and nullability with it — and the one distinction this whole
 * slice turns on, `cost_usd = null` (nothing could price it, #663) versus
 * `cost_usd = 0`, is exactly the distinction CSV can only express by
 * convention and Parquet expresses in the format.
 *
 * The runtime dependency list of this tree is `hono` and `zod`. Pulling a
 * Parquet writer into a Worker BUNDLE to serve one admin route would be the
 * largest dependency in the fleet, for a file format whose subset we need is
 * small and completely specified. So the writer is here, and the PROOF that it
 * is a real Parquet file is a round trip through `hyparquet` — a DEV dependency
 * that shares no code with this module — in
 * `test/cost-records-read.test.ts`. A self-consistent encoder/decoder pair
 * would prove nothing; a file an independent reader opens is the claim.
 *
 * ============================================================================
 * THE SUBSET, STATED
 * ============================================================================
 *
 *  - ONE row group, UNCOMPRESSED, PLAIN-encoded, data page V1.
 *  - A FLAT schema: every column is a leaf, so max repetition level is 0 and no
 *    repetition levels are written at all.
 *  - Every column is OPTIONAL (max definition level 1), because every column of
 *    a cost record can legitimately be unknown — an un-attributed request has
 *    no `tenant_id`, an unmetered one has no `cost_usd`.
 *  - Four physical types: `BYTE_ARRAY` (UTF8), `INT64`, `DOUBLE`, `BOOLEAN`.
 *
 * What is deliberately NOT here, and why none of it is needed: compression
 * (the export is streamed once and read once; a Worker's CPU budget is a
 * harder limit than the customer's bandwidth), dictionary encoding (the same
 * argument, and PLAIN is the encoding every reader supports), column
 * statistics (a reader that needs min/max for pushdown is reading a lake table,
 * not a one-shot export), and multiple row groups (the page is bounded to
 * {@link ../routes/admin_cost_record.ts} `COST_EXPORT_MAX_LIMIT` rows and
 * materialized in memory anyway — an export that dies at 2 GB has exported
 * nothing, so the bound is the answer, not row-group striping).
 *
 * ============================================================================
 * FILE LAYOUT
 * ============================================================================
 *
 * ```
 *   "PAR1"
 *   [ page header (thrift) | def levels (RLE) | values (PLAIN) ]   × columns
 *   FileMetaData (thrift compact)
 *   uint32 LE  — byte length of FileMetaData
 *   "PAR1"
 * ```
 */

// ---------------------------------------------------------------------------
// A growable byte sink
// ---------------------------------------------------------------------------

/**
 * A growable little-endian byte buffer.
 *
 * Doubling rather than an array of numbers: the export is up to 10,000 rows ×
 * ~30 columns, and a JS number array of that size costs an order of magnitude
 * more memory than the bytes it represents — inside a Worker's 128 MB isolate
 * that is the difference between an export and an OOM.
 */
class ByteSink {
  #bytes = new Uint8Array(1024);
  #length = 0;

  get length(): number {
    return this.#length;
  }

  #reserve(extra: number): void {
    if (this.#length + extra <= this.#bytes.length) return;
    let capacity = this.#bytes.length * 2;
    while (capacity < this.#length + extra) capacity *= 2;
    const grown = new Uint8Array(capacity);
    grown.set(this.#bytes.subarray(0, this.#length));
    this.#bytes = grown;
  }

  byte(value: number): void {
    this.#reserve(1);
    this.#bytes[this.#length] = value & 0xff;
    this.#length += 1;
  }

  raw(values: Uint8Array): void {
    this.#reserve(values.length);
    this.#bytes.set(values, this.#length);
    this.#length += values.length;
  }

  /** Unsigned LEB128 — thrift compact's integer transport. */
  varint(value: number): void {
    let remaining = value;
    while (remaining >= 0x80) {
      this.byte((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    this.byte(remaining);
  }

  /** Unsigned LEB128 over a `bigint`, for the zig-zagged 64-bit fields. */
  varintBig(value: bigint): void {
    let remaining = value;
    while (remaining >= 0x80n) {
      this.byte(Number(remaining & 0x7fn) | 0x80);
      remaining >>= 7n;
    }
    this.byte(Number(remaining));
  }

  uint32LE(value: number): void {
    this.byte(value);
    this.byte(value >>> 8);
    this.byte(value >>> 16);
    this.byte(value >>> 24);
  }

  int64LE(value: bigint): void {
    const buffer = new ArrayBuffer(8);
    new DataView(buffer).setBigInt64(0, value, true);
    this.raw(new Uint8Array(buffer));
  }

  float64LE(value: number): void {
    const buffer = new ArrayBuffer(8);
    new DataView(buffer).setFloat64(0, value, true);
    this.raw(new Uint8Array(buffer));
  }

  toBytes(): Uint8Array {
    return this.#bytes.slice(0, this.#length);
  }
}

// ---------------------------------------------------------------------------
// Thrift compact protocol
// ---------------------------------------------------------------------------

/** Thrift compact field types (TCompactProtocol). */
const T_TRUE = 1;
const T_FALSE = 2;
const T_I32 = 5;
const T_I64 = 6;
const T_DOUBLE = 7;
const T_BINARY = 8;
const T_LIST = 9;
const T_STRUCT = 12;

const UTF8 = new TextEncoder();

/**
 * The thrift compact protocol writer.
 *
 * Field ids are written as a DELTA from the previous field of the same struct
 * whenever the delta fits in four bits — which is the whole point of the
 * compact protocol and the one part of it that is easy to get subtly wrong, so
 * the previous id is stacked and restored around every nested struct.
 */
class CompactWriter {
  readonly sink: ByteSink;
  #lastField = 0;
  readonly #stack: number[] = [];

  constructor(sink: ByteSink) {
    this.sink = sink;
  }

  structBegin(): void {
    this.#stack.push(this.#lastField);
    this.#lastField = 0;
  }

  structEnd(): void {
    this.sink.byte(0);
    this.#lastField = this.#stack.pop() ?? 0;
  }

  #header(id: number, type: number): void {
    const delta = id - this.#lastField;
    if (delta > 0 && delta <= 15) {
      this.sink.byte((delta << 4) | type);
    } else {
      // A non-positive or too-large delta falls back to the long form: the
      // type alone, then the id as a zig-zag varint.
      this.sink.byte(type);
      this.sink.varint(zigzag32(id));
    }
    this.#lastField = id;
  }

  bool(id: number, value: boolean): void {
    // A boolean field encodes its VALUE in the type nibble; there is no
    // separate payload.
    this.#header(id, value ? T_TRUE : T_FALSE);
  }

  i32(id: number, value: number): void {
    this.#header(id, T_I32);
    this.sink.varint(zigzag32(value));
  }

  i64(id: number, value: bigint): void {
    this.#header(id, T_I64);
    this.sink.varintBig(zigzag64(value));
  }

  double(id: number, value: number): void {
    this.#header(id, T_DOUBLE);
    this.sink.float64LE(value);
  }

  string(id: number, value: string): void {
    this.#header(id, T_BINARY);
    const bytes = UTF8.encode(value);
    this.sink.varint(bytes.length);
    this.sink.raw(bytes);
  }

  /** Open a list field; the caller writes `size` elements of `elementType`. */
  listBegin(id: number, elementType: number, size: number): void {
    this.#header(id, T_LIST);
    if (size <= 14) {
      this.sink.byte((size << 4) | elementType);
    } else {
      this.sink.byte(0xf0 | elementType);
      this.sink.varint(size);
    }
  }

  /** A bare i32 list element (thrift enums travel as i32). */
  listI32(value: number): void {
    this.sink.varint(zigzag32(value));
  }

  /** A bare string list element. */
  listString(value: string): void {
    const bytes = UTF8.encode(value);
    this.sink.varint(bytes.length);
    this.sink.raw(bytes);
  }

  /** Open a struct-typed field. */
  structField(id: number): void {
    this.#header(id, T_STRUCT);
    this.structBegin();
  }
}

function zigzag32(value: number): number {
  return ((value << 1) ^ (value >> 31)) >>> 0;
}

function zigzag64(value: bigint): bigint {
  return (value << 1n) ^ (value >> 63n);
}

// ---------------------------------------------------------------------------
// Parquet vocabulary
// ---------------------------------------------------------------------------

/** `parquet.thrift` `Type`. */
const TYPE_BOOLEAN = 0;
const TYPE_INT64 = 2;
const TYPE_DOUBLE = 5;
const TYPE_BYTE_ARRAY = 6;

/** `parquet.thrift` `FieldRepetitionType`. */
const REPETITION_OPTIONAL = 1;

/** `parquet.thrift` `ConvertedType.UTF8`. */
const CONVERTED_UTF8 = 0;

/** `parquet.thrift` `Encoding`. */
const ENCODING_PLAIN = 0;
const ENCODING_RLE = 3;

/** `parquet.thrift` `CompressionCodec.UNCOMPRESSED`. */
const CODEC_UNCOMPRESSED = 0;

/** `parquet.thrift` `PageType.DATA_PAGE`. */
const PAGE_TYPE_DATA = 0;

/** The magic at both ends of the file — how a reader recognises it at all. */
const MAGIC = UTF8.encode("PAR1");

// ---------------------------------------------------------------------------
// The public shape
// ---------------------------------------------------------------------------

/** The logical types one chargeback column can carry. */
export type ParquetColumnType = "string" | "int64" | "double" | "boolean";

export interface ParquetColumn {
  readonly name: string;
  readonly type: ParquetColumnType;
}

/** A cell: `null`/`undefined` both mean "not known", and are written as NULL. */
export type ParquetValue = string | number | bigint | boolean | null | undefined;

/** The root schema element's name — cosmetic, but readers surface it. */
const ROOT_NAME = "ferrogate_cost_record";

/** `created_by`, so an operator debugging a file knows what wrote it. */
const CREATED_BY = "ferrogate (apps/control-plane/src/export/parquet.ts)";

// ---------------------------------------------------------------------------
// Level and value encoding
// ---------------------------------------------------------------------------

/**
 * Definition levels for one column, RLE/bit-packed hybrid, bit width 1.
 *
 * Only RLE runs are emitted (never bit-packed groups): a chargeback column is
 * overwhelmingly all-present or all-absent, so runs are both the smaller and
 * the simpler encoding, and a reader must support them either way.
 *
 * The 4-byte little-endian length prefix is required by data page V1 and is
 * NOT part of the RLE stream itself — omitting it is the classic way to write
 * a file that every reader rejects at the first page.
 */
function encodeDefinitionLevels(present: readonly boolean[]): Uint8Array {
  const body = new ByteSink();
  let index = 0;
  while (index < present.length) {
    const value = present[index] === true;
    let run = 1;
    while (index + run < present.length && (present[index + run] === true) === value) run += 1;
    // RLE run header: the run length, shifted left one, with a 0 low bit.
    body.varint(run << 1);
    body.byte(value ? 1 : 0);
    index += run;
  }
  const out = new ByteSink();
  const bytes = body.toBytes();
  out.uint32LE(bytes.length);
  out.raw(bytes);
  return out.toBytes();
}

/** PLAIN-encode the PRESENT values of one column. Nulls occupy no bytes. */
function encodeValues(
  type: ParquetColumnType,
  values: readonly ParquetValue[],
  present: readonly boolean[],
): Uint8Array {
  const sink = new ByteSink();
  if (type === "boolean") {
    // PLAIN BOOLEAN is bit-packed, least-significant bit first, over the
    // non-null values only.
    let bit = 0;
    let byte = 0;
    for (let index = 0; index < values.length; index += 1) {
      if (present[index] !== true) continue;
      if (values[index] === true) byte |= 1 << bit;
      bit += 1;
      if (bit === 8) {
        sink.byte(byte);
        bit = 0;
        byte = 0;
      }
    }
    if (bit > 0) sink.byte(byte);
    return sink.toBytes();
  }

  for (let index = 0; index < values.length; index += 1) {
    if (present[index] !== true) continue;
    const value = values[index];
    if (type === "string") {
      const bytes = UTF8.encode(String(value));
      sink.uint32LE(bytes.length);
      sink.raw(bytes);
    } else if (type === "int64") {
      sink.int64LE(typeof value === "bigint" ? value : BigInt(Math.trunc(Number(value))));
    } else {
      sink.float64LE(Number(value));
    }
  }
  return sink.toBytes();
}

function physicalType(type: ParquetColumnType): number {
  switch (type) {
    case "string":
      return TYPE_BYTE_ARRAY;
    case "int64":
      return TYPE_INT64;
    case "double":
      return TYPE_DOUBLE;
    default:
      return TYPE_BOOLEAN;
  }
}

// ---------------------------------------------------------------------------
// The encoder
// ---------------------------------------------------------------------------

/** One column's page, plus everything its `ColumnMetaData` has to state. */
interface EncodedColumn {
  readonly column: ParquetColumn;
  /**
   * The chunk's byte length INCLUDING its page header.
   *
   * `total_uncompressed_size` is the size of the whole column chunk, not of the
   * page body — a reader that sequentially walks chunks by that figure would
   * land mid-header on every column after the first if this were the body
   * alone.
   */
  readonly totalLength: number;
  readonly offset: number;
  readonly numValues: number;
}

/**
 * Encode `rows` as a single-row-group Parquet file.
 *
 * A zero-row export produces a VALID file with the schema and no row groups,
 * not an empty body: a reader handed zero bytes reports a corrupt file, and an
 * operator whose filter matched nothing has to be able to tell "no spend" from
 * "the export broke".
 */
export function encodeParquet(
  columns: readonly ParquetColumn[],
  rows: readonly Readonly<Record<string, ParquetValue>>[],
): Uint8Array {
  const file = new ByteSink();
  file.raw(MAGIC);

  const encoded: EncodedColumn[] = [];
  for (const column of columns) {
    const values = rows.map((row) => row[column.name]);
    const present = values.map((value) => value !== null && value !== undefined);
    const levels = encodeDefinitionLevels(present);
    const payload = encodeValues(column.type, values, present);

    const pageBody = new ByteSink();
    pageBody.raw(levels);
    pageBody.raw(payload);
    const body = pageBody.toBytes();

    const offset = file.length;
    const header = new CompactWriter(file);
    header.structBegin();
    header.i32(1, PAGE_TYPE_DATA);
    header.i32(2, body.length); // uncompressed_page_size
    header.i32(3, body.length); // compressed_page_size — UNCOMPRESSED, so equal
    header.structField(5); // data_page_header
    header.i32(1, rows.length); // num_values INCLUDES the nulls
    header.i32(2, ENCODING_PLAIN);
    header.i32(3, ENCODING_RLE); // definition_level_encoding
    header.i32(4, ENCODING_RLE); // repetition_level_encoding (unused, still required)
    header.structEnd();
    header.structEnd();
    file.raw(body);

    encoded.push({ column, totalLength: file.length - offset, offset, numValues: rows.length });
  }

  const metadataStart = file.length;
  writeFileMetadata(file, columns, encoded, rows.length);
  const metadataLength = file.length - metadataStart;

  file.uint32LE(metadataLength);
  file.raw(MAGIC);
  return file.toBytes();
}

function writeFileMetadata(
  file: ByteSink,
  columns: readonly ParquetColumn[],
  encoded: readonly EncodedColumn[],
  numRows: number,
): void {
  const writer = new CompactWriter(file);
  writer.structBegin();

  // 1: version. `2` is the format version every current reader expects; the
  // PAGES are still V1, which is a separate choice and is stated per page.
  writer.i32(1, 2);

  // 2: schema — a depth-first flattening, root first.
  writer.listBegin(2, T_STRUCT, columns.length + 1);
  writer.structBegin();
  // The root carries no type and no repetition: it is the record, not a field.
  writer.string(4, ROOT_NAME);
  writer.i32(5, columns.length);
  writer.structEnd();
  for (const column of columns) {
    writer.structBegin();
    writer.i32(1, physicalType(column.type));
    writer.i32(3, REPETITION_OPTIONAL);
    writer.string(4, column.name);
    if (column.type === "string") {
      // UTF8, so a reader hands back a string rather than raw bytes.
      writer.i32(6, CONVERTED_UTF8);
    }
    writer.structEnd();
  }

  // 3: num_rows
  writer.i64(3, BigInt(numRows));

  // 4: row_groups — exactly one, or none for an empty export.
  const totalByteSize = encoded.reduce((sum, entry) => sum + entry.totalLength, 0);
  writer.listBegin(4, T_STRUCT, numRows === 0 ? 0 : 1);
  if (numRows > 0) {
    writer.structBegin();
    writer.listBegin(1, T_STRUCT, encoded.length);
    for (const entry of encoded) {
      // ColumnChunk
      writer.structBegin();
      writer.i64(2, BigInt(entry.offset)); // file_offset
      writer.structField(3); // meta_data
      writer.i32(1, physicalType(entry.column.type));
      writer.listBegin(2, T_I32, 2);
      writer.listI32(ENCODING_PLAIN);
      writer.listI32(ENCODING_RLE);
      writer.listBegin(3, T_BINARY, 1);
      writer.listString(entry.column.name); // path_in_schema — flat, one segment
      writer.i32(4, CODEC_UNCOMPRESSED);
      writer.i64(5, BigInt(entry.numValues));
      writer.i64(6, BigInt(entry.totalLength)); // total_uncompressed_size
      writer.i64(7, BigInt(entry.totalLength)); // total_compressed_size
      writer.i64(9, BigInt(entry.offset)); // data_page_offset
      writer.structEnd(); // meta_data
      writer.structEnd(); // ColumnChunk
    }
    writer.i64(2, BigInt(totalByteSize));
    writer.i64(3, BigInt(numRows));
    writer.structEnd(); // RowGroup
  }

  // 6: created_by
  writer.string(6, CREATED_BY);
  writer.structEnd();
}
