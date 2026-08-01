/**
 * The minimum DER reader needed to walk an X.509 `Certificate` to its
 * `SubjectPublicKeyInfo`.
 *
 * ## Why hand-rolled rather than a dependency
 *
 * The Rust port used `x509-parser`, a full X.509 implementation. On Workers
 * there is no built-in X.509 parse, and the obvious candidate (`@peculiar/x509`,
 * which `docs/legacy/inventory-edge-control.md` §5.4 names) pulls in
 * `@peculiar/asn1-schema` + `asn1js` + `pvtsutils` + `pvutils` — four packages,
 * ~200 KB, in the request path of the login endpoint of an auth service, to
 * extract ONE field.
 *
 * The field in question is reachable with ~120 lines of tag/length walking,
 * and — this is the part that matters — **nothing here is trusted**. The bytes
 * this parser reads are the TENANT'S OWN configured IdP certificate, admitted
 * at config time by a tenant owner; they are not attacker-controlled in the
 * way the assertion is. And the parser's OUTPUT is not trusted either: it is
 * handed straight to `crypto.subtle.importKey("spki", ...)`, which does its own
 * full structural validation and refuses anything malformed. A bug here can
 * therefore cause a REFUSAL (fail-closed) but cannot cause an ACCEPTANCE — the
 * signature check downstream is done by WebCrypto against a key WebCrypto
 * itself parsed.
 *
 * The reader is strict where strictness is free: indefinite lengths (legal BER,
 * illegal DER, and a classic parser-differential wedge) are refused, and every
 * length is bounds-checked against the buffer.
 */

export class DerError extends Error {}

export interface DerNode {
  /** The identifier octet (we never need multi-byte tags here). */
  readonly tag: number;
  /** Offset of the first content octet. */
  readonly contentStart: number;
  /** Offset one past the last content octet. */
  readonly contentEnd: number;
  /** Offset one past the whole TLV — where the next sibling begins. */
  readonly end: number;
  /** The whole TLV, header included, as a view over the original buffer. */
  readonly raw: Uint8Array;
  /** The content octets, as a view over the original buffer. */
  readonly content: Uint8Array;
}

/** Reads one TLV starting at `offset`. */
export function readTlv(bytes: Uint8Array, offset: number): DerNode {
  if (offset + 2 > bytes.length) {
    throw new DerError(`truncated TLV header at offset ${offset}`);
  }
  const tag = bytes[offset] as number;
  if ((tag & 0x1f) === 0x1f) {
    throw new DerError(`multi-byte tag at offset ${offset} is not supported`);
  }
  const first = bytes[offset + 1] as number;
  let length: number;
  let contentStart: number;
  if (first === 0x80) {
    throw new DerError(`indefinite length at offset ${offset} is BER, not DER`);
  }
  if (first < 0x80) {
    length = first;
    contentStart = offset + 2;
  } else {
    const lengthOfLength = first & 0x7f;
    if (lengthOfLength > 4) {
      throw new DerError(`length field of ${lengthOfLength} octets is implausible`);
    }
    if (offset + 2 + lengthOfLength > bytes.length) {
      throw new DerError(`truncated long-form length at offset ${offset}`);
    }
    length = 0;
    for (let index = 0; index < lengthOfLength; index += 1) {
      length = length * 256 + (bytes[offset + 2 + index] as number);
    }
    contentStart = offset + 2 + lengthOfLength;
  }
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) {
    throw new DerError(
      `TLV at offset ${offset} claims ${length} content octets but only ` +
        `${bytes.length - contentStart} remain`,
    );
  }
  return {
    tag,
    contentStart,
    contentEnd,
    end: contentEnd,
    raw: bytes.subarray(offset, contentEnd),
    content: bytes.subarray(contentStart, contentEnd),
  };
}

/** Reads every direct child of a constructed node's content. */
export function readChildren(node: DerNode, bytes: Uint8Array): DerNode[] {
  const children: DerNode[] = [];
  let offset = node.contentStart;
  while (offset < node.contentEnd) {
    const child = readTlv(bytes, offset);
    if (child.end <= offset) throw new DerError("zero-length TLV would not terminate");
    if (child.end > node.contentEnd) {
      throw new DerError("child TLV overruns its parent");
    }
    children.push(child);
    offset = child.end;
  }
  return children;
}

export const TAG_SEQUENCE = 0x30;
export const TAG_OID = 0x06;
export const TAG_BIT_STRING = 0x03;

export function expectTag(node: DerNode, tag: number, what: string): DerNode {
  if (node.tag !== tag) {
    throw new DerError(
      `expected ${what} to have tag 0x${tag.toString(16)}, found 0x${node.tag.toString(16)}`,
    );
  }
  return node;
}

/** Renders an OBJECT IDENTIFIER's content octets as dotted decimal. */
export function decodeOid(content: Uint8Array): string {
  if (content.length === 0) throw new DerError("empty OBJECT IDENTIFIER");
  const first = content[0] as number;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let index = 1; index < content.length; index += 1) {
    const byte = content[index] as number;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new DerError("OBJECT IDENTIFIER ends mid-arc");
  return parts.join(".");
}
