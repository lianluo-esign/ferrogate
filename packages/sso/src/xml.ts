/**
 * A minimal, strict, streaming XML scanner — the `quick-xml` stand-in.
 *
 * Workers offer no XML parser: there is no `DOMParser`, and `HTMLRewriter` is
 * an HTML parser (it lower-cases names, applies HTML's error recovery, and has
 * no notion of a mismatched tag being an error) — using it on a security
 * document would be a parser-differential waiting to happen.
 *
 * This scanner is STRICTER than quick-xml in three ways, all fail-closed:
 *
 *  1. **`<!DOCTYPE` is refused outright.** That kills XXE and entity-expansion
 *     ("billion laughs") at the door, rather than relying on a parser flag.
 *  2. **Unknown entity references are refused** rather than passed through as
 *     literal text. A parser that leaves `&whatever;` in place lets an IdP —
 *     or an attacker who can influence one attribute — smuggle a value that
 *     looks different to us than it did to whoever reviewed it.
 *  3. **Element nesting is checked.** An end tag that does not match the open
 *     element is an error, not a silently-popped stack.
 *
 * It is namespace-AGNOSTIC on purpose: only local names are matched, mirroring
 * the Rust port's `local_name()` calls. Real IdPs use every prefix under the
 * sun (`samlp:`, `saml2p:`, `ns0:`, none at all), so matching a prefixed name
 * would reject valid responses.
 *
 * The scanner never recurses, so a deeply-nested document costs stack depth 0.
 */

export class XmlError extends Error {}

export interface XmlAttribute {
  /** The attribute's local name (prefix stripped). */
  readonly name: string;
  readonly value: string;
}

export type XmlEvent =
  | { readonly kind: "start"; readonly name: string; readonly attributes: XmlAttribute[] }
  | { readonly kind: "empty"; readonly name: string; readonly attributes: XmlAttribute[] }
  | { readonly kind: "end"; readonly name: string }
  | { readonly kind: "text"; readonly value: string };

const NAME_START = /[A-Za-z_:]/;
const NAME_CHAR = /[A-Za-z0-9_:.\-]/;

export function localName(qualified: string): string {
  const colon = qualified.lastIndexOf(":");
  return colon < 0 ? qualified : qualified.slice(colon + 1);
}

function unescapeXmlText(raw: string): string {
  if (!raw.includes("&")) return raw;
  let out = "";
  let index = 0;
  while (index < raw.length) {
    const ch = raw[index] as string;
    if (ch !== "&") {
      out += ch;
      index += 1;
      continue;
    }
    const end = raw.indexOf(";", index + 1);
    if (end < 0 || end === index + 1) {
      throw new XmlError(`unterminated entity reference at offset ${index}`);
    }
    const entity = raw.slice(index + 1, end);
    switch (entity) {
      case "amp":
        out += "&";
        break;
      case "lt":
        out += "<";
        break;
      case "gt":
        out += ">";
        break;
      case "quot":
        out += '"';
        break;
      case "apos":
        out += "'";
        break;
      default: {
        if (/^#[0-9]+$/.test(entity)) {
          out += String.fromCodePoint(Number(entity.slice(1)));
        } else if (/^#x[0-9A-Fa-f]+$/.test(entity)) {
          out += String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
        } else {
          // Fail closed: an undeclared entity is either a document we cannot
          // faithfully read or an expansion attempt.
          throw new XmlError(`unknown entity reference &${entity};`);
        }
      }
    }
    index = end + 1;
  }
  return out;
}

/** Scans `text`, invoking `onEvent` for each event. Throws `XmlError` on any malformity. */
export function scanXml(text: string, onEvent: (event: XmlEvent) => void): void {
  const stack: string[] = [];
  let index = 0;
  const length = text.length;

  const fail = (message: string): never => {
    throw new XmlError(`${message} at offset ${index}`);
  };

  while (index < length) {
    if (text[index] !== "<") {
      const next = text.indexOf("<", index);
      const raw = next < 0 ? text.slice(index) : text.slice(index, next);
      const value = unescapeXmlText(raw).trim();
      if (value.length > 0) onEvent({ kind: "text", value });
      if (next < 0) break;
      index = next;
      continue;
    }

    // `<!...` — comment, CDATA, or a DOCTYPE we refuse.
    if (text.startsWith("<!--", index)) {
      const end = text.indexOf("-->", index + 4);
      if (end < 0) fail("unterminated comment");
      index = end + 3;
      continue;
    }
    if (text.startsWith("<![CDATA[", index)) {
      const end = text.indexOf("]]>", index + 9);
      if (end < 0) fail("unterminated CDATA section");
      const value = text.slice(index + 9, end).trim();
      if (value.length > 0) onEvent({ kind: "text", value });
      index = end + 3;
      continue;
    }
    if (text.startsWith("<!DOCTYPE", index) || text.startsWith("<!doctype", index)) {
      throw new XmlError(
        "a DOCTYPE declaration is not permitted in a SAML document (XXE / entity-expansion guard)",
      );
    }
    if (text.startsWith("<!", index)) fail("unsupported declaration");
    if (text.startsWith("<?", index)) {
      const end = text.indexOf("?>", index + 2);
      if (end < 0) fail("unterminated processing instruction");
      index = end + 2;
      continue;
    }

    // `</name>`
    if (text.startsWith("</", index)) {
      let cursor = index + 2;
      const nameStart = cursor;
      while (cursor < length && NAME_CHAR.test(text[cursor] as string)) cursor += 1;
      if (cursor === nameStart) fail("end tag with no name");
      const name = localName(text.slice(nameStart, cursor));
      while (cursor < length && /\s/.test(text[cursor] as string)) cursor += 1;
      if (text[cursor] !== ">") fail("malformed end tag");
      const open = stack.pop();
      if (open === undefined) fail(`end tag </${name}> with no open element`);
      if (open !== name) fail(`end tag </${name}> does not close <${open}>`);
      onEvent({ kind: "end", name });
      index = cursor + 1;
      continue;
    }

    // `<name attr="value" ...>` or `<name .../>`
    let cursor = index + 1;
    if (cursor >= length || !NAME_START.test(text[cursor] as string)) fail("malformed start tag");
    const nameStart = cursor;
    while (cursor < length && NAME_CHAR.test(text[cursor] as string)) cursor += 1;
    const name = localName(text.slice(nameStart, cursor));

    const attributes: XmlAttribute[] = [];
    for (;;) {
      while (cursor < length && /\s/.test(text[cursor] as string)) cursor += 1;
      if (cursor >= length) fail("unterminated start tag");
      const ch = text[cursor] as string;
      if (ch === ">") {
        stack.push(name);
        onEvent({ kind: "start", name, attributes });
        cursor += 1;
        break;
      }
      if (ch === "/") {
        if (text[cursor + 1] !== ">") fail("malformed self-closing tag");
        onEvent({ kind: "empty", name, attributes });
        cursor += 2;
        break;
      }
      if (!NAME_START.test(ch)) fail("malformed attribute name");
      const attrStart = cursor;
      while (cursor < length && NAME_CHAR.test(text[cursor] as string)) cursor += 1;
      const attrName = localName(text.slice(attrStart, cursor));
      while (cursor < length && /\s/.test(text[cursor] as string)) cursor += 1;
      if (text[cursor] !== "=") fail(`attribute ${attrName} has no value`);
      cursor += 1;
      while (cursor < length && /\s/.test(text[cursor] as string)) cursor += 1;
      const quote = text[cursor];
      if (quote === undefined || (quote !== '"' && quote !== "'")) {
        fail(`attribute ${attrName} value is not quoted`);
      }
      const valueStart = cursor + 1;
      const valueEnd = text.indexOf(quote as string, valueStart);
      if (valueEnd < 0) fail(`attribute ${attrName} value is unterminated`);
      attributes.push({ name: attrName, value: unescapeXmlText(text.slice(valueStart, valueEnd)) });
      cursor = valueEnd + 1;
    }
    index = cursor;
  }

  if (stack.length > 0) {
    throw new XmlError(`document ended with <${stack[stack.length - 1]}> still open`);
  }
}
