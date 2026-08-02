/**
 * Shared primitives for the `Config::validate()` port (inventory §5.4). These
 * are the free functions at the bottom of the Rust `config/validate.rs`
 * (`validate_headers`, `validate_postgres_identifier`, `version_parts`,
 * `validate_extension_permission_names`, the prompt-placeholder scanner, ...),
 * ported 1:1 so every caller produces the exact Rust `field <path>: <reason>`
 * text.
 */
import { parseSecretRef } from "@ferrogate/secrets";

/** Throw the Rust `bail!("field {field}: {reason}")` shape. */
export function fail(field: string, reason: string): never {
  throw new Error(`field ${field}: ${reason}`);
}

/** `str::trim().is_empty()`. */
export function isBlank(value: string): boolean {
  return value.trim().length === 0;
}

/** `Option<String>::as_deref().is_some_and(str::is_empty)` — set but the empty string. */
export function isSetAndEmpty(value: string | null | undefined): boolean {
  return value !== null && value !== undefined && value.length === 0;
}

/** `Option<String>::as_deref().is_some_and(|v| v.trim().is_empty())` — set but blank. */
export function isSetAndBlank(value: string | null | undefined): boolean {
  return value !== null && value !== undefined && value.trim().length === 0;
}

/** `Option<String>::as_deref().is_some_and(|v| !v.trim().is_empty())` — set and non-blank. */
export function isSetAndPresent(value: string | null | undefined): boolean {
  return value !== null && value !== undefined && value.trim().length > 0;
}

/** `validate_positive_optional_u32` / `validate_positive_optional_u64` (one shape, two Rust widths). */
export function validatePositiveOptional(value: number | null | undefined, field: string): void {
  if (value === 0) throw new Error(`${field}: must be greater than zero`);
}

/**
 * `SecretRef::parse` (`ferrogate_secrets`), attributed to `field`. Delegates to
 * `@ferrogate/secrets` so config-load validity and runtime resolvability are one
 * definition, exactly as the Rust crate does.
 */
export function validateSecretRef(field: string, reference: string): void {
  try {
    parseSecretRef(reference);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : String(error));
  }
}

// --- header names/values (Rust `http::HeaderName` / `http::HeaderValue`) -----

/**
 * `HeaderName::from_bytes`: a non-empty RFC 7230 token. (Rust lowercases on the
 * way in; uppercase input is accepted, so this accepts it too.)
 */
export function isValidHeaderName(name: string): boolean {
  if (name.length === 0) return false;
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name);
}

/**
 * `HeaderValue::from_str`: visible ASCII (0x20..=0x7E) or horizontal tab. The
 * empty value is legal; NUL/CR/LF and any byte >= 0x80 are not.
 */
export function isValidHeaderValue(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const visible = code >= 0x20 && code <= 0x7e;
    if (!visible && code !== 0x09) return false;
  }
  return true;
}

/** `validate_headers::<T: HeaderLike>` — route header matchers/mutations. */
export function validateHeaders(
  routeIndex: number,
  field: string,
  headers: { name: string; value: string }[],
): void {
  for (let index = 0; index < headers.length; index += 1) {
    const header = headers[index]!;
    if (!isValidHeaderName(header.name)) {
      fail(`routes[${routeIndex}].${field}[${index}].name`, "invalid header name");
    }
    if (!isValidHeaderValue(header.value)) {
      fail(`routes[${routeIndex}].${field}[${index}].value`, "invalid header value");
    }
  }
}

// --- postgres identifiers ---------------------------------------------------

/** `validate_postgres_identifier`: unquoted-identifier shape, no injection surface. */
export function validatePostgresIdentifier(field: string, rawValue: string): void {
  const value = rawValue.trim();
  if (value.length === 0) fail(field, "must not be empty");
  const first = value[0]!;
  if (!(first === "_" || /^[A-Za-z]$/.test(first))) {
    fail(field, "must start with an ASCII letter or underscore");
  }
  for (const character of value.slice(1)) {
    if (!(character === "_" || /^[0-9A-Za-z]$/.test(character))) {
      fail(field, "must contain only ASCII letters, digits, or underscores");
    }
  }
}

// --- extension/plugin permission + manifest names ---------------------------

/** `validate_extension_permission_names`: non-empty and unique. */
export function validateExtensionPermissionNames(
  section: string,
  extensionIndex: number,
  field: string,
  names: string[],
): void {
  const seen = new Set<string>();
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index]!;
    if (isBlank(name)) fail(`${section}[${extensionIndex}].${field}[${index}]`, "cannot be empty");
    if (seen.has(name)) {
      fail(`${section}[${extensionIndex}].${field}[${index}]`, `duplicate permission value ${name}`);
    }
    seen.add(name);
  }
}

/** `is_plugin_manifest_name`. */
export function isPluginManifestName(name: string): boolean {
  return !isBlank(name) && /^[0-9A-Za-z._:\-]+$/.test(name);
}

/** `validate_plugin_manifest_names`: charset-restricted and unique. */
export function validatePluginManifestNames(
  section: string,
  extensionIndex: number,
  field: string,
  names: string[],
): void {
  const seen = new Set<string>();
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index]!;
    if (!isPluginManifestName(name)) {
      fail(
        `${section}[${extensionIndex}].${field}[${index}]`,
        "must contain only letters, numbers, dot, underscore, colon, or dash",
      );
    }
    if (seen.has(name)) {
      fail(`${section}[${extensionIndex}].${field}[${index}]`, `duplicate value ${name}`);
    }
    seen.add(name);
  }
}

// --- plugin versions --------------------------------------------------------

/**
 * `version_parts`: `[v]major.minor.patch`, exactly three unsigned parts.
 * (Rust `trim_start_matches('v')` strips EVERY leading `v`.)
 */
export function versionParts(value: string): [number, number, number] | null {
  const parts = value.replace(/^v+/, "").split(".");
  if (parts.length !== 3) return null;
  const numbers: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    numbers.push(Number.parseInt(part, 10));
  }
  return [numbers[0]!, numbers[1]!, numbers[2]!];
}

/** `compare_version_parts`: unparsable sorts as `0.0.0`, then lexicographic. */
export function compareVersionParts(left: string, right: string): number {
  const a = versionParts(left) ?? [0, 0, 0];
  const b = versionParts(right) ?? [0, 0, 0];
  for (let index = 0; index < 3; index += 1) {
    if (a[index]! !== b[index]!) return a[index]! < b[index]! ? -1 : 1;
  }
  return 0;
}

/** `validate_plugin_version`. */
export function validatePluginVersion(
  section: string,
  extensionIndex: number,
  field: string,
  value: string,
): void {
  if (versionParts(value) === null) {
    fail(`${section}[${extensionIndex}].${field}`, "must be a semantic version");
  }
}

/** `validate_optional_plugin_version`. */
export function validateOptionalPluginVersion(
  section: string,
  extensionIndex: number,
  field: string,
  value: string | null,
): void {
  if (value !== null) validatePluginVersion(section, extensionIndex, field, value);
}

// --- prompt templates -------------------------------------------------------

/** `is_prompt_variable_name`. */
export function isPromptVariableName(name: string): boolean {
  return name.length > 0 && /^[0-9A-Za-z_\-]+$/.test(name);
}

/** `validate_prompt_message_role`. */
export function validatePromptMessageRole(
  templateIndex: number,
  versionIndex: number,
  messageIndex: number,
  role: string,
): void {
  if (!["system", "developer", "user", "assistant", "tool"].includes(role)) {
    fail(
      `prompt_templates[${templateIndex}].versions[${versionIndex}].messages[${messageIndex}].role`,
      "must be system, developer, user, assistant, or tool",
    );
  }
}

/** `validate_prompt_placeholders`: every `{{name}}` closes, is well-formed, and is declared. */
export function validatePromptPlaceholders(
  templateIndex: number,
  versionIndex: number,
  messageIndex: number,
  content: string,
  variableNames: Set<string>,
): void {
  const field = `prompt_templates[${templateIndex}].versions[${versionIndex}].messages[${messageIndex}].content`;
  let cursor = 0;
  for (;;) {
    const start = content.slice(cursor).indexOf("{{");
    if (start === -1) return;
    const placeholderStart = cursor + start + 2;
    const end = content.slice(placeholderStart).indexOf("}}");
    if (end === -1) fail(field, "unclosed prompt variable");
    const placeholderEnd = placeholderStart + end;
    const name = content.slice(placeholderStart, placeholderEnd).trim();
    if (!isPromptVariableName(name)) fail(field, `invalid prompt variable name ${name}`);
    if (!variableNames.has(name)) fail(field, `unknown prompt variable ${name}`);
    cursor = placeholderEnd + 2;
  }
}

// --- guardrail regex engine parity ------------------------------------------

/**
 * `regex::Regex::new(pattern)` accept-set parity for the two constructs where
 * the Rust `regex` crate is STRICTLY stricter than JS `RegExp`.
 *
 * The Rust crate is a finite-automaton engine with linear-time guarantees, so it
 * REFUSES the two backtracking-only constructs that JS accepts:
 *
 *   - backreferences — `\1`..`\9` and `\k<name>`
 *   - lookaround — `(?=`, `(?!`, `(?<=`, `(?<!`
 *
 * Without this check a `[[guardrails]]` block that Rust refuses at load would be
 * accepted here and then run with entirely different match semantics, i.e. a
 * detector that silently stops detecting. Rust's message is
 * `regex::Regex::new(..).with_context(|| "... invalid regex")` and anyhow's
 * `Display` renders only the OUTERMOST context, so every rejection reason —
 * these two included — is observable as exactly `invalid regex`.
 *
 * Scanned rather than pattern-matched because the constructs are only special in
 * some positions: `\\1` is an escaped backslash then a literal `1`, `[(?=]` is a
 * character class of literals, and `(?<name>` is a NAMED GROUP the `regex` crate
 * does support (only `(?<=` / `(?<!` are lookbehind).
 *
 * RESIDUAL GAP (deliberately not papered over): the other direction — patterns
 * the `regex` crate accepts but JS `RegExp` rejects (`\p{Greek}` without the `u`
 * flag, `(?P<name>...)`) — fails CLOSED here as `invalid regex`, so it can never
 * admit a rule the Rust engine would have matched differently.
 */
export function usesRegexCrateUnsupportedSyntax(pattern: string): boolean {
  let inClass = false;
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]!;
    if (char === "\\") {
      const next = pattern[index + 1];
      if (next === undefined) return false; // trailing `\` — `new RegExp` rejects it anyway
      if (!inClass && next >= "1" && next <= "9") return true; // \1..\9 backreference
      if (!inClass && next === "k" && pattern[index + 2] === "<") return true; // \k<name>
      index += 1; // consume the escaped character
      continue;
    }
    if (inClass) {
      if (char === "]") inClass = false;
      continue;
    }
    if (char === "[") {
      inClass = true;
      continue;
    }
    if (char === "(" && pattern[index + 1] === "?") {
      const third = pattern[index + 2];
      if (third === "=" || third === "!") return true; // (?= (?!
      const fourth = pattern[index + 3];
      if (third === "<" && (fourth === "=" || fourth === "!")) return true; // (?<= (?<!
    }
  }
  return false;
}

// --- listen addresses -------------------------------------------------------

/**
 * Rust `Ipv4Addr::from_str`: exactly four dot-separated decimal octets, each
 * 1–3 digits, value <= 255, and **no leading zeros** (`127.0.0.01` is REFUSED
 * by std, deliberately, so an octal-looking octet can never be misread).
 */
function isIpv4Literal(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (part.length === 0 || part.length > 3) return false;
    if (!/^\d+$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    if (Number.parseInt(part, 10) > 255) return false;
  }
  return true;
}

/**
 * Rust `Ipv6Addr::from_str`: up to eight groups of 1–4 hex digits, at most one
 * `::` elision, optionally ending in a dotted-quad that occupies the last two
 * groups. std's parser accepts **no** zone/scope id (`%eth0`), so neither does
 * this.
 */
function isIpv6Literal(value: string): boolean {
  if (value.includes("%")) return false;
  const elisions = value.split("::").length - 1;
  if (elisions > 1) return false;

  const readGroups = (text: string): number | null => {
    // Returns the number of 16-bit groups the text occupies, or null if invalid.
    if (text.length === 0) return 0;
    const pieces = text.split(":");
    let groups = 0;
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index]!;
      if (index === pieces.length - 1 && piece.includes(".")) {
        if (!isIpv4Literal(piece)) return null;
        groups += 2; // an embedded IPv4 fills the low 32 bits
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      groups += 1;
    }
    return groups;
  };

  if (elisions === 1) {
    const at = value.indexOf("::");
    const head = readGroups(value.slice(0, at));
    const tail = readGroups(value.slice(at + 2));
    if (head === null || tail === null) return false;
    // `::` must stand for AT LEAST one elided group.
    return head + tail <= 7;
  }
  return readGroups(value) === 8;
}

/**
 * `normalize_listen_addr`: a `SocketAddr`, with `localhost:<port>` rewritten to
 * `127.0.0.1:<port>` first (the Rust helper's one extra spelling).
 *
 * The HOST HALF IS AN IP LITERAL, NOT A NAME. `std::net::SocketAddr`'s
 * `FromStr` parses an address, never a hostname — it performs no resolution —
 * so Rust REFUSES `example.com:8080`, `999.1.1.1:80` and an unbracketed
 * `::1:8080`, and accepts an IPv6 address only in brackets (`[::1]:8080`). This
 * used to accept any non-empty host, which let a config Rust rejects at load
 * time load here instead: an operator who wrote a DNS name for a bind address
 * got silence rather than the Rust diagnostic. Pinned by
 * `validate-sections.test.ts` > "listen addresses are IP literals".
 */
export function isValidSocketAddr(value: string): boolean {
  let v = value;
  if (v.startsWith("localhost:")) v = `127.0.0.1:${v.slice("localhost:".length)}`;
  const lastColon = v.lastIndexOf(":");
  if (lastColon === -1) return false;
  const host = v.slice(0, lastColon);
  const portStr = v.slice(lastColon + 1);
  // Rust's port scanner reads at most five decimal digits and then demands
  // end-of-input, so `:000080` is refused while `:00080` is 80.
  if (!/^\d{1,5}$/.test(portStr)) return false;
  if (Number.parseInt(portStr, 10) > 65535) return false;
  if (host.startsWith("[") && host.endsWith("]")) {
    return isIpv6Literal(host.slice(1, -1));
  }
  return isIpv4Literal(host);
}

// --- misc -------------------------------------------------------------------

/** `url.starts_with("http://") || url.starts_with("https://")`. */
export function hasHttpScheme(url: string): boolean {
  return url.startsWith("http://") || url.startsWith("https://");
}

/**
 * `ferrogate_observability::endpoint_protects_credentials` (issue #520).
 *
 * Inlined rather than imported: `@ferrogate/observability` does not re-export it
 * from its package root, and the Rust `ferrogate-config` dependency edge is on
 * the function, not the exporter. Ported verbatim from
 * `crates/ferrogate-observability/src/cloudflare.rs`.
 */
export function endpointProtectsCredentials(rawEndpoint: string): boolean {
  const endpoint = rawEndpoint.trim();
  if (endpoint.startsWith("https://")) return true;
  if (!endpoint.startsWith("http://")) return false;
  const rest = endpoint.slice("http://".length);
  const authorityEnd = rest.search(/[/?#]/);
  let authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd);
  const at = authority.lastIndexOf("@");
  if (at !== -1) authority = authority.slice(at + 1);
  let host: string;
  if (authority.startsWith("[")) {
    host = authority.slice(1).split("]")[0] ?? "";
  } else {
    host = authority.split(":")[0] ?? "";
  }
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}
