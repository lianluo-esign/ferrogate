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

// --- listen addresses -------------------------------------------------------

/**
 * `normalize_listen_addr`: a `SocketAddr`, with `localhost:<port>` rewritten to
 * `127.0.0.1:<port>` first (the Rust helper's one extra spelling).
 */
export function isValidSocketAddr(value: string): boolean {
  let v = value;
  if (v.startsWith("localhost:")) v = `127.0.0.1:${v.slice("localhost:".length)}`;
  const lastColon = v.lastIndexOf(":");
  if (lastColon === -1) return false;
  const host = v.slice(0, lastColon);
  const portStr = v.slice(lastColon + 1);
  if (!/^\d+$/.test(portStr)) return false;
  const port = Number.parseInt(portStr, 10);
  if (port > 65535) return false;
  return host.length > 0;
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
