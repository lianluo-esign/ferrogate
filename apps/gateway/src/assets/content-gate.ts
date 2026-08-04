/**
 * Gate 1 of the asset publish screening — the per-`asset_type` content-type
 * allowlist and the `mcp_manifest` **stdio refusal**.
 *
 * Port of `crates/ferrogate-gateway/src/server/asset_security.rs`
 * (`validate_asset_content`, `validate_streamed_asset_content`,
 * `content_type_allowed`, `mcp_manifest_transport` — issues #179 / #259 / #261).
 *
 * ## Why this file exists (data-plane certification finding D4/D5 → D5)
 *
 * `screen_asset_push` runs THREE gates and the rewrite ported the second and
 * third — detached signature (`signature-screener.ts`) and malware scan
 * (`scan.ts`) — while dropping the FIRST, which is the cheap synchronous one:
 * a pure function of two strings and a byte buffer, no binding, no I/O, no
 * platform limit. Its absence was live and tenant-exploitable:
 *
 *  - any byte stream was publishable under any `asset_type`, and
 *  - **a tenant could publish an `mcp_manifest` declaring `"transport":
 *    "stdio"`.** That is the serious one. FerroGate is a distribution point:
 *    the manifest is fetched by a DIFFERENT tenant's agent, whose MCP client
 *    reads `transport` and, for `stdio`, spawns the declared local process.
 *    Publishing one is therefore remote code execution on the consumer, and it
 *    is refused at publish because that is the only place FerroGate controls.
 *
 * ## Where the gate is enforced, and why it is not a screener
 *
 * `AssetService` calls {@link assetContentRejection} DIRECTLY, ahead of
 * `AssetScreener.screen`, on both write paths (`putAsset` and `commitUpload`) —
 * the same position and the same order Rust uses inside `screen_asset_push`.
 *
 * It is deliberately NOT implemented as an `AssetScreener` decorator. The
 * screener is a configurable seam (`assetScreenerFromEnv`, publisher-key
 * policy, test doubles), and a security control reachable through a
 * configurable seam is a control an operator's misconfiguration — or a test
 * double — can switch off. `test/assets/content-gate.test.ts` pins that with a
 * screener that admits everything and is never even consulted for a gate-1
 * refusal.
 */

/** The Rust `ScreeningRejection { code: "asset_rejected" }` HTTP status. */
export const ASSET_REJECTED_STATUS = 422;
/** The Rust `ScreeningRejection.code` for every gate-1 refusal. */
export const ASSET_REJECTED_CODE = "asset_rejected";

/**
 * `asset_security.rs::content_type_allowed` (line 107), transcribed exactly —
 * same asset types, same members, same order.
 *
 * An `asset_type` NOT named here is unrestricted, which is the Rust `_ => true`
 * arm: no allowlist is defined for it, so it is not blocked on content-type
 * alone. The EICAR and `mcp_manifest` checks still apply independently.
 */
export const ASSET_CONTENT_TYPE_ALLOWLIST: Readonly<Record<string, readonly string[]>> = {
  cli_tool: [
    "text/plain",
    "application/x-sh",
    "application/x-shellscript",
    "application/octet-stream",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-gtar",
  ],
  // ONE entry. A manifest is a JSON document and nothing else; widening this
  // list is how the stdio gate below gets bypassed by a content-type the
  // transport parser never sees.
  mcp_manifest: ["application/json"],
  skill_bundle: [
    "text/plain",
    "text/markdown",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/octet-stream",
  ],
  static_site: [
    "text/html",
    "text/css",
    "text/plain",
    "text/markdown",
    "application/javascript",
    "application/json",
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "image/x-icon",
    "application/zip",
    "application/gzip",
    "application/x-tar",
  ],
  config_file: [
    "application/json",
    "text/plain",
    "application/x-yaml",
    "text/yaml",
    "application/toml",
  ],
};

/** The `asset_type` whose declared transport is a code-execution vector. */
export const MCP_MANIFEST_ASSET_TYPE = "mcp_manifest";

/** Rust: the stdio refusal message, verbatim (`asset_security.rs:58-63`). */
export const MCP_MANIFEST_STDIO_MESSAGE =
  "mcp_manifest assets with a stdio transport are not allowed: a stdio manifest causes the " +
  "consuming agent's MCP client to spawn an arbitrary local process";

/** Rust: the EICAR refusal message, verbatim (`asset_security.rs:52`). */
export const MALWARE_SIGNATURE_MESSAGE = "content matched a known malware test signature";

/** The byte signature the bounded streamed gate can detect across chunks. */
export const EICAR_SIGNATURE =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/** Rust: the unbufferable-manifest refusal, verbatim (`asset_security.rs:93-100`). */
export const MCP_MANIFEST_UNBUFFERABLE_MESSAGE =
  "mcp_manifest assets larger than the gateway's in-memory screening budget " +
  "([asset_bucket].max_gateway_buffer_bytes) are not allowed: the declared transport can only " +
  "be checked by parsing the whole manifest, and an unchecked stdio manifest causes the " +
  "consuming agent's MCP client to spawn an arbitrary local process";

/** Rust: the content-type refusal message, verbatim (`asset_security.rs:48-50`). */
export function contentTypeRejectionMessage(assetType: string, contentType: string): string {
  return `content-type ${contentType} is not allowed for asset_type ${assetType}`;
}

/**
 * `content_type_allowed` — is `contentType` admissible for `assetType`?
 *
 * Only the BASE type is compared: Rust splits on `;`, takes the head and trims,
 * so `application/json; charset=utf-8` is `application/json`. That also means a
 * parameter cannot be used to smuggle an allowed token past a disallowed base
 * type (`text/html; x=application/json` is `text/html`, and refused).
 */
export function contentTypeAllowed(assetType: string, contentType: string): boolean {
  const allowed = ASSET_CONTENT_TYPE_ALLOWLIST[assetType];
  if (allowed === undefined) return true;
  const baseType = (contentType.split(";")[0] ?? contentType).trim();
  return allowed.includes(baseType);
}

/**
 * `mcp_manifest_transport` — best-effort read of a manifest's declared
 * transport (`{"transport": "stdio" | "http" | "sse", …}`).
 *
 * `undefined` (not "blocked") when the content is not JSON, is not an object,
 * or carries no STRING `transport` field — the same three `None` cases the Rust
 * `serde_json` chain produces. A manifest with no declared transport is not a
 * spawn vector; refusing it would break every legitimate publish.
 */
export function mcpManifestTransport(content: Uint8Array): string | undefined {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(content);
  } catch {
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null) return undefined;
  const transport = (value as Record<string, unknown>).transport;
  return typeof transport === "string" ? transport : undefined;
}

/**
 * `validate_asset_content` — the buffered gate, in the Rust's order.
 *
 * Returns the refusal MESSAGE when the push must be refused, or `undefined`
 * when it may proceed. The order is load-bearing and asserted: content-type
 * first, then the malware signature, then (for `mcp_manifest` only) the
 * transport — so a stdio manifest pushed under a disallowed content-type
 * reports the content-type refusal, exactly as Rust does.
 *
 * The EICAR arm is NOT run here: this tree's `BuiltinEicarScreener` /
 * `ScannerBackedScreener` own the malware verdict (and the builtin
 * deliberately QUARANTINES rather than refuses — see `scan.ts`). Duplicating it
 * here would silently override that posture. {@link MALWARE_SIGNATURE_MESSAGE}
 * is exported for the streamed arm, which has no scanner to defer to.
 */
export function assetContentRejection(
  assetType: string,
  contentType: string,
  content: Uint8Array,
): string | undefined {
  if (!contentTypeAllowed(assetType, contentType)) {
    return contentTypeRejectionMessage(assetType, contentType);
  }
  if (assetType === MCP_MANIFEST_ASSET_TYPE) {
    const transport = mcpManifestTransport(content);
    // `eq_ignore_ascii_case`: `STDIO` is the same spawn vector as `stdio`.
    if (transport !== undefined && transport.toLowerCase() === "stdio") {
      return MCP_MANIFEST_STDIO_MESSAGE;
    }
  }
  return undefined;
}

/**
 * `validate_streamed_asset_content` (issue #259) — the gate for an object the
 * gateway verified byte-by-byte without ever holding it.
 *
 * Two of the three rules answer identically from streamed evidence. The third
 * does not, and the Rust's resolution is the important one: an `mcp_manifest`
 * too large to parse is REJECTED rather than admitted with its most dangerous
 * field unread. The stdio check must not become optional above a size
 * threshold, because "too big to check" is exactly the shape an attacker would
 * pad a manifest into.
 *
 * Reachable today only through a future streamed-commit path; exported and
 * pinned now so that path cannot land without it.
 */
export function streamedAssetContentRejection(
  assetType: string,
  contentType: string,
  eicarFound: boolean,
): string | undefined {
  if (!contentTypeAllowed(assetType, contentType)) {
    return contentTypeRejectionMessage(assetType, contentType);
  }
  if (eicarFound) return MALWARE_SIGNATURE_MESSAGE;
  if (assetType === MCP_MANIFEST_ASSET_TYPE) return MCP_MANIFEST_UNBUFFERABLE_MESSAGE;
  return undefined;
}
