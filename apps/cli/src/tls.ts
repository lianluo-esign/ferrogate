/**
 * The transport's TLS policy: `--ca-bundle` and `--insecure-skip-tls-verify`.
 *
 * Clean-room port of `ferrogate-control-plane-client::transport::ReqwestTransport::new`
 * (inventory-edge-control.md §2.1). The Rust client builds a `reqwest::Client`
 * with `add_root_certificate` / `danger_accept_invalid_certs`; the shipped
 * `ferrogate` binary is a **Bun** binary, and Bun's `fetch` takes the equivalent
 * per-request `tls: { ca, rejectUnauthorized }` option, so the behaviour ports
 * 1:1 rather than becoming a platform limit.
 *
 * The contract this module exists to keep is the #188 one the Rust comment
 * names: **a TLS field that deserializes but never reaches the client is a
 * lie.** Both settings are either honoured or the command refuses — a context
 * that says `tls_insecure_skip_verify = true` must never quietly get full
 * verification, and a `ca_bundle_path` that cannot be read must never quietly
 * fall back to the system roots.
 */
import { CliError } from "./errors.js";
import type { RequestContext } from "./ports.js";

/** The `tls` option Bun's `fetch` accepts. Node's `fetch` ignores it entirely. */
export interface FetchTlsOptions {
  readonly ca?: string;
  readonly rejectUnauthorized?: boolean;
}

/** How the transport reads a CA bundle off disk (injected, so tests stay socket- and fs-free). */
export type CaBundleReader = (path: string) => Promise<string>;

/**
 * Whether this runtime's `fetch` honours a per-request `tls` option.
 *
 * Bun does (verified against a local self-signed TLS server: `rejectUnauthorized:
 * false` and `ca: <pem>` both connect where the default rejects). Node's `fetch`
 * is undici and silently drops unknown `RequestInit` keys, so under Node the
 * only honest answer is to refuse.
 */
export function runtimeHonorsFetchTls(): boolean {
  return typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";
}

const PEM_CERTIFICATE_BLOCK = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

/**
 * Structurally validate a PEM bundle, mirroring the Rust refusals.
 *
 * `reqwest::Certificate::from_pem_bundle` fails on a malformed bundle and the
 * Rust code then refuses again when the bundle parsed to zero certificates.
 * Both refusals are reproduced here from a PEM scan; the DER/X.509 validation
 * itself belongs to the runtime's TLS stack, which sees this same text.
 */
export function assertPemBundle(path: string, pem: string): void {
  const blocks = [...pem.matchAll(PEM_CERTIFICATE_BLOCK)];
  if (blocks.length === 0) {
    if (pem.includes("-----BEGIN CERTIFICATE-----")) {
      throw CliError.usage(
        `CA bundle '${path}' is not a valid PEM certificate bundle: a '-----BEGIN CERTIFICATE-----' block is never closed by a matching '-----END CERTIFICATE-----'`,
      );
    }
    throw CliError.usage(`CA bundle '${path}' contains no certificates`);
  }
  for (const [, body] of blocks) {
    const base64 = (body ?? "").replace(/\s+/g, "");
    if (base64 === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
      throw CliError.usage(
        `CA bundle '${path}' is not a valid PEM certificate bundle: a certificate block does not contain base64-encoded DER`,
      );
    }
  }
}

/**
 * Resolve one invocation's TLS policy into the `tls` option `fetch` receives,
 * or `undefined` when the context asked for the platform defaults.
 *
 * Memoised per client so an `--all-pages` walk reads the bundle once.
 */
export function createTlsPolicy(deps: {
  readonly readFile?: CaBundleReader;
  /** Overridable so a test can drive both the honoured and the refused branch. */
  readonly honorsFetchTls?: boolean;
}): (context: RequestContext) => Promise<FetchTlsOptions | undefined> {
  const cache = new Map<string, string>();
  const honors = deps.honorsFetchTls ?? runtimeHonorsFetchTls();

  return async (context) => {
    const wantsCaBundle = context.caBundlePath !== undefined;
    if (!context.tlsInsecureSkipVerify && !wantsCaBundle) return undefined;

    if (!honors) {
      // Refusing beats connecting under a TLS policy the operator did not ask
      // for — in EITHER direction. Skipping verification silently would be a
      // security lie; silently keeping it would strand an operator whose
      // private CA the system roots do not know, with an opaque handshake
      // error instead of this sentence.
      throw CliError.usage(
        `${
          context.tlsInsecureSkipVerify
            ? "tls_insecure_skip_verify"
            : `ca_bundle_path '${context.caBundlePath ?? ""}'`
        } cannot be honoured: this runtime's fetch() ignores per-request TLS options, so the connection would silently use a TLS policy you did not ask for. The shipped \`ferrogate\` binary is a Bun binary, whose fetch does honour them — run it under Bun (\`bun run ferrogate ...\`) rather than a plain Node host.`,
      );
    }

    let ca: string | undefined;
    if (context.caBundlePath !== undefined) {
      const path = context.caBundlePath;
      const cached = cache.get(path);
      if (cached !== undefined) {
        ca = cached;
      } else {
        if (deps.readFile === undefined) {
          throw CliError.usage(
            `cannot read CA bundle '${path}': this client was built without filesystem access`,
          );
        }
        let pem: string;
        try {
          pem = await deps.readFile(path);
        } catch (error) {
          throw CliError.usage(
            `failed to read CA bundle '${path}': ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
        assertPemBundle(path, pem);
        cache.set(path, pem);
        ca = pem;
      }
    }

    return {
      ...(ca === undefined ? {} : { ca }),
      ...(context.tlsInsecureSkipVerify ? { rejectUnauthorized: false } : {}),
    };
  };
}
