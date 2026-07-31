/**
 * Minimal, dependency-light HTTP(S) client — the TS analogue of the Rust
 * `http_get` / `http_post` helpers.
 *
 * The Rust version hand-rolls a blocking rustls TCP client (custom CA trust,
 * raw sockets) precisely because it must avoid pulling in `reqwest`. On the
 * Workers platform raw sockets and custom TLS trust are unavailable, so this
 * re-implementation is a thin wrapper over the platform `fetch`, which is the
 * idiomatic — and only — outbound HTTP primitive.
 *
 * PORT-TODO(4.8): the Rust client supports an explicit `ca_cert_path` for
 * custom/self-signed CA trust. `workerd` cannot install ad-hoc roots, so
 * `caCertPath` is accepted for signature fidelity but ignored under `fetch`
 * (honour it only on a Node/Bun host that wires it into an Agent). Callers on a
 * self-hosted gateway that truly need a private CA must run outside a Worker.
 */

/** A single request header as a `[name, value]` pair (mirrors the Rust slice). */
export type Header = readonly [name: string, value: string];

/** Tuning + test seam for the minimal HTTP client. */
export interface HttpOptions {
  /** Request timeout in milliseconds (Rust used a `Duration`). */
  readonly timeoutMs?: number;
  /**
   * Custom CA cert path. Accepted for parity; ignored under `fetch`.
   * PORT-TODO(4.8): unsupported on Workers.
   */
  readonly caCertPath?: string | null;
  /** Injectable `fetch` (test seam). Defaults to the platform `fetch`. */
  readonly fetchImpl?: typeof fetch;
}

async function httpRequest(
  method: "GET" | "POST",
  url: string,
  headers: readonly Header[],
  body: Uint8Array | null,
  options: HttpOptions,
): Promise<Uint8Array> {
  let scheme: string;
  try {
    scheme = new URL(url).protocol;
  } catch {
    throw new Error(`invalid URL ${url}`);
  }
  if (scheme !== "http:" && scheme !== "https:") {
    throw new Error(`URL must use http or https: ${url}`);
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const headerBag: Record<string, string> = { Accept: "application/json" };
  for (const [name, value] of headers) headerBag[name] = value;

  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method,
      headers: headerBag,
      body: body ?? undefined,
      signal: controller.signal,
    });
  } catch (cause) {
    throw new Error(`failed to connect to ${url}: ${String(cause)}`);
  } finally {
    clearTimeout(timer);
  }

  const raw = new Uint8Array(await response.arrayBuffer());
  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      `request failed with HTTP ${response.status}: ${new TextDecoder().decode(raw)}`,
    );
  }
  return raw;
}

/** Perform a single `GET` and return the raw response body. */
export function httpGet(
  url: string,
  headers: readonly Header[] = [],
  options: HttpOptions = {},
): Promise<Uint8Array> {
  return httpRequest("GET", url, headers, null, options);
}

/** Perform a single `POST` with a raw body and return the raw response body. */
export function httpPost(
  url: string,
  headers: readonly Header[] = [],
  body: Uint8Array = new Uint8Array(),
  options: HttpOptions = {},
): Promise<Uint8Array> {
  return httpRequest("POST", url, headers, body, options);
}
