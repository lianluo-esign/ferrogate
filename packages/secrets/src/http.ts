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
 * PORT-TODO(4.8) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **workerd exposes no TLS trust-store hook.** The Rust
 * client hand-rolls a blocking rustls TCP client precisely so it can install a
 * caller-supplied root (`ca_cert_path`) for a self-signed Vault/Cloudflare
 * endpoint. On Workers, `fetch()` is the only outbound HTTP primitive, raw TCP
 * with a custom `ClientConfig` is unavailable, and there is no API — no
 * `fetch` option, no binding, no compatibility flag — to add a root to the
 * runtime trust store. `connect()` (the `cloudflare:sockets` TCP API) does not
 * change this: its `secureTransport` uses the same fixed roots.
 *
 * The closest behavior implemented instead: {@link HttpOptions.caCertPath} is
 * ACCEPTED for signature fidelity and IGNORED under `fetch`, so the same config
 * struct round-trips between the CLI (Node/Bun, where a host could wire it into
 * an Agent) and the Worker. It is deliberately not an error: rejecting a config
 * that is valid for the CLI would split the two deployments' config schemas.
 *
 * The consequence is stated rather than papered over: a self-hosted gateway
 * that genuinely needs a private CA must run OUTSIDE a Worker. Reaching a
 * self-signed endpoint from the Worker will fail the TLS handshake, which is
 * the correct failure — a silently-trusted unknown root would be worse.
 * `test/platform-limits.test.ts` pins the ignore.
 */

/** A single request header as a `[name, value]` pair (mirrors the Rust slice). */
export type Header = readonly [name: string, value: string];

/** Tuning + test seam for the minimal HTTP client. */
export interface HttpOptions {
  /** Request timeout in milliseconds (Rust used a `Duration`). */
  readonly timeoutMs?: number;
  /**
   * Custom CA cert path. Accepted for parity; IGNORED under `fetch` — workerd
   * exposes no trust-store hook. See the module PORT-TODO(4.8).
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
