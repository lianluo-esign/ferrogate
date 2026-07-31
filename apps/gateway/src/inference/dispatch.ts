/**
 * The transport half of `server/dispatch.rs`, expressed against the Workers
 * `fetch`.
 *
 * `dispatch.rs` is more than "call the provider": it is where the Rust tree
 * enforces four separate guards that the TS port carried as *declared but
 * unread* configuration (`InferenceLimits.dispatchTimeoutMs`,
 * `InferenceLimits.providerResponseMaxBytes`) or not at all:
 *
 *  1. `build_provider_request(...).timeout(timeout)` — a reqwest **request
 *     level** deadline. It is not a connect deadline: it covers connect,
 *     headers AND the body read, which is why `ProviderBodyStream` says "the
 *     reqwest request-level timeout keeps covering body reads exactly as
 *     before". A stream that stalls past the deadline is killed mid-body.
 *  2. `parse_provider_endpoint` — `http`/`https` only, everything else is
 *     refused before a socket is opened.
 *  3. `read_bounded_response_body` — a chunk-by-chunk cap on the NON-streaming
 *     provider body, checked against `Content-Length` first and then against
 *     the accumulated length, so a chunked or `Content-Length`-lying upstream
 *     cannot force unbounded buffering. Deliberately not applied to the
 *     streaming path, where `dispatch_provider_streaming_request` takes no cap.
 *  4. `provider_transport_failure_class` (issue #384) — the failure class is
 *     named in the message (`"provider request failed (timeout)"`) so a refused
 *     connection and an elapsed deadline stop collapsing into one indistinct
 *     string, without ever putting the operator-configured (possibly
 *     credential-bearing) URL in a client-visible message.
 *
 * All four are ported here. The pieces that are NOT 1:1 are called out on
 * {@link providerTransportFailureClass}.
 */

/**
 * `provider_transport_failure_class`, as far as workerd can discriminate.
 *
 * PORT-TODO(inventory-request-path §1.6 "provider dispatch", issue #384):
 * PLATFORM LIMIT — reqwest exposes seven orthogonal predicates on its error
 * type (`is_connect`, `is_timeout`, `is_redirect`, `is_body`, `is_decode`,
 * `is_request`), so Rust can name the class structurally. The Workers `fetch`
 * rejects with a plain `TypeError`/`DOMException` carrying only `name` and a
 * runtime-authored `message`; there is no error taxonomy on the platform and no
 * hook to obtain one. Three of the Rust classes are therefore UNREACHABLE here
 * and collapse into `"transport"`:
 *
 *   - `redirect` — `redirect: "manual"` means workerd hands the 3xx back as a
 *     normal response instead of failing, so no error is ever raised;
 *   - `body` / `decode` — a truncated or undecodable body errors the
 *     `ReadableStream` while it is being read, not the `fetch()` promise.
 *
 * The classes the port DOES reproduce faithfully are `timeout` (our own
 * deadline is the thing that aborted, so this is decided structurally, not by
 * string matching), `request` (an abort that was NOT our deadline, i.e. the
 * inbound client hung up — Rust never produced an error for this because
 * dropping the response future was silent) and a best-effort `connect`, matched
 * on the connection-failure wording workerd uses. Do not "fix" this by
 * inventing classes the runtime cannot tell apart.
 */
export function providerTransportFailureClass(error: unknown, timedOut: boolean): string {
  // Checked first and structurally: OUR deadline signal is the only thing that
  // can have aborted with a timeout, so this never depends on error wording.
  if (timedOut) {
    return "timeout";
  }
  const name = error instanceof Error ? error.name : "";
  if (name === "TimeoutError") {
    return "timeout";
  }
  if (name === "AbortError") {
    // Not a Rust class in practice: reqwest reports nothing when the caller
    // drops the future. `request` is reqwest's own label for "the request never
    // got off the ground", which is the closest true statement.
    return "request";
  }
  const message = error instanceof Error ? error.message : String(error);
  if (
    /refused|connection (was )?(refused|reset|lost)|failed to connect|could not connect|unable to connect|network connection|getaddrinfo|dns/i.test(
      message,
    )
  ) {
    return "connect";
  }
  return "transport";
}

/**
 * `provider_transport_error` — the message `{error}` renders on the anyhow
 * chain, i.e. only the outermost context.
 *
 * The label is the Rust one for the arm that dispatched: `dispatch.rs` uses
 * `"provider request failed"` for the buffered path and
 * `"provider streaming request failed"` for the SSE path.
 */
export function providerTransportMessage(
  streaming: boolean,
  error: unknown,
  timedOut: boolean,
): string {
  const label = streaming ? "provider streaming request failed" : "provider request failed";
  return `${label} (${providerTransportFailureClass(error, timedOut)})`;
}

/** Thrown by {@link parseProviderEndpoint}; carries the Rust message verbatim. */
export class ProviderEndpointError extends Error {}

/**
 * `parse_provider_endpoint` — http/https only.
 *
 * The messages include the endpoint exactly as the Rust ones do. That is a
 * deliberate asymmetry in the Rust tree, not an oversight: a MALFORMED endpoint
 * is operator misconfiguration that the operator has to be able to see, whereas
 * `provider_transport_error` (a working endpoint that failed) keeps the URL out
 * of the message because it can carry a credential.
 */
export function parseProviderEndpoint(endpoint: string): URL {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new ProviderEndpointError(`invalid provider endpoint ${endpoint}`);
  }
  const scheme = url.protocol.replace(/:$/, "");
  if (scheme !== "http" && scheme !== "https") {
    throw new ProviderEndpointError(
      `provider dispatch supports http and https endpoints only, got ${scheme}`,
    );
  }
  return url;
}

/** A live request-level deadline plus the question "was it YOU that fired?". */
export interface DispatchDeadline {
  /** The signal to hand to `fetch`. `undefined` ⇒ nothing to enforce. */
  readonly signal: AbortSignal | undefined;
  /** True once the deadline (not the client) aborted the request. */
  expired(): boolean;
}

/**
 * Build the reqwest-equivalent request-level deadline.
 *
 * `AbortSignal.timeout` owns its own timer inside the runtime, so nothing here
 * has to be cleared — which matters because the deadline must stay armed AFTER
 * the response headers arrive (Rust's timeout covers the body read too), and
 * there is no point at which this module would know the body had finished.
 *
 * The deadline is combined with the inbound client signal rather than replacing
 * it: a client that hangs up must still stop the upstream generating tokens
 * (see `src/streaming/abort.ts`).
 *
 * `timeoutMs <= 0` disables the deadline. The Rust config validator forbids a
 * zero `provider_dispatch_timeout_secs`, so this only ever fires for a test or
 * a caller that explicitly opts out.
 */
export function dispatchDeadline(
  timeoutMs: number,
  clientSignal?: AbortSignal,
): DispatchDeadline {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return { signal: clientSignal, expired: () => false };
  }
  const deadline = AbortSignal.timeout(timeoutMs);
  const signal =
    clientSignal === undefined ? deadline : AbortSignal.any([clientSignal, deadline]);
  return { signal, expired: () => deadline.aborted };
}

/** Thrown by {@link readBoundedProviderBody}; carries the Rust `bail!` message. */
export class ProviderBodyTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(
      `provider_response_body_too_large: provider response body exceeds ${maxBytes} bytes`,
    );
  }
}

/**
 * `dispatch_provider_request`'s `Content-Length` pre-check +
 * `read_bounded_response_body`.
 *
 * Both halves are load-bearing and both are ported: the header check refuses an
 * honestly-declared oversized body without reading a byte, and the accumulating
 * check is what actually bounds a chunked or `Content-Length`-lying upstream.
 * The Rust holds "at most cap + one chunk" because it appends and then tests;
 * this tests before appending, so it holds strictly at most `maxBytes` — the
 * refusal boundary (`> maxBytes`) is identical either way.
 */
export async function readBoundedProviderBody(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > maxBytes) {
      throw new ProviderBodyTooLargeError(maxBytes);
    }
  }

  const body = response.body;
  if (body === null) {
    return "";
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined) {
        continue;
      }
      if (total + value.byteLength > maxBytes) {
        await reader.cancel();
        throw new ProviderBodyTooLargeError(maxBytes);
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}
