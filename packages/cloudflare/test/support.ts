/**
 * Test seams for `@ferrogate/cloudflare`.
 *
 * Both of the client's injection points are faked here — the HTTP transport and
 * the clock — so every test in this package runs with no network, no real
 * sleep, and no live Cloudflare account. The clock records the exact millisecond
 * sequence it was asked to sleep, which is the whole reason the ported backoff
 * schedule is deterministic (no jitter): the schedule is *asserted*, not merely
 * observed to have happened.
 */

import type { HttpRequest, HttpResponse, HttpTransport } from "../src/client.js";
import type { Clock } from "../src/retry.js";

/** A scripted response, or a thrown transport failure. */
export type ScriptEntry = HttpResponse | { readonly throws: unknown };

/** A transport that replays a fixed script and records every request. */
export class ScriptedTransport implements HttpTransport {
  readonly requests: HttpRequest[] = [];
  #index = 0;

  constructor(private readonly script: readonly ScriptEntry[]) {}

  get callCount(): number {
    return this.#index;
  }

  async execute(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    const entry = this.script[this.#index];
    this.#index += 1;
    if (entry === undefined) {
      throw new Error(
        `ScriptedTransport ran out of scripted responses at call ${this.#index} for ${request.method} ${request.url}`,
      );
    }
    if ("throws" in entry) throw entry.throws;
    return entry;
  }
}

/** A clock that records requested sleeps instead of performing them. */
export class RecordingClock implements Clock {
  readonly slept: number[] = [];
  async sleep(milliseconds: number): Promise<void> {
    this.slept.push(milliseconds);
  }
}

/** A `success: true` envelope carrying `result`. */
export function okResponse(result: unknown, resultInfo?: unknown): HttpResponse {
  const envelope: Record<string, unknown> = { success: true, errors: [], messages: [], result };
  if (resultInfo !== undefined) envelope.result_info = resultInfo;
  return { status: 200, body: JSON.stringify(envelope) };
}

/** A failure envelope with an explicit HTTP status and error codes. */
export function errorResponse(
  status: number,
  errors: readonly { code: number; message: string }[],
  retryAfterMs?: number,
): HttpResponse {
  const response: HttpResponse = {
    status,
    body: JSON.stringify({ success: false, errors, messages: [] }),
  };
  return retryAfterMs === undefined ? response : { ...response, retryAfterMs };
}
