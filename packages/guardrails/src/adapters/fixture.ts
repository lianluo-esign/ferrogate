/**
 * Recorded request/response fixture transport — port of
 * `ferrogate-guardrails::adapters::fixture`.
 *
 * Replays recorded JSON exchanges for deterministic, network-free adapter tests.
 * Matching is by exact JSON equality of the request body, so any drift between
 * the adapter serializer and the recorded contract fails loudly. `"hang"`
 * exercises the adapter's own deadline enforcement.
 */

import { PROBE_SECRET } from "../conformance.js";
import { DetectorError } from "../contract.js";
import type { DetectorTransport, TransportReply } from "./transport.js";

interface RecordedReply {
  status: number;
  body?: unknown;
  body_raw?: string;
}

interface RecordedExchange {
  name?: string;
  note?: string;
  request: unknown;
  response?: RecordedReply;
  outcome?: string;
}

interface RecordedFile {
  adapter?: string;
  exchanges: RecordedExchange[];
}

export class FixtureTransport implements DetectorTransport {
  private exchanges: RecordedExchange[];

  private constructor(exchanges: RecordedExchange[]) {
    this.exchanges = exchanges;
  }

  /** Load from recorded JSON (string or parsed object). `${PROBE_SECRET}` is substituted. */
  static fromRecorded(fixture: string | RecordedFile): FixtureTransport {
    let file: RecordedFile;
    if (typeof fixture === "string") {
      file = JSON.parse(fixture.replaceAll("${PROBE_SECRET}", PROBE_SECRET)) as RecordedFile;
    } else {
      file = JSON.parse(
        JSON.stringify(fixture).replaceAll("${PROBE_SECRET}", PROBE_SECRET),
      ) as RecordedFile;
    }
    return new FixtureTransport(file.exchanges);
  }

  async postJson(body: Uint8Array): Promise<TransportReply> {
    let request: unknown;
    try {
      request = JSON.parse(new TextDecoder().decode(body));
    } catch {
      throw DetectorError.new("internal", "fixture transport received a non-JSON request body");
    }
    const exchange = this.exchanges.find((e) => deepEqual(e.request, request));
    if (!exchange) {
      throw DetectorError.new(
        "internal",
        "no recorded fixture exchange matches the adapter request (wire drift?)",
      );
    }
    if (exchange.outcome === "hang") {
      return new Promise<TransportReply>(() => {
        /* never resolves: the adapter's deadline wrap must fire */
      });
    }
    const reply = exchange.response;
    if (!reply) {
      throw DetectorError.new(
        "internal",
        "recorded fixture exchange has neither response nor outcome",
      );
    }
    let bodyBytes: Uint8Array;
    if (reply.body !== undefined) {
      bodyBytes = new TextEncoder().encode(JSON.stringify(reply.body));
    } else if (reply.body_raw !== undefined) {
      bodyBytes = new TextEncoder().encode(reply.body_raw);
    } else {
      bodyBytes = new Uint8Array();
    }
    return { status: reply.status, body: bodyBytes };
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b || a === null || b === null) {
    return false;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  if (typeof a === "object" && typeof b === "object") {
    const ak = Object.keys(a as object);
    const bk = Object.keys(b as object);
    return (
      ak.length === bk.length &&
      ak.every((k) =>
        deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
      )
    );
  }
  return false;
}
