/**
 * Pins for the `@ferrogate/billing` behavior KEPT as a PORT-TODO marker because
 * the Cloudflare platform cannot express the Rust behavior (§2.4 / §2.5), plus
 * the seam widening that limit forced.
 *
 * A kept marker without a test is a claim. These make it falsifiable: the Rust
 * `serve()` transport is GONE on purpose, the accept-loop guards that only a
 * socket owner can enforce are GONE with it, and the one guard that lives
 * inside the isolate is still enforced. If a future workerd grew `listen()`,
 * the first describe below is where the marker should be revisited.
 */
import { describe, expect, it } from "vitest";
import * as billing from "../src/index.js";
import {
  BillingError,
  charge,
  createBillingService,
  InMemoryLedgerSink,
  MAX_REQUEST_BYTES,
  modelPriceUsd,
  parseBillingEvent,
  priceEntry,
  PriceBook,
  type BillingServiceConfig,
  type LedgerEntry,
  type LedgerListFilter,
  type LedgerSink,
} from "../src/index.js";

const BOOK = PriceBook.new([priceEntry("openai", "gpt-5.5", modelPriceUsd(5.0, 15.0))]);

function eventBody(requestId = "req-1"): string {
  return JSON.stringify({
    request_id: requestId,
    trace_id: `trace-${requestId}`,
    provider_attempt_id: `${requestId}:provider-attempt:0`,
    provider_attempt_index: 0,
    tenant: { organization_id: "org-1" },
    logical_model: "fast-chat",
    provider: "openai",
    provider_model: "gpt-5.5",
    usage: { prompt_tokens: 1_000, completion_tokens: 2_000, total_tokens: 3_000 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1,
    metadata: {},
  });
}

function post(path: string, body: string, bearer?: string): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  return new Request(`https://billing.test${path}`, { method: "POST", body, headers });
}

describe("PLATFORM LIMIT — a Worker cannot bind a listening socket (§2.4/§2.5)", () => {
  /**
   * The Rust service owns its transport: `TcpListener::bind`, a thread per
   * connection, a 15 s read timeout against slowloris, and a 512-connection
   * load shed. workerd has no `listen()` — `cloudflare:sockets`' `connect()` is
   * outbound only — so the transport and the guards that require owning it are
   * deliberately NOT ported. The approximation is a Web Fetch handler.
   */
  it("exports NO listening transport — not even a stubbed one", () => {
    // A `serve()` that ignored its bind address would be worse than its
    // absence: it would read as ported. If one ever appears, this fails.
    expect(Object.keys(billing)).not.toContain("serve");
    expect(Object.keys(billing)).not.toContain("BillingServiceListener");
    // The accept-loop guards have no referent without a socket to accept on:
    // there is no connection to time out and no connection count to shed.
    expect(Object.keys(billing)).not.toContain("CONNECTION_TIMEOUT_MS");
    expect(Object.keys(billing)).not.toContain("MAX_CONCURRENT_CONNECTIONS");
    // …and the config carries no `listen` address, unlike Rust's.
    const cfg: BillingServiceConfig = { price_book: BOOK, sink: new InMemoryLedgerSink() };
    expect(Object.keys(cfg)).not.toContain("listen");
  });

  it("the ONE guard enforceable inside the isolate IS still enforced (1 MiB)", async () => {
    // `MAX_REQUEST_BYTES` survives the transport's deletion because it is a
    // property of the body the runtime already handed us, not of the socket.
    expect(MAX_REQUEST_BYTES).toBe(1024 * 1024);
    const svc = createBillingService({ price_book: BOOK, sink: new InMemoryLedgerSink() });
    const oversized = `{"pad":"${"x".repeat(MAX_REQUEST_BYTES + 1)}"}`;
    const res = await svc(post("/v1/billing/charge", oversized));
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "payload_too_large",
    );
  });

  it("the readiness probe stays open while every other route needs the token (#136)", async () => {
    const svc = createBillingService({
      price_book: BOOK,
      sink: new InMemoryLedgerSink(),
      token: "s3cret",
    });
    expect((await svc(new Request("https://billing.test/healthz"))).status).toBe(200);
    expect((await svc(post("/v1/billing/charge", eventBody()))).status).toBe(401);
  });
});

/**
 * A durable sink is necessarily asynchronous on this platform: D1, KV, R2,
 * Queues and Durable Object stubs are all promise-returning. This fake is the
 * shape any of them would have — it records completion order so the test can
 * prove the handler waited.
 */
class AsyncLedgerSink implements LedgerSink {
  readonly settled: string[] = [];
  #recordSettled = false;
  #rejectWith: BillingError | undefined;
  #entries: LedgerEntry[] = [];

  constructor(rejectWith?: BillingError) {
    this.#rejectWith = rejectWith;
  }

  /** True only after the promise returned by `record` has actually settled. */
  get recordSettled(): boolean {
    return this.#recordSettled;
  }

  async record(entry: LedgerEntry): Promise<boolean> {
    // Two macro/micro-task hops, as a real D1 round trip would take.
    await new Promise((resolve) => setTimeout(resolve, 0));
    this.#recordSettled = true;
    if (this.#rejectWith) throw this.#rejectWith;
    this.#entries.push(entry);
    this.settled.push(entry.id);
    return true;
  }

  async list(_filter: LedgerListFilter, offset: number, limit: number): Promise<LedgerEntry[]> {
    await new Promise((resolve) => setTimeout(resolve, 0));
    return this.#entries.slice(offset, offset + limit);
  }

  async get(id: string): Promise<LedgerEntry | undefined> {
    await new Promise((resolve) => setTimeout(resolve, 0));
    return this.#entries.find((entry) => entry.id === id);
  }
}

describe("the widening that limit forced — an async (durable) sink is honored", () => {
  it("a promise-returning sink satisfies the seam at all (type-level)", () => {
    // If `LedgerSink` were still synchronous this line would not compile, and
    // NO Cloudflare-durable sink could ever mount on the service.
    const sink: LedgerSink = new AsyncLedgerSink();
    expect(typeof sink.record).toBe("function");
  });

  it("the 200 is not shipped until the durable write has SETTLED", async () => {
    const sink = new AsyncLedgerSink();
    const svc = createBillingService({ price_book: BOOK, sink });
    const res = await svc(post("/v1/billing/charge", eventBody()));
    expect(res.status).toBe(200);
    // Fire-and-forget would leave this false: the response would be built while
    // the row was still in flight, and a failed write would vanish.
    expect(sink.recordSettled).toBe(true);
    expect(sink.settled).toEqual(["ferrogate:provider-attempt:req-1:provider-attempt:0"]);
  });

  it("an async idempotency conflict still reaches the client as 409, not a lost rejection", async () => {
    const sink = new AsyncLedgerSink(
      new BillingError("billing_idempotency_conflict", "replayed with different settlement"),
    );
    const svc = createBillingService({ price_book: BOOK, sink });
    const res = await svc(post("/v1/billing/charge", eventBody()));
    // Unawaited, this would be a 200 plus an unhandled rejection — the caller
    // would believe a settlement it never got was recorded.
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "billing_idempotency_conflict",
    );
  });

  it("async list/get are awaited before serialization", async () => {
    const sink = new AsyncLedgerSink();
    const svc = createBillingService({ price_book: BOOK, sink });
    await svc(post("/v1/billing/charge", eventBody("req-a")));

    const list = await svc(new Request("https://billing.test/v1/billing/ledger"));
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { entries: { id: string }[]; page_totals: { entries: number } };
    // An unawaited `list` would serialize a Promise: `{"entries":{}}`.
    expect(listed.entries.map((e) => e.id)).toEqual([
      "ferrogate:provider-attempt:req-a:provider-attempt:0",
    ]);
    expect(listed.page_totals.entries).toBe(1);

    const one = await svc(
      new Request(
        "https://billing.test/v1/billing/ledger/ferrogate:provider-attempt:req-a:provider-attempt:0",
      ),
    );
    expect(one.status).toBe(200);
    const missing = await svc(new Request("https://billing.test/v1/billing/ledger/nope"));
    expect(missing.status).toBe(404);
  });

  it("the in-memory sink stays synchronous — the widening added no ceremony", () => {
    // `InMemoryLedgerSink` is the executable specification of the idempotency
    // contract; it must remain directly assertable without awaiting.
    const sink = new InMemoryLedgerSink();
    const entry = charge(BOOK, parseBillingEvent(JSON.parse(eventBody())));
    expect(sink.record(entry)).toBe(true);
    expect(sink.record(entry)).toBe(false);
    expect(sink.get(entry.id)?.id).toBe(entry.id);
  });
});
