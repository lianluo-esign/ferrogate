import { describe, expect, it } from "vitest";
import {
  billingErrorHttpStatus,
  BillingError,
  constantTimeEq,
  createBillingService,
  InMemoryLedgerSink,
  modelPriceUsd,
  priceEntry,
  PriceBook,
  type BillingServiceConfig,
} from "../src/index.js";

function config(token?: string): BillingServiceConfig & { sink: InMemoryLedgerSink } {
  return {
    price_book: PriceBook.new([priceEntry("openai", "gpt-5.5", modelPriceUsd(5.0, 15.0))]),
    sink: new InMemoryLedgerSink(),
    token,
  };
}

function eventBody(provider: string, model: string, org?: string): string {
  return JSON.stringify({
    request_id: `req-${org ?? "http"}`,
    trace_id: `trace-${org ?? "http"}`,
    provider_attempt_id: `req-${org ?? "http"}:provider-attempt:0`,
    provider_attempt_index: 0,
    tenant: org ? { organization_id: org } : {},
    logical_model: "fast-chat",
    provider,
    provider_model: model,
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
function get(path: string, bearer?: string): Request {
  const headers: Record<string, string> = {};
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  return new Request(`https://billing.test${path}`, { method: "GET", headers });
}

describe("billing service routing", () => {
  it("charge route records and returns the ledger entry", async () => {
    const cfg = config();
    const svc = createBillingService(cfg);
    const res = await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5")));
    expect(res.status).toBe(200);
    const entry = (await res.json()) as { cost: { total_cost: number }; provider_attempt_id: string };
    expect(entry.cost.total_cost).toBeCloseTo(0.035, 12);
    expect(entry.provider_attempt_id).toBe("req-http:provider-attempt:0");
    expect(cfg.sink.length).toBe(1);
  });

  it("fails closed with 422 price_not_found", async () => {
    const res = await createBillingService(config())(
      post("/v1/billing/charge", eventBody("mystery", "model")),
    );
    expect(res.status).toBe(422);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("price_not_found");
  });

  it("rejects a provider-attempt key collision with 409", async () => {
    const svc = createBillingService(config());
    expect((await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5")))).status).toBe(200);
    const collision = JSON.parse(eventBody("openai", "gpt-5.5"));
    collision.tenant = { organization_id: "different-tenant" };
    const res = await svc(post("/v1/billing/charge", JSON.stringify(collision)));
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("billing_idempotency_conflict");
  });

  it("rejects a malformed body with 400 invalid_json", async () => {
    const res = await createBillingService(config())(post("/v1/billing/charge", "{not json"));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("invalid_json");
  });

  it("lists the ledger with page totals", async () => {
    const svc = createBillingService(config());
    await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5")));
    const res = await svc(get("/v1/billing/ledger?limit=10"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { entries: unknown[]; page_totals: { entries: number } };
    expect(body.entries).toHaveLength(1);
    expect(body.page_totals.entries).toBe(1);
  });

  it("scopes ledger reads by the tenant query (#136/#149)", async () => {
    const svc = createBillingService(config());
    await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5", "org-a")));
    await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5", "org-b")));
    const all = (await (await svc(get("/v1/billing/ledger"))).json()) as { entries: unknown[] };
    expect(all.entries).toHaveLength(2);
    const scoped = (await (
      await svc(get("/v1/billing/ledger?organization_id=org-a"))
    ).json()) as { entries: Array<{ tenant: { organization_id: string } }> };
    expect(scoped.entries).toHaveLength(1);
    expect(scoped.entries[0]!.tenant.organization_id).toBe("org-a");
  });

  it("fetches a single entry by id and 404s a miss", async () => {
    const svc = createBillingService(config());
    const entry = (await (
      await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5")))
    ).json()) as { id: string };
    expect((await svc(get(`/v1/billing/ledger/${entry.id}`))).status).toBe(200);
    expect((await svc(get("/v1/billing/ledger/missing"))).status).toBe(404);
  });

  it("serves healthz open", async () => {
    expect((await createBillingService(config())(get("/healthz"))).status).toBe(200);
    expect((await createBillingService(config())(get("/v1/healthz"))).status).toBe(200);
  });
});

describe("bearer auth (issue #136)", () => {
  it("rejects a missing or wrong token and records nothing", async () => {
    const cfg = config("s3cret");
    const svc = createBillingService(cfg);
    expect((await svc(get("/v1/billing/ledger"))).status).toBe(401);
    expect((await svc(get("/v1/billing/ledger", "nope"))).status).toBe(401);
    expect((await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5")))).status).toBe(401);
    expect(cfg.sink.length).toBe(0);
  });

  it("allows the correct token and leaves health open", async () => {
    const svc = createBillingService(config("s3cret"));
    expect(
      (await svc(post("/v1/billing/charge", eventBody("openai", "gpt-5.5"), "s3cret"))).status,
    ).toBe(200);
    expect((await svc(get("/healthz"))).status).toBe(200);
  });
});

describe("helpers", () => {
  it("constantTimeEq matches only equal byte slices", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(constantTimeEq(enc("abc"), enc("abc"))).toBe(true);
    expect(constantTimeEq(enc("abc"), enc("abd"))).toBe(false);
    expect(constantTimeEq(enc("abc"), enc("ab"))).toBe(false);
  });

  it("billingErrorHttpStatus classifies the taxonomy", () => {
    expect(billingErrorHttpStatus(new BillingError("price_not_found", ""))).toBe(422);
    expect(billingErrorHttpStatus(new BillingError("billing_idempotency_conflict", ""))).toBe(409);
    expect(billingErrorHttpStatus(new BillingError("billing_ledger_poisoned", ""))).toBe(500);
  });
});
