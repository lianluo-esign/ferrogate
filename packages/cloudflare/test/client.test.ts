/**
 * `CloudflareClient` — auth, `{account_id}` templating, envelope decoding,
 * typed error mapping, the retry loop, and `preflight()` (slice S3).
 *
 * Ported from `crates/ferrogate-cloudflare/src/client.rs`, with ONE deliberate
 * divergence, recorded in `cf-crate-assessment.md` §S4 and pinned by the
 * "idempotency gate" tests below: the Rust loop retried EVERY method on a 5xx.
 * On Workers that is unsafe for `POST /accounts/{id}/tokens`, where a retried
 * mint creates a second credential whose secret is lost forever. So retry is
 * opt-in per call and defaults to GET-only.
 */
import { describe, expect, test } from "vitest";
import { CloudflareClient, DEFAULT_API_BASE_URL, EnvTokenResolver } from "../src/client.js";
import { CloudflareError } from "../src/errors.js";
import { REQUIRED_TOKEN_PERMISSION_GROUPS } from "../src/scopes.js";
import { RecordingClock, ScriptedTransport, errorResponse, okResponse } from "./support.js";

function client(
  transport: ScriptedTransport,
  clock = new RecordingClock(),
  overrides: { accountId?: string; apiBaseUrl?: string } = {},
) {
  return new CloudflareClient({
    config: {
      accountId: overrides.accountId ?? "acct_123",
      tokenReference: "env://CF_TOKEN",
      ...(overrides.apiBaseUrl === undefined ? {} : { apiBaseUrl: overrides.apiBaseUrl }),
    },
    resolver: new EnvTokenResolver({ CF_TOKEN: "secret-token" }),
    transport,
    clock,
  });
}

describe("URL construction and auth", () => {
  test("templates {account_id} and joins onto the default v4 base", async () => {
    const transport = new ScriptedTransport([okResponse({ ok: true })]);
    await client(transport).getJson("accounts/{account_id}/d1/database");
    expect(transport.requests[0]?.url).toBe(
      `${DEFAULT_API_BASE_URL}/accounts/acct_123/d1/database`,
    );
    expect(DEFAULT_API_BASE_URL).toBe("https://api.cloudflare.com/client/v4");
  });

  test("templates EVERY occurrence of the placeholder", async () => {
    const transport = new ScriptedTransport([okResponse({})]);
    await client(transport).getJson("accounts/{account_id}/x/{account_id}");
    expect(transport.requests[0]?.url).toBe(`${DEFAULT_API_BASE_URL}/accounts/acct_123/x/acct_123`);
  });

  test("normalises a trailing base slash and a leading path slash", async () => {
    const transport = new ScriptedTransport([okResponse({})]);
    await client(transport, new RecordingClock(), {
      apiBaseUrl: "https://cf.test/client/v4/",
    }).getJson("/accounts/{account_id}");
    expect(transport.requests[0]?.url).toBe("https://cf.test/client/v4/accounts/acct_123");
  });

  test("resolves the env:// token reference and sends it as a Bearer", async () => {
    const transport = new ScriptedTransport([okResponse({})]);
    await client(transport).getJson("accounts/{account_id}");
    expect(transport.requests[0]?.bearerToken).toBe("secret-token");
  });

  test("an unresolvable token reference fails BEFORE any request is issued", async () => {
    const transport = new ScriptedTransport([]);
    const bare = new CloudflareClient({
      config: { accountId: "a", tokenReference: "env://MISSING" },
      resolver: new EnvTokenResolver({}),
      transport,
    });
    await expect(bare.getJson("accounts/{account_id}")).rejects.toThrowError(
      /cloudflare token resolution error/,
    );
    expect(transport.callCount).toBe(0);
  });

  test("an empty account id is a config error before any request", async () => {
    const transport = new ScriptedTransport([]);
    const bare = new CloudflareClient({
      config: { accountId: "", tokenReference: "inline-token" },
      resolver: new EnvTokenResolver({}),
      transport,
    });
    await expect(bare.getJson("accounts/{account_id}")).rejects.toThrowError(
      /cloudflare config error/,
    );
    expect(transport.callCount).toBe(0);
  });

  test("a per-tenant token override is used when configured", async () => {
    const transport = new ScriptedTransport([okResponse({}), okResponse({})]);
    const scoped = new CloudflareClient({
      config: {
        accountId: "acct_123",
        tokenReference: "env://CF_TOKEN",
        tenantTokenReferences: { acme: "env://CF_TOKEN_ACME" },
      },
      resolver: new EnvTokenResolver({ CF_TOKEN: "account", CF_TOKEN_ACME: "acme-token" }),
      transport,
    });
    await scoped.getJson("accounts/{account_id}", { tenant: "acme" });
    await scoped.getJson("accounts/{account_id}", { tenant: "other" });
    expect(transport.requests[0]?.bearerToken).toBe("acme-token");
    expect(transport.requests[1]?.bearerToken).toBe("account");
  });

  test("a JSON body defaults to application/json; an explicit content type wins", async () => {
    const transport = new ScriptedTransport([okResponse({}), okResponse({})]);
    const c = client(transport);
    await c.requestJson("POST", "accounts/{account_id}/x", { body: { a: 1 } });
    expect(transport.requests[0]?.contentType).toBe("application/json");
    expect(transport.requests[0]?.body).toBe('{"a":1}');
    await c.requestJson("POST", "accounts/{account_id}/x", {
      rawBody: "--b--",
      contentType: "multipart/form-data; boundary=b",
    });
    expect(transport.requests[1]?.contentType).toBe("multipart/form-data; boundary=b");
  });

  test("a bearer override replaces the resolved token verbatim", async () => {
    const transport = new ScriptedTransport([okResponse({})]);
    await client(transport).requestJson("POST", "accounts/{account_id}/x", {
      body: {},
      bearerOverride: "upload-session-jwt",
    });
    expect(transport.requests[0]?.bearerToken).toBe("upload-session-jwt");
  });
});

describe("the R2 S3 endpoint", () => {
  test("defaults to the per-account host", () => {
    const c = client(new ScriptedTransport([]));
    expect(c.r2S3Endpoint()).toBe("https://acct_123.r2.cloudflarestorage.com");
  });

  test("an explicit override wins — jurisdictional buckets need one", async () => {
    const scoped = new CloudflareClient({
      config: {
        accountId: "acct_123",
        tokenReference: "inline",
        r2S3Endpoint: "https://eu.custom.r2.example",
      },
      resolver: new EnvTokenResolver({}),
      transport: new ScriptedTransport([]),
    });
    expect(scoped.r2S3Endpoint()).toBe("https://eu.custom.r2.example");
  });
});

describe("error mapping", () => {
  test("a 403 + 9109 becomes a MissingScope naming the permission groups", async () => {
    const transport = new ScriptedTransport([
      errorResponse(403, [{ code: 9109, message: "Unauthorized to access requested resource" }]),
    ]);
    await expect(client(transport).getJson("accounts/{account_id}")).rejects.toMatchObject({
      kind: "missing_scope",
    });
  });

  test("a 401 becomes Unauthorized", async () => {
    const transport = new ScriptedTransport([errorResponse(401, [])]);
    await expect(client(transport).getJson("accounts/{account_id}")).rejects.toMatchObject({
      kind: "unauthorized",
    });
  });

  test("a non-JSON body under a 2xx is a decode error", async () => {
    const transport = new ScriptedTransport([{ status: 200, body: "<html/>" }]);
    await expect(client(transport).getJson("accounts/{account_id}")).rejects.toThrowError(
      /decode error/,
    );
  });

  test("a transport throw surfaces as a typed transport error", async () => {
    const transport = new ScriptedTransport([{ throws: new TypeError("network failure") }]);
    await expect(client(transport).getJson("accounts/{account_id}")).rejects.toBeInstanceOf(
      CloudflareError,
    );
  });
});

describe("retry loop", () => {
  test("a GET is retried on a 503 and succeeds", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([errorResponse(503, []), okResponse({ id: "ok" })]);
    const result = await client(transport, clock).getJson<{ id: string }>("accounts/{account_id}");
    expect(result).toEqual({ id: "ok" });
    expect(transport.callCount).toBe(2);
    expect(clock.slept).toEqual([1_000]);
  });

  test("an exhausted 429 surfaces RateLimited carrying the attempt count", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport(
      Array.from({ length: 5 }, () => errorResponse(429, [], 2_000)),
    );
    await expect(client(transport, clock).getJson("accounts/{account_id}")).rejects.toMatchObject({
      kind: "rate_limited",
      attempts: 5,
      retryAfterMs: 2_000,
    });
    expect(transport.callCount).toBe(5);
    expect(clock.slept).toEqual([2_000, 2_000, 2_000, 2_000]);
  });

  test("a repeated transport failure exhausts into ExhaustedRetries", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport(
      Array.from({ length: 5 }, () => ({ throws: new TypeError("reset") })),
    );
    await expect(client(transport, clock).getJson("accounts/{account_id}")).rejects.toMatchObject({
      kind: "exhausted_retries",
      attempts: 5,
    });
  });

  test("a 400 is issued exactly once — TRAP 1's real consequence", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([
      errorResponse(400, [{ code: 10013, message: "IncompleteBody" }]),
    ]);
    await expect(client(transport, clock).getJson("accounts/{account_id}")).rejects.toMatchObject({
      kind: "api",
      status: 400,
    });
    expect(transport.callCount).toBe(1);
    expect(clock.slept).toEqual([]);
  });
});

describe("the idempotency gate — the deliberate divergence from Rust", () => {
  test("a POST is NOT retried by default, even on a 500", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([errorResponse(500, []), okResponse({})]);
    await expect(
      client(transport, clock).requestJson("POST", "accounts/{account_id}/tokens", { body: {} }),
    ).rejects.toMatchObject({ kind: "api", status: 500 });
    expect(transport.callCount).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("a POST that opts in IS retried", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([errorResponse(500, []), okResponse({ ok: 1 })]);
    await client(transport, clock).requestJson("POST", "accounts/{account_id}/x", {
      body: {},
      idempotent: true,
    });
    expect(transport.callCount).toBe(2);
  });

  test("a GET that opts OUT is not retried", async () => {
    const transport = new ScriptedTransport([errorResponse(503, []), okResponse({})]);
    await expect(
      client(transport).getJson("accounts/{account_id}", { idempotent: false }),
    ).rejects.toMatchObject({ kind: "api", status: 503 });
    expect(transport.callCount).toBe(1);
  });
});

describe("preflight (slice S3)", () => {
  test("issues a cheap GET /accounts/{account_id}", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "acct_123" })]);
    await client(transport).preflight();
    expect(transport.requests[0]?.method).toBe("GET");
    expect(transport.requests[0]?.url).toBe(`${DEFAULT_API_BASE_URL}/accounts/acct_123`);
  });

  test("an under-scoped token names EVERY permission group an operator must grant", async () => {
    const transport = new ScriptedTransport([
      errorResponse(403, [{ code: 9109, message: "Unauthorized to access requested resource" }]),
    ]);
    const error = await client(transport)
      .preflight()
      .then(
        () => undefined,
        (e: CloudflareError) => e,
      );
    expect(error?.kind).toBe("missing_scope");
    for (const group of REQUIRED_TOKEN_PERMISSION_GROUPS) {
      expect(error?.message).toContain(group.name);
    }
  });

  test("a bad credential is Unauthorized, DISTINGUISHABLE from under-scoped", async () => {
    const transport = new ScriptedTransport([
      errorResponse(400, [{ code: 1000, message: "Invalid API Token" }]),
    ]);
    await expect(client(transport).preflight()).rejects.toMatchObject({ kind: "unauthorized" });
  });

  test("a healthy account answers without throwing", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "acct_123", name: "FerroGate" })]);
    await expect(client(transport).preflight()).resolves.toBeUndefined();
  });
});

describe("requestAck", () => {
  test("a success envelope with a null result is an ack", async () => {
    const transport = new ScriptedTransport([okResponse(null)]);
    await expect(
      client(transport).requestAck("DELETE", "accounts/{account_id}/x", { idempotent: true }),
    ).resolves.toBeUndefined();
  });
});

describe("getJsonPaged", () => {
  test("hands back result_info alongside the result", async () => {
    const transport = new ScriptedTransport([okResponse({ buckets: [] }, { cursor: "c1" })]);
    const { resultInfo } = await client(transport).getJsonPaged<{ buckets: unknown[] }>(
      "accounts/{account_id}/r2/buckets",
    );
    expect(resultInfo?.cursor).toBe("c1");
  });
});
