/**
 * The REAL `fetch` transports — `createFetchControlPlaneClient` and
 * `createFetchGatewayClient`.
 *
 * These are what `createDefaultRuntime()` wires into the shipped binary, so
 * every other suite in this app (which drives the scripted in-memory client)
 * proves nothing about them. Covered here: URL assembly against `/admin/v1/*`,
 * the header set, the failure classification the exit-code contract depends on,
 * and the TLS policy.
 *
 * No socket is opened: `fetch` is injected. The one place a real socket WAS
 * used is documented in `src/tls.ts` — Bun's honouring of `tls:` was verified
 * against a local self-signed server before this code was written.
 */
import { describe, expect, test, vi } from "vitest";
import { CliError, exitCode } from "../src/errors.js";
import { main } from "../src/index.js";
import type { RequestContext, RequestSpec } from "../src/ports.js";
import {
  classifyFailure,
  createFetchControlPlaneClient,
  createFetchGatewayClient,
  decodeBody,
  defaultCodeForStatus,
} from "../src/ports.js";
import { assertPemBundle } from "../src/tls.js";
import { createTestRuntime } from "./helpers.js";

const CONTEXT: RequestContext = {
  endpoint: "https://cp.example",
  token: "sk-token",
  timeoutMillis: 5_000,
  headers: { "x-ferrogate-action-id": "fgact_deadbeef", "user-agent": "ferrogate-cli/0.0.0" },
  tlsInsecureSkipVerify: false,
};

const GET: RequestSpec = { method: "GET", path: "/admin/v1/tenants", query: [] };

/**
 * Await a call that MUST reject, and hand back the `CliError`.
 *
 * Deliberately not `.catch(e => e as CliError)`: that shape passes silently if
 * the call ever starts succeeding, leaving the assertions below to compare
 * against a response object instead of failing on the real regression.
 */
async function rejection(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise;
  } catch (thrown) {
    if (thrown instanceof CliError) return thrown;
    throw thrown;
  }
  throw new Error("expected the call to reject, but it resolved");
}

/** A fetch stub that records its calls and answers a canned response. */
function stubFetch(response: Response | (() => Response | Promise<Response>)) {
  const calls: { url: string; init: RequestInit & { tls?: unknown } }[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit & { tls?: unknown } });
    return typeof response === "function" ? await response() : response.clone();
  }) as unknown as typeof fetch;
  return { impl, calls };
}

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

describe("request assembly against /admin/v1/*", () => {
  test("the absolute path is joined onto the endpoint and query is appended in order", async () => {
    const stub = stubFetch(json({ data: [] }));
    await createFetchControlPlaneClient(stub.impl).send(
      {
        method: "GET",
        path: "/admin/v1/tenants",
        query: [
          ["sort", "-created_at"],
          ["sort", "name"],
          ["filter", "a b"],
        ],
      },
      CONTEXT,
    );
    expect(stub.calls[0]?.url).toBe(
      "https://cp.example/admin/v1/tenants?sort=-created_at&sort=name&filter=a+b",
    );
  });

  test("a base path in the endpoint is preserved as a prefix", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl).send(GET, {
      ...CONTEXT,
      endpoint: "https://edge.example/gw/",
    });
    expect(stub.calls[0]?.url).toBe("https://edge.example/gw/admin/v1/tenants");
  });

  test("a relative internal path is refused rather than resolved against something", async () => {
    const stub = stubFetch(json({}));
    await expect(
      createFetchControlPlaneClient(stub.impl).send(
        { method: "GET", path: "admin/v1/tenants", query: [] },
        CONTEXT,
      ),
    ).rejects.toThrowError(/must be absolute/);
    expect(stub.calls).toHaveLength(0);
  });

  test("an unparseable endpoint fails in the usage class, not as a transport error", async () => {
    const stub = stubFetch(json({}));
    const error = await rejection(
      createFetchControlPlaneClient(stub.impl).send(GET, { ...CONTEXT, endpoint: "not a url" }),
    );
    expect(error).toBeInstanceOf(CliError);
    expect(error.exitCode()).toBe(exitCode("usage"));
  });

  test("identity headers, auth, tenant and content-type all reach the wire", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl).send(
      { method: "POST", path: "/admin/v1/tenants", query: [], body: { name: "acme" } },
      { ...CONTEXT, tenant: "t-1" },
    );
    const headers = stub.calls[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer sk-token");
    expect(headers["x-ferrogate-tenant"]).toBe("t-1");
    expect(headers["x-ferrogate-action-id"]).toBe("fgact_deadbeef");
    expect(headers.accept).toBe("application/json");
    expect(headers["content-type"]).toBe("application/json");
    expect(stub.calls[0]?.init.body).toBe('{"name":"acme"}');
  });

  test("an anonymous context simply omits the authorization header", async () => {
    const stub = stubFetch(json({}));
    const { token: _dropped, ...anonymous } = CONTEXT;
    await createFetchControlPlaneClient(stub.impl).send(GET, anonymous);
    const headers = stub.calls[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBeUndefined();
  });

  test("a body-less request sends no body and no content-type", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl).send(GET, CONTEXT);
    expect(stub.calls[0]?.init.body).toBeUndefined();
    expect((stub.calls[0]?.init.headers as Record<string, string>)["content-type"]).toBeUndefined();
  });

  test("a multipart upload sends FormData and no hand-set content-type", async () => {
    const stub = stubFetch(json({ id: "file-new" }));
    await createFetchControlPlaneClient(stub.impl).send(
      {
        method: "POST",
        path: "/v1/files",
        query: [],
        upload: {
          fields: [["purpose", "batch"]],
          file: {
            fieldName: "file",
            filename: "in.jsonl",
            bytes: new TextEncoder().encode('{"a":1}\n'),
          },
        },
      },
      CONTEXT,
    );
    const init = stub.calls[0]?.init;
    // The body is a FormData: `fetch` derives the multipart boundary from it, so
    // the client must NOT set content-type (a hand-set one omits the boundary).
    expect(init?.body).toBeInstanceOf(FormData);
    expect((init?.headers as Record<string, string>)["content-type"]).toBeUndefined();
    const form = init?.body as FormData;
    expect(form.get("purpose")).toBe("batch");
    const filePart = form.get("file");
    expect(filePart).toBeInstanceOf(Blob);
    expect(await (filePart as Blob).text()).toBe('{"a":1}\n');
  });

  test("`sendRaw` asks for the export media type, not JSON", async () => {
    const stub = stubFetch(new Response(new Uint8Array([1, 2, 3])));
    const result = await createFetchControlPlaneClient(stub.impl).sendRaw(
      { method: "GET", path: "/admin/v1/request-logs/export", query: [] },
      "text/csv",
      CONTEXT,
    );
    expect((stub.calls[0]?.init.headers as Record<string, string>).accept).toBe("text/csv");
    expect([...result.bytes]).toEqual([1, 2, 3]);
  });
});

describe("success classification", () => {
  test("correlation headers and the server time token are preserved", async () => {
    const stub = stubFetch(
      json(
        { data: [] },
        {
          headers: {
            "x-request-id": "req-1",
            "x-trace-id": "trace-1",
            "x-ferrogate-time-token": "v1;issued_at=1;ttl=60;action_id=fgact_deadbeef",
          },
        },
      ),
    );
    const response = await createFetchControlPlaneClient(stub.impl).send(GET, CONTEXT);
    expect(response.requestId).toBe("req-1");
    expect(response.traceId).toBe("trace-1");
    expect(response.timeToken).toBe("v1;issued_at=1;ttl=60;action_id=fgact_deadbeef");
  });

  test("an empty 204 body decodes to null, not to an empty string", async () => {
    const stub = stubFetch(new Response(null, { status: 204 }));
    const response = await createFetchControlPlaneClient(stub.impl).send(GET, CONTEXT);
    expect(response.body).toBeNull();
  });

  test("a 2xx with a non-JSON body is surfaced as a string, not dropped", () => {
    expect(decodeBody("plain text")).toBe("plain text");
    expect(decodeBody("   ")).toBeNull();
    expect(decodeBody('{"a":1}')).toEqual({ a: 1 });
  });
});

describe("failure classification drives the exit-code contract", () => {
  test.each([
    [401, "auth", 3],
    [403, "auth", 3],
    [404, "not_found_conflict", 4],
    [409, "not_found_conflict", 4],
    [400, "validation", 5],
    [422, "validation", 5],
    [402, "validation", 5],
    [429, "transport", 6],
    [408, "transport", 6],
    [500, "server", 7],
    [503, "server", 7],
  ])("HTTP %i exits %i", async (status, _class, code) => {
    const stub = stubFetch(() => json({ error: { code: "x", message: "m" } }, { status }));
    const error = await rejection(createFetchControlPlaneClient(stub.impl).send(GET, CONTEXT));
    expect(error).toBeInstanceOf(CliError);
    expect(error.exitCode()).toBe(code);
  });

  test("the server's own code and message survive verbatim", () => {
    const error = classifyFailure(
      409,
      new Headers(),
      JSON.stringify({ error: { code: "tenant_already_exists", message: "acme is taken" } }),
    );
    expect(error.api?.code).toBe("tenant_already_exists");
    expect(error.api?.message).toBe("acme is taken");
  });

  test("a codeless envelope gets the status-derived code, never 'unknown'", () => {
    expect(defaultCodeForStatus(401)).toBe("unauthorized");
    expect(defaultCodeForStatus(404)).toBe("not_found");
    expect(defaultCodeForStatus(422)).toBe("invalid_request");
    expect(defaultCodeForStatus(429)).toBe("retryable_error");
    expect(defaultCodeForStatus(500)).toBe("server_error");
    expect(classifyFailure(500, new Headers(), "{}").api?.code).toBe("server_error");
  });

  test("a non-JSON error body becomes the message rather than being thrown away", () => {
    expect(classifyFailure(502, new Headers(), "  upstream is down  ").api?.message).toBe(
      "upstream is down",
    );
    expect(classifyFailure(502, new Headers(), "").api?.message).toBe(
      "request failed with HTTP 502",
    );
  });

  test("Retry-After becomes the retry hint the diagnostic renderer prints", () => {
    const error = classifyFailure(429, new Headers({ "retry-after": " 30 " }), "{}");
    expect(error.api?.retryAfterSecs).toBe(30);
    // An HTTP-date Retry-After is not a second count; refuse to invent one.
    expect(
      classifyFailure(429, new Headers({ "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" }), "{}")
        .api?.retryAfterSecs,
    ).toBeUndefined();
  });

  test("the envelope's request_id is used when the edge stripped the header", () => {
    const body = JSON.stringify({ error: { code: "c", message: "m", request_id: "req-envelope" } });
    expect(classifyFailure(500, new Headers(), body).api?.requestId).toBe("req-envelope");
    expect(
      classifyFailure(500, new Headers({ "x-request-id": "req-header" }), body).api?.requestId,
    ).toBe("req-envelope");
  });

  test("every extra envelope field survives as details — resource detail is not dropped", () => {
    const error = classifyFailure(
      422,
      new Headers(),
      JSON.stringify({
        error: {
          code: "invalid_request",
          message: "bad",
          type: "validation_error",
          request_id: "r",
          field: "name",
          allowed_values: ["a", "b"],
        },
      }),
    );
    expect(error.api?.details).toEqual({ field: "name", allowed_values: ["a", "b"] });
  });

  test("an error with no extra fields carries no empty details blob", () => {
    const error = classifyFailure(
      404,
      new Headers(),
      JSON.stringify({ error: { code: "not_found", message: "gone" } }),
    );
    expect(error.api?.details).toBeUndefined();
  });

  test("a failed raw export is decoded as an envelope, not reported as an opaque status", async () => {
    const stub = stubFetch(() =>
      json({ error: { code: "export_window_too_large", message: "narrow it" } }, { status: 422 }),
    );
    const error = await rejection(
      createFetchControlPlaneClient(stub.impl).sendRaw(
        { method: "GET", path: "/admin/v1/x/export", query: [] },
        "text/csv",
        CONTEXT,
      ),
    );
    expect(error.api?.code).toBe("export_window_too_large");
    expect(error.api?.message).toBe("narrow it");
    expect(error.exitCode()).toBe(exitCode("validation"));
  });

  test("a socket failure is a transport error (exit 6), not a server error", async () => {
    const impl = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    const error = await rejection(createFetchControlPlaneClient(impl).send(GET, CONTEXT));
    expect(error.exitCode()).toBe(exitCode("transport"));
    expect(error.message).toContain("https://cp.example/admin/v1/tenants");
  });
});

describe("the timeout is armed and disarmed", () => {
  test("the abort signal is passed and the timer is cleared on success", async () => {
    vi.useFakeTimers();
    try {
      const stub = stubFetch(json({}));
      await createFetchControlPlaneClient(stub.impl).send(GET, CONTEXT);
      expect(stub.calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
      expect((stub.calls[0]?.init.signal as AbortSignal).aborted).toBe(false);
      // If the timer leaked, advancing past the deadline would abort a request
      // that already completed.
      vi.advanceTimersByTime(10_000);
      expect((stub.calls[0]?.init.signal as AbortSignal).aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// TLS policy — `--ca-bundle` / `--insecure-skip-tls-verify`
// ---------------------------------------------------------------------------

const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----\n";

describe("TLS policy is honoured, not decorative (#188)", () => {
  test("no TLS setting sends no tls option at all", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl, { honorsFetchTls: true }).send(GET, CONTEXT);
    expect(stub.calls[0]?.init.tls).toBeUndefined();
  });

  test("--insecure-skip-tls-verify reaches fetch as rejectUnauthorized:false", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl, { honorsFetchTls: true }).send(GET, {
      ...CONTEXT,
      tlsInsecureSkipVerify: true,
    });
    expect(stub.calls[0]?.init.tls).toEqual({ rejectUnauthorized: false });
  });

  test("a CA bundle is read and handed to fetch as the trust root", async () => {
    const stub = stubFetch(json({}));
    await createFetchControlPlaneClient(stub.impl, {
      honorsFetchTls: true,
      readFile: async (path) => (path === "/etc/corp.pem" ? CA_PEM : ""),
    }).send(GET, { ...CONTEXT, caBundlePath: "/etc/corp.pem" });
    expect(stub.calls[0]?.init.tls).toEqual({ ca: CA_PEM });
  });

  test("the bundle is read once and reused across an --all-pages walk", async () => {
    const stub = stubFetch(json({ data: [] }));
    const readFile = vi.fn(async () => CA_PEM);
    const client = createFetchControlPlaneClient(stub.impl, { honorsFetchTls: true, readFile });
    const context = { ...CONTEXT, caBundlePath: "/etc/corp.pem" };
    await client.send(GET, context);
    await client.send(GET, context);
    await client.send(GET, context);
    expect(readFile).toHaveBeenCalledTimes(1);
    expect(stub.calls).toHaveLength(3);
  });

  test("an unreadable bundle fails the command BEFORE the socket opens", async () => {
    const stub = stubFetch(json({}));
    const error = await rejection(
      createFetchControlPlaneClient(stub.impl, {
        honorsFetchTls: true,
        readFile: async () => {
          throw new Error("ENOENT");
        },
      }).send(GET, { ...CONTEXT, caBundlePath: "/nope.pem" }),
    );
    expect(error.message).toContain("failed to read CA bundle '/nope.pem'");
    expect(error.exitCode()).toBe(exitCode("usage"));
    // The refusal is the point: falling back to the system roots would connect
    // under a trust policy the operator explicitly replaced.
    expect(stub.calls).toHaveLength(0);
  });

  test("a bundle with no certificates is refused rather than silently ignored", async () => {
    const stub = stubFetch(json({}));
    const error = await rejection(
      createFetchControlPlaneClient(stub.impl, {
        honorsFetchTls: true,
        readFile: async () => "# just a comment\n",
      }).send(GET, { ...CONTEXT, caBundlePath: "/empty.pem" }),
    );
    expect(error.message).toContain("contains no certificates");
    expect(stub.calls).toHaveLength(0);
  });

  test("a malformed PEM block is refused as malformed, not as empty", () => {
    expect(() => assertPemBundle("/x.pem", "-----BEGIN CERTIFICATE-----\nabc\n")).toThrowError(
      /never closed by a matching/,
    );
    expect(() =>
      assertPemBundle("/x.pem", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
    ).toThrowError(/base64-encoded DER/);
    expect(() =>
      assertPemBundle("/x.pem", "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"),
    ).toThrowError(/base64-encoded DER/);
    expect(() => assertPemBundle("/x.pem", CA_PEM)).not.toThrow();
    expect(() => assertPemBundle("/x.pem", `${CA_PEM}${CA_PEM}`)).not.toThrow();
  });

  test("a runtime whose fetch ignores tls REFUSES instead of connecting either way", async () => {
    const stub = stubFetch(json({}));
    const client = createFetchControlPlaneClient(stub.impl, { honorsFetchTls: false });

    const skip = await rejection(client.send(GET, { ...CONTEXT, tlsInsecureSkipVerify: true }));
    expect(skip.message).toContain("tls_insecure_skip_verify");
    expect(skip.message).toContain("ignores per-request TLS options");
    expect(skip.exitCode()).toBe(exitCode("usage"));

    const bundle = await rejection(client.send(GET, { ...CONTEXT, caBundlePath: "/etc/corp.pem" }));
    expect(bundle.message).toContain("ca_bundle_path '/etc/corp.pem'");

    // Neither request was sent: silently verifying a connection the operator
    // asked NOT to verify (or vice versa) is the lie this branch prevents.
    expect(stub.calls).toHaveLength(0);
  });

  test("the same policy governs the legacy assets/plans gateway client", async () => {
    const stub = stubFetch(new Response(new Uint8Array([9])));
    await createFetchGatewayClient(stub.impl, { honorsFetchTls: true }).send(
      { method: "GET", path: "/v1/assets", query: [] },
      { ...CONTEXT, tlsInsecureSkipVerify: true },
    );
    expect(stub.calls[0]?.init.tls).toEqual({ rejectUnauthorized: false });

    const refusing = createFetchGatewayClient(stub.impl, { honorsFetchTls: false });
    await expect(
      refusing.send(
        { method: "GET", path: "/v1/assets", query: [] },
        { ...CONTEXT, tlsInsecureSkipVerify: true },
      ),
    ).rejects.toThrowError(/ignores per-request TLS options/);
    expect(stub.calls).toHaveLength(1);
  });
});

describe("the shipped runtime wires the real transports", () => {
  test("`ctl` on the default runtime reaches fetch, not the in-memory fake", async () => {
    // The composition-root check: if `createDefaultRuntime` ever regressed to
    // `createInMemoryControlPlaneClient`, this command would succeed offline.
    const original = globalThis.fetch;
    const seen: string[] = [];
    globalThis.fetch = (async (url: string | URL | Request) => {
      seen.push(String(url));
      return json({ status: "ok" });
    }) as unknown as typeof fetch;
    try {
      const { createDefaultRuntime } = await import("../src/index.js");
      const runtime = createDefaultRuntime();
      const io = createTestRuntime().io;
      const code = await main(["ops", "status", "--endpoint", "https://real.example"], {
        ...runtime,
        // Keep stdout/stderr and the context store in memory; the CLIENT stays
        // the production one, which is what this test is about.
        io: { ...io, env: {} },
        contextStorage: createTestRuntime().contextStorage,
      });
      expect(code).toBe(0);
      expect(seen).toHaveLength(1);
      expect(seen[0]).toContain("https://real.example");
    } finally {
      globalThis.fetch = original;
    }
  });
});
