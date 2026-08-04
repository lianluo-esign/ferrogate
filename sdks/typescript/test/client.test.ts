/**
 * The admin SDK against a STUB transport.
 *
 * No server, no account, no credential: every case injects a `fetch` and reads
 * the `Request` the client built, or hands back a `Response` and reads the
 * value/exception the client produced. That is the whole contract of a thin
 * client — what goes on the wire, and what comes back off it.
 *
 * The operations used below (`/admin/v1/projects`,
 * `/admin/v1/plugins/{plugin_id}`) are real entries in the generated types, so
 * these cases are also the proof that the generated surface is wired: a typo in
 * a path, a missing query parameter or a wrong body shape is a TYPE error here,
 * which is exactly the class of bug a hand-written client ships to production.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  FerrogateApiError,
  FerrogateTransportError,
  createAdminClient,
  isFerrogateApiError,
  unwrap,
} from "../src/index.js";

/** Requests the stub saw, in order. */
let seen: Request[] = [];

beforeEach(() => {
  seen = [];
});

/** A `fetch` that records the request and answers `response`. */
function stub(response: Response | ((request: Request) => Response | Promise<Response>)) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input as string, init);
    seen.push(request.clone());
    return typeof response === "function" ? await response(request) : response.clone();
  };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

const PROJECT_LIST = {
  object: "list" as const,
  data: [{ id: "proj_1", tenant_id: "t_1", name: "Example", slug: "example" }],
  total: 1,
};

describe("createAdminClient — the request it builds", () => {
  it("joins the base URL, templates the path and serializes the query", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com/",
      token: "fg_admin_token",
      fetch: stub(json(PROJECT_LIST)),
    });

    const page = await unwrap(
      client.GET("/admin/v1/projects", {
        params: { query: { tenant_id: "t_1", limit: 50 } },
      }),
    );

    // Typed: `data` is `AdminProject[]`, not `unknown`.
    expect(page.data[0]?.slug).toBe("example");

    const request = seen[0] as Request;
    // The trailing slash on `baseUrl` did not produce `//admin/v1`.
    expect(new URL(request.url).pathname).toBe("/admin/v1/projects");
    expect(new URL(request.url).searchParams.get("tenant_id")).toBe("t_1");
    expect(new URL(request.url).searchParams.get("limit")).toBe("50");
    expect(request.method).toBe("GET");
  });

  it("sends the bearer credential, and `x-api-key` when that is the credential", async () => {
    const bearer = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "fg_admin_token",
      fetch: stub(json(PROJECT_LIST)),
    });
    await unwrap(bearer.GET("/admin/v1/projects", {}));
    expect((seen[0] as Request).headers.get("authorization")).toBe("Bearer fg_admin_token");
    expect((seen[0] as Request).headers.get("x-api-key")).toBeNull();

    const keyed = createAdminClient({
      baseUrl: "https://gateway.example.com",
      apiKey: "fg_admin_key",
      fetch: stub(json(PROJECT_LIST)),
    });
    await unwrap(keyed.GET("/admin/v1/projects", {}));
    expect((seen[1] as Request).headers.get("x-api-key")).toBe("fg_admin_key");
    expect((seen[1] as Request).headers.get("authorization")).toBeNull();
  });

  it("REFUSES both credentials rather than letting the server's precedence decide", () => {
    // `extractApiKey` prefers `x-api-key`, so sending both would silently
    // authenticate with one and leave the caller believing it used the other.
    expect(() =>
      createAdminClient({
        baseUrl: "https://gateway.example.com",
        token: "fg_admin_token",
        apiKey: "fg_admin_key",
      }),
    ).toThrow(TypeError);
  });

  it("carries the tenant header and any caller-supplied headers", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      tenant: "tenant_42",
      headers: { "x-ferrogate-action-id": "act_7" },
      fetch: stub(json(PROJECT_LIST)),
    });

    await unwrap(client.GET("/admin/v1/projects", {}));

    const request = seen[0] as Request;
    expect(request.headers.get("x-ferrogate-tenant")).toBe("tenant_42");
    expect(request.headers.get("x-ferrogate-action-id")).toBe("act_7");
    expect(request.headers.get("accept")).toBe("application/json");
  });

  it("serializes a JSON body with its content type", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(json({ id: "proj_2" }, 201)),
    });

    await unwrap(
      client.POST("/admin/v1/projects", {
        body: { tenant_id: "t_1", name: "Second", slug: "second" },
      }),
    );

    const request = seen[0] as Request;
    expect(request.method).toBe("POST");
    expect(request.headers.get("content-type")).toContain("application/json");
    expect(await request.json()).toEqual({ tenant_id: "t_1", name: "Second", slug: "second" });
  });

  it("serves the same operation under the /control/v1 alias when asked", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      prefix: "/control/v1",
      fetch: stub(json(PROJECT_LIST)),
    });

    await unwrap(client.GET("/admin/v1/projects", { params: { query: { limit: 10 } } }));

    // ONLY the prefix moved: the query and the rest of the path are untouched,
    // and the caller wrote the generated `/admin/v1/...` key either way.
    const url = new URL((seen[0] as Request).url);
    expect(url.pathname).toBe("/control/v1/projects");
    expect(url.searchParams.get("limit")).toBe("10");
  });
});

describe("createAdminClient — the errors it raises", () => {
  it("decodes the FerroGate envelope into a typed error", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(
        json(
          {
            error: {
              message: "credential lacks admin.write",
              type: "ferrogate_error",
              code: "scope_denied",
              request_id: "fg-body-id",
              required_scope: "admin.write",
            },
          },
          403,
          { "x-request-id": "fg-header-id", "x-trace-id": "trace-9" },
        ),
      ),
    });

    const error = await client
      .GET("/admin/v1/projects", {})
      .then(() => null)
      .catch((raised: unknown) => raised);

    expect(isFerrogateApiError(error)).toBe(true);
    const api = error as FerrogateApiError;
    expect(api.status).toBe(403);
    expect(api.code).toBe("scope_denied");
    expect(api.message).toBe("credential lacks admin.write");
    // The HEADER wins over the body: an edge that rewrites the id is the
    // authority on what the operator will find in the log.
    expect(api.requestId).toBe("fg-header-id");
    expect(api.traceId).toBe("trace-9");
    // Everything beyond the four envelope members survives — this is the
    // resource-specific detail a caller cannot reconstruct from `code` alone.
    expect(api.details).toEqual({ required_scope: "admin.write" });
  });

  it("falls back to the envelope's request_id when the header was stripped", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(
        json(
          {
            error: {
              message: "nope",
              type: "ferrogate_error",
              code: "not_found",
              request_id: "fg-body-only",
            },
          },
          404,
        ),
      ),
    });

    const error = (await client
      .GET("/admin/v1/projects", {})
      .catch((raised: unknown) => raised)) as FerrogateApiError;

    expect(error.requestId).toBe("fg-body-only");
  });

  it("types a NON-JSON error body instead of throwing a SyntaxError", async () => {
    // The load-balancer 502. A client that cannot survive this is not usable
    // behind any real edge, and `JSON.parse` on it throws by default.
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(
        new Response("<html><title>502 Bad Gateway</title></html>", {
          status: 502,
          headers: { "content-type": "text/html" },
        }),
      ),
    });

    const error = (await client
      .GET("/admin/v1/projects", {})
      .catch((raised: unknown) => raised)) as FerrogateApiError;

    expect(error).toBeInstanceOf(FerrogateApiError);
    expect(error.status).toBe(502);
    // No `code` in the body ⇒ the status-derived fallback, so a caller can
    // still switch on `code` for a response FerroGate never wrote.
    expect(error.code).toBe("server_error");
    expect(error.message).toContain("502 Bad Gateway");
    expect(error.body).toBe("<html><title>502 Bad Gateway</title></html>");
  });

  it("types an EMPTY error body and reads Retry-After", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(new Response("", { status: 429, headers: { "retry-after": "12" } })),
    });

    const error = (await client
      .GET("/admin/v1/projects", {})
      .catch((raised: unknown) => raised)) as FerrogateApiError;

    expect(error.status).toBe(429);
    expect(error.code).toBe("retryable_error");
    expect(error.message).toBe("request failed with HTTP 429");
    expect(error.retryAfterSeconds).toBe(12);
  });

  it("reports a transport failure as FerrogateTransportError, not as a bare TypeError", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: () => Promise.reject(new TypeError("fetch failed")),
    });

    const error = (await client
      .GET("/admin/v1/projects", {})
      .catch((raised: unknown) => raised)) as FerrogateTransportError;

    expect(error).toBeInstanceOf(FerrogateTransportError);
    expect(error.url).toContain("/admin/v1/projects");
    expect(error.message).toContain("fetch failed");
  });

  /**
   * The per-test timeout is raised, and the number under test is NOT.
   *
   * This is the only test in the file whose subject is a WALL-CLOCK deadline: it
   * hands the client a `fetch` that never settles and asserts the client aborts
   * itself. Everything else here resolves synchronously. Run alone it finishes in
   * ~240 ms, but `bun run test` fans 24 workspace packages out at once, and on a
   * loaded machine the 20 ms timer can be delivered late enough to eat vitest's
   * 5 s default — a green suite locally and a red one under load, which is the
   * worst signal a gate can give.
   *
   * Raising the BUDGET is not the same as loosening the ASSERTION: the client
   * still gets `timeoutMs: 20`, still has to abort, and still has to report
   * "timed out after 20ms". A client that genuinely hangs fails here exactly as
   * before, 30 s later instead of 5 s later. Raising `timeoutMs` instead would
   * have been the loosening, because it would move the number being tested.
   */
  it("aborts at the deadline rather than hanging forever", { timeout: 30_000 }, async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      timeoutMs: 20,
      fetch: (input, init) =>
        new Promise((_resolve, reject) => {
          const signal = (init?.signal ?? (input as Request).signal) as AbortSignal | undefined;
          signal?.addEventListener("abort", () => {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        }),
    });

    const error = (await client
      .GET("/admin/v1/projects", {})
      .catch((raised: unknown) => raised)) as FerrogateTransportError;

    expect(error).toBeInstanceOf(FerrogateTransportError);
    expect(error.message).toContain("timed out after 20ms");
  });

  it("answers `undefined` for a 204 rather than failing to parse it", async () => {
    const client = createAdminClient({
      baseUrl: "https://gateway.example.com",
      token: "t",
      fetch: stub(new Response(null, { status: 204 })),
    });

    await expect(
      unwrap(
        client.DELETE("/admin/v1/plugins/{plugin_id}", {
          params: { path: { plugin_id: "plug_1" } },
        }),
      ),
    ).resolves.toBeUndefined();

    expect(new URL((seen[0] as Request).url).pathname).toBe("/admin/v1/plugins/plug_1");
  });
});
