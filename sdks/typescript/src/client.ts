/**
 * The FerroGate Control Plane API client.
 *
 * ## Why this is ~200 lines and not 209 methods
 *
 * The control plane is 209 operations (`docs/rewrite/ROUTE-MAP.md`), and the
 * contract that describes them — `docs/openapi/admin-api.openapi.json` — is
 * machine-readable and already the source of truth for the console's types and
 * for `scripts/check-openapi.py`. Hand-writing a method per operation would
 * produce ~209 places for the client to drift from the server, all of which a
 * generator keeps in step for free.
 *
 * So the SHAPE of every request and response is GENERATED
 * (`src/api-types.generated.ts`, `openapi-typescript` 7.13.0 — the version
 * `tools/openapi-client-smoke` and `admin-console` already pin) and the
 * BEHAVIOUR that a generator cannot know is hand-written here:
 *
 *  - the base URL, and the `/admin/v1` ⇄ `/control/v1` alias (issue #453);
 *  - the credential: `Authorization: Bearer` or `x-api-key`, exactly the two
 *    `apps/control-plane/src/middleware/auth.ts` accepts;
 *  - the tenant header a platform-operator credential uses to act on one
 *    tenant (`x-ferrogate-tenant`);
 *  - decoding the error envelope into a typed exception (`./errors.ts`);
 *  - a request deadline, because `fetch` has none by default and a hung admin
 *    call in a deploy script is indistinguishable from a slow one.
 *
 * Everything else — path templating, query serialization, JSON encoding, and
 * the per-operation response types — is `openapi-fetch` 0.17.0, also already
 * pinned in `tools/openapi-client-smoke`. Nothing new enters the dependency
 * closure of the repo for this SDK.
 *
 * ## Usage
 *
 * ```ts
 * // The credential is always an ARGUMENT — this client never reads ambient
 * // process state, so the same code authenticates identically in a Worker, in
 * // Bun and in Node (`test/source-hygiene.test.ts`).
 * const client = createAdminClient({
 *   baseUrl: "https://gateway.example.com",
 *   token: await readOperatorToken(),
 * });
 *
 * // Typed both ways; `data` is the operation's own 200 schema.
 * const tenants = await unwrap(client.GET("/admin/v1/tenants", {
 *   params: { query: { limit: 50 } },
 * }));
 *
 * try {
 *   await unwrap(client.DELETE("/admin/v1/tenants/{tenant_id}", {
 *     params: { path: { tenant_id: "t_1" } },
 *   }));
 * } catch (error) {
 *   if (isFerrogateApiError(error) && error.code === "scope_denied") { … }
 * }
 * ```
 */
import createClient, { type Client, type Middleware } from "openapi-fetch";
import type { paths } from "./api-types.generated.js";
import { FerrogateTransportError, apiErrorFrom } from "./errors.js";

/** The two URI prefixes the same stable surface is served under (#453). */
export type ControlPlanePrefix = "/admin/v1" | "/control/v1";

export interface AdminClientOptions {
  /**
   * Origin the control plane is served on, e.g. `https://gateway.example.com`.
   * A trailing slash is tolerated; a path component is not stripped, so a
   * deployment behind `https://host/ferrogate` works.
   */
  readonly baseUrl: string;
  /** Bearer credential. Mutually exclusive with {@link apiKey}. */
  readonly token?: string;
  /**
   * `x-api-key` credential. The control plane accepts either and prefers
   * `x-api-key` when BOTH are present (`middleware/auth.ts::extractApiKey`),
   * so this client refuses to send both rather than let that precedence decide
   * silently which credential a request was made with.
   */
  readonly apiKey?: string;
  /** `x-ferrogate-tenant` — the tenant a platform-operator call acts on. */
  readonly tenant?: string;
  /** Extra headers on every request (e.g. `x-ferrogate-action-id`). */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Serve `/admin/v1` operations under the canonical `/control/v1` alias.
   * Both dispatch to one operation set — `docs/openapi/COMPATIBILITY.md`
   * documents the normalization — so this changes the URL and nothing else.
   * Defaults to `/admin/v1`, the prefix the generated paths carry.
   */
  readonly prefix?: ControlPlanePrefix;
  /** Injected `fetch` (a test double, an agent-bound fetch, a Worker binding). */
  readonly fetch?: typeof globalThis.fetch;
  /** Deadline in milliseconds. `0` disables it. Defaults to 30_000. */
  readonly timeoutMs?: number;
}

/** The generated client type, exported so callers can name it. */
export type AdminClient = Client<paths>;

const DEFAULT_TIMEOUT_MS = 30_000;

function credentialHeaders(options: AdminClientOptions): Record<string, string> {
  if (options.token !== undefined && options.apiKey !== undefined) {
    throw new TypeError(
      "createAdminClient: pass `token` or `apiKey`, not both — the server prefers " +
        "x-api-key when both are sent, which would silently decide which credential " +
        "authenticated the request",
    );
  }
  if (options.token !== undefined) return { authorization: `Bearer ${options.token}` };
  if (options.apiKey !== undefined) return { "x-api-key": options.apiKey };
  return {};
}

function validateCredentialHeaders(
  headers: Headers,
  configured: Readonly<Record<string, string>>,
): void {
  const authorization = headers.get("authorization");
  const apiKey = headers.get("x-api-key");

  if (authorization !== null && apiKey !== null) {
    throw new TypeError("request headers cannot contain both authorization and x-api-key");
  }

  for (const [name, expected] of Object.entries(configured)) {
    const received = headers.get(name);
    if (received !== null && received !== expected) {
      throw new TypeError(`request header ${name} conflicts with the configured SDK credential`);
    }
  }

  if (configured.authorization !== undefined && apiKey !== null) {
    throw new TypeError("request header x-api-key conflicts with the configured bearer credential");
  }
  if (configured["x-api-key"] !== undefined && authorization !== null) {
    throw new TypeError("request header authorization conflicts with the configured API key");
  }
}

/**
 * Rewrite `/admin/v1/**` to the configured prefix.
 *
 * Applied to the REQUEST URL rather than to the generated path keys, so the
 * types a caller writes against never change with the alias.
 */
function withPrefix(url: string, prefix: ControlPlanePrefix): string {
  if (prefix === "/admin/v1") return url;
  const parsed = new URL(url);
  const marker = "/admin/v1";
  const markerIndex = parsed.pathname.indexOf(marker);
  if (markerIndex < 0) return url;
  const boundary = parsed.pathname[markerIndex + marker.length];
  if (boundary !== undefined && boundary !== "/") {
    return url;
  }
  parsed.pathname =
    parsed.pathname.slice(0, markerIndex) + prefix + parsed.pathname.slice(markerIndex + marker.length);
  return parsed.toString();
}

/**
 * A `fetch` that aborts at the deadline and reports transport failures as
 * {@link FerrogateTransportError} rather than as a bare `TypeError`.
 *
 * A caller's own `signal` still wins: `AbortSignal.any` is used when the
 * runtime has it (workerd, Node 20+, Bun), and the deadline alone otherwise.
 */
function deadlineFetch(
  base: typeof globalThis.fetch,
  timeoutMs: number,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    if (timeoutMs <= 0) {
      try {
        return await base(request);
      } catch (error) {
        throw transportError(request.url, error);
      }
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("request deadline exceeded"));
      }, timeoutMs);
    });
    try {
      const signal =
        typeof AbortSignal.any === "function"
          ? AbortSignal.any([request.signal, controller.signal])
          : controller.signal;
      // Abort compliant fetch implementations and release callers whose
      // injected fetch does not observe AbortSignal.
      //
      // The signal rides in BOTH places on purpose. `new Request(request,
      // { signal })` hands undici a signal it tracks through an internal
      // DEPENDENT signal, and that link is weakly held — under GC pressure the
      // dependent signal is collected and an injected fetch reading
      // `input.signal` never observes the abort (seen as a
      // once-in-several-runs flake in `test/client.test.ts`). `init.signal`
      // is the same signal by strong reference; a real fetch treats it as the
      // override it already equals, and an injected fetch gets a delivery
      // that cannot be collected out from under it.
      return await Promise.race([base(new Request(request, { signal }), { signal }), timeout]);
    } catch (error) {
      if (controller.signal.aborted) {
        throw new FerrogateTransportError(
          request.url,
          `request to ${request.url} timed out after ${timeoutMs}ms`,
          { cause: error },
        );
      }
      throw transportError(request.url, error);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
}

function transportError(url: string, error: unknown): FerrogateTransportError {
  if (error instanceof FerrogateTransportError) return error;
  const detail = error instanceof Error ? error.message : String(error);
  return new FerrogateTransportError(url, `request to ${url} failed: ${detail}`, { cause: error });
}

/**
 * Build a client for the control plane.
 *
 * The returned value IS an `openapi-fetch` client: every operation in
 * `docs/openapi/admin-api.openapi.json` is reachable as
 * `client.GET("/admin/v1/…", …)` with the operation's own parameter and
 * response types, and `client.use()` accepts further middleware.
 */
export function createAdminClient(options: AdminClientOptions): AdminClient {
  const prefix = options.prefix ?? "/admin/v1";
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const configuredCredentials = credentialHeaders(options);
  validateCredentialHeaders(
    new Headers(options.headers as Record<string, string> | undefined),
    configuredCredentials,
  );

  const client = createClient<paths>({
    baseUrl,
    headers: { accept: "application/json", ...configuredCredentials, ...options.headers },
    fetch: deadlineFetch(fetchImpl, timeoutMs),
  });

  const alias: Middleware = {
    onRequest({ request }) {
      const rewritten = withPrefix(request.url, prefix);
      return rewritten === request.url ? undefined : new Request(rewritten, request);
    },
  };

  const tenantHeader: Middleware = {
    onRequest({ request }) {
      if (options.tenant === undefined) return undefined;
      request.headers.set("x-ferrogate-tenant", options.tenant);
      return request;
    },
  };

  const credentialGuard: Middleware = {
    onRequest({ request }) {
      validateCredentialHeaders(request.headers, configuredCredentials);
      return undefined;
    },
  };

  /**
   * The reason a caller never has to look at `response.ok`.
   *
   * Throwing HERE rather than in {@link unwrap} means the exception is raised
   * for every call — including one made through `client.GET(...)` directly, or
   * through a caller's own middleware chain — so there is exactly one failure
   * path in the SDK and it cannot be bypassed by forgetting a helper.
   */
  const throwOnError: Middleware = {
    async onResponse({ response }) {
      if (response.ok) return undefined;
      throw apiErrorFrom(response.status, response.headers, await response.clone().text());
    },
  };

  client.use(alias, tenantHeader, credentialGuard, throwOnError);
  return client;
}

/**
 * Take the `data` of a successful call.
 *
 * `openapi-fetch` answers `{ data, error, response }`, and `data` is typed
 * `T | undefined` because the error arm exists. This client never populates the
 * error arm (see `throwOnError`), so `unwrap` narrows it away while KEEPING the
 * per-operation type — the generic is inferred at the call site, which a
 * wrapper method per verb could not do without collapsing every path to
 * `unknown`.
 *
 * A 204 answers `undefined`, which is the operation's own type.
 */
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data } = await call;
  return data as T;
}
