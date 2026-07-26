import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import { ApiError, type ApiErrorBody } from "@/types/auth";
import type { components, paths } from "@/lib/api-types.generated";

export interface AdminPage<T> {
  data: T[];
  total: number;
  offset: number;
  limit: number;
}

// ---------------------------------------------------------------------------
// Typed layer over the generated OpenAPI contract (#314).
//
// `src/lib/api-types.generated.ts` is generated from
// docs/openapi/admin-api.openapi.json via `npm run generate:api`. The helpers
// below are generic over those `paths`/`components`, so a contract change
// that the console doesn't handle becomes a TYPE ERROR at `npm run build`.
//
// Exemplar adopters: tenant-accounts, plans, virtual-keys (see
// src/resources/*.ts). New/migrated pages should call `adminGet`/`adminPost`/
// etc. with a contract path literal instead of the legacy untyped
// `gatewayGet`/`gatewayPost` helpers further down (kept for resources that
// haven't migrated yet; each UI slice migrates its own).
// ---------------------------------------------------------------------------

/** Named schema from the Admin API contract, e.g. `AdminSchema<"AdminPlan">`. */
export type AdminSchema<K extends keyof components["schemas"]> =
  components["schemas"][K];

type HttpMethod = "get" | "post" | "put" | "patch" | "delete";

/** Contract paths that implement a given method (template form, e.g. "/admin/v1/plans/{plan_id}"). */
export type AdminPathWith<M extends HttpMethod> = {
  [P in keyof paths]: paths[P] extends Record<M, unknown> ? P : never;
}[keyof paths];

export type OpFor<P extends keyof paths, M extends HttpMethod> =
  paths[P] extends Record<M, infer Op> ? Op : never;

type SuccessCode = 200 | 201 | 202 | 204;

/** JSON body of the operation's 2xx response (undefined for 204-style ops). */
type SuccessBody<Op> = Op extends { responses: infer R }
  ? {
      [S in Extract<keyof R, SuccessCode>]: R[S] extends {
        content: { "application/json": infer B };
      }
        ? B
        : undefined;
    }[Extract<keyof R, SuccessCode>]
  : never;

/** JSON request body the operation accepts (never for body-less ops). */
type JsonRequestBody<Op> = Op extends {
  requestBody: { content: { "application/json": infer B } };
}
  ? B
  : Op extends { requestBody?: { content: { "application/json": infer B } } }
    ? B | undefined
    : never;

export type PathParamsFor<Op> = Op extends { parameters: { path: infer PP } }
  ? PP extends Record<string, string | number>
    ? PP
    : never
  : never;

/** Typed header parameters an operation declares (all optional in the contract),
 * with the surrounding optionality stripped so callers can name them exactly. */
export type HeaderParamsFor<Op> = Op extends {
  parameters: { header?: infer H };
}
  ? NonNullable<H>
  : never;

type QueryFor<Op> = Op extends { parameters: { query?: infer Q } }
  ? Q extends Record<string, unknown>
    ? Q
    : never
  : never;

interface TypedRequestOptions<Op> {
  /** Values substituted into `{placeholder}` segments of the path template. */
  params?: PathParamsFor<Op>;
  query?: QueryFor<Op>;
  signal?: AbortSignal;
}

/** Substitutes `{name}` placeholders; throws if a placeholder has no value. */
function resolvePathTemplate(
  template: string,
  params?: Record<string, string | number>,
): string {
  return template.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = params?.[name];
    if (value === undefined) {
      throw new Error(`missing path parameter "${name}" for ${template}`);
    }
    return encodeURIComponent(String(value));
  });
}

/**
 * Resolves a typed contract path template into a request path, applying the
 * same `encodeURIComponent` substitution the `admin*` helpers use. Intended for
 * the rare caller that must run its OWN transport — e.g. an XHR upload-progress
 * shim, since `fetch` exposes no upload-progress event — yet should still derive
 * its URL from the generated contract (a `keyof paths` literal) rather than a
 * hand-built string. Annotate the `params` argument with `PathParamsFor<Op>` at
 * the call site to have the placeholder names checked against the contract.
 */
export function resolveAdminPath(
  path: keyof paths & string,
  params: Record<string, string | number>,
): string {
  return resolvePathTemplate(path, params);
}

function typedRequest<P extends keyof paths & string, M extends HttpMethod>(
  method: M,
  apiKey: string,
  path: P,
  options?: TypedRequestOptions<OpFor<P, M>>,
  body?: unknown,
): Promise<SuccessBody<OpFor<P, M>>> {
  return gatewayRequest(
    resolvePathTemplate(path, options?.params as Record<string, string | number> | undefined),
    {
      method: method.toUpperCase(),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    },
    apiKey,
    {
      query: options?.query as GatewayRequestOptions["query"],
      signal: options?.signal,
    },
  );
}

export function adminGet<P extends AdminPathWith<"get"> & string>(
  apiKey: string,
  path: P,
  options?: TypedRequestOptions<OpFor<P, "get">>,
): Promise<SuccessBody<OpFor<P, "get">>> {
  return typedRequest("get", apiKey, path, options);
}

export function adminPost<P extends AdminPathWith<"post"> & string>(
  apiKey: string,
  path: P,
  body: JsonRequestBody<OpFor<P, "post">>,
  options?: TypedRequestOptions<OpFor<P, "post">>,
): Promise<SuccessBody<OpFor<P, "post">>> {
  return typedRequest("post", apiKey, path, options, body);
}

export function adminPut<P extends AdminPathWith<"put"> & string>(
  apiKey: string,
  path: P,
  body: JsonRequestBody<OpFor<P, "put">>,
  options?: TypedRequestOptions<OpFor<P, "put">>,
): Promise<SuccessBody<OpFor<P, "put">>> {
  return typedRequest("put", apiKey, path, options, body);
}

export function adminPatch<P extends AdminPathWith<"patch"> & string>(
  apiKey: string,
  path: P,
  body: JsonRequestBody<OpFor<P, "patch">>,
  options?: TypedRequestOptions<OpFor<P, "patch">>,
): Promise<SuccessBody<OpFor<P, "patch">>> {
  return typedRequest("patch", apiKey, path, options, body);
}

export function adminDelete<P extends AdminPathWith<"delete"> & string>(
  apiKey: string,
  path: P,
  options?: TypedRequestOptions<OpFor<P, "delete">>,
): Promise<SuccessBody<OpFor<P, "delete">>> {
  return typedRequest("delete", apiKey, path, options);
}

// ---------------------------------------------------------------------------
// Legacy untyped helpers. Prefer the typed `admin*` functions above for new
// code; these remain for resources whose UI slice hasn't migrated yet.
// ---------------------------------------------------------------------------

export interface GatewayRequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: GatewayRequestOptions["query"]): string {
  const url = new URL(path, GATEWAY_ADMIN_BASE_URL);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function gatewayRequest<T>(
  path: string,
  init: RequestInit,
  apiKey: string,
  options?: GatewayRequestOptions,
): Promise<T> {
  let signal = options?.signal;
  if (signal) {
    try {
      // Embedded/test DOMs can expose Request and AbortSignal from different
      // realms. Browsers accept this path; incompatible realms must not turn
      // an otherwise valid Admin API request into a synchronous TypeError.
      new Request("data:,", { signal });
    } catch {
      signal = undefined;
    }
  }
  const response = await fetch(buildUrl(path, options?.query), {
    ...init,
    signal,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      ...init.headers,
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const body = await response.json().catch(() => null);

  if (!response.ok) {
    const errorBody = body as ApiErrorBody | null;
    throw new ApiError(
      response.status,
      errorBody?.error?.code ?? "unknown_error",
      errorBody?.error?.message ?? response.statusText,
    );
  }

  return body as T;
}

export function gatewayGet<T>(
  apiKey: string,
  path: string,
  options?: GatewayRequestOptions,
): Promise<T> {
  return gatewayRequest<T>(path, { method: "GET" }, apiKey, options);
}

export function gatewayPost<T>(
  apiKey: string,
  path: string,
  body?: unknown,
): Promise<T> {
  return gatewayRequest<T>(
    path,
    { method: "POST", body: body !== undefined ? JSON.stringify(body) : undefined },
    apiKey,
  );
}

export function gatewayPut<T>(
  apiKey: string,
  path: string,
  body?: unknown,
): Promise<T> {
  return gatewayRequest<T>(
    path,
    { method: "PUT", body: body !== undefined ? JSON.stringify(body) : undefined },
    apiKey,
  );
}

export function gatewayPatch<T>(
  apiKey: string,
  path: string,
  body?: unknown,
): Promise<T> {
  return gatewayRequest<T>(
    path,
    { method: "PATCH", body: body !== undefined ? JSON.stringify(body) : undefined },
    apiKey,
  );
}

export function gatewayDelete<T>(apiKey: string, path: string): Promise<T> {
  return gatewayRequest<T>(path, { method: "DELETE" }, apiKey);
}

/**
 * Uploads raw bytes (not JSON) to a `/v1/assets/*`-shaped endpoint (issue
 * #178): unlike every other gateway-client call, the body here is the
 * file's own bytes with its own Content-Type, not a JSON payload, so this
 * bypasses `gatewayRequest`'s JSON-serialize-and-set-application/json
 * behavior entirely rather than trying to make one function cover both
 * shapes.
 */
export async function gatewayPutBinary<T>(
  apiKey: string,
  path: string,
  body: Blob,
  contentType: string,
  // #345: static-site publishing rides the same raw-bytes PUT as any asset but
  // carries its serving policy in `x-site-*` request headers (public opt-in,
  // SPA fallback, Cache-Control override). Optional so every existing caller is
  // unchanged; empty/undefined values are dropped so we never send blanks.
  extraHeaders?: Record<string, string | undefined>,
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": contentType || "application/octet-stream",
  };
  if (extraHeaders) {
    for (const [key, value] of Object.entries(extraHeaders)) {
      if (value !== undefined && value !== "") headers[key] = value;
    }
  }
  const response = await fetch(buildUrl(path), {
    method: "PUT",
    headers,
    body,
  });
  const responseBody = await response.json().catch(() => null);
  if (!response.ok) {
    const errorBody = responseBody as ApiErrorBody | null;
    throw new ApiError(
      response.status,
      errorBody?.error?.code ?? "unknown_error",
      errorBody?.error?.message ?? response.statusText,
    );
  }
  return responseBody as T;
}

/**
 * Headers the browser refuses to let `fetch` set (Fetch spec "forbidden header
 * names"). `content-length` is in the intent's `required_headers` because the
 * SigV4 signature binds it, but a browser derives it from the body and silently
 * drops any explicit value — so we must NOT try to send it, and instead assert
 * the body length matches what was signed. Node/CLI clients that can set it
 * should send it verbatim.
 */
const BROWSER_FORBIDDEN_UPLOAD_HEADERS = new Set(["content-length", "host"]);

/**
 * PUTs raw bytes DIRECTLY to a presigned bucket URL (the large-object path,
 * #338/#259). Unlike every other helper here this does NOT target the gateway
 * and sends NO gateway `Authorization` header: the presigned URL already
 * carries its own signed authorization in its query string, and the whole
 * point of the flow is to keep a large bundle's bytes off the gateway body.
 * The gateway later verifies size + SHA-256 at the commit step. Bucket errors
 * (often XML, not our JSON envelope) surface verbatim as the thrown message.
 *
 * #368: the presigned URL now signs `content-length` and
 * `x-amz-content-sha256` as SigV4 `SignedHeaders`, so a PUT that omits them is
 * rejected by the bucket with 403. `requiredHeaders` is the intent's
 * `required_headers` map and MUST be forwarded verbatim; passing it is not
 * optional against a real bucket. Two browser-specific consequences:
 *
 * - `content-length` cannot be set from `fetch`, so it is filtered out and the
 *   body length is asserted against the signed value instead — a mismatch is a
 *   guaranteed 403 and is worth failing on locally with a legible message.
 * - the bucket's CORS policy must list `x-amz-content-sha256` in
 *   `Access-Control-Allow-Headers`, or the preflight fails before the PUT.
 *   See docs/assets/private-bucket-migration.md.
 */
export async function putPresignedObject(
  uploadUrl: string,
  body: Blob,
  contentType: string,
  requiredHeaders: Readonly<Record<string, string>> = {},
): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": contentType || "application/octet-stream",
  };
  for (const [name, value] of Object.entries(requiredHeaders)) {
    const lower = name.toLowerCase();
    if (lower === "content-length") {
      const signed = Number(value);
      if (Number.isFinite(signed) && signed !== body.size) {
        throw new Error(
          `presigned upload is signed for ${signed} bytes but the selected file is ${body.size}; the bucket would reject this PUT`,
        );
      }
      continue;
    }
    if (BROWSER_FORBIDDEN_UPLOAD_HEADERS.has(lower)) continue;
    headers[name] = value;
  }
  const response = await fetch(uploadUrl, {
    method: "PUT",
    headers,
    body,
  });
  if (!response.ok) {
    const detail = (await response.text().catch(() => "")).trim();
    throw new Error(
      detail !== ""
        ? `${response.status} ${response.statusText}: ${detail}`
        : `${response.status} ${response.statusText}`,
    );
  }
}

/** Downloads raw bytes from a `/v1/assets/*`-shaped endpoint (issue #178). */
export async function gatewayGetBinary(apiKey: string, path: string): Promise<Blob> {
  const response = await fetch(buildUrl(path), {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as ApiErrorBody | null;
    throw new ApiError(
      response.status,
      errorBody?.error?.code ?? "unknown_error",
      errorBody?.error?.message ?? response.statusText,
    );
  }
  return response.blob();
}
