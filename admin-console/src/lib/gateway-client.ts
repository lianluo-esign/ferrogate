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

type OpFor<P extends keyof paths, M extends HttpMethod> =
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

type PathParamsFor<Op> = Op extends { parameters: { path: infer PP } }
  ? PP extends Record<string, string | number>
    ? PP
    : never
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
    { query: options?.query as GatewayRequestOptions["query"] },
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
  const response = await fetch(buildUrl(path, options?.query), {
    ...init,
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
): Promise<T> {
  const response = await fetch(buildUrl(path), {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": contentType || "application/octet-stream",
    },
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
