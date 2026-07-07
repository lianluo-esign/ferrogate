import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import { ApiError, type ApiErrorBody } from "@/types/auth";

export interface AdminPage<T> {
  data: T[];
  total: number;
  offset: number;
  limit: number;
}

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
