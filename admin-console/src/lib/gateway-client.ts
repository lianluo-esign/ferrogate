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
