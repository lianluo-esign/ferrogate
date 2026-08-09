import { AUTH_BASE_URL } from "@/lib/config";
import {
  type AdminLoginRequest,
  type AdminMeResponse,
  type AdminRefreshResponse,
  type AdminRegisterRequest,
  type AdminSessionResponse,
  ApiError,
  type ApiErrorBody,
} from "@/types/auth";

async function request<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${AUTH_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
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

export function registerAdminAccount(payload: AdminRegisterRequest): Promise<AdminSessionResponse> {
  return request("/v1/admin/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loginAdminAccount(payload: AdminLoginRequest): Promise<AdminSessionResponse> {
  return request("/v1/admin/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function refreshAdminSession(refreshToken: string): Promise<AdminRefreshResponse> {
  return request("/v1/admin/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export function logoutAdminSession(refreshToken: string): Promise<void> {
  return request("/v1/admin/logout", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export function fetchAdminMe(accessToken: string): Promise<AdminMeResponse> {
  return request("/v1/admin/me", {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}
