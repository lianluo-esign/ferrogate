import type { AdminRefreshResponse, AdminSessionResponse } from "@/types/auth";

const STORAGE_KEY = "ferrogate-admin-session";

export interface StoredSession {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  user: AdminSessionResponse["user"];
  tenant: AdminSessionResponse["tenant"];
  gatewayApiKey: string;
}

export function sessionFromResponse(response: AdminSessionResponse): StoredSession {
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
    expiresAt: Date.now() + response.expires_in * 1000,
    user: response.user,
    tenant: response.tenant,
    gatewayApiKey: response.gateway_api_key,
  };
}

export function applyRefreshResponse(
  session: StoredSession,
  response: AdminRefreshResponse,
): StoredSession {
  return {
    ...session,
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
    expiresAt: Date.now() + response.expires_in * 1000,
  };
}

export function loadStoredSession(): StoredSession | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredSession;
  } catch {
    return null;
  }
}

export function saveStoredSession(session: StoredSession): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearStoredSession(): void {
  localStorage.removeItem(STORAGE_KEY);
}
