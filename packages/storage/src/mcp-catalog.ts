/**
 * Pure MCP admin-document decoding shared by the control-plane writer and the
 * MCP reader. Keeping this at the storage boundary prevents the two workers
 * from drifting on transport/auth aliases or fail-closed allowlist rules.
 */

export type TenantMcpTransport = "streamable_http" | "sse" | "stdio";

export type TenantMcpAuthType =
  | "none"
  | "shared_headers"
  | "oauth"
  | "per_user_oauth"
  | "per_user_headers"
  | "original_bearer"
  | "ferrogate_signed_jwt";

export interface TenantMcpOauthConfig {
  issuer: string;
  clientId: string;
  clientSecretRef?: string;
  redirectUri?: string;
  scopes: string[];
  audience?: string;
}

export interface TenantMcpServerConfig {
  name: string;
  transport: TenantMcpTransport;
  url?: string;
  authType: TenantMcpAuthType;
  toolsToExecute: string[];
  toolsToExclude?: string[];
  toolsToAutoExecute: string[];
  headers?: Record<string, string>;
  oauth?: TenantMcpOauthConfig;
  signedJwtAudience?: string;
  timeoutMs: number;
}

export const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;

export const ADMIN_TRANSPORTS: Readonly<Record<string, TenantMcpTransport>> = {
  http: "streamable_http",
  streamable_http: "streamable_http",
  sse: "sse",
  stdio: "stdio",
};

export const ADMIN_AUTH_TYPES: Readonly<Record<string, TenantMcpAuthType>> = {
  none: "none",
  headers: "shared_headers",
  shared_headers: "shared_headers",
  oauth: "oauth",
  per_user_oauth: "per_user_oauth",
  per_user_headers: "per_user_headers",
  original_bearer: "original_bearer",
  ferrogate_signed_jwt: "ferrogate_signed_jwt",
};

type Document = Record<string, unknown>;

function isObject(value: unknown): value is Document {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readAllowlist(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") return undefined;
    out.push(entry);
  }
  return out;
}

function readHeaders(value: unknown): Record<string, string> | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value)) return null;
  const out: Record<string, string> = {};
  for (const [name, entry] of Object.entries(value)) {
    if (typeof entry !== "string") return null;
    out[name] = entry;
  }
  return out;
}

function readOauth(value: unknown): TenantMcpOauthConfig | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value)) return null;
  const issuer = value.issuer ?? value.iss;
  const clientId = value.client_id ?? value.clientId;
  if (typeof issuer !== "string" || issuer === "") return null;
  if (typeof clientId !== "string" || clientId === "") return null;
  const scopes = readAllowlist(value.scopes ?? value.scope);
  if (scopes === undefined) return null;
  const config: TenantMcpOauthConfig = {
    issuer,
    clientId,
    scopes: scopes.length === 0 ? ["openid", "profile", "email"] : scopes,
  };
  const secretRef = value.client_secret_ref ?? value.clientSecretRef;
  if (typeof secretRef === "string" && secretRef !== "") config.clientSecretRef = secretRef;
  const redirect = value.redirect_uri ?? value.redirectUri;
  if (typeof redirect === "string" && redirect !== "") config.redirectUri = redirect;
  if (typeof value.audience === "string" && value.audience !== "") {
    config.audience = value.audience;
  }
  return config;
}

/** Decode one admin MCP document; invalid input is refused rather than defaulted. */
export function decodeTenantMcpServerDocument(
  document: unknown,
): TenantMcpServerConfig | undefined {
  if (!isObject(document)) return undefined;
  const name = document.name ?? document.id;
  if (typeof name !== "string" || name.trim() === "") return undefined;
  if (document.enabled === false) return undefined;

  const rawTransport = document.transport;
  if (typeof rawTransport !== "string") return undefined;
  const transport = ADMIN_TRANSPORTS[rawTransport];
  if (transport === undefined) return undefined;

  const rawAuth = document.auth_type ?? document.authType ?? "none";
  if (typeof rawAuth !== "string") return undefined;
  const authType = ADMIN_AUTH_TYPES[rawAuth];
  if (authType === undefined) return undefined;

  const toolsToExecute = readAllowlist(document.tools_to_execute ?? document.toolsToExecute);
  if (toolsToExecute === undefined) return undefined;
  const toolsToAutoExecute = readAllowlist(
    document.tools_to_auto_execute ?? document.toolsToAutoExecute,
  );
  if (toolsToAutoExecute === undefined) return undefined;
  const toolsToExclude = readAllowlist(document.tools_to_exclude ?? document.toolsToExclude);
  if (toolsToExclude === undefined) return undefined;

  const headers = readHeaders(document.headers);
  if (headers === null) return undefined;
  const oauth = readOauth(document.oauth);
  if (oauth === null) return undefined;

  const rawTimeout = document.timeout_ms ?? document.timeoutMs;
  let timeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS;
  if (rawTimeout !== undefined && rawTimeout !== null) {
    if (typeof rawTimeout !== "number" || !Number.isFinite(rawTimeout) || rawTimeout <= 0) {
      return undefined;
    }
    timeoutMs = Math.floor(rawTimeout);
  }

  const config: TenantMcpServerConfig = {
    name: name.trim(),
    transport,
    authType,
    toolsToExecute,
    toolsToAutoExecute,
    timeoutMs,
  };
  if (toolsToExclude.length > 0) config.toolsToExclude = toolsToExclude;
  if (typeof document.url === "string" && document.url !== "") config.url = document.url;
  if (headers !== undefined) config.headers = headers;
  if (oauth !== undefined) config.oauth = oauth;
  const audience = document.signed_jwt_audience ?? document.signedJwtAudience;
  if (typeof audience === "string" && audience !== "") config.signedJwtAudience = audience;
  return config;
}
