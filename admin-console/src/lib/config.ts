// Runtime config takes precedence over the Vite build-time env: the same
// container image is deployed across environments (dev/staging/prod), each
// with different backend URLs, so those can't be baked in at `npm run
// build` time. The Docker image's entrypoint renders /env-config.js from
// container env vars before nginx starts; index.html loads it before the
// app bundle. Local dev (`npm run dev`) has no such script, so it falls
// through to the Vite `.env.local` value.
declare global {
  interface Window {
    __ENV__?: {
      VITE_AUTH_BASE_URL?: string;
      VITE_GATEWAY_ADMIN_BASE_URL?: string;
      VITE_ADMIN_API_BASE_URL?: string;
    };
  }
}

export const AUTH_BASE_URL: string =
  window.__ENV__?.VITE_AUTH_BASE_URL ||
  import.meta.env.VITE_AUTH_BASE_URL ||
  "http://localhost:8081";

// The console's admin backend (issue #315): prefer the dedicated
// `ferrogate admin-api serve` service when ADMIN_API_BASE_URL is set, and
// fall back to the legacy GATEWAY_ADMIN_BASE_URL (the gateway's own
// /admin/v1/* surface) for backward compatibility. Every gateway-client
// call flows through this constant, so setting the new env var switches
// the whole console without further code changes.
export const GATEWAY_ADMIN_BASE_URL: string =
  window.__ENV__?.VITE_ADMIN_API_BASE_URL ||
  import.meta.env.VITE_ADMIN_API_BASE_URL ||
  window.__ENV__?.VITE_GATEWAY_ADMIN_BASE_URL ||
  import.meta.env.VITE_GATEWAY_ADMIN_BASE_URL ||
  "http://localhost:8080";

// Alias for call sites that want to name the dedicated service explicitly.
export const ADMIN_API_BASE_URL: string = GATEWAY_ADMIN_BASE_URL;
