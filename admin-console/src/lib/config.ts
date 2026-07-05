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
    };
  }
}

export const AUTH_BASE_URL: string =
  window.__ENV__?.VITE_AUTH_BASE_URL ||
  import.meta.env.VITE_AUTH_BASE_URL ||
  "http://localhost:8081";

export const GATEWAY_ADMIN_BASE_URL: string =
  window.__ENV__?.VITE_GATEWAY_ADMIN_BASE_URL ||
  import.meta.env.VITE_GATEWAY_ADMIN_BASE_URL ||
  "http://localhost:8080";
