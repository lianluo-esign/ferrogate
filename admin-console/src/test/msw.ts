// MSW (v2) foundation for mocking the FerroGate backends in tests.
//
// ## The pattern (use this in every UI-slice test)
//
// One shared node `server` is started/reset/closed by `src/test/setup.ts`;
// individual tests register per-test handlers with `server.use(...)` (reset
// automatically after each test). Unhandled requests FAIL the test, so every
// request a component makes must be mocked explicitly.
//
// Base URLs match `src/lib/config.ts` fallbacks (tests run without
// `window.__ENV__` or Vite env): gateway Admin API on :8080, auth on :8081.
//
// ```ts
// import { HttpResponse, http } from "msw";
// import { gatewayUrl, mockAdminList, server } from "@/test/msw";
//
// // shorthand for a `{ object: "list", data: [...] }` Admin API list:
// mockAdminList("/admin/v1/plans", [{ id: "p1", ... }]);
//
// // anything else — plain MSW:
// server.use(
//   http.post(gatewayUrl("/admin/v1/plans"), async ({ request }) =>
//     HttpResponse.json({ object: "plan", plan: { ...(await request.json()) } }),
//   ),
// );
// ```
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { AUTH_BASE_URL, GATEWAY_ADMIN_BASE_URL } from "@/lib/config";

export const server = setupServer();

/** Absolute URL for a gateway Admin API path, e.g. `gatewayUrl("/admin/v1/plans")`. */
export function gatewayUrl(path: string): string {
  return new URL(path, GATEWAY_ADMIN_BASE_URL).toString();
}

/** Absolute URL for an auth-service path, e.g. `authUrl("/v1/admin/login")`. */
export function authUrl(path: string): string {
  return new URL(path, AUTH_BASE_URL).toString();
}

/** Mocks `GET <path>` with the Admin API `{ object: "list", data }` envelope. */
export function mockAdminList<T>(path: string, data: T[]): void {
  server.use(
    http.get(gatewayUrl(path), () => HttpResponse.json({ object: "list", data })),
  );
}

/** Mocks any method/path with the Admin API `{ error: { code, message } }` body. */
export function mockAdminError(
  method: "get" | "post" | "put" | "patch" | "delete",
  path: string,
  status: number,
  code: string,
  message: string,
): void {
  server.use(
    http[method](gatewayUrl(path), () =>
      HttpResponse.json({ error: { code, message } }, { status }),
    ),
  );
}
