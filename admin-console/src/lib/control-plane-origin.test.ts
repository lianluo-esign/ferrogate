// The console talks to ONE origin: its own (#696).
//
// THE DEFECT THIS PINS
// --------------------
// `src/lib/config.ts` used to resolve two absolute origins — `AUTH_BASE_URL`
// (`http://localhost:8081`, the Rust `ferrogate-auth-service`) and
// `GATEWAY_ADMIN_BASE_URL` (`http://localhost:8080`, the Rust gateway's
// `/admin/v1`) — so every request the console made was CROSS-ORIGIN to whatever
// host served the console itself. Both services are gone, and their TypeScript
// replacement (`apps/control-plane`) cannot be reached that way even when
// pointed at correctly:
//
//   * `adminCrossSiteRejection` (apps/control-plane/src/middleware/auth.ts)
//     answers `403 cross_site_admin_denied` to any state-changing request whose
//     `sec-fetch-site` is `cross-site`. The browser sets that header; a page
//     cannot forge it. Every create/update/delete the console makes — and
//     `POST /v1/admin/login`, via `consoleCsrf` — is refused.
//   * the CORS preflight surface (apps/control-plane/src/middleware/cors.ts)
//     answers `OPTIONS /admin/{*rest}` and nothing else, so the
//     `content-type: application/json` login preflight
//     (`OPTIONS /v1/admin/login`) 404s and the login is never even sent.
//
// Neither is a bug to relax: they are the CSRF posture of an admin surface.
// The fix is to stop being cross-origin, which `apps/control-plane`'s
// `[assets]` block now makes true in production by serving this console from
// the control-plane Worker itself.
//
// WHY THE ASSERTION IS ON THE REQUEST AND NOT ON THE CONSTANT
// ----------------------------------------------------------
// Asserting `AUTH_BASE_URL === ""` would pin a spelling, and any of the four
// call paths below could still reintroduce an absolute origin of its own (two
// of them — the static-site XHR upload and the request-log export link — build
// URLs outside the shared client). So the spy sits on `fetch` and the subject
// is the URL that actually goes out.
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchAdminMe,
  loginAdminAccount,
  logoutAdminSession,
  refreshAdminSession,
  registerAdminAccount,
} from "@/lib/auth-client";
import {
  gatewayDelete,
  gatewayGet,
  gatewayPatch,
  gatewayPost,
  gatewayPut,
} from "@/lib/gateway-client";

/** Every URL `fetch` was called with during one test, resolved absolute. */
function requestedUrls(spy: ReturnType<typeof vi.spyOn>): string[] {
  return spy.mock.calls.map((call) => {
    const input = call[0] as string | URL | Request;
    const raw =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    // A relative path IS the same-origin answer; resolve it the way the browser
    // would so the assertion reads one way for both spellings.
    return new URL(raw, window.location.href).href;
  });
}

describe("every control-plane request the console makes is same-origin", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Not MSW: the point is the URL, not the response, and a handler would have
    // to name an origin — which is the thing under test.
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ object: "list", data: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  });

  it("keeps the admin-console SESSION surface (/v1/admin/*) on this origin", async () => {
    await registerAdminAccount({
      organization_name: "Acme",
      email: "operator@example.test",
      password: "hunter2hunter2",
    });
    await loginAdminAccount({ email: "operator@example.test", password: "hunter2hunter2" });
    await refreshAdminSession("refresh-token");
    await logoutAdminSession("refresh-token");
    await fetchAdminMe("access-token");

    const urls = requestedUrls(fetchSpy);
    expect(urls).toHaveLength(5);
    for (const url of urls) {
      expect(new URL(url).origin, `${url} is cross-origin`).toBe(window.location.origin);
    }
    // …and still the paths the control plane actually mounts.
    expect(urls.map((url) => new URL(url).pathname)).toEqual([
      "/v1/admin/register",
      "/v1/admin/login",
      "/v1/admin/refresh",
      "/v1/admin/logout",
      "/v1/admin/me",
    ]);
  });

  it("keeps the Admin API surface (/admin/v1/*) on this origin, every verb", async () => {
    await gatewayGet("key", "/admin/v1/request-logs");
    await gatewayPost("key", "/admin/v1/plans", { id: "p1" });
    await gatewayPut("key", "/admin/v1/plans/p1", { id: "p1" });
    await gatewayPatch("key", "/admin/v1/tenant-accounts/t1", { status: "active" });
    await gatewayDelete("key", "/admin/v1/plans/p1");

    const urls = requestedUrls(fetchSpy);
    expect(urls).toHaveLength(5);
    for (const url of urls) {
      // The four mutating verbs are exactly the ones `adminCrossSiteRejection`
      // refuses cross-site, so a regression here is a console that reads fine
      // and cannot write at all.
      expect(new URL(url).origin, `${url} is cross-origin`).toBe(window.location.origin);
    }
  });

  it("keeps query parameters intact while doing so", async () => {
    // `buildUrl` composes the query through `new URL(path, base)`; a base swap
    // is exactly the kind of change that can drop it.
    await gatewayGet("key", "/admin/v1/request-logs", { query: { limit: 25, offset: 50 } });
    const url = new URL(requestedUrls(fetchSpy)[0] as string);
    expect(url.pathname).toBe("/admin/v1/request-logs");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("offset")).toBe("50");
  });
});
