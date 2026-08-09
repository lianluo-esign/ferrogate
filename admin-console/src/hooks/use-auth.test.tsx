import { AuthProvider, useAuth } from "@/hooks/use-auth";
import { loadStoredSession } from "@/lib/session-storage";
import { authUrl, server } from "@/test/msw";
import { seedSession } from "@/test/test-utils";
import { ApiError } from "@/types/auth";
import { act, renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

const sessionResponse = {
  access_token: "access-1",
  refresh_token: "refresh-1",
  expires_in: 3600,
  user: { id: "user-1", email: "admin@example.com", display_name: "Admin" },
  tenant: { id: "tenant-1", name: "Acme", role: "owner" },
  gateway_api_key: "fg-live-key",
};

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

describe("useAuth", () => {
  it("login stores the session in state and localStorage", async () => {
    server.use(http.post(authUrl("/v1/admin/login"), () => HttpResponse.json(sessionResponse)));
    const { result } = renderHook(() => useAuth(), { wrapper });
    expect(result.current.session).toBeNull();

    await act(() => result.current.login({ email: "admin@example.com", password: "hunter2" }));

    expect(result.current.session?.gatewayApiKey).toBe("fg-live-key");
    expect(result.current.session?.user.email).toBe("admin@example.com");
    expect(loadStoredSession()?.accessToken).toBe("access-1");
  });

  it("login surfaces the backend ApiError and leaves no session behind", async () => {
    server.use(
      http.post(authUrl("/v1/admin/login"), () =>
        HttpResponse.json(
          { error: { code: "invalid_credentials", message: "wrong password" } },
          { status: 401 },
        ),
      ),
    );
    const { result } = renderHook(() => useAuth(), { wrapper });

    await act(async () => {
      const error = await result.current
        .login({ email: "admin@example.com", password: "nope" })
        .catch((e: unknown) => e);
      // the rejection is the typed ApiError from the shared request helper
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({ code: "invalid_credentials", status: 401 });
    });
    expect(result.current.session).toBeNull();
    expect(loadStoredSession()).toBeNull();
  });

  it("restores an existing session from localStorage on mount, and logout clears it", async () => {
    seedSession({ refreshToken: "refresh-existing" });
    let revokedToken: string | null = null;
    server.use(
      http.post(authUrl("/v1/admin/logout"), async ({ request }) => {
        const body = (await request.json()) as { refresh_token: string };
        revokedToken = body.refresh_token;
        return new HttpResponse(null, { status: 204 });
      }),
    );

    const { result } = renderHook(() => useAuth(), { wrapper });
    expect(result.current.session?.user.email).toBe("admin@example.com");

    await act(() => result.current.logout());

    await waitFor(() => expect(result.current.session).toBeNull());
    expect(loadStoredSession()).toBeNull();
    expect(revokedToken).toBe("refresh-existing");
  });

  it("throws when used outside an AuthProvider", () => {
    expect(() => renderHook(() => useAuth())).toThrow(
      "useAuth must be used within an AuthProvider",
    );
  });
});
