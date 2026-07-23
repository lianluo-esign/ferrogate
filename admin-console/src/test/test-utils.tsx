// Shared render helpers for component tests.
//
// ## The pattern
//
// Most console components assume three providers: an authenticated session
// (`AuthProvider` reading localStorage), a TanStack Query client, and a
// router. `renderWithProviders` wires all three; `seedSession()` puts a
// valid session into localStorage BEFORE render so `useAuth()` sees an
// authenticated user (ResourcePage dereferences `session!.gatewayApiKey`).
//
// ```ts
// seedSession();
// mockAdminList("/admin/v1/plans", [plan()]);
// renderWithProviders(<ResourcePage config={plansConfig} />);
// ```
import type { ReactElement, ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import { saveStoredSession, type StoredSession } from "@/lib/session-storage";

export const TEST_GATEWAY_API_KEY = "fg-test-gateway-key";

/** Writes a valid admin session to localStorage (call before rendering). */
export function seedSession(overrides: Partial<StoredSession> = {}): StoredSession {
  const session: StoredSession = {
    accessToken: "test-access-token",
    refreshToken: "test-refresh-token",
    // Far enough out that AuthProvider's proactive refresh never fires mid-test.
    expiresAt: Date.now() + 60 * 60 * 1000,
    user: { id: "user-1", email: "admin@example.com", display_name: "Admin" },
    tenant: { id: "tenant-1", name: "Acme", role: "owner" },
    gatewayApiKey: TEST_GATEWAY_API_KEY,
    ...overrides,
  };
  saveStoredSession(session);
  return session;
}

/** A Query client with retries off so error paths surface immediately. */
export function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
}

export function AllProviders({ children }: { children: ReactNode }) {
  return (
    <MemoryRouter>
      <I18nProvider>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            {children}
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>
  );
}

export function renderWithProviders(ui: ReactElement): RenderResult {
  return render(ui, { wrapper: AllProviders });
}
