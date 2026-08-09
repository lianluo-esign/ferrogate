import { AuthProvider } from "@/hooks/use-auth";
import { CatalogScopeProvider } from "@/hooks/use-catalog-scope";
import { I18nProvider, type Locale } from "@/i18n";
import { type StoredSession, saveStoredSession } from "@/lib/session-storage";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { type RenderResult, render } from "@testing-library/react";
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
import { MemoryRouter } from "react-router-dom";

export const TEST_GATEWAY_API_KEY = "fg-test-gateway-key";

/** Writes a valid admin session to localStorage (call before rendering). */
export function seedSession(overrides: Partial<StoredSession> = {}): StoredSession {
  const session: StoredSession = {
    accessToken: "test-access-token",
    refreshToken: "test-refresh-token",
    // Far enough out that AuthProvider's proactive refresh never fires mid-test.
    expiresAt: Date.now() + 60 * 60 * 1000,
    user: { id: "user-1", email: "admin@example.com", display_name: "Admin", superadmin: false },
    tenant: { id: "tenant-1", name: "Acme", role: "owner" },
    gatewayApiKey: TEST_GATEWAY_API_KEY,
    // Default: a non-superadmin session with no platform-operator credential, so
    // `canUsePlatform` is false and the catalog scope toggle stays hidden.
    platformOperatorApiKey: null,
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

export function AllProviders({
  children,
  locale,
}: {
  children: ReactNode;
  locale?: Locale;
}) {
  return (
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <CatalogScopeProvider>
            <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>
          </CatalogScopeProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>
  );
}

/**
 * Render `ui` inside the console's provider stack. Pass `locale` to force a
 * catalog for locale-specific assertions (defaults to the resolved locale,
 * which is `en` under jsdom).
 */
export function renderWithProviders(
  ui: ReactElement,
  options: { locale?: Locale } = {},
): RenderResult {
  return render(ui, {
    wrapper: ({ children }) => <AllProviders locale={options.locale}>{children}</AllProviders>,
  });
}
