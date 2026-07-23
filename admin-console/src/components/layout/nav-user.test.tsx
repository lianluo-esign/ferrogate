import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { NavUser } from "@/components/layout/nav-user";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, translate, type Locale } from "@/i18n";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

function renderNavUser(locale: Locale = "en") {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <SidebarProvider>
              <NavUser />
            </SidebarProvider>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession({
    user: { id: "user-1", email: "admin@example.com", display_name: "Admin" },
  });
});

describe("NavUser", () => {
  it.each<[Locale]>([["en"], ["zh-CN"]])(
    "exposes the sign-out action from the account menu in %s",
    async (locale) => {
      const user = userEvent.setup();
      renderNavUser(locale);

      await user.click(screen.getByRole("button", { name: /Admin/ }));

      expect(
        await screen.findByRole("menuitem", {
          name: translate(locale, "shell.logout"),
        }),
      ).toBeInTheDocument();
    },
  );
});
