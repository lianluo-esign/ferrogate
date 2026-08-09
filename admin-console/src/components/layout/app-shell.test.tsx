import { AppShell } from "@/components/layout/app-shell";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale, translate } from "@/i18n";
import { createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

function renderShell(path: string, locale: Locale = "en") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route element={<AppShell />}>
                <Route path="/app/agent-runs" element={<h1>Agent runs page</h1>} />
                <Route path="/app/mystery" element={<h1>Mystery page</h1>} />
              </Route>
            </Routes>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("AppShell chrome", () => {
  it("renders skip link, breadcrumb, brand, and page title in English", () => {
    renderShell("/app/agent-runs");

    expect(
      screen.getByRole("link", { name: translate("en", "shell.skipToContent") }),
    ).toBeInTheDocument();

    const breadcrumb = screen.getByRole("navigation", {
      name: translate("en", "common.breadcrumb"),
    });
    expect(
      within(breadcrumb).getByRole("link", {
        name: translate("en", "shell.breadcrumb.root"),
      }),
    ).toBeInTheDocument();
    expect(within(breadcrumb).getByRole("link", { current: "page" })).toHaveTextContent(
      translate("en", "nav.item.agentRuns"),
    );

    // Sidebar brand + control-plane label.
    expect(screen.getByText(translate("en", "shell.brand.name"))).toBeInTheDocument();
    expect(screen.getByText(translate("en", "shell.brand.tagline"))).toBeInTheDocument();
    expect(screen.getByText(translate("en", "nav.controlPlane"))).toBeInTheDocument();
  });

  it("falls back to the dashboard label for routes outside the nav registry", () => {
    renderShell("/app/mystery");

    const breadcrumb = screen.getByRole("navigation", {
      name: translate("en", "common.breadcrumb"),
    });
    expect(within(breadcrumb).getByRole("link", { current: "page" })).toHaveTextContent(
      translate("en", "nav.dashboard"),
    );
  });

  it("renders the shell chrome in Simplified Chinese", () => {
    renderShell("/app/agent-runs", "zh-CN");

    expect(
      screen.getByRole("link", { name: translate("zh-CN", "shell.skipToContent") }),
    ).toBeInTheDocument();

    const breadcrumb = screen.getByRole("navigation", {
      name: translate("zh-CN", "common.breadcrumb"),
    });
    expect(
      within(breadcrumb).getByRole("link", {
        name: translate("zh-CN", "shell.breadcrumb.root"),
      }),
    ).toBeInTheDocument();
    expect(within(breadcrumb).getByRole("link", { current: "page" })).toHaveTextContent(
      translate("zh-CN", "nav.item.agentRuns"),
    );
    expect(screen.getByText(translate("zh-CN", "shell.brand.tagline"))).toBeInTheDocument();
    expect(screen.getByText(translate("zh-CN", "nav.controlPlane"))).toBeInTheDocument();
  });
});
