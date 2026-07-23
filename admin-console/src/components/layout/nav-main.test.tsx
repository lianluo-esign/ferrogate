import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useNavigate } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { NavMain } from "@/components/layout/nav-main";
import { NAV_DASHBOARD, NAV_GROUPS } from "@/components/layout/nav-config";
import { SidebarProvider } from "@/components/ui/sidebar";
import { I18nProvider, translate, type Locale } from "@/i18n";

function NavigationHarness() {
  const navigate = useNavigate();
  return (
    <SidebarProvider>
      <button type="button" onClick={() => navigate("/app/ops/status")}>Go to status</button>
      <NavMain groups={NAV_GROUPS} />
    </SidebarProvider>
  );
}

function renderNavigation(path: string, locale: Locale = "en") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <I18nProvider initialLocale={locale}>
        <NavigationHarness />
      </I18nProvider>
    </MemoryRouter>,
  );
}

describe("NavMain", () => {
  it("renders Dashboard as an explicit exact-match destination", () => {
    renderNavigation("/app");

    expect(
      screen.getByRole("link", { name: translate("en", NAV_DASHBOARD.titleKey) }),
    ).toHaveAttribute("data-active", "true");
  });

  it.each(NAV_GROUPS)(
    "reveals the active destination for a direct $titleKey deep link",
    (group) => {
      const destination = group.items[0];
      renderNavigation(destination.url);

      expect(
        screen.getByRole("link", { name: translate("en", destination.titleKey) }),
      ).toHaveAttribute("data-active", "true");
    },
  );

  it("marks only the native gateway key destination active", () => {
    renderNavigation("/app/api-keys-native");

    expect(
      screen.getByRole("link", { name: translate("en", "nav.item.gatewayApiKeys") }),
    ).toHaveAttribute("data-active", "true");
    expect(
      screen.getByRole("link", { name: translate("en", "nav.item.virtualKeys") }),
    ).toHaveAttribute("data-active", "false");
  });

  it("reveals the active group after programmatic cross-group navigation", async () => {
    const user = userEvent.setup();
    renderNavigation("/app/api-keys-native");

    await user.click(screen.getByRole("button", { name: "Go to status" }));

    expect(
      await screen.findByRole("link", {
        name: translate("en", "nav.item.systemStatus"),
      }),
    ).toHaveAttribute("data-active", "true");
  });

  it("renders the control-plane label and destinations in Simplified Chinese", () => {
    renderNavigation("/app", "zh-CN");

    expect(
      screen.getByText(translate("zh-CN", "nav.controlPlane")),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: translate("zh-CN", NAV_DASHBOARD.titleKey) }),
    ).toHaveAttribute("data-active", "true");
    // A collapsed group label still resolves from the zh-CN catalog.
    expect(
      screen.getByText(translate("zh-CN", "nav.group.operations")),
    ).toBeInTheDocument();
  });
});
