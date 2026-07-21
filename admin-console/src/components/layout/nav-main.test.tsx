import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useNavigate } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { NavMain } from "@/components/layout/nav-main";
import { NAV_GROUPS } from "@/components/layout/nav-config";
import { SidebarProvider } from "@/components/ui/sidebar";

function NavigationHarness() {
  const navigate = useNavigate();
  return (
    <SidebarProvider>
      <button type="button" onClick={() => navigate("/app/ops/status")}>Go to status</button>
      <NavMain groups={NAV_GROUPS} />
    </SidebarProvider>
  );
}

function renderNavigation(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <NavigationHarness />
    </MemoryRouter>,
  );
}

describe("NavMain", () => {
  it("renders Dashboard as an explicit exact-match destination", () => {
    renderNavigation("/app");

    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute(
      "data-active",
      "true",
    );
  });

  it.each(NAV_GROUPS)(
    "reveals the active destination for a direct $title deep link",
    (group) => {
      const destination = group.items[0];
      renderNavigation(destination.url);

      expect(screen.getByRole("link", { name: destination.title })).toHaveAttribute(
        "data-active",
        "true",
      );
    },
  );

  it("marks only the native gateway key destination active", () => {
    renderNavigation("/app/api-keys-native");

    expect(screen.getByRole("link", { name: "Gateway API Keys" })).toHaveAttribute(
      "data-active",
      "true",
    );
    expect(screen.getByRole("link", { name: "Virtual Keys" })).toHaveAttribute(
      "data-active",
      "false",
    );
  });

  it("reveals the active group after programmatic cross-group navigation", async () => {
    const user = userEvent.setup();
    renderNavigation("/app/api-keys-native");

    await user.click(screen.getByRole("button", { name: "Go to status" }));

    expect(await screen.findByRole("link", { name: "System Status" })).toHaveAttribute(
      "data-active",
      "true",
    );
  });
});
