import { lazy } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  RouteLoadBoundary,
  RouteLoadErrorBoundary,
} from "@/components/route-load-boundary";
import { I18nProvider } from "@/i18n";

describe("RouteLoadBoundary", () => {
  it("announces a stable loading state while a route module is pending", () => {
    const PendingRoute = lazy(() => new Promise<never>(() => {}));
    render(
      <I18nProvider>
        <RouteLoadBoundary>
          <PendingRoute />
        </RouteLoadBoundary>
      </I18nProvider>,
    );

    expect(screen.getByRole("status")).toHaveTextContent("Loading page…");
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
  });

  it("renders an explicit reload path when a route module throws", async () => {
    const user = userEvent.setup();
    const onReload = vi.fn();
    vi.spyOn(console, "error").mockImplementation(() => {});

    function BrokenRoute(): never {
      throw new Error("chunk request failed");
    }

    render(
      <I18nProvider>
        <RouteLoadErrorBoundary onReload={onReload}>
          <BrokenRoute />
        </RouteLoadErrorBoundary>
      </I18nProvider>,
    );

    expect(screen.getByRole("heading", { name: "Page failed to load" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("could not be downloaded");
    await user.click(screen.getByRole("button", { name: "Reload page" }));
    expect(onReload).toHaveBeenCalledOnce();
  });
});
