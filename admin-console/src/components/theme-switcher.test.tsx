import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppThemeProvider, THEME_STORAGE_KEY } from "@/components/theme-provider";
import { ThemeSwitcher } from "@/components/theme-switcher";

function installColorScheme(dark: boolean) {
  let matches = dark;
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  const mediaQuery = {
    get matches() {
      return matches;
    },
    media: "(prefers-color-scheme: dark)",
    onchange: null,
    addListener(listener: (event: MediaQueryListEvent) => void) {
      listeners.add(listener);
    },
    removeListener(listener: (event: MediaQueryListEvent) => void) {
      listeners.delete(listener);
    },
    addEventListener(_type: string, listener: (event: MediaQueryListEvent) => void) {
      listeners.add(listener);
    },
    removeEventListener(_type: string, listener: (event: MediaQueryListEvent) => void) {
      listeners.delete(listener);
    },
    dispatchEvent: () => true,
  } as MediaQueryList;

  vi.stubGlobal("matchMedia", () => mediaQuery);

  return {
    setDark(next: boolean) {
      matches = next;
      const event = { matches: next, media: mediaQuery.media } as MediaQueryListEvent;
      listeners.forEach((listener) => listener(event));
    },
  };
}

describe("ThemeSwitcher", () => {
  beforeEach(() => {
    document.documentElement.className = "";
    document.documentElement.style.colorScheme = "";
    document.querySelector('meta[name="theme-color"]')?.remove();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("follows the operating-system theme only while System is selected", async () => {
    const colorScheme = installColorScheme(true);
    const user = userEvent.setup();

    render(
      <AppThemeProvider>
        <ThemeSwitcher />
      </AppThemeProvider>,
    );

    await waitFor(() => expect(document.documentElement).toHaveClass("dark"));
    expect(document.documentElement.style.colorScheme).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute(
      "content",
      "#09090b",
    );
    expect(screen.getByRole("button", { name: "Theme: System. Change theme" })).toBeVisible();

    act(() => colorScheme.setDark(false));
    await waitFor(() => expect(document.documentElement).toHaveClass("light"));

    await user.click(screen.getByRole("button", { name: "Theme: System. Change theme" }));
    await user.click(screen.getByRole("menuitemradio", { name: "Dark" }));
    await waitFor(() => expect(document.documentElement).toHaveClass("dark"));

    act(() => colorScheme.setDark(false));
    expect(document.documentElement).toHaveClass("dark");
  });

  it("persists an explicit choice and restores focus to the trigger", async () => {
    installColorScheme(false);
    const user = userEvent.setup();

    render(
      <AppThemeProvider>
        <ThemeSwitcher />
      </AppThemeProvider>,
    );

    const trigger = await screen.findByRole("button", {
      name: "Theme: System. Change theme",
    });
    await user.click(trigger);
    await user.click(screen.getByRole("menuitemradio", { name: "Dark" }));

    await waitFor(() => {
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
      expect(document.documentElement).toHaveClass("dark");
      expect(screen.getByRole("button", { name: "Theme: Dark. Change theme" })).toHaveFocus();
    });
  });
});
