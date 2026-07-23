import { render, renderHook, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { I18nProvider, useI18n } from "./i18n-provider";
import { LanguageSwitcher } from "./language-switcher";
import { LOCALE_STORAGE_KEY } from "./detect";

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("lang");
  vi.restoreAllMocks();
});

function wrapper(initialLocale?: "en" | "zh-CN") {
  return ({ children }: { children: ReactNode }) => (
    <I18nProvider initialLocale={initialLocale}>{children}</I18nProvider>
  );
}

describe("useI18n", () => {
  it("throws a clear error outside a provider", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => renderHook(() => useI18n())).toThrow(/must be used within an <I18nProvider>/);
  });

  it("resolves keys for the active locale", () => {
    const { result } = renderHook(() => useI18n(), { wrapper: wrapper("en") });
    expect(result.current.t("language.label")).toBe("Language");

    const zh = renderHook(() => useI18n(), { wrapper: wrapper("zh-CN") });
    expect(zh.result.current.t("language.label")).toBe("语言");
  });

  it("interpolates placeholders through t()", () => {
    const { result } = renderHook(() => useI18n(), { wrapper: wrapper("en") });
    expect(result.current.t("common.selected", { count: 3 })).toBe("3 selected");
  });

  it("exposes formatters bound to the active locale", () => {
    const { result } = renderHook(() => useI18n(), { wrapper: wrapper("en") });
    expect(result.current.format.number(1234567)).toBe("1,234,567");
    expect(result.current.format.percent(0.5)).toBe("50%");
  });

  it("sets <html lang> to the active locale", () => {
    renderHook(() => useI18n(), { wrapper: wrapper("zh-CN") });
    expect(document.documentElement.lang).toBe("zh-CN");
  });
});

describe("LanguageSwitcher", () => {
  it("switches locale in place, persists it, and updates <html lang>", async () => {
    const user = userEvent.setup();
    render(
      <I18nProvider initialLocale="en">
        <LanguageSwitcher />
        <span data-testid="label">
          <Label />
        </span>
      </I18nProvider>,
    );

    expect(screen.getByTestId("label")).toHaveTextContent("Language");
    expect(document.documentElement.lang).toBe("en");

    await user.click(screen.getByRole("button", { name: /Change language/i }));
    await user.click(screen.getByRole("menuitemradio", { name: "简体中文" }));

    // No reload: same React tree re-renders with the new locale.
    expect(screen.getByTestId("label")).toHaveTextContent("语言");
    expect(document.documentElement.lang).toBe("zh-CN");
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
  });
});

// Small consumer that renders a translated string, to prove re-render on switch.
function Label() {
  const { t } = useI18n();
  return <>{t("language.label")}</>;
}
