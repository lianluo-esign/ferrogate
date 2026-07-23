import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import LoginPage from "@/pages/login";
import { translate, type Locale } from "@/i18n";
import { renderWithProviders } from "@/test/test-utils";

const CASES: Locale[] = ["en", "zh-CN"];

describe("LoginPage", () => {
  it.each(CASES)("renders every visible string from the %s catalog", (locale) => {
    renderWithProviders(<LoginPage />, { locale });

    expect(
      screen.getByRole("heading", { name: translate(locale, "common.appName") }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(translate(locale, "auth.login.subtitle")),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(translate(locale, "auth.field.email")),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(translate(locale, "auth.field.password")),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: translate(locale, "auth.login.submit") }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(translate(locale, "auth.login.registerPrompt")),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: translate(locale, "auth.login.registerLink") }),
    ).toBeInTheDocument();
  });

  it("uses the localized fallback error copy per locale", () => {
    expect(translate("en", "auth.login.error")).toBe("Login failed");
    expect(translate("zh-CN", "auth.login.error")).not.toBe(
      translate("en", "auth.login.error"),
    );
  });
});
