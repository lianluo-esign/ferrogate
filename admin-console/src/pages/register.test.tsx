import { type Locale, translate } from "@/i18n";
import RegisterPage from "@/pages/register";
import { renderWithProviders } from "@/test/test-utils";
import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

const CASES: Locale[] = ["en", "zh-CN"];

describe("RegisterPage", () => {
  it.each(CASES)("renders every visible string from the %s catalog", (locale) => {
    renderWithProviders(<RegisterPage />, { locale });

    expect(
      screen.getByRole("heading", { name: translate(locale, "auth.register.title") }),
    ).toBeInTheDocument();
    expect(screen.getByText(translate(locale, "auth.register.subtitle"))).toBeInTheDocument();
    expect(screen.getByLabelText(translate(locale, "auth.register.orgName"))).toBeInTheDocument();
    expect(
      screen.getByLabelText(translate(locale, "auth.register.displayName")),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(translate(locale, "auth.field.email"))).toBeInTheDocument();
    expect(screen.getByLabelText(translate(locale, "auth.field.password"))).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: translate(locale, "auth.register.submit") }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: translate(locale, "auth.register.loginLink") }),
    ).toBeInTheDocument();
  });
});
