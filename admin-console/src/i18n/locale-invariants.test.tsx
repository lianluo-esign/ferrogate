// Test-gate coverage for #348 acceptance boxes 5 and 6, in jsdom.
//
// Box 5 ("dates, numbers, token counts, bytes, percentages, relative times, and
// currencies are locale-correct AND TESTED") was only asserted for `en` by
// `format.test.ts`: the zh-CN side had exactly two assertions (a currency
// substring and "the date differs from en"). A zh-CN regression — a formatter
// silently binding `en`, or a 12-hour clock leaking into 简体中文 — could not
// fail that suite. These tests pin the zh-CN output itself.
//
// Box 6 ("identifiers/code/user content remain byte-for-byte unchanged when
// switching locale") was only asserted in the browser matrix, which cannot run
// in this environment. This file proves the same invariant across a REAL
// `setLocale()` switch under jsdom.
//
// Dates pin `timeZone: "UTC"` so the assertions are machine-independent (this
// gate box runs in Asia/Shanghai; CI does not).
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceTable } from "@/components/resource/resource-table";
import {
  formatBytes,
  formatCurrency,
  formatDate,
  formatNumber,
  formatPercent,
  formatRelativeTime,
  formatTime,
  formatTokens,
} from "@/i18n/format";
import { useI18n } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import { providersConfig, type AdminProvider } from "@/resources/providers";
import { renderWithProviders } from "@/test/test-utils";

const INSTANT = new Date("2026-07-23T15:04:05Z");
const UTC = { timeZone: "UTC" } as const;

/**
 * `ResourceTable` falls back to a compact record view unless the desktop media
 * query matches; the shared jsdom `matchMedia` stub answers `false`. Force the
 * desktop branch so the assertions below run against the real column table
 * (same helper the sibling resource i18n suites use).
 */
function setDesktopViewport() {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockImplementation(() => ({
      matches: true,
      media: "(min-width: 1024px)",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

beforeEach(setDesktopViewport);

describe("#348 box 5 — zh-CN value formatting is locale-correct", () => {
  it("groups numbers and token counts with zh-CN separators", () => {
    expect(formatNumber("zh-CN", 1234567)).toBe("1,234,567");
    expect(formatTokens("zh-CN", 1234567)).toBe("1,234,567");
    // A fractional token count is still an integer count.
    expect(formatTokens("zh-CN", 1234.6)).toBe("1,235");
  });

  it("renders percentages with the same rounding contract as en", () => {
    expect(formatPercent("zh-CN", 0.42)).toBe("42%");
    expect(formatPercent("zh-CN", 0.1234, 1)).toBe("12.3%");
    // Rounding, not truncation, in both locales.
    expect(formatPercent("zh-CN", 0.005)).toBe(formatPercent("en", 0.005));
    expect(formatPercent("en", 0.005)).toBe("1%");
  });

  it("renders currency with the locale's own symbol while the digits survive", () => {
    expect(formatCurrency("en", 1234.5, "USD")).toBe("$1,234.50");
    // zh-CN disambiguates a foreign dollar; the amount is byte-identical.
    expect(formatCurrency("zh-CN", 1234.5, "USD")).toBe("US$1,234.50");
    expect(formatCurrency("zh-CN", 1234.5, "CNY")).toBe("¥1,234.50");
    expect(formatCurrency("zh-CN", 1234.5, "USD")).toContain("1,234.50");
  });

  it("steps bytes through binary units with a zh-CN mantissa", () => {
    expect(formatBytes("zh-CN", 0)).toBe("0 B");
    expect(formatBytes("zh-CN", 512)).toBe("512 B");
    expect(formatBytes("zh-CN", 1024)).toBe("1 KB");
    expect(formatBytes("zh-CN", 1536)).toBe("1.5 KB");
    expect(formatBytes("zh-CN", 1024 * 1024)).toBe("1 MB");
    expect(formatBytes("zh-CN", -2048)).toBe("-2 KB");
    // Above the largest unit the mantissa keeps locale grouping.
    expect(formatBytes("zh-CN", 1234 * 1024 ** 5)).toBe("1,234 PB");
  });

  it("puts the date in zh-CN order and the clock on 24 hours", () => {
    expect(formatDate("zh-CN", INSTANT, { dateStyle: "medium", ...UTC })).toBe(
      "2026年7月23日",
    );
    expect(formatDate("en", INSTANT, { dateStyle: "medium", ...UTC })).toBe(
      "Jul 23, 2026",
    );
    // The classic trap: a 12-hour clock leaking into 简体中文.
    expect(formatTime("zh-CN", INSTANT, { timeStyle: "short", ...UTC })).toBe("15:04");
    expect(formatTime("en", INSTANT, { timeStyle: "short", ...UTC })).toBe("3:04 PM");
    // Year-first, not month-first.
    expect(
      formatDate("zh-CN", INSTANT, { year: "numeric", month: "long", day: "numeric", ...UTC }),
    ).toBe("2026年7月23日");
  });

  it("renders relative times in Chinese, not English", () => {
    const now = new Date("2026-07-23T12:00:00Z");
    expect(formatRelativeTime("zh-CN", new Date("2026-07-23T11:58:30Z"), now)).toBe(
      "1分钟前",
    );
    expect(formatRelativeTime("zh-CN", new Date("2026-07-23T14:00:00Z"), now)).toBe(
      "2小时后",
    );
    expect(formatRelativeTime("zh-CN", new Date("2026-07-22T12:00:00Z"), now)).toBe("昨天");
    // Nothing English survived the switch.
    expect(formatRelativeTime("zh-CN", new Date("2026-07-22T12:00:00Z"), now)).not.toBe(
      formatRelativeTime("en", new Date("2026-07-22T12:00:00Z"), now),
    );
  });
});

/** Renders the bound formatters from the provider so the WIRING is covered too. */
function BoundFormatterProbe() {
  const { format, locale, setLocale } = useI18n();
  return (
    <div>
      <span data-testid="locale">{locale}</span>
      <span data-testid="number">{format.number(1234567)}</span>
      <span data-testid="tokens">{format.tokens(9876543)}</span>
      <span data-testid="bytes">{format.bytes(1536)}</span>
      <span data-testid="percent">{format.percent(0.1234, 1)}</span>
      <span data-testid="currency">{format.currency(1234.5, "USD")}</span>
      <span data-testid="date">{format.date(INSTANT, { dateStyle: "medium", ...UTC })}</span>
      <button type="button" onClick={() => setLocale("zh-CN")}>
        switch
      </button>
    </div>
  );
}

describe("#348 box 5 — the provider binds formatters to the ACTIVE locale", () => {
  it("re-formats every value kind when the locale switches at runtime", async () => {
    const user = userEvent.setup();
    renderWithProviders(<BoundFormatterProbe />, { locale: "en" });

    expect(screen.getByTestId("date").textContent).toBe("Jul 23, 2026");
    expect(screen.getByTestId("currency").textContent).toBe("$1,234.50");

    await user.click(screen.getByRole("button", { name: "switch" }));

    expect(screen.getByTestId("locale").textContent).toBe("zh-CN");
    expect(screen.getByTestId("date").textContent).toBe("2026年7月23日");
    expect(screen.getByTestId("currency").textContent).toBe("US$1,234.50");
    // Grouping-only values are legitimately identical across these two locales;
    // asserting that explicitly stops a future "they differ" from being read as
    // the only proof the switch worked.
    expect(screen.getByTestId("number").textContent).toBe("1,234,567");
    expect(screen.getByTestId("tokens").textContent).toBe("9,876,543");
    expect(screen.getByTestId("bytes").textContent).toBe("1.5 KB");
    expect(screen.getByTestId("percent").textContent).toBe("12.3%");
  });
});

// ---------------------------------------------------------------------------
// Box 6 — identifiers / code / user content are byte-for-byte stable.
// ---------------------------------------------------------------------------

/** Identifier-shaped values an operator must be able to copy verbatim. */
const IDENTIFIERS = {
  /** A provider slug: an identifier the gateway matches on. */
  name: "openai",
  /** A content hash — one changed byte is a different artifact. */
  kind: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  /** Operator-supplied free text, including CJK, which must not be rewritten. */
  compatibility: "用户上传的名称 · user content · req_01J8Z9K2QW3E4R5T6Y7U8I9O0P",
  /** An API path/URL. */
  base_url: "https://api.openai.com/v1",
} as const;

const identifierRow: AdminProvider = {
  ...IDENTIFIERS,
  has_api_key: true,
  enabled: true,
};

function IdentifierTable() {
  const { setLocale, locale } = useI18n();
  return (
    <div>
      <span data-testid="locale">{locale}</span>
      <button type="button" onClick={() => setLocale("zh-CN")}>
        switch
      </button>
      <ResourceTable
        columns={providersConfig.columns}
        rows={[identifierRow]}
        isLoading={false}
        readOnly
      />
    </div>
  );
}

describe("#348 box 6 — identifiers survive a locale switch byte-for-byte", () => {
  it("keeps every identifier cell identical while the headers localize", async () => {
    const user = userEvent.setup();
    renderWithProviders(<IdentifierTable />, { locale: "en" });

    // The English header proves the table really is in `en` to start with.
    expect(
      screen.getByRole("columnheader", { name: en["resource.providers.col.baseUrl"] }),
    ).toBeInTheDocument();

    const before = Object.values(IDENTIFIERS).map((value) => {
      const cell = screen.getByText(value);
      // Compare the raw DOM text, not a normalized accessible name.
      return { value, text: cell.textContent };
    });

    await user.click(screen.getByRole("button", { name: "switch" }));

    // The switch really happened: the header is now Simplified Chinese...
    expect(screen.getByTestId("locale").textContent).toBe("zh-CN");
    expect(
      screen.getByRole("columnheader", { name: zhCN["resource.providers.col.baseUrl"] }),
    ).toBeInTheDocument();
    expect(zhCN["resource.providers.col.baseUrl"]).not.toBe(
      en["resource.providers.col.baseUrl"],
    );

    // ...and not one byte of the identifier/user-content cells moved.
    for (const { value, text } of before) {
      const after = screen.getByText(value);
      expect(after.textContent, `identifier "${value}" changed across the switch`).toBe(
        text,
      );
      expect([...(after.textContent ?? "")]).toEqual([...(text ?? "")]);
    }
  });

  it("localizes a derived boolean cell in the SAME table (so the switch is not a no-op)", async () => {
    const user = userEvent.setup();
    renderWithProviders(<IdentifierTable />, { locale: "en" });

    expect(screen.getAllByText(en["common.yes"]).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "switch" }));
    expect(screen.getAllByText(zhCN["common.yes"]).length).toBeGreaterThan(0);
    expect(screen.queryByText(en["common.yes"])).toBeNull();
  });
});
