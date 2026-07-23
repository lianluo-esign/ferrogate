import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatCurrency,
  formatDate,
  formatNumber,
  formatPercent,
  formatRelativeTime,
  formatTokens,
  interpolate,
  selectPlural,
} from "./format";

describe("interpolate", () => {
  it("substitutes named placeholders", () => {
    expect(interpolate("{count} selected", { count: 3 })).toBe("3 selected");
    expect(interpolate("Hi {name}, {name}!", { name: "Ada" })).toBe("Hi Ada, Ada!");
  });

  it("returns the template unchanged when no values are given", () => {
    expect(interpolate("no placeholders")).toBe("no placeholders");
  });

  it("leaves unmatched placeholders verbatim so the gap is visible", () => {
    expect(interpolate("Hi {name}", { other: "x" })).toBe("Hi {name}");
  });
});

describe("selectPlural", () => {
  it("uses English CLDR categories", () => {
    const forms = { one: "1 item", other: "{count} items" };
    expect(selectPlural("en", 1, forms)).toBe("1 item");
    expect(selectPlural("en", 5, forms)).toBe("{count} items");
    expect(selectPlural("en", 0, forms)).toBe("{count} items");
  });

  it("Chinese has only the `other` category", () => {
    expect(selectPlural("zh-CN", 1, { one: "one", other: "other" })).toBe("other");
  });
});

describe("locale-aware number formatters", () => {
  it("groups integers and tokens per locale", () => {
    expect(formatNumber("en", 1234567)).toBe("1,234,567");
    expect(formatTokens("en", 1234567)).toBe("1,234,567");
  });

  it("formats percentages from a fraction", () => {
    expect(formatPercent("en", 0.42)).toBe("42%");
    expect(formatPercent("en", 0.1234, 1)).toBe("12.3%");
  });

  it("formats currency with the given ISO code", () => {
    expect(formatCurrency("en", 1234.5, "USD")).toBe("$1,234.50");
    // zh-CN renders USD with a locale-specific symbol; assert the digits survive.
    expect(formatCurrency("zh-CN", 1234.5, "USD")).toContain("1,234.50");
  });
});

describe("formatBytes", () => {
  it("steps through binary units with a locale mantissa", () => {
    expect(formatBytes("en", 0)).toBe("0 B");
    expect(formatBytes("en", 512)).toBe("512 B");
    expect(formatBytes("en", 1024)).toBe("1 KB");
    expect(formatBytes("en", 1536)).toBe("1.5 KB");
    expect(formatBytes("en", 1024 * 1024)).toBe("1 MB");
    expect(formatBytes("en", -2048)).toBe("-2 KB");
  });
});

describe("date/time formatters", () => {
  const instant = new Date("2026-07-23T15:04:05Z");

  it("differ by locale", () => {
    const en = formatDate("en", instant, { year: "numeric", month: "long", day: "numeric" });
    const zh = formatDate("zh-CN", instant, { year: "numeric", month: "long", day: "numeric" });
    expect(en).toContain("2026");
    expect(zh).toContain("2026");
    expect(en).not.toEqual(zh);
  });
});

describe("formatRelativeTime", () => {
  const now = new Date("2026-07-23T12:00:00Z");

  it("picks the largest sensible unit and direction", () => {
    expect(formatRelativeTime("en", new Date("2026-07-23T11:58:30Z"), now)).toBe("1 minute ago");
    expect(formatRelativeTime("en", new Date("2026-07-23T14:00:00Z"), now)).toBe("in 2 hours");
    expect(formatRelativeTime("en", new Date("2026-07-22T12:00:00Z"), now)).toBe("yesterday");
  });
});
