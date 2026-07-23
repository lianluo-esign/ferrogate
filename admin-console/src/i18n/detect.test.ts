import { afterEach, describe, expect, it, vi } from "vitest";
import {
  LOCALE_STORAGE_KEY,
  readStoredLocale,
  resolveInitialLocale,
  writeStoredLocale,
} from "./detect";

afterEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
});

describe("persistence", () => {
  it("round-trips a validated locale", () => {
    writeStoredLocale("zh-CN");
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
    expect(readStoredLocale()).toBe("zh-CN");
  });

  it("treats an unknown persisted value as no preference", () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "klingon");
    expect(readStoredLocale()).toBeNull();
  });

  it("survives storage throwing (private mode)", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    expect(readStoredLocale()).toBeNull();
    expect(() => writeStoredLocale("en")).not.toThrow();
  });
});

describe("resolveInitialLocale", () => {
  it("prefers a valid persisted choice over the browser languages", () => {
    writeStoredLocale("zh-CN");
    expect(resolveInitialLocale(["en-US", "en"])).toBe("zh-CN");
  });

  it("matches navigator languages exactly", () => {
    expect(resolveInitialLocale(["zh-CN", "en"])).toBe("zh-CN");
  });

  it("falls back to a base-language match", () => {
    // "zh-Hans-CN" / "zh-TW" share base language "zh" -> our zh-CN catalog.
    expect(resolveInitialLocale(["zh-Hans-CN"])).toBe("zh-CN");
    expect(resolveInitialLocale(["en-GB"])).toBe("en");
  });

  it("falls back to English when nothing matches", () => {
    expect(resolveInitialLocale(["fr-FR", "de"])).toBe("en");
    expect(resolveInitialLocale([])).toBe("en");
  });
});
