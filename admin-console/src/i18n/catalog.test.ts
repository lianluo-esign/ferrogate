import { beforeAll, describe, expect, it } from "vitest";
import { en } from "./locales/en";
import {
  LOCALES,
  LOCALE_META,
  isLocale,
  loadCatalog,
  type Locale,
  type Messages,
} from "./catalog";

// Compile-time consistency is already enforced (English derives `TranslationKey`
// and zh-CN is pinned `satisfies Messages`). These runtime checks give a
// readable failure and catch value-level drift the type system can't (e.g. an
// accidentally blank string). zh-CN loads lazily (#393), so we resolve every
// catalog through `loadCatalog` up front — which also proves the lazy loader
// returns a complete catalog for each locale.
describe("catalog consistency", () => {
  const englishKeys = Object.keys(en).sort();
  const CATALOGS = {} as Record<Locale, Messages>;

  beforeAll(async () => {
    for (const locale of LOCALES) {
      CATALOGS[locale] = await loadCatalog(locale);
    }
  });

  it("every locale defines exactly the English key set (no missing/extra keys)", () => {
    for (const locale of LOCALES) {
      expect(Object.keys(CATALOGS[locale]).sort(), `locale ${locale} key drift`).toEqual(
        englishKeys,
      );
    }
  });

  it("no catalog has empty or whitespace-only values", () => {
    for (const locale of LOCALES) {
      for (const [key, value] of Object.entries(CATALOGS[locale])) {
        expect(value.trim(), `${locale}:${key} is blank`).not.toBe("");
      }
    }
  });

  it("interpolation placeholders match across locales", () => {
    const placeholders = (value: string) =>
      [...value.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
    for (const key of englishKeys) {
      const expected = placeholders(en[key as keyof typeof en]);
      for (const locale of LOCALES) {
        expect(
          placeholders(CATALOGS[locale][key as keyof typeof en]),
          `${locale}:${key} placeholder drift`,
        ).toEqual(expected);
      }
    }
  });

  it("every locale has display metadata", () => {
    for (const locale of LOCALES) {
      expect(LOCALE_META[locale].nativeName.length).toBeGreaterThan(0);
      expect(LOCALE_META[locale].htmlLang.length).toBeGreaterThan(0);
    }
  });
});

describe("isLocale", () => {
  it("accepts supported codes and rejects everything else", () => {
    expect(isLocale("en")).toBe(true);
    expect(isLocale("zh-CN")).toBe(true);
    expect(isLocale("fr")).toBe(false);
    expect(isLocale("zh")).toBe(false);
    expect(isLocale(null)).toBe(false);
    expect(isLocale(undefined)).toBe(false);
    expect(isLocale(42)).toBe(false);
  });
});
