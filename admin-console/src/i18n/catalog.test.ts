import { beforeAll, describe, expect, it } from "vitest";
import {
  BOOTSTRAP_CATALOG,
  LOCALES,
  LOCALE_META,
  type Locale,
  type Messages,
  isLocale,
  loadCatalog,
} from "./catalog";
import { en } from "./locales/en";

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

// #394: the DEFAULT (EN) catalog is code-split. Only a small chrome "bootstrap"
// subset is eager (in the entry chunk); the bulk (dashboard/resource/page.*) is
// pulled in by a dynamic import() and merged in by `loadCatalog("en")`. These
// tests pin the split boundary so an accidental re-merge of the whole EN catalog
// back into the eager subset (which would defeat the entry-budget win) is caught.
describe("EN bootstrap code-split (#394)", () => {
  it("bootstrap subset holds always-visible chrome keys synchronously", () => {
    // No await: these resolve from the eagerly bundled subset on the render path.
    expect(BOOTSTRAP_CATALOG["language.label"]).toBe("Language");
    expect(BOOTSTRAP_CATALOG["common.status"]).toBe("Status");
    // The route-load-boundary copy MUST be eager — it shows WHILE a route chunk
    // (and its namespace copy) is still downloading.
    expect(BOOTSTRAP_CATALOG["component.routeBoundary.loading"]).toBe("Loading page…");
  });

  it("bootstrap subset excludes route/page copy (it is split OUT of the entry)", () => {
    // These live in the lazy `./locales/en/rest` chunk, not the eager subset.
    expect(BOOTSTRAP_CATALOG["page.assets.title"]).toBeUndefined();
    expect(BOOTSTRAP_CATALOG["dashboard.title"]).toBeUndefined();
    expect(BOOTSTRAP_CATALOG["resource.action.new"]).toBeUndefined();
    // The bootstrap subset is a strict, small fraction of the whole catalog.
    expect(Object.keys(BOOTSTRAP_CATALOG).length).toBeLessThan(Object.keys(en).length / 4);
  });

  it("loadCatalog('en') merges the code-split rest over the bootstrap subset", async () => {
    const full = await loadCatalog("en");
    // Route/page copy is present only after the dynamic import() resolves...
    expect(full["page.assets.title"]).toBe("Assets");
    expect(full["dashboard.title"]).toBe("Operations overview");
    // ...and the eager chrome keys are still there in the merged full catalog.
    expect(full["language.label"]).toBe("Language");
    // The merged catalog is the WHOLE key set — same size as the source union.
    expect(Object.keys(full).length).toBe(Object.keys(en).length);
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
