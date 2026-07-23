// Type-level tests. These assertions are checked by `tsc -b` (this file is in
// `src`, so the app build type-checks it) AND executed by Vitest. Each
// `@ts-expect-error` FAILS the build if the line below it stops being a type
// error — i.e. if key/locale safety silently regresses.
import { describe, expect, it } from "vitest";
import { translate } from "./i18n-provider";
import type { Locale, Messages, TranslationKey } from "./catalog";

// Never executed — its ONLY purpose is to be type-checked by `tsc -b`. Each
// `@ts-expect-error` turns "this line must be a type error" into a build gate.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function __compileTimeChecks(good: TranslationKey) {
  // @ts-expect-error — "language.lable" is a typo: not a TranslationKey.
  translate("en", "language.lable");

  // @ts-expect-error — arbitrary strings are not valid keys.
  translate("en", "totally.made.up");

  // @ts-expect-error — "fr" is not a supported Locale.
  translate("fr", good);

  // @ts-expect-error — an incomplete catalog cannot satisfy Messages.
  const incomplete: Messages = { "language.label": "x" };
  void incomplete;
}

describe("key safety", () => {
  it("resolves a well-typed key at runtime", () => {
    const good: TranslationKey = "language.label";
    expect(translate("en", good)).toBe("Language");
  });

  it("narrows the Locale union", () => {
    const en: Locale = "en";
    expect(en).toBe("en");
  });
});
