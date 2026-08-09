import type { TranslationKey } from "@/i18n";
import { GLOSSARY, MAX_TERM_WORDS, SENSE_EXCEPTIONS } from "@/i18n/glossary";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
// Enforces the Simplified Chinese glossary (#348) against the real catalogs.
//
// The acceptance item is "review Chinese terminology for consistent
// control-plane vocabulary; maintain a small glossary". A glossary that is only
// a document drifts the moment the next page lands — this is the executable
// half: the moment a term GAINS a second Chinese rendering, `npx vitest run`
// fails and names both keys.
import { describe, expect, it } from "vitest";

type Entry = { key: TranslationKey; zh: string };

const KEYS = Object.keys(en) as TranslationKey[];

/** Catalog keys whose English value is exactly `label`. */
function keysFor(label: string): Entry[] {
  return KEYS.filter((key) => en[key] === label).map((key) => ({ key, zh: zhCN[key] }));
}

function isExcepted(key: TranslationKey): boolean {
  return key in SENSE_EXCEPTIONS;
}

describe("zh-CN glossary", () => {
  it("renders every glossary term with its single canonical Chinese value", () => {
    const offenders: string[] = [];
    for (const term of GLOSSARY) {
      const entries = keysFor(term.en);
      // A term nobody uses is a stale glossary row, not a passing test.
      expect(entries.length, `glossary term "${term.en}" matches no catalog key`).toBeGreaterThan(
        0,
      );
      for (const entry of entries) {
        if (isExcepted(entry.key)) continue;
        if (entry.zh !== term.zh) {
          offenders.push(`${entry.key}: "${entry.zh}" (glossary says "${term.zh}")`);
        }
      }
    }
    expect(offenders, `glossary violations:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("gives every repeated short English label exactly one Chinese rendering", () => {
    // The general sweep behind the glossary: any short label used by 2+ keys is
    // a term whether or not it is written down, so a NEW divergence fails here
    // even before someone adds it to GLOSSARY.
    const byEnglish = new Map<string, Entry[]>();
    for (const key of KEYS) {
      const value = en[key];
      if (value.trim().split(/\s+/).length > MAX_TERM_WORDS) continue;
      if (isExcepted(key)) continue;
      const bucket = byEnglish.get(value) ?? [];
      bucket.push({ key, zh: zhCN[key] });
      byEnglish.set(value, bucket);
    }

    const divergent: string[] = [];
    for (const [label, entries] of byEnglish) {
      const renderings = new Set(entries.map((entry) => entry.zh));
      if (renderings.size > 1) {
        divergent.push(
          `"${label}" -> ${[...renderings].join(" / ")}  [${entries.map((e) => e.key).join(", ")}]`,
        );
      }
    }
    expect(
      divergent,
      `English labels with more than one zh-CN rendering:\n${divergent.join("\n")}`,
    ).toEqual([]);
  });

  it("keeps the exception list honest: every entry still diverges and says why", () => {
    for (const [key, reason] of Object.entries(SENSE_EXCEPTIONS)) {
      const typedKey = key as TranslationKey;
      expect(KEYS, `exception for unknown key ${key}`).toContain(typedKey);
      expect(reason?.trim().length ?? 0, `exception ${key} has no reason`).toBeGreaterThan(10);
      // If it no longer collides with anything, the exception is stale: delete
      // it rather than let it hide a future divergence on the same key.
      const siblings = keysFor(en[typedKey]).filter((entry) => entry.key !== typedKey);
      const stillDiverges = siblings.some((entry) => entry.zh !== zhCN[typedKey]);
      expect(
        stillDiverges,
        `exception ${key} no longer diverges from its siblings — delete it`,
      ).toBe(true);
    }
  });

  it("keeps 代理 for the proxy sense only, never for an AI agent", () => {
    // 代理 means "proxy" — in an AI GATEWAY that is a live ambiguity, so the
    // agent surfaces all read 智能体. The one legitimate use is the request-log
    // description, whose English really is "proxied requests".
    const proxyUses = KEYS.filter((key) => zhCN[key].includes("代理"));
    for (const key of proxyUses) {
      expect(en[key].toLowerCase(), `${key} renders "agent" as 代理 (proxy); use 智能体`).toContain(
        "proxied",
      );
    }
  });
});
