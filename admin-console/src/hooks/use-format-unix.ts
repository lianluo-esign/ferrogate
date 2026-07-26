// Locale-aware unix-seconds timestamp rendering (#348).
//
// Twelve surfaces formatted operator-visible timestamps with a bare
// `new Date(unix * 1000).toLocaleString()`. With no locale argument that follows
// `navigator.language`, NOT the console's active locale — so an operator on an
// `en-US` browser reading the console in 简体中文 still got `7/25/2026, 3:04:12 PM`
// in every timestamp cell, and the acceptance box ("dates … are locale-correct")
// could not hold no matter what the catalog said.
//
// This hook is the replacement. It keeps the exact `formatUnix(unix)` call
// signature the pages already use — so the ~40 call sites are untouched — while
// resolving through the active locale's `Intl.DateTimeFormat` (`format.date`
// from `useI18n`).
//
// NOT for evidence timestamps: `lib/guardrails.ts` and
// `components/agent-ops/agent-ops-primitives.tsx` deliberately render UTC ISO
// strings for audit/evidence rows, which must stay byte-for-byte identical
// across a locale switch. Those are correct as they are and are left alone.
import { useCallback } from "react";
import { useI18n } from "@/i18n";

/**
 * A `formatUnix(unix)` bound to the active locale.
 *
 * `placeholder` is what an absent timestamp renders as — the console's existing
 * convention is "-" on operational tables and "—" on billing tables; pass it
 * explicitly rather than normalizing an unrelated visual difference here.
 */
export function useFormatUnix(
  placeholder = "-",
): (unix: number | null | undefined) => string {
  const { format } = useI18n();
  return useCallback(
    (unix: number | null | undefined): string => {
      if (unix === null || unix === undefined) return placeholder;
      // `dateStyle`+`timeStyle` (not a bare `toLocaleString`) so BOTH halves are
      // locale-correct: "Jul 25, 2026, 3:04 PM" vs "2026年7月25日 15:04".
      return format.date(unix * 1000, { dateStyle: "medium", timeStyle: "short" });
    },
    [format, placeholder],
  );
}
