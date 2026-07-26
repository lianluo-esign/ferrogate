// Adoption layer for the #346 backend-error -> localized-copy scaffold (#348).
//
// `src/i18n/errors.ts` maps a thrown backend failure to a GENERIC, localized
// operator headline KEY plus the retained, never-translated technical detail.
// It landed with zero consumers: every failing mutation called
// `toast.error(err.message)`, which surfaces the raw English server string with
// no localized headline at all — so a zh-CN operator got an English sentence out
// of an otherwise-Chinese page, and an unknown backend error produced no
// localized copy whatsoever. This hook is the one place that resolves the
// descriptor and renders it, so the acceptance contract ("unknown backend errors
// fall back to localized generic copy plus unchanged technical detail") holds
// identically at every call site.
//
// The technical detail is rendered inside `translate="no"`: it is the server's
// own phrasing (and often carries identifiers), so browser auto-translation must
// not rewrite it, and neither do we.
import { useCallback, useMemo } from "react";
import { toast } from "sonner";
import { operatorErrorFor, useI18n } from "@/i18n";
import { isLocalizedError } from "@/lib/localized-error";

export interface OperatorErrorCopy {
  /** Localized, operator-facing headline for the failure. */
  title: string;
  /** Verbatim server-supplied detail, or `null` when there is nothing to add. */
  detail: string | null;
}

export interface OperatorErrorHelpers {
  /**
   * Resolve any thrown value into localized headline + retained technical
   * detail. For inline error regions (a `role="alert"` panel) that need the
   * two parts separately.
   */
  describeError: (error: unknown) => OperatorErrorCopy;
  /**
   * Show a failure toast: localized headline, with the verbatim server detail
   * as a `translate="no"` description when it adds information.
   */
  toastError: (error: unknown) => void;
}

/**
 * Render the server-supplied detail so neither we nor the browser translates it.
 * Exported for the inline (non-toast) error regions that show the same detail.
 */
export function TechnicalDetail({ detail }: { detail: string }) {
  return (
    <span translate="no" className="font-mono text-xs break-all">
      {detail}
    </span>
  );
}

/** Localized operator-error helpers bound to the active locale. */
export function useOperatorError(): OperatorErrorHelpers {
  const { t } = useI18n();

  const describeError = useCallback(
    (error: unknown): OperatorErrorCopy => {
      // A page-composed failure is ALREADY localized and is more specific than
      // any generic headline — show it verbatim rather than replacing it (see
      // lib/localized-error.ts).
      if (isLocalizedError(error)) return { title: error.message, detail: null };
      const operatorError = operatorErrorFor(error);
      return { title: t(operatorError.titleKey), detail: operatorError.technicalDetail };
    },
    [t],
  );

  const toastError = useCallback(
    (error: unknown): void => {
      const { title, detail } = describeError(error);
      // `description` is omitted (not passed as null) when the headline already
      // says everything the backend told us, so the toast stays one line.
      if (detail === null) {
        toast.error(title);
        return;
      }
      toast.error(title, { description: <TechnicalDetail detail={detail} /> });
    },
    [describeError],
  );

  return useMemo(() => ({ describeError, toastError }), [describeError, toastError]);
}
