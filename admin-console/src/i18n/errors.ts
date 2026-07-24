// Backend error/status-code -> localized operator-copy mapping (#346).
//
// The console surfaces backend failures to operators. This module is the STABLE,
// central mapping from an error's HTTP status (and, when present, its backend
// error `code`) to a GENERIC, localized operator headline — a translation KEY
// resolved by the caller through `t()` / `translate()`, so the copy tracks the
// active locale like everything else. It never returns a translated string
// itself; keeping keys (not strings) here means one source of truth for the copy
// and no locale plumbing in this pure module.
//
// What is NOT translated (per #346): identifiers and server phrasing. The raw
// server `message` and the backend `code` are IDENTIFIERS / provider detail, so
// they are retained VERBATIM on the descriptor as `technicalDetail` / `code` for
// the UI to render inside a `translate="no"` boundary — never localized, never
// paraphrased. Unknown/unmapped detail is preserved rather than swallowed.
//
// This is a SCAFFOLD (#346 non-goal: full per-page migration). It maps the
// cross-cutting status/code buckets every route shares; resource-specific reasons
// (an asset-scan rejection, a guardrail block, ...) keep their bespoke copy in
// their own page namespace and are not generalized here. Adopting it in a page is
// follow-up: `const e = operatorErrorFor(err); t(e.titleKey)` for the headline,
// plus the retained `e.technicalDetail` / `e.code` shown `translate="no"`.
import type { TranslationKey } from "./catalog";

/** Shape of a backend error we can read a status/code/message from. */
interface ApiErrorLike {
  status: number;
  code: string;
  message: string;
}

/**
 * A localized-ready descriptor for an operator-facing error.
 *
 * `titleKey` is the localized headline (resolve with `t()`); `status` and `code`
 * are the backend identifiers as received (never translated); `technicalDetail`
 * is the retained, unlocalized server message to render inside a `translate="no"`
 * boundary when it adds information beyond the generic headline.
 */
export interface OperatorError {
  /** Translation key for the localized, operator-facing headline. */
  titleKey: TranslationKey;
  /** HTTP status if the error carried one, else `null`. */
  status: number | null;
  /** Backend error code if present — an IDENTIFIER, never translated. */
  code: string | null;
  /**
   * Verbatim server-supplied detail to surface as MARKED technical detail
   * (`translate="no"`), or `null`. Retained for unmapped/generic buckets where
   * the raw message carries the real reason; suppressed when a specific `code`
   * already produced a bespoke localized headline (the message would be
   * redundant with the copy we show).
   */
  technicalDetail: string | null;
}

/**
 * Stable backend-`code` -> headline key. Only GENERIC, cross-cutting codes live
 * here; a match wins over the HTTP-status bucket because the code is the more
 * specific signal. Resource-specific codes are intentionally absent (see file
 * header). Extend this as new cross-cutting codes appear — it is the one place
 * the code vocabulary is mapped.
 */
const CODE_COPY: Readonly<Record<string, TranslationKey>> = {
  invalid_credentials: "error.code.invalidCredentials",
  forbidden: "error.http.forbidden",
  not_found: "error.http.notFound",
  conflict: "error.http.conflict",
  rate_limited: "error.http.rateLimited",
  backend_unavailable: "error.http.unavailable",
  provider_unavailable: "error.http.unavailable",
  storage_unavailable: "error.http.unavailable",
};

/** Exact HTTP status -> headline key for the statuses with bespoke copy. */
const STATUS_COPY: Readonly<Record<number, TranslationKey>> = {
  400: "error.http.badRequest",
  401: "error.http.unauthorized",
  403: "error.http.forbidden",
  404: "error.http.notFound",
  409: "error.http.conflict",
  422: "error.http.unprocessable",
  429: "error.http.rateLimited",
  500: "error.http.server",
  502: "error.http.unavailable",
  503: "error.http.unavailable",
  504: "error.http.unavailable",
};

/**
 * Map an HTTP status to a generic operator headline key. Exact matches win;
 * otherwise fall back by class: 5xx -> server error, other 4xx -> bad request,
 * anything else -> unknown.
 */
export function statusCopyKey(status: number): TranslationKey {
  const exact = STATUS_COPY[status];
  if (exact) return exact;
  if (status >= 500) return "error.http.server";
  if (status >= 400) return "error.http.badRequest";
  return "error.unknown";
}

/** Duck-type an object as an `ApiError` (avoids a hard `instanceof` coupling). */
function isApiErrorLike(value: unknown): value is ApiErrorLike {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.status === "number" &&
    typeof candidate.code === "string" &&
    typeof candidate.message === "string"
  );
}

/**
 * A thrown `fetch` failure (no HTTP response) is a `TypeError`. Treat it as a
 * connectivity problem so the operator gets "could not reach the server" rather
 * than the raw "Failed to fetch".
 */
function isNetworkError(value: unknown): boolean {
  return value instanceof TypeError;
}

/**
 * Resolve any thrown value into an {@link OperatorError}: a localized headline
 * key plus the retained, unlocalized backend identifiers/detail. Pure and
 * synchronous — safe to call from a render path or an error handler.
 */
export function operatorErrorFor(error: unknown): OperatorError {
  if (isApiErrorLike(error)) {
    const code = error.code.trim() || null;
    const message = error.message.trim();
    const codeKey = code ? CODE_COPY[code] : undefined;
    const titleKey = codeKey ?? statusCopyKey(error.status);
    // A specific code produced a bespoke headline -> the server message is
    // understood; drop it to avoid restating the copy. Otherwise retain it as
    // the marked technical detail (the real, unlocalizable reason).
    const technicalDetail = message && !codeKey ? message : null;
    return { titleKey, status: error.status, code, technicalDetail };
  }

  if (isNetworkError(error)) {
    return { titleKey: "error.network", status: null, code: null, technicalDetail: null };
  }

  // Unknown throwable: keep any message string as technical detail so nothing is
  // silently swallowed, but show the generic headline.
  const detail = error instanceof Error ? error.message.trim() || null : null;
  return { titleKey: "error.unknown", status: null, code: null, technicalDetail: detail };
}
