// An Error whose `message` is ALREADY localized operator copy (#348).
//
// Two very different things are thrown into the same `onError` handlers:
//
//   1. a backend failure (`ApiError`, a `fetch` TypeError, ...) whose `message`
//      is the SERVER's English phrasing — never localizable, and the thing
//      `operatorErrorFor` maps to a localized generic headline plus retained
//      technical detail;
//   2. a failure the PAGE composed itself out of `t()` — a client-side
//      validation refusal, an "uncommitted publish" explanation, a partial-purge
//      report. Its message is already in the operator's language and is far more
//      specific than any generic headline.
//
// Without a marker the two are indistinguishable at the handler (both are just
// `Error`), and running (2) through the generic mapping would DOWNGRADE precise
// localized copy to "Something went wrong." This class is that marker: throw it
// wherever the message is built with `t()`, and `useOperatorError` shows the
// message as-is instead of replacing it.
export class LocalizedError extends Error {
  /**
   * Structural marker. A plain field (not just `instanceof`) so the check
   * survives the realm/bundle boundaries a class identity check does not.
   */
  readonly isLocalizedCopy = true as const;

  constructor(message: string) {
    super(message);
    this.name = "LocalizedError";
  }
}

/** True when `value` carries operator copy that is already in the active locale. */
export function isLocalizedError(value: unknown): value is LocalizedError {
  return value instanceof Error && (value as Partial<LocalizedError>).isLocalizedCopy === true;
}
