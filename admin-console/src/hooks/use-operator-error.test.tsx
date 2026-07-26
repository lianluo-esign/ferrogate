// #348 acceptance: "unknown backend errors fall back to localized generic copy
// plus unchanged technical detail."
//
// Before this hook every failing mutation called `toast.error(err.message)`,
// which put the SERVER's English sentence on a Chinese page and gave an unknown
// backend error no localized copy at all. These tests pin both halves of the
// contract: the headline is localized (asserted in zh-CN, so an un-localized
// regression cannot pass), and the server's own words survive byte-for-byte
// inside a `translate="no"` boundary.
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { describe, expect, it, vi } from "vitest";
import { useOperatorError } from "@/hooks/use-operator-error";
import { I18nProvider, type Locale } from "@/i18n";
import { LocalizedError } from "@/lib/localized-error";
import { ApiError } from "@/types/auth";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";

/** Renders nothing; fires `toastError(error)` once on mount. */
function ToastOnMount({ error }: { error: unknown }) {
  const { toastError, describeError } = useOperatorError();
  const described = describeError(error);
  return (
    <button type="button" onClick={() => toastError(error)}>
      {described.title}
    </button>
  );
}

/** Render in `locale` and fire the failure toast once. */
function toastFor(error: unknown, locale: Locale) {
  render(
    <I18nProvider initialLocale={locale}>
      <ToastOnMount error={error} />
    </I18nProvider>,
  );
  screen.getByRole("button").click();
}

/** The description sonner was handed, rendered so its markup can be asserted. */
function renderedDescription(spy: { mock: { calls: unknown[][] } }): HTMLElement {
  const options = spy.mock.calls[0][1] as { description?: ReactNode } | undefined;
  const { container } = render(<>{options?.description}</>);
  return container;
}

describe("useOperatorError", () => {
  it("localizes an unmapped backend error headline and keeps the server detail verbatim", () => {
    const errorToast = vi.spyOn(toast, "error");
    // 500 + an unmapped code -> the generic server-error headline; the server's
    // own message is the only thing that carries the real reason, so it is kept.
    const error = new ApiError(500, "unknown_error", "quota shard 7 is offline");

    toastFor(error, "zh-CN");

    expect(errorToast).toHaveBeenCalledTimes(1);
    expect(errorToast.mock.calls[0][0]).toBe(zhCN["error.http.server"]);
    // Not the English catalog copy, and not the raw server string as headline.
    expect(errorToast.mock.calls[0][0]).not.toBe(en["error.http.server"]);
    expect(errorToast.mock.calls[0][0]).not.toBe("quota shard 7 is offline");

    const description = renderedDescription(errorToast);
    expect(description.textContent).toBe("quota shard 7 is offline");
    // The server's phrasing is marked so neither we nor the browser rewrite it.
    expect(description.querySelector("[translate='no']")).not.toBeNull();
  });

  it("renders the same failure in English under the en catalog", () => {
    const errorToast = vi.spyOn(toast, "error");
    toastFor(new ApiError(503, "unknown_error", "upstream pool drained"), "en");

    expect(errorToast.mock.calls[0][0]).toBe(en["error.http.unavailable"]);
    expect(renderedDescription(errorToast).textContent).toBe("upstream pool drained");
  });

  it("uses the code-specific headline and drops the now-redundant message", () => {
    const errorToast = vi.spyOn(toast, "error");
    toastFor(new ApiError(403, "forbidden", "forbidden"), "zh-CN");

    expect(errorToast.mock.calls[0][0]).toBe(zhCN["error.http.forbidden"]);
    // A bespoke headline already says it — no restating description.
    expect(errorToast.mock.calls[0][1]).toBeUndefined();
  });

  it("shows a page-composed LocalizedError verbatim instead of a generic headline", () => {
    // The message was built with `t()` by the page, so it is already in the
    // operator's language AND more specific than any generic copy. Replacing it
    // would be a downgrade.
    const errorToast = vi.spyOn(toast, "error");
    const composed = "已删除 3 / 5 行，站点 marketing 仍未完全清除";

    toastFor(new LocalizedError(composed), "zh-CN");

    expect(errorToast.mock.calls[0][0]).toBe(composed);
    expect(errorToast.mock.calls[0][1]).toBeUndefined();
  });

  it("treats a dropped connection as localized connectivity copy, not 'Failed to fetch'", () => {
    const errorToast = vi.spyOn(toast, "error");
    toastFor(new TypeError("Failed to fetch"), "zh-CN");

    expect(errorToast.mock.calls[0][0]).toBe(zhCN["error.network"]);
    expect(errorToast.mock.calls[0][1]).toBeUndefined();
  });
});
