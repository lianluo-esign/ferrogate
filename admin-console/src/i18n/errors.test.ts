import { ApiError } from "@/types/auth";
// Unit coverage for the backend error/status-code -> operator-copy scaffold (#346).
//
// Proves the four contracts the mapping must hold: (1) a stable status/code ->
// headline-KEY mapping (code wins over status); (2) unknown/network detail is
// preserved, not swallowed; (3) identifiers (code, server message) are retained
// verbatim and never localized; (4) every headline key the mapper can emit
// actually resolves to real, non-empty copy in BOTH locales (catalog consistency
// for the `error.*` namespace).
import { beforeAll, describe, expect, it } from "vitest";
import { LOCALES, type Locale, type Messages, loadCatalog } from "./catalog";
import { operatorErrorFor, statusCopyKey } from "./errors";
import { translate } from "./i18n-provider";

// The full generic error namespace the scaffold owns (the exact key contract the
// EN + zh-CN catalogs must both cover).
const ERROR_KEYS = [
  "error.unknown",
  "error.network",
  "error.http.badRequest",
  "error.http.unauthorized",
  "error.http.forbidden",
  "error.http.notFound",
  "error.http.conflict",
  "error.http.unprocessable",
  "error.http.rateLimited",
  "error.http.server",
  "error.http.unavailable",
  "error.code.invalidCredentials",
  "error.technicalDetail",
] as const;

describe("statusCopyKey", () => {
  it("maps the statuses with bespoke copy exactly", () => {
    expect(statusCopyKey(401)).toBe("error.http.unauthorized");
    expect(statusCopyKey(403)).toBe("error.http.forbidden");
    expect(statusCopyKey(404)).toBe("error.http.notFound");
    expect(statusCopyKey(409)).toBe("error.http.conflict");
    expect(statusCopyKey(429)).toBe("error.http.rateLimited");
    expect(statusCopyKey(503)).toBe("error.http.unavailable");
  });

  it("falls back by status class for unmapped codes", () => {
    expect(statusCopyKey(418)).toBe("error.http.badRequest"); // other 4xx
    expect(statusCopyKey(599)).toBe("error.http.server"); // other 5xx
    expect(statusCopyKey(200)).toBe("error.unknown"); // not an error class
  });
});

describe("operatorErrorFor", () => {
  it("maps an ApiError by HTTP status when the code is not specifically mapped", () => {
    const result = operatorErrorFor(new ApiError(403, "tenant_scope_denied", "Scope denied"));
    expect(result.titleKey).toBe("error.http.forbidden");
    expect(result.status).toBe(403);
    // The backend code is an identifier -> retained verbatim, never translated.
    expect(result.code).toBe("tenant_scope_denied");
    // Unmapped code -> the raw server message is retained as technical detail.
    expect(result.technicalDetail).toBe("Scope denied");
  });

  it("prefers a specifically-mapped backend code over the HTTP status", () => {
    // 400 would map to badRequest, but the code has bespoke copy and wins.
    const result = operatorErrorFor(
      new ApiError(400, "invalid_credentials", "Invalid credentials"),
    );
    expect(result.titleKey).toBe("error.code.invalidCredentials");
    expect(result.code).toBe("invalid_credentials");
    // A specific code produced bespoke copy -> the redundant message is dropped.
    expect(result.technicalDetail).toBeNull();
  });

  it("maps unavailability codes to the shared unavailable headline", () => {
    for (const code of ["backend_unavailable", "provider_unavailable", "storage_unavailable"]) {
      expect(operatorErrorFor(new ApiError(500, code, "down")).titleKey).toBe(
        "error.http.unavailable",
      );
    }
  });

  it("treats a thrown fetch TypeError as a network error with no server detail", () => {
    const result = operatorErrorFor(new TypeError("Failed to fetch"));
    expect(result.titleKey).toBe("error.network");
    expect(result.status).toBeNull();
    expect(result.code).toBeNull();
    expect(result.technicalDetail).toBeNull();
  });

  it("falls back to unknown for an arbitrary Error but keeps its message as detail", () => {
    const result = operatorErrorFor(new Error("boom in the pipeline"));
    expect(result.titleKey).toBe("error.unknown");
    expect(result.status).toBeNull();
    expect(result.code).toBeNull();
    expect(result.technicalDetail).toBe("boom in the pipeline");
  });

  it("falls back to unknown with no detail for a non-error throwable", () => {
    const result = operatorErrorFor("just a string");
    expect(result.titleKey).toBe("error.unknown");
    expect(result.technicalDetail).toBeNull();
  });

  it("normalizes a blank code to null so it is not treated as an identifier", () => {
    const result = operatorErrorFor(new ApiError(404, "   ", "missing"));
    expect(result.code).toBeNull();
    expect(result.titleKey).toBe("error.http.notFound");
  });
});

describe("error namespace catalog consistency", () => {
  const CATALOGS = {} as Record<Locale, Messages>;

  beforeAll(async () => {
    for (const locale of LOCALES) CATALOGS[locale] = await loadCatalog(locale);
  });

  it("every locale defines non-empty copy for the whole error namespace", () => {
    for (const locale of LOCALES) {
      for (const key of ERROR_KEYS) {
        expect(CATALOGS[locale][key]?.trim(), `${locale}:${key}`).toBeTruthy();
      }
    }
  });

  it("resolves an emitted headline key to real localized copy (not the key)", () => {
    const key = operatorErrorFor(new ApiError(403, "x", "y")).titleKey;
    expect(translate("en", key)).toBe("You do not have permission to perform this action.");
    // zh-CN loaded above -> the resolver returns Chinese copy, not the raw key.
    expect(translate("zh-CN", key)).not.toBe(key);
    expect(translate("zh-CN", key)).toBe("您没有执行此操作的权限。");
  });
});
