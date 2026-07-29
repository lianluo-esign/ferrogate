// Client-side mirror of the gateway's site-domain hostname validation
// (crates/ferrogate-gateway/src/server/site_domains.rs :: validate_site_domain_hostname
// + routing::normalize_host, #265). The backend is authoritative; this only
// gives immediate, matching feedback in the bind form so an operator sees why
// a hostname is rejected before the POST round-trips. Keep the two in sync.
//
// Rules: lowercase + portless normalization, non-empty, <= 253 chars, no
// wildcard, no IP literal (v4 dotted-quad or bracketed v6), at least two DNS
// labels, each label 1..=63 chars of [a-z0-9-] with no leading/trailing hyphen.
//
// i18n (#348): the rejection reason is returned as a TRANSLATION KEY plus its
// interpolation values, never as prose. This module is pure/`lib`-owned — it has
// no locale and no `t` — and its return value is rendered directly in a live
// `role="alert"` by the bind forms, so returning an English sentence here put
// English inside an otherwise-Chinese form (the `no-untranslated-literal` rule
// cannot see it: it is neither JSX text nor a `toast.*` argument). Callers hold
// the locale and resolve the key with `t(error.key, error.values)`.
import type { TranslationKey } from "@/i18n";

/** Lowercases and strips a trailing port, matching routing::normalize_host. */
export function normalizeHostname(raw: string): string {
  return raw.split(":")[0].trim().toLowerCase();
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * A localizable rejection reason: the catalog key for the operator-facing copy
 * plus the values it interpolates. `hostname` is the operator's own normalized
 * input — an identifier, echoed back verbatim, never translated.
 */
export interface HostnameError {
  key: TranslationKey;
  values?: { hostname: string };
}

export interface HostnameValidation {
  /** Normalized hostname when valid; empty string when invalid/blank. */
  hostname: string;
  /** Localizable reason the hostname is rejected, or null when valid. */
  error: HostnameError | null;
}

/** Validates a bind hostname, returning the normalized form or a reason. */
export function validateSiteDomainHostname(raw: string): HostnameValidation {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { hostname: "", error: { key: "validation.hostname.required" } };
  }
  const hostname = normalizeHostname(trimmed);
  if (hostname.length > 253) {
    return {
      hostname: "",
      error: { key: "validation.hostname.tooLong", values: { hostname } },
    };
  }
  if (hostname.includes("*")) {
    return { hostname: "", error: { key: "validation.hostname.wildcard" } };
  }
  if (IPV4_RE.test(hostname) || trimmed.startsWith("[")) {
    return { hostname: "", error: { key: "validation.hostname.ipAddress" } };
  }
  const labels = hostname.split(".");
  if (labels.length < 2) {
    return {
      hostname: "",
      error: { key: "validation.hostname.notFqdn", values: { hostname } },
    };
  }
  for (const label of labels) {
    const valid =
      label.length > 0 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[a-z0-9-]+$/.test(label);
    if (!valid) {
      return {
        hostname: "",
        error: { key: "validation.hostname.invalidDns", values: { hostname } },
      };
    }
  }
  return { hostname, error: null };
}
