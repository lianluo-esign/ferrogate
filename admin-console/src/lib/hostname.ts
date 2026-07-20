// Client-side mirror of the gateway's site-domain hostname validation
// (crates/ferrogate-cli/src/gateway/site_domains.rs :: validate_site_domain_hostname
// + routing::normalize_host, #265). The backend is authoritative; this only
// gives immediate, matching feedback in the bind form so an operator sees why
// a hostname is rejected before the POST round-trips. Keep the two in sync.
//
// Rules: lowercase + portless normalization, non-empty, <= 253 chars, no
// wildcard, no IP literal (v4 dotted-quad or bracketed v6), at least two DNS
// labels, each label 1..=63 chars of [a-z0-9-] with no leading/trailing hyphen.

/** Lowercases and strips a trailing port, matching routing::normalize_host. */
export function normalizeHostname(raw: string): string {
  return raw.split(":")[0].trim().toLowerCase();
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export interface HostnameValidation {
  /** Normalized hostname when valid; empty string when invalid/blank. */
  hostname: string;
  /** Human-readable reason the hostname is rejected, or null when valid. */
  error: string | null;
}

/** Validates a bind hostname, returning the normalized form or a reason. */
export function validateSiteDomainHostname(raw: string): HostnameValidation {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { hostname: "", error: "hostname is required" };
  }
  const hostname = normalizeHostname(trimmed);
  if (hostname.length > 253) {
    return { hostname: "", error: `hostname ${hostname} exceeds 253 characters` };
  }
  if (hostname.includes("*")) {
    return {
      hostname: "",
      error: "wildcard hostnames cannot be bound to a site",
    };
  }
  if (IPV4_RE.test(hostname) || trimmed.startsWith("[")) {
    return { hostname: "", error: "an IP address cannot be bound to a site" };
  }
  const labels = hostname.split(".");
  if (labels.length < 2) {
    return {
      hostname: "",
      error: `hostname ${hostname} must be a fully qualified domain name`,
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
        error: `hostname ${hostname} is not a valid DNS name`,
      };
    }
  }
  return { hostname, error: null };
}
