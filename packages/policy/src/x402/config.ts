/**
 * Typed x402 (Solana SVM `exact`) spend policy config + validation + the
 * checked-integer atomic→credits conversion (port of `ferrogate-policy`
 * `x402_spend.rs`, issue #351 — DEPRIORITIZED per inventory §2.1).
 *
 * Two money domains are kept strictly separate and integer-only (bigint, never
 * float): on-chain atomic token units, and internal wallet credits. They are
 * bridged only through a checked-integer {@link ConversionRule}; overflow or an
 * impossible ratio yields `undefined` (which the decision layer turns into a
 * deny), never a silent zero.
 */
import {
  MAX_TIMEOUT_SECONDS,
  isValidSolanaAddress,
  networkCaip2,
  type SolanaNetwork,
} from "./wire.js";

/** Largest representable `u64` — the range bound for the credit conversion. */
export const U64_MAX = 18_446_744_073_709_551_615n;

/** On-chain SPL amount in the mint's smallest unit. Integer-only (bigint). */
export type AtomicAmount = bigint;
/** Internal wallet credits — the tenant's own money domain. Integer-only (bigint). */
export type Credits = bigint;

/** Policy-layer network wrapper serialising as its canonical CAIP-2 string. */
export interface PolicyNetwork {
  network: SolanaNetwork;
}
export const POLICY_NETWORK_MAINNET: PolicyNetwork = { network: "mainnet" };
export const POLICY_NETWORK_DEVNET: PolicyNetwork = { network: "devnet" };
export function policyNetworkCaip2(n: PolicyNetwork): string {
  return networkCaip2(n.network);
}
export function policyNetworkIsMainnet(n: PolicyNetwork): boolean {
  return n.network === "mainnet";
}
export function policyNetworkEquals(a: PolicyNetwork, b: PolicyNetwork): boolean {
  return a.network === b.network;
}

/** Rounding direction applied when a conversion does not divide evenly. */
export type Rounding = "down" | "up";

/** Checked-integer conversion `credits = round(atomic * numerator / denominator)`. */
export interface ConversionRule {
  /** Credits numerator. Must be non-zero. */
  numerator: bigint;
  /** Atomic-unit denominator. Must be non-zero. */
  denominator: bigint;
  rounding: Rounding;
  /** Operator-set version tag, persisted into every snapshot. */
  version: string;
  /** Unix second the ratio stops being usable; `undefined` = never expires. */
  expiresAtUnix?: number;
}

/**
 * Convert an atomic amount into credits, or `undefined` on overflow / impossible
 * ratio. Arithmetic is done in bigint and range-checked back into `u64`; never
 * returns a coerced zero for a non-zero input with a valid ratio (unless the true
 * rounded result is genuinely zero).
 */
export function convert(rule: ConversionRule, atomic: AtomicAmount): Credits | undefined {
  if (rule.numerator === 0n || rule.denominator === 0n) return undefined;
  const scaled = atomic * rule.numerator;
  const den = rule.denominator;
  const credits = rule.rounding === "down" ? scaled / den : (scaled + den - 1n) / den;
  return credits <= U64_MAX ? credits : undefined;
}

/** Immutable record of a single atomic→credits conversion (decision evidence). */
export interface ConversionSnapshot {
  atomicAmount: AtomicAmount;
  /** `undefined` iff the conversion overflowed / the ratio was impossible. */
  computedCredits: Credits | undefined;
  numerator: bigint;
  denominator: bigint;
  rounding: Rounding;
  version: string;
  expiresAtUnix?: number;
}

/** Produce the immutable conversion evidence for `atomic`. */
export function snapshot(rule: ConversionRule, atomic: AtomicAmount): ConversionSnapshot {
  return {
    atomicAmount: atomic,
    computedCredits: convert(rule, atomic),
    numerator: rule.numerator,
    denominator: rule.denominator,
    rounding: rule.rounding,
    version: rule.version,
    expiresAtUnix: rule.expiresAtUnix,
  };
}

/** One explicitly allowlisted `(network, mint)` pair. Mint is a base58 address. */
export interface AllowedAsset {
  network: PolicyNetwork;
  mint: string;
}

/** Which HTTPS origin + path prefix a payment may unlock. */
export interface ResourceRule {
  /** Canonical origin, `scheme://host[:port]`. */
  origin: string;
  /** Path prefix that gates the origin. `"/"` allows the whole origin. */
  pathPrefix: string;
}

/**
 * Spend caps, denominated in internal credits except the two atomic bounds. An
 * `undefined` dimension is uncapped; a `0n` cap is rejected by validation.
 */
export interface X402SpendCaps {
  maxCreditsPerPayment?: bigint;
  maxCreditsPerRun?: bigint;
  maxCreditsPerWindow?: bigint;
  /** Informational window width in seconds. */
  windowSeconds?: bigint;
  maxAtomicPerPayment?: bigint;
  minAtomicPerPayment?: bigint;
}

/** Approval-mode policy: payments above the threshold require explicit approval. */
export interface ApprovalPolicy {
  /** Threshold above which approval is required; `undefined` = never require it. */
  thresholdCredits?: bigint;
}

/** The typed, disabled-by-default x402 spend policy for one scope. */
export interface X402SpendPolicy {
  enabled: boolean;
  revision: bigint;
  allowedNetworks: PolicyNetwork[];
  allowedAssets: AllowedAsset[];
  allowedRecipients: string[];
  allowedResources: ResourceRule[];
  caps: X402SpendCaps;
  conversion: ConversionRule;
  approval: ApprovalPolicy;
  /** Test-only escape hatch permitting `http://` resource origins. */
  allowInsecureLocalResources: boolean;
}

/** A fully disabled policy: the safe default. Denies every payment. */
export function disabledX402SpendPolicy(): X402SpendPolicy {
  return {
    enabled: false,
    revision: 0n,
    allowedNetworks: [],
    allowedAssets: [],
    allowedRecipients: [],
    allowedResources: [],
    caps: {},
    conversion: { numerator: 1n, denominator: 1n, rounding: "up", version: "disabled" },
    approval: {},
    allowInsecureLocalResources: false,
  };
}

// ---------------------------------------------------------------------------
// Config validation errors
// ---------------------------------------------------------------------------

/** Structured config-validation failures (distinct rejection classes). */
export type X402PolicyConfigError =
  | { kind: "empty_allowlist"; field: string }
  | { kind: "token_symbol_mint"; value: string }
  | { kind: "invalid_recipient"; value: string }
  | { kind: "asset_network_not_allowed"; network: string; mint: string }
  | { kind: "wildcard_mainnet" }
  | { kind: "insecure_resource"; origin: string }
  | { kind: "invalid_resource_origin"; origin: string }
  | { kind: "zero_cap"; field: string }
  | { kind: "inverted_atomic_band"; min: bigint; max: bigint }
  | { kind: "duplicate_rule"; ruleKind: string; value: string }
  | { kind: "impossible_conversion"; reason: string };

/** A policy that has passed {@link validateX402SpendPolicy} (opaque wrapper). */
export class ValidatedX402SpendPolicy {
  /** @internal — construct only via {@link validateX402SpendPolicy}. */
  constructor(private readonly inner: X402SpendPolicy) {}
  policy(): X402SpendPolicy {
    return this.inner;
  }
}

/** Result envelope for validation (Rust `Result<Validated, ConfigError>`). */
export type ValidateResult =
  | { ok: true; value: ValidatedX402SpendPolicy }
  | { ok: false; error: X402PolicyConfigError };

function rejectDuplicates(items: string[], ruleKind: string): X402PolicyConfigError | undefined {
  const seen: string[] = [];
  for (const item of items) {
    if (seen.includes(item)) return { kind: "duplicate_rule", ruleKind, value: item };
    seen.push(item);
  }
  return undefined;
}

function validateCaps(caps: X402SpendCaps): X402PolicyConfigError | undefined {
  const fields: [string, bigint | undefined][] = [
    ["caps.max_credits_per_payment", caps.maxCreditsPerPayment],
    ["caps.max_credits_per_run", caps.maxCreditsPerRun],
    ["caps.max_credits_per_window", caps.maxCreditsPerWindow],
    ["caps.window_seconds", caps.windowSeconds],
    ["caps.max_atomic_per_payment", caps.maxAtomicPerPayment],
    ["caps.min_atomic_per_payment", caps.minAtomicPerPayment],
  ];
  for (const [field, value] of fields) {
    if (value === 0n) return { kind: "zero_cap", field };
  }
  if (caps.minAtomicPerPayment !== undefined && caps.maxAtomicPerPayment !== undefined) {
    if (caps.minAtomicPerPayment > caps.maxAtomicPerPayment) {
      return { kind: "inverted_atomic_band", min: caps.minAtomicPerPayment, max: caps.maxAtomicPerPayment };
    }
  }
  return undefined;
}

function validateEnabled(p: X402SpendPolicy): X402PolicyConfigError | undefined {
  if (p.allowedNetworks.length === 0) return { kind: "empty_allowlist", field: "networks" };
  if (p.allowedAssets.length === 0) return { kind: "empty_allowlist", field: "assets" };
  if (p.allowedRecipients.length === 0) return { kind: "empty_allowlist", field: "recipients" };

  const dupNet = rejectDuplicates(p.allowedNetworks.map((n) => policyNetworkCaip2(n)), "network");
  if (dupNet !== undefined) return dupNet;

  for (const asset of p.allowedAssets) {
    if (!isValidSolanaAddress(asset.mint)) return { kind: "token_symbol_mint", value: asset.mint };
    if (!p.allowedNetworks.some((n) => policyNetworkEquals(n, asset.network))) {
      return { kind: "asset_network_not_allowed", network: policyNetworkCaip2(asset.network), mint: asset.mint };
    }
  }
  const dupAsset = rejectDuplicates(
    p.allowedAssets.map((a) => `${policyNetworkCaip2(a.network)}|${a.mint}`),
    "asset",
  );
  if (dupAsset !== undefined) return dupAsset;

  for (const recipient of p.allowedRecipients) {
    if (!isValidSolanaAddress(recipient)) return { kind: "invalid_recipient", value: recipient };
  }
  const dupRecip = rejectDuplicates([...p.allowedRecipients], "recipient");
  if (dupRecip !== undefined) return dupRecip;

  // Mainnet must never be a wildcard: it needs at least one explicit mainnet mint.
  if (
    p.allowedNetworks.some((n) => policyNetworkIsMainnet(n)) &&
    !p.allowedAssets.some((a) => policyNetworkIsMainnet(a.network))
  ) {
    return { kind: "wildcard_mainnet" };
  }

  for (const rule of p.allowedResources) {
    const origin = canonicalOrigin(rule.origin);
    if (origin === undefined) return { kind: "invalid_resource_origin", origin: rule.origin };
    if (origin.scheme !== "https" && !p.allowInsecureLocalResources) {
      return { kind: "insecure_resource", origin: rule.origin };
    }
    if (origin.scheme !== "https" && origin.scheme !== "http") {
      return { kind: "invalid_resource_origin", origin: rule.origin };
    }
  }
  const dupResource = rejectDuplicates(
    p.allowedResources.map((r) => {
      const o = canonicalOrigin(r.origin);
      const origin = o !== undefined ? canonicalOriginString(o) : r.origin;
      return `${origin}|${normalisePath(r.pathPrefix)}`;
    }),
    "resource",
  );
  if (dupResource !== undefined) return dupResource;

  const capsErr = validateCaps(p.caps);
  if (capsErr !== undefined) return capsErr;
  if (p.approval.thresholdCredits === 0n) {
    return { kind: "zero_cap", field: "approval.threshold_credits" };
  }
  return undefined;
}

/**
 * Structurally validate this config. Checks run in a fixed order so the reported
 * error is deterministic. A disabled policy is validated leniently (only its
 * conversion ratio must be sane); an enabled policy must satisfy every invariant.
 */
export function validateX402SpendPolicy(policy: X402SpendPolicy): ValidateResult {
  if (policy.conversion.numerator === 0n) {
    return { ok: false, error: { kind: "impossible_conversion", reason: "conversion numerator is zero" } };
  }
  if (policy.conversion.denominator === 0n) {
    return { ok: false, error: { kind: "impossible_conversion", reason: "conversion denominator is zero" } };
  }
  if (policy.conversion.expiresAtUnix !== undefined && policy.conversion.expiresAtUnix <= 0) {
    return {
      ok: false,
      error: {
        kind: "impossible_conversion",
        reason: `conversion expires_at_unix ${policy.conversion.expiresAtUnix} is not a positive unix second`,
      },
    };
  }
  if (policy.enabled) {
    const err = validateEnabled(policy);
    if (err !== undefined) return { ok: false, error: err };
  }
  return { ok: true, value: new ValidatedX402SpendPolicy(policy) };
}

/** Render a config error as a stable human string (mirrors the `Display` impl). */
export function x402PolicyConfigErrorMessage(e: X402PolicyConfigError): string {
  switch (e.kind) {
    case "empty_allowlist":
      return `enabled x402 policy has an empty ${e.field} allowlist`;
    case "token_symbol_mint":
      return `mint ${JSON.stringify(e.value)} is not a canonical base58 mint address (token symbols are not accepted)`;
    case "invalid_recipient":
      return `recipient ${JSON.stringify(e.value)} is not a valid base58 Solana address`;
    case "asset_network_not_allowed":
      return `asset mint ${e.mint} names network ${e.network}, which is not in allowed_networks`;
    case "wildcard_mainnet":
      return "mainnet is allowed without an explicit mainnet mint (wildcard mainnet forbidden)";
    case "insecure_resource":
      return `resource origin ${JSON.stringify(e.origin)} is not https`;
    case "invalid_resource_origin":
      return `resource origin ${JSON.stringify(e.origin)} is not a valid origin`;
    case "zero_cap":
      return `cap ${e.field} is zero`;
    case "inverted_atomic_band":
      return `min_atomic_per_payment ${e.min} exceeds max ${e.max}`;
    case "duplicate_rule":
      return `duplicate ${e.ruleKind} rule: ${e.value}`;
    case "impossible_conversion":
      return `impossible conversion: ${e.reason}`;
  }
}

// ---------------------------------------------------------------------------
// Minimal URL canonicalisation (no external URL dependency) — security-critical
// ---------------------------------------------------------------------------

/** A canonical origin: lowercased scheme + host, default port dropped. */
export interface CanonicalOrigin {
  scheme: string;
  /** `host[:port]`, port present only when non-default. */
  authority: string;
}

/** A canonical URL: origin + normalised path (no query/fragment). */
export interface CanonicalUrl {
  origin: CanonicalOrigin;
  path: string;
}

export function canonicalOriginString(o: CanonicalOrigin): string {
  return `${o.scheme}://${o.authority}`;
}

function defaultPort(scheme: string): string | undefined {
  if (scheme === "https") return "443";
  if (scheme === "http") return "80";
  return undefined;
}

function canonicalAuthority(scheme: string, hostPort: string): CanonicalOrigin {
  const idx = hostPort.lastIndexOf(":");
  let host = hostPort;
  let port: string | undefined;
  if (idx >= 0) {
    const p = hostPort.slice(idx + 1);
    if (p.length > 0 && /^[0-9]+$/.test(p)) {
      host = hostPort.slice(0, idx);
      port = p;
    }
  }
  let authority: string;
  if (port !== undefined && defaultPort(scheme) === port) {
    authority = host.toLowerCase();
  } else if (port !== undefined) {
    authority = `${host.toLowerCase()}:${port}`;
  } else {
    authority = host.toLowerCase();
  }
  return { scheme, authority };
}

/** Canonicalise a `scheme://host[:port]` origin (rejects a stray path). */
export function canonicalOrigin(origin: string): CanonicalOrigin | undefined {
  const sep = origin.indexOf("://");
  if (sep < 0) return undefined;
  const scheme = origin.slice(0, sep).toLowerCase();
  const rest = origin.slice(sep + 3);
  if (scheme.length === 0 || rest.length === 0) return undefined;
  const hostPort = rest.split(/[/?#]/, 1)[0];
  if (hostPort !== rest || hostPort.length === 0) return undefined;
  return canonicalAuthority(scheme, hostPort);
}

/** Canonicalise a full URL to origin + path, dropping query and fragment. */
export function canonicalUrl(url: string): CanonicalUrl | undefined {
  const sep = url.indexOf("://");
  if (sep < 0) return undefined;
  const scheme = url.slice(0, sep).toLowerCase();
  const rest = url.slice(sep + 3);
  if (scheme.length === 0 || rest.length === 0) return undefined;
  const m = rest.match(/[/?#]/);
  const i = m ? (m.index as number) : -1;
  const hostPort = i >= 0 ? rest.slice(0, i) : rest;
  const tail = i >= 0 ? rest.slice(i) : "";
  if (hostPort.length === 0) return undefined;
  const origin = canonicalAuthority(scheme, hostPort);
  let path: string;
  if (tail.startsWith("/")) {
    const end = tail.search(/[?#]/);
    path = normalisePath(end >= 0 ? tail.slice(0, end) : tail);
  } else {
    path = "/";
  }
  return { origin, path };
}

/** Ensure a leading slash and strip a trailing slash except for the root. */
export function normalisePath(path: string): string {
  const withLeading = path.startsWith("/") ? path : `/${path}`;
  if (withLeading.length > 1) return withLeading.replace(/\/+$/, "");
  return withLeading;
}

/** Is `path` at or beneath `prefix`? A `"/"` prefix matches everything. */
export function pathIsUnder(path: string, prefix: string): boolean {
  const p = normalisePath(prefix);
  if (p === "/") return true;
  if (path === p) return true;
  return path.startsWith(p) && path.charCodeAt(p.length) === 47 /* '/' */;
}

/** Does a resource rule cover a canonical URL? Origin exact + path at/under prefix. */
export function resourceRuleMatches(rule: ResourceRule, url: CanonicalUrl): boolean {
  const ruleOrigin = canonicalOrigin(rule.origin);
  if (ruleOrigin === undefined) return false;
  if (canonicalOriginString(ruleOrigin) !== canonicalOriginString(url.origin)) return false;
  return pathIsUnder(url.path, rule.pathPrefix);
}

/** True iff the timeout is within `1..=MAX_TIMEOUT_SECONDS` (helper for callers). */
export function timeoutInRange(seconds: bigint): boolean {
  return seconds >= 1n && seconds <= MAX_TIMEOUT_SECONDS;
}
