/**
 * The PRE-AUTHENTICATION network gate — Rust
 * `AppState::check_network_access` (`state.rs:5011`, issue #166), mounted at
 * the same point in the ingress order (`server/handlers.rs:68`: after the
 * request id is minted, before anything that costs a credential lookup).
 *
 * Two ANDed conditions, in this order:
 *
 *   1. **IP allowlist.** With a non-empty `ip_allowlist`, a request whose
 *      resolved client IP is outside every configured CIDR answers
 *      `403 ip_denied`. A missing or unparsable client IP is DENIED whenever an
 *      allowlist is configured — fail closed, exactly the Rust
 *      `client_ip.is_some_and(..)`.
 *   2. **Unauthenticated per-source-IP flood limit.** A fixed one-minute window
 *      per source IP; over it answers `429 unauthenticated_rate_limited`. A
 *      request with no resolvable client IP is EXEMPT (there is nothing to key
 *      it on) — also verbatim Rust.
 *
 * Both run before `contractAuth`, which is the entire point: the Rust doc
 * comment says the gate exists "so a flood or credential-stuffing scan never
 * pays the virtual-key/storage lookup cost". Mounting it after the auth guard
 * would satisfy the allowlist but not that, so `createGatewayApp` registers it
 * between `requestId` and `contractAuth` and `test/routes/network.test.ts`
 * asserts the ORDER directly (an anonymous, credential-less request from a
 * denied IP must answer 403 `ip_denied`, never 401 `missing_api_key`).
 *
 * ## What this closes
 *
 * `packages/config` has carried the whole `[network_access]` section — CIDR
 * validators, `resolveClientIp`'s anti-spoof `X-Forwarded-For`-from-the-RIGHT
 * walk, and `UnauthenticatedIpRateLimiter`'s fixed-window arithmetic — since
 * wave 2, and NOTHING READ IT. An operator who set `ip_allowlist` got a green
 * `ferrogate check` and a gateway open to the world. This module is the reader.
 * Every primitive below comes from `@ferrogate/config`; nothing is
 * re-implemented here.
 *
 * ## Two platform differences, both stated rather than hidden
 *
 * 1. **No peer address.** The Rust gate started from the TCP peer address off
 *    the Pingora socket. A Worker never sees a socket, so the substitute is
 *    Cloudflare's `CF-Connecting-IP` — the one header on this platform with the
 *    same trust property, because the edge sets it and strips any client-sent
 *    copy. It is passed as `peerAddr` into the unmodified Rust
 *    `resolveClientIp`, so the `trust_forwarded_for` / `trusted_proxy_hops`
 *    behaviour on top of it is identical.
 * 2. **The limiter is isolate-local.** Workers isolates share no memory and the
 *    only cross-isolate counters (Durable Objects, the Rate Limiting binding)
 *    are ASYNC, so they cannot hide behind `UnauthenticatedIpRateLimiter`'s
 *    synchronous `allow()`. The consequence is a WEAKER bound, not a different
 *    rule: N isolates admit up to N×limit. That is why this stays a coarse
 *    pre-auth flood gate and the billing-accurate per-tenant limiter is the
 *    Durable Object in `src/ratelimit/` — which runs AFTER auth, where a tenant
 *    identity exists to key it on.
 *
 * ## Misconfiguration fails CLOSED, and says so
 *
 * In Rust an invalid CIDR or a zero rate limit is a `validate_network_access`
 * diagnostic: `ferrogate check` fails and the process never binds a listener.
 * Worker vars get no such gate — `wrangler deploy` ships whatever string is
 * there. So a DECLARED-but-unusable `[network_access]` var answers
 * `503 network_access_misconfigured` on every request instead of silently
 * reverting to "no allowlist", which would turn a typo into an open gateway.
 * The 503 is deliberately NOT `403 ip_denied`: an operator must be able to tell
 * "your IP is not on the list" from "this deployment's list is unreadable".
 */
import {
  IpCidr,
  UnauthenticatedIpRateLimiter,
  isIpAddress,
  resolveClientIp,
} from "@ferrogate/config";
import type { MiddlewareHandler } from "hono";
import type { GatewayEnv } from "../ports.js";
import { HttpError } from "./errors.js";

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/** `network_access.ip_allowlist` — JSON array of CIDR/IP strings, or a comma list. */
export const IP_ALLOWLIST_VAR = "GATEWAY_IP_ALLOWLIST";
/** `network_access.trust_forwarded_for` — `"true"` and nothing else enables it. */
export const TRUST_FORWARDED_FOR_VAR = "GATEWAY_TRUST_FORWARDED_FOR";
/** `network_access.trusted_proxy_hops` — positive integer, clamped to >= 1. */
export const TRUSTED_PROXY_HOPS_VAR = "GATEWAY_TRUSTED_PROXY_HOPS";
/** `network_access.unauthenticated_rate_limit_per_minute` — positive integer. */
export const UNAUTHENTICATED_RATE_LIMIT_VAR = "GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE";

/**
 * The header the Cloudflare edge sets to the real client IP. It is the closest
 * thing to the Rust peer address: the edge overwrites any client-supplied copy,
 * so unlike `X-Forwarded-For` it cannot be spoofed from outside.
 */
export const CLIENT_IP_HEADER = "cf-connecting-ip";

/** The four vars this module reads. */
export interface NetworkAccessBindings {
  readonly GATEWAY_IP_ALLOWLIST?: string | undefined;
  readonly GATEWAY_TRUST_FORWARDED_FOR?: string | undefined;
  readonly GATEWAY_TRUSTED_PROXY_HOPS?: string | undefined;
  readonly GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE?: string | undefined;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** Rust `NetworkAccessDecision`, plus the Workers-only misconfiguration arm. */
export type NetworkAccessDecision = "allowed" | "ip_denied" | "rate_limited" | "misconfigured";

/** The parsed `[network_access]` section. */
export interface NetworkAccessPolicy {
  /** Usable allowlist entries. Empty ⇒ no allowlist (Rust `is_empty()`). */
  readonly allowlist: readonly IpCidr[];
  readonly trustForwardedFor: boolean;
  readonly trustedProxyHops: number;
  /** `undefined` ⇒ unlimited (Rust `None`). */
  readonly unauthenticatedRateLimitPerMinute: number | undefined;
  /**
   * Non-`null` when the operator DECLARED a setting this module cannot honour.
   * The string is the diagnostic, shaped like the `ferrogate check` one that
   * would have stopped the Rust process from starting.
   */
  readonly misconfiguration: string | null;
}

/** The wide-open default: what an unconfigured deployment gets. */
export const OPEN_NETWORK_ACCESS_POLICY: NetworkAccessPolicy = {
  allowlist: [],
  trustForwardedFor: false,
  trustedProxyHops: 1,
  unauthenticatedRateLimitPerMinute: undefined,
  misconfiguration: null,
};

/**
 * Split the allowlist var into raw entries.
 *
 * A JSON array is the canonical form (every other table in `wrangler.toml` is
 * JSON); a bare comma-separated list is also accepted because a single CIDR is
 * the overwhelmingly common case and `"10.0.0.0/8"` is not valid JSON for an
 * array. Anything that parses as JSON but is NOT an array of strings is left to
 * the CIDR parser, which rejects it — a malformed declaration must never
 * degrade to "no allowlist".
 */
export function splitAllowlistVar(raw: string): readonly string[] {
  const trimmed = raw.trim();
  if (trimmed === "") return [];
  if (trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return parsed.map((entry) => (typeof entry === "string" ? entry.trim() : String(entry)));
      }
    } catch {
      // Fall through: the entries below will fail to parse and the whole
      // declaration is reported as a misconfiguration rather than ignored.
    }
  }
  return trimmed
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

/**
 * `[network_access]` out of the Worker vars — the Workers equivalent of the
 * TOML section, validated the way `validate_network_access` validates it.
 */
export function networkAccessPolicy(env: NetworkAccessBindings | undefined): NetworkAccessPolicy {
  const rawAllowlist = env?.GATEWAY_IP_ALLOWLIST ?? "";
  const entries = splitAllowlistVar(rawAllowlist);
  const allowlist: IpCidr[] = [];
  const rejected: string[] = [];
  for (const entry of entries) {
    try {
      allowlist.push(IpCidr.parse(entry));
    } catch (error) {
      rejected.push(`${JSON.stringify(entry)}: ${error instanceof Error ? error.message : error}`);
    }
  }

  let misconfiguration: string | null = null;
  if (rejected.length > 0) {
    misconfiguration = `${IP_ALLOWLIST_VAR} has unparsable entries — ${rejected.join("; ")}`;
  } else if (rawAllowlist.trim() !== "" && allowlist.length === 0) {
    // A declared-but-empty allowlist is not "no allowlist": the operator asked
    // for a restriction and named nothing that can satisfy it.
    misconfiguration = `${IP_ALLOWLIST_VAR} is set but declares no usable CIDR entry`;
  }

  const rawLimit = (env?.GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE ?? "").trim();
  let limit: number | undefined;
  if (rawLimit !== "") {
    const parsed = Number(rawLimit);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      // `validate_network_access` fails on 0 with "must be greater than zero
      // when set"; a non-numeric value never reaches the Rust at all.
      misconfiguration ??= `${UNAUTHENTICATED_RATE_LIMIT_VAR} must be a positive integer when set (value: ${JSON.stringify(rawLimit)})`;
    } else {
      limit = parsed;
    }
  }

  const rawHops = (env?.GATEWAY_TRUSTED_PROXY_HOPS ?? "").trim();
  let hops = 1;
  if (rawHops !== "") {
    const parsed = Number(rawHops);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      misconfiguration ??= `${TRUSTED_PROXY_HOPS_VAR} must be a positive integer when set (value: ${JSON.stringify(rawHops)})`;
    } else {
      hops = parsed;
    }
  }

  return {
    allowlist,
    // Only the exact string `"true"` trusts the forwarded chain. Anything else
    // — including a typo'd `"ture"` — keeps the anti-spoof posture.
    trustForwardedFor: (env?.GATEWAY_TRUST_FORWARDED_FOR ?? "").trim().toLowerCase() === "true",
    trustedProxyHops: hops,
    unauthenticatedRateLimitPerMinute: limit,
    misconfiguration,
  };
}

/**
 * Policies are memoized by the VAR VALUES, not by the env object.
 *
 * Parsing a CIDR is bigint work and the vars are identical on every request of
 * a deployment, so caching is worth it — but caching on the env object would
 * make a changed var invisible until the isolate recycled, which is exactly the
 * kind of staleness a security control must not have. Keying on the values
 * themselves cannot go stale by construction.
 */
const POLICY_CACHE = new Map<string, NetworkAccessPolicy>();
const POLICY_CACHE_LIMIT = 32;

/**
 * The separator is the ESCAPE `"\0"`, never a literal NUL byte typed into the
 * source. Both produce the same one-character string at runtime, but a source
 * file that CONTAINS a raw NUL is classified BINARY by `grep`, which then skips
 * it silently — this file carried one until it was found by a byte scan, and
 * for as long as it did, every `grep -r PORT-TODO` audit of `apps/gateway/src`
 * reported on 199 files and quietly omitted the 200th.
 */
function policyCacheKey(env: NetworkAccessBindings | undefined): string {
  return [
    env?.GATEWAY_IP_ALLOWLIST ?? "",
    env?.GATEWAY_TRUST_FORWARDED_FOR ?? "",
    env?.GATEWAY_TRUSTED_PROXY_HOPS ?? "",
    env?.GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE ?? "",
  ].join("\0");
}

/** {@link networkAccessPolicy}, memoized per distinct var tuple. */
export function networkAccessPolicyFromEnv(
  env: NetworkAccessBindings | undefined,
): NetworkAccessPolicy {
  const key = policyCacheKey(env);
  const cached = POLICY_CACHE.get(key);
  if (cached !== undefined) return cached;
  const policy = networkAccessPolicy(env);
  if (POLICY_CACHE.size >= POLICY_CACHE_LIMIT) POLICY_CACHE.clear();
  POLICY_CACHE.set(key, policy);
  return policy;
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/**
 * The Workers substitute for the Rust peer address: `CF-Connecting-IP`, or
 * `null` when it is absent or not an IP literal. `null` is DENIED by an
 * allowlist and EXEMPT from the flood limiter, both matching Rust.
 */
export function peerAddressOf(headers: Headers): string | null {
  const raw = headers.get(CLIENT_IP_HEADER)?.trim();
  if (raw === undefined || raw === "") return null;
  return isIpAddress(raw) ? raw : null;
}

/** `AppState::check_network_access`, decision-for-decision. */
export function checkNetworkAccess(
  headers: Headers,
  policy: NetworkAccessPolicy,
  limiter: UnauthenticatedIpRateLimiter,
  nowUnixSeconds: number,
): NetworkAccessDecision {
  if (policy.misconfiguration !== null) return "misconfigured";

  const clientIp = resolveClientIp(
    headers,
    peerAddressOf(headers),
    policy.trustForwardedFor,
    policy.trustedProxyHops,
  );

  if (policy.allowlist.length > 0) {
    const allowed = clientIp !== null && policy.allowlist.some((cidr) => cidr.contains(clientIp));
    if (!allowed) return "ip_denied";
  }

  const limit = policy.unauthenticatedRateLimitPerMinute;
  if (limit !== undefined && clientIp !== null) {
    const nowMinute = Math.floor(nowUnixSeconds / 60);
    if (!limiter.allow(clientIp, nowMinute, limit)) return "rate_limited";
  }

  return "allowed";
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * The isolate's flood-limit state. Module scope is deliberate and is the whole
 * of the "isolate-local" caveat in the header: one instance per isolate, shared
 * by every request that isolate serves.
 */
const ISOLATE_RATE_LIMITER = new UnauthenticatedIpRateLimiter();

export interface NetworkAccessOptions {
  /** Override the isolate limiter (tests want a fresh window per case). */
  readonly limiter?: UnauthenticatedIpRateLimiter;
  /** Override the clock, in unix SECONDS. */
  readonly now?: () => number;
}

/**
 * The gate as Hono middleware. Mounted unconditionally by `createGatewayApp`:
 * with none of the four vars set the policy is {@link
 * OPEN_NETWORK_ACCESS_POLICY} and every request is `allowed`, so an
 * unconfigured deployment behaves exactly as it did before this existed. There
 * is deliberately no "enable" switch — a security control that must be turned
 * on is a security control that is off.
 */
export function networkAccess(options: NetworkAccessOptions = {}): MiddlewareHandler<GatewayEnv> {
  const limiter = options.limiter ?? ISOLATE_RATE_LIMITER;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  return async function networkAccessMiddleware(c, next) {
    const policy = networkAccessPolicyFromEnv(c.env as NetworkAccessBindings | undefined);
    switch (checkNetworkAccess(c.req.raw.headers, policy, limiter, now())) {
      case "ip_denied":
        throw new HttpError(403, "ip_denied", "source IP is not permitted");
      case "rate_limited":
        throw new HttpError(
          429,
          "unauthenticated_rate_limited",
          "too many requests from this source; try again later",
        );
      case "misconfigured":
        throw new HttpError(
          503,
          "network_access_misconfigured",
          policy.misconfiguration ?? "network access configuration is unusable",
        );
      default:
        await next();
    }
  };
}
