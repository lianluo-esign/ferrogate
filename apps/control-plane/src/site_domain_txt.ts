/**
 * The DNS-TXT ownership challenge behind the site-domain serve gate (#488).
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/site_domain_verification.rs`.
 * Binding a hostname proves nothing about who controls it, so a bound hostname
 * only verifies once the tenant has published a per-`(tenant, hostname)` token
 * as a TXT record at `_ferrogate-challenge.<hostname>`.
 *
 * ## What this module owns
 *
 *  - the challenge derivation — the published value is a SHA-256 digest over the
 *    LENGTH-PREFIXED `(tenant_id, hostname, token)` triple, so the proof is
 *    cryptographically bound to ONE tenant AND ONE hostname and cannot be
 *    replayed by another tenant that merely reads the published record;
 *  - the resolver SEAM, so the ownership check is testable with scripted
 *    answers and a deployment can choose the resolver it trusts;
 *  - the fail-closed fold — "resolver unavailable" is a first-class outcome that
 *    is NEVER folded into "verified", and never demotes an existing proof
 *    either.
 *
 * ## The CF mapping of the three Rust backends
 *
 * | Rust                   | here                        | why |
 * |------------------------|-----------------------------|-----|
 * | `UnboundTxtResolver`   | {@link UnboundTxtResolver}  | identical: the DEFAULT, resolves nothing |
 * | `DohTxtResolver` (reqwest) | {@link DohTxtResolver} (`fetch`) | DNS-over-HTTPS is plain HTTPS, which a Worker can do |
 * | `ZoneFileTxtResolver` (`std::fs`) | {@link StaticAnswersTxtResolver} | a Worker has NO filesystem; the curated answers move from a file to a var |
 *
 * The zone-file backend's contract is preserved exactly, including the part that
 * matters: there is no "accept anything" mode. The configured answers must carry
 * the exact expected digest under the exact challenge name, so this backend can
 * only ever confirm a record somebody deliberately published — it is a
 * deterministic resolver, not a bypass.
 *
 * There is no raw-UDP-DNS option because workerd exposes no UDP socket and no
 * resolver hook; that is a platform limitation, and DoH is the same choice Rust
 * made anyway (authenticated and integrity-protected by TLS, endpoint an
 * explicit deployment decision rather than whatever `/etc/resolv.conf` says).
 */
import { sha256Hex } from "@ferrogate/storage";

/**
 * The DNS label the challenge TXT record is published under, prefixed to the
 * bound hostname. Underscore-prefixed so it can never collide with a servable
 * hostname.
 */
export const SITE_DOMAIN_CHALLENGE_LABEL = "_ferrogate-challenge";

/**
 * Prefix on the published TXT value, so an operator can tell FerroGate's record
 * apart from every other verification TXT on the same name.
 */
export const SITE_DOMAIN_CHALLENGE_VALUE_PREFIX = "ferrogate-site-verification=";

/**
 * Domain-separation tag mixed into the digest, so a token can never be replayed
 * against another FerroGate digest surface.
 */
const SITE_DOMAIN_CHALLENGE_DOMAIN_TAG = "ferrogate-site-domain-challenge-v1";

/** The fully qualified name the operator publishes the TXT record at. */
export function challengeRecordName(hostname: string): string {
  return `${SITE_DOMAIN_CHALLENGE_LABEL}.${hostname}`;
}

/**
 * The exact TXT value that proves `tenantId` controls `hostname`.
 *
 * The digest input is LENGTH-PREFIXED on every variable segment, so no crafted
 * `(tenant, hostname, token)` triple can canonicalise to the same bytes as
 * another — tenant `a` + host `b.c` cannot alias tenant `a:b` + host `c`.
 *
 * This is what binds a challenge to ONE tenant. Tenant B cannot complete the
 * challenge tenant A started, even standing in front of the published record:
 * B's own row holds a DIFFERENT random token, so the value B must publish is a
 * different digest, and the token is never recoverable from A's published
 * digest.
 *
 * Async because WebCrypto's `digest` is; the Rust twin is synchronous.
 */
export async function challengeTxtValue(
  tenantId: string,
  hostname: string,
  token: string,
): Promise<string> {
  const canonical =
    `${SITE_DOMAIN_CHALLENGE_DOMAIN_TAG}\0${tenantId.length}:${tenantId}` +
    `\0${hostname.length}:${hostname}\0${token.length}:${token}`;
  const digest = await sha256Hex(new TextEncoder().encode(canonical));
  return `${SITE_DOMAIN_CHALLENGE_VALUE_PREFIX}${digest}`;
}

/** A fresh 128-bit challenge token (`new_challenge_token`). */
export function newChallengeToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * What a TXT lookup returned.
 *
 * `unavailable` (resolver unreachable, timed out, malformed reply, or simply not
 * configured) is deliberately DISTINCT from an empty `answers` set, so it can
 * never be read as "no record, therefore fail" nor as "fine, therefore
 * verified" — it is its own outcome with its own (503) response.
 */
export type TxtLookup =
  | { readonly kind: "answers"; readonly answers: readonly string[] }
  | { readonly kind: "unavailable"; readonly reason: string };

/** The DNS lookup seam. */
export interface SiteDomainTxtResolver {
  lookupTxt(name: string): Promise<TxtLookup>;
  /** Stable identifier surfaced in the admin response / audit line. */
  readonly backendName: string;
}

/**
 * Default backend: NO resolver is bound, so every lookup is `unavailable`.
 *
 * Fail-closed on purpose. An un-configured deployment cannot verify anything,
 * which means nothing new starts serving — it can never mean "verified by
 * default".
 */
export class UnboundTxtResolver implements SiteDomainTxtResolver {
  readonly backendName = "unbound";

  lookupTxt(): Promise<TxtLookup> {
    return Promise.resolve({
      kind: "unavailable",
      reason:
        "no DNS resolver is bound for site-domain ownership verification; set SITE_DOMAIN_RESOLVER=doh (and optionally SITE_DOMAIN_RESOLVER_ENDPOINT) to enable it",
    });
  }
}

/** Rust `DEFAULT` DoH endpoint shape; an explicit deployment decision. */
export const DEFAULT_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/** Rust `FERROGATE_SITE_DOMAIN_RESOLVER_TIMEOUT_SECS` default. */
export const DEFAULT_DOH_TIMEOUT_MS = 5_000;

/**
 * DNS-over-HTTPS backend: an `application/dns-json` GET against a resolver
 * endpoint (RFC 8484's JSON companion, as served by Cloudflare/Google).
 *
 * The timeout is an `AbortSignal` rather than reqwest's client timeout, and it
 * is NOT optional: on a path whose entire design principle is "unavailable is
 * not verified", a black-holed endpoint that hangs the admin request is a worse
 * outcome than a refusal to verify.
 */
export class DohTxtResolver implements SiteDomainTxtResolver {
  readonly backendName = "doh";
  readonly #endpoint: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(
    endpoint: string = DEFAULT_DOH_ENDPOINT,
    timeoutMs: number = DEFAULT_DOH_TIMEOUT_MS,
    fetchImpl: typeof fetch = fetch,
  ) {
    this.#endpoint = endpoint;
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchImpl;
  }

  async lookupTxt(name: string): Promise<TxtLookup> {
    // Defence in depth: the caller only ever passes
    // `_ferrogate-challenge.<validated hostname>`, but refuse to put anything
    // else in a URL rather than trusting that upstream.
    if (!isQuerySafeDnsName(name)) {
      return { kind: "unavailable", reason: `refusing to resolve unsafe DNS name ${name}` };
    }
    const separator = this.#endpoint.includes("?") ? "&" : "?";
    const url = `${this.#endpoint}${separator}name=${name}&type=TXT`;
    let response: Response;
    try {
      response = await this.#fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      return {
        kind: "unavailable",
        reason: `DNS-over-HTTPS error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    if (!response.ok) {
      return {
        kind: "unavailable",
        reason: `DNS-over-HTTPS resolver returned status ${response.status}`,
      };
    }
    try {
      return parseDnsJsonAnswers(name, await response.text());
    } catch (error) {
      return {
        kind: "unavailable",
        reason: `DNS-over-HTTPS body error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }
}

/**
 * The Workers stand-in for Rust's `ZoneFileTxtResolver`: TXT records from a
 * curated `<name><whitespace><value>` document, supplied as a Worker var because
 * a Worker has no filesystem to read one from.
 *
 * For deployments that publish challenge records through their own DNS
 * automation, and for tests, which need a deterministic resolver without
 * reaching the public DNS. Note what it is NOT: there is no "accept anything"
 * mode — the document must carry the exact expected value under the exact
 * challenge name.
 */
export class StaticAnswersTxtResolver implements SiteDomainTxtResolver {
  readonly backendName = "static-answers";
  readonly #document: string | undefined;

  constructor(document: string | undefined) {
    this.#document = document;
  }

  lookupTxt(name: string): Promise<TxtLookup> {
    // An ABSENT document is an outage, not an empty answer set: it must surface
    // as 503, never as "the record is not there" (the unreadable-zone-file
    // branch).
    if (this.#document === undefined) {
      return Promise.resolve({
        kind: "unavailable",
        reason:
          "SITE_DOMAIN_RESOLVER=static but SITE_DOMAIN_TXT_ANSWERS is not configured; no answers to resolve against",
      });
    }
    return Promise.resolve({ kind: "answers", answers: staticAnswers(this.#document, name) });
  }
}

/**
 * The TXT values a curated document carries for `name` (`zone_file_answers`).
 * `#` comments and blank lines are skipped; the trailing root dot and ASCII case
 * are insignificant in DNS.
 */
export function staticAnswers(contents: string, name: string): string[] {
  const wanted = normalizeDnsName(name);
  const out: string[] = [];
  for (const rawLine of contents.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const split = line.search(/\s/);
    if (split === -1) continue;
    if (normalizeDnsName(line.slice(0, split)) !== wanted) continue;
    out.push(normalizeTxtValue(line.slice(split).trim()));
  }
  return out;
}

/**
 * Whether a name is safe to interpolate into a resolver query string: the exact
 * character set a validated hostname plus the `_ferrogate-challenge` label can
 * produce, and nothing else.
 */
export function isQuerySafeDnsName(name: string): boolean {
  if (name === "") return false;
  if (name.length > 253 + SITE_DOMAIN_CHALLENGE_LABEL.length + 1) return false;
  return /^[a-z0-9._-]+$/.test(name);
}

/**
 * Case-folds a DNS name and drops the trailing root dot, so a reply's `name` can
 * be compared with the queried name across resolvers that disagree about both.
 */
export function normalizeDnsName(name: string): string {
  return name.trim().replace(/\.+$/, "").toLowerCase();
}

/**
 * Strip the presentation-format quoting a DNS TXT record carries. A long TXT
 * record is transmitted as adjacent quoted chunks (`"part1" "part2"`) that
 * concatenate into one string, so quotes and inter-chunk whitespace are removed
 * rather than kept.
 */
export function normalizeTxtValue(raw: string): string {
  const parts = raw.split('"');
  // Odd segments are inside quotes; even segments are the separators.
  const unquoted = parts
    .filter((_part, index) => index % 2 === 1)
    .join("")
    .trim();
  // Some resolvers omit the presentation quoting entirely; fall back to the
  // trimmed raw value rather than collapsing to an empty string.
  return unquoted === "" ? raw.trim() : unquoted;
}

/**
 * Fold an `application/dns-json` reply into a {@link TxtLookup}. Pure/offline so
 * the resolver contract is tested without a network.
 *
 * Only `Status: 0` (NOERROR) and `Status: 3` (NXDOMAIN) are authoritative
 * answers — NXDOMAIN definitively means "no such name", a legitimate empty
 * answer set. Every other RCODE (SERVFAIL, REFUSED, …) is a resolver failure and
 * stays `unavailable`, because "the resolver could not tell us" must never read
 * as "the record is absent" and certainly not as "verified".
 *
 * The answer must also be FOR the name we asked about and must actually be a TXT
 * record (`type: 16`). An entry with NO `type` is not assumed to be one: that
 * default is what let an untyped forged answer through in the Rust tree, and
 * chained with a plaintext endpoint it verified EVERY hostname from one body. A
 * CNAME chain is followed by accepting an answer whose name matches any CNAME
 * target already seen in the same reply.
 */
export function parseDnsJsonAnswers(queriedName: string, body: string): TxtLookup {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    return {
      kind: "unavailable",
      reason: `DNS-over-HTTPS reply is not JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (value === null || typeof value !== "object") {
    return { kind: "unavailable", reason: "DNS-over-HTTPS reply is not a JSON object" };
  }
  const reply = value as { Status?: unknown; Answer?: unknown };
  if (typeof reply.Status !== "number") {
    return { kind: "unavailable", reason: "DNS-over-HTTPS reply carries no Status field" };
  }
  if (reply.Status !== 0 && reply.Status !== 3) {
    return { kind: "unavailable", reason: `DNS resolver returned RCODE ${reply.Status}` };
  }

  const entries: { type?: unknown; name?: unknown; data?: unknown }[] = Array.isArray(reply.Answer)
    ? (reply.Answer as { type?: unknown; name?: unknown; data?: unknown }[])
    : [];
  const accepted = [normalizeDnsName(queriedName)];
  for (const entry of entries) {
    // Type 5 is CNAME: its target becomes an acceptable answer name.
    if (entry.type !== 5) continue;
    if (typeof entry.name !== "string") continue;
    if (!accepted.includes(normalizeDnsName(entry.name))) continue;
    if (typeof entry.data === "string") accepted.push(normalizeDnsName(entry.data));
  }

  const answers = entries
    .filter((entry) => entry.type === 16)
    .filter(
      (entry) => typeof entry.name === "string" && accepted.includes(normalizeDnsName(entry.name)),
    )
    .filter((entry): entry is { data: string } => typeof entry.data === "string")
    .map((entry) => normalizeTxtValue(entry.data));
  return { kind: "answers", answers };
}

/** The resolved verdict of one ownership check. */
export type ChallengeOutcome =
  /** The expected TXT value was present. The ONLY outcome that verifies. */
  | { readonly kind: "verified" }
  /** The resolver answered, but nothing matched. The binding stays pending. */
  | { readonly kind: "not_published"; readonly reason: string }
  /** The lookup could not be completed. NEVER a verification, never a demotion. */
  | { readonly kind: "resolver_unavailable"; readonly reason: string };

/**
 * Fold a lookup result against the expected value. Deliberately total and pure:
 * there is exactly ONE path to `verified`, and it requires an authoritative
 * answer that CONTAINS the expected digest.
 */
export function resolveChallenge(expectedValue: string, lookup: TxtLookup): ChallengeOutcome {
  if (lookup.kind === "unavailable") {
    return { kind: "resolver_unavailable", reason: lookup.reason };
  }
  if (lookup.answers.some((answer) => answer.trim() === expectedValue)) {
    return { kind: "verified" };
  }
  return {
    kind: "not_published",
    reason: `expected TXT value not found (${lookup.answers.length} record(s) observed)`,
  };
}
