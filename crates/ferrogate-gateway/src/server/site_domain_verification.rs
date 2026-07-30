// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: The DNS-TXT ownership challenge behind the #488 site-domain
// serve gate. Binding a hostname (#265) proves nothing about who controls it,
// so a bound hostname now only serves once the tenant has published a
// per-(tenant, hostname) token as a TXT record at
// `_ferrogate-challenge.<hostname>`. This module owns:
//
//   * the challenge derivation -- the published value is a SHA-256 digest over
//     the LENGTH-PREFIXED `(tenant_id, hostname, token)` triple (the
//     `agent_cost_burn_key` / `observed_agent_presence_key` canonicalisation
//     precedent), so the proof is cryptographically bound to one tenant AND one
//     hostname and cannot be replayed by another tenant that merely reads the
//     published record;
//   * the resolver SEAM (`SiteDomainTxtResolver`) -- the DNS lookup is I/O, so
//     it sits behind a trait the way `AssetScanner`, `OnChainSettlementRpc` and
//     `AgentRuntimeUsageSource` do. The default backend performs NO lookup and
//     reports `Unavailable`, which can never verify anything; a DNS-over-HTTPS
//     backend is opt-in per deployment; tests script the answers;
//   * the fail-closed fold (`resolve_challenge`) -- "resolver unavailable" is a
//     first-class outcome that is NEVER folded into "verified", the same
//     "unavailable is not zero/ok" discipline as #458/#464/#473; and
//   * the one-time migration backfill for bindings that predate #488.

use std::time::Duration;

use async_trait::async_trait;
use ferrogate_storage::{
    sha256_hex, SiteDomainVerificationAttempt, SiteDomainVerificationState, StoredSiteDomain,
    StoredSiteDomainVerification,
};

/// The DNS label the challenge TXT record is published under, prefixed to the
/// bound hostname: `_ferrogate-challenge.<hostname>`. Underscore-prefixed so it
/// can never collide with a servable hostname.
pub(super) const SITE_DOMAIN_CHALLENGE_LABEL: &str = "_ferrogate-challenge";

/// Prefix on the published TXT value, so an operator can tell FerroGate's
/// record apart from every other verification TXT on the same name.
pub(super) const SITE_DOMAIN_CHALLENGE_VALUE_PREFIX: &str = "ferrogate-site-verification=";

/// Domain-separation tag mixed into the digest, so a token can never be
/// replayed against another FerroGate digest surface.
const SITE_DOMAIN_CHALLENGE_DOMAIN_TAG: &str = "ferrogate-site-domain-challenge-v1";

/// The fully qualified name the operator publishes the TXT record at.
pub(super) fn challenge_record_name(hostname: &str) -> String {
    format!("{SITE_DOMAIN_CHALLENGE_LABEL}.{hostname}")
}

/// The exact TXT value that proves `tenant_id` controls `hostname`.
///
/// The digest input is LENGTH-PREFIXED on every variable segment
/// (`agent_cost_burn_key` precedent), so no crafted `(tenant, hostname, token)`
/// triple can ever canonicalise to the same bytes as another -- e.g. tenant
/// `a` + host `b.c` cannot alias tenant `a:b` + host `c`.
///
/// This is what binds a challenge to ONE tenant. Tenant B cannot complete the
/// challenge tenant A started, even standing in front of the published record:
/// B's own row holds a DIFFERENT random token, so the value B must publish is a
/// different digest, and the token is never recoverable from A's published
/// digest.
pub(super) fn challenge_txt_value(tenant_id: &str, hostname: &str, token: &str) -> String {
    let canonical = format!(
        "{SITE_DOMAIN_CHALLENGE_DOMAIN_TAG}\0{}:{tenant_id}\0{}:{hostname}\0{}:{token}",
        tenant_id.len(),
        hostname.len(),
        token.len()
    );
    format!(
        "{SITE_DOMAIN_CHALLENGE_VALUE_PREFIX}{}",
        sha256_hex(canonical.as_bytes())
    )
}

/// A fresh 128-bit challenge token. Fails loudly if the OS entropy source is
/// unavailable rather than falling back to anything guessable.
pub(super) fn new_challenge_token() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("operating-system random source unavailable: {error}"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

/// What a TXT lookup returned. `Unavailable` (resolver unreachable, timed out,
/// malformed reply, or simply not configured) is deliberately DISTINCT from an
/// empty `Answers` set so it can never be read as "no record, therefore fail"
/// nor as "fine, therefore verified" -- it is its own outcome with its own
/// (503) response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TxtLookup {
    /// The resolver answered authoritatively with this set of TXT strings
    /// (possibly empty: the name exists but carries no matching record, or
    /// NXDOMAIN).
    Answers(Vec<String>),
    Unavailable(String),
}

/// The DNS lookup seam. Kept behind a trait so the ownership check is testable
/// with scripted answers and so a deployment can bind whatever resolver it
/// trusts without touching the verification logic.
#[async_trait]
pub(super) trait SiteDomainTxtResolver: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> TxtLookup;
    /// Stable identifier surfaced in the admin response / audit line.
    fn backend_name(&self) -> &'static str;
}

/// Default backend: NO resolver is bound, so every lookup is `Unavailable`.
///
/// This is the fail-closed default on purpose (the `UnboundOnChainRpc`
/// precedent): an un-configured deployment cannot verify anything, which means
/// nothing new starts serving -- it can never mean "verified by default". A
/// deployment turns verification on by selecting a real backend
/// (`FERROGATE_SITE_DOMAIN_RESOLVER=doh`).
pub(super) struct UnboundTxtResolver;

#[async_trait]
impl SiteDomainTxtResolver for UnboundTxtResolver {
    async fn lookup_txt(&self, _name: &str) -> TxtLookup {
        TxtLookup::Unavailable(
            "no DNS resolver is bound for site-domain ownership verification; \
             set FERROGATE_SITE_DOMAIN_RESOLVER=doh (and optionally \
             FERROGATE_SITE_DOMAIN_RESOLVER_ENDPOINT) to enable it"
                .to_string(),
        )
    }

    fn backend_name(&self) -> &'static str {
        "unbound"
    }
}

/// DNS-over-HTTPS backend: a `application/dns-json` GET against a resolver
/// endpoint (RFC 8484's JSON companion, as served by Cloudflare/Google). Chosen
/// over a raw UDP resolver because it needs no new dependency, it is
/// authenticated and integrity-protected by TLS, and the endpoint is an
/// explicit deployment decision instead of whatever `/etc/resolv.conf` happens
/// to point at.
pub(super) struct DohTxtResolver {
    endpoint: String,
    client: reqwest::Client,
}

impl DohTxtResolver {
    /// Returns `None` when the client cannot be built with the configured
    /// timeout (#488 review item 2).
    ///
    /// This used to be `.build().unwrap_or_default()`, which silently dropped
    /// the timeout: `reqwest::Client::default()` has NONE. On the one path
    /// whose entire design principle is "unavailable is not verified", a
    /// black-holed endpoint would then hang the admin request indefinitely
    /// instead of failing at FERROGATE_SITE_DOMAIN_RESOLVER_TIMEOUT_SECS. The
    /// caller falls back to the unbound resolver, so the failure is a refusal
    /// to verify rather than a hang.
    pub(super) fn new(endpoint: impl Into<String>, timeout: Duration) -> Option<Self> {
        let client = reqwest::Client::builder().timeout(timeout).build().ok()?;
        Some(Self {
            endpoint: endpoint.into(),
            client,
        })
    }
}

#[async_trait]
impl SiteDomainTxtResolver for DohTxtResolver {
    async fn lookup_txt(&self, name: &str) -> TxtLookup {
        // Defence in depth: the caller only ever passes
        // `_ferrogate-challenge.<validated hostname>`, but refuse to put
        // anything else in a URL rather than trusting that upstream.
        if !is_query_safe_dns_name(name) {
            return TxtLookup::Unavailable(format!("refusing to resolve unsafe DNS name {name}"));
        }
        let separator = if self.endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!("{}{separator}name={name}&type=TXT", self.endpoint);
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => return TxtLookup::Unavailable(format!("DNS-over-HTTPS error: {error}")),
        };
        if !response.status().is_success() {
            return TxtLookup::Unavailable(format!(
                "DNS-over-HTTPS resolver returned status {}",
                response.status()
            ));
        }
        match response.bytes().await {
            Ok(body) => parse_dns_json_answers(name, &body),
            Err(error) => TxtLookup::Unavailable(format!("DNS-over-HTTPS body error: {error}")),
        }
    }

    fn backend_name(&self) -> &'static str {
        "doh"
    }
}

/// Zone-file backend: resolves TXT records from a locally curated file of
/// `<name><whitespace><value>` lines, re-read on every lookup.
///
/// For deployments that publish challenge records through their own DNS
/// automation (and for end-to-end tests, which need a deterministic resolver
/// without reaching the public DNS). Note what it is NOT: there is no
/// "accept anything" mode -- the file must carry the exact expected value under
/// the exact challenge name, so this backend can only ever confirm a record
/// somebody deliberately published.
pub(super) struct ZoneFileTxtResolver {
    path: std::path::PathBuf,
}

impl ZoneFileTxtResolver {
    pub(super) fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl SiteDomainTxtResolver for ZoneFileTxtResolver {
    async fn lookup_txt(&self, name: &str) -> TxtLookup {
        // A small local read on an admin-only path, not the request hot path.
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => TxtLookup::Answers(zone_file_answers(&contents, name)),
            // An unreadable/absent zone file is an OUTAGE, not an empty answer
            // set: it must surface as 503, never as "the record is not there".
            Err(error) => TxtLookup::Unavailable(format!(
                "zone file {} is unreadable: {error}",
                self.path.display()
            )),
        }
    }

    fn backend_name(&self) -> &'static str {
        "zone-file"
    }
}

/// The TXT values a zone file carries for `name`. `#` comments and blank lines
/// are skipped; the trailing root dot and ASCII case are insignificant in DNS.
pub(super) fn zone_file_answers(contents: &str, name: &str) -> Vec<String> {
    let wanted = name.trim_end_matches('.').to_ascii_lowercase();
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(char::is_whitespace))
        .filter(|(record, _)| record.trim_end_matches('.').to_ascii_lowercase() == wanted)
        .map(|(_, value)| normalize_txt_value(value.trim()))
        .collect()
}

/// Whether a name is safe to interpolate into a resolver query string: the
/// exact character set a validated hostname plus the `_ferrogate-challenge`
/// label can produce, and nothing else.
fn is_query_safe_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253 + SITE_DOMAIN_CHALLENGE_LABEL.len() + 1
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'
                || byte == b'.'
                || byte == b'_'
        })
}

/// Case-folds a DNS name and drops the trailing root dot, so a reply's `name`
/// can be compared with the queried name across resolvers that disagree about
/// both (#488 review item 3).
fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Fold a `application/dns-json` reply into a [`TxtLookup`]. Pure/offline so
/// the resolver contract is tested without a network.
///
/// Only `Status: 0` (NOERROR) and `Status: 3` (NXDOMAIN) are authoritative
/// answers -- NXDOMAIN definitively means "no such name", which is a legitimate
/// empty answer set. Every other RCODE (SERVFAIL, REFUSED, ...) is a resolver
/// failure and stays `Unavailable`, because "the resolver could not tell us"
/// must never read as "the record is absent" and certainly not as "verified".
pub(super) fn parse_dns_json_answers(queried_name: &str, body: &[u8]) -> TxtLookup {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return TxtLookup::Unavailable(format!("DNS-over-HTTPS reply is not JSON: {error}"))
        }
    };
    match value.get("Status").and_then(serde_json::Value::as_i64) {
        Some(0) | Some(3) => {}
        Some(status) => {
            return TxtLookup::Unavailable(format!("DNS resolver returned RCODE {status}"))
        }
        None => {
            return TxtLookup::Unavailable(
                "DNS-over-HTTPS reply carries no Status field".to_string(),
            )
        }
    }
    // #488 review item 3: the answer must be FOR the name we asked about, and
    // must actually be a TXT record.
    //
    // Before this, `type` was accepted when ABSENT (`is_none_or`) and the
    // reply's `name` was never compared with the query at all. A resolver that
    // ignores the question -- a fixed-response proxy, a cached or misrouted
    // endpoint, or a forged reply over a plaintext endpoint (item 1) -- could
    // verify EVERY hostname with a single body. On its own that is hardening;
    // chained with item 1 it was the forgery.
    //
    // Names are compared case-insensitively with the trailing root dot
    // normalised away, since resolvers differ on both. A CNAME chain is
    // followed by accepting an answer whose name matches any CNAME target
    // already seen in the same reply.
    let mut accepted_names = vec![normalize_dns_name(queried_name)];
    if let Some(entries) = value.get("Answer").and_then(serde_json::Value::as_array) {
        for entry in entries {
            let kind = entry.get("type").and_then(serde_json::Value::as_i64);
            let name = entry
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(normalize_dns_name);
            // Type 5 is CNAME: its target becomes an acceptable answer name.
            if kind == Some(5)
                && name.is_some_and(|name| accepted_names.iter().any(|seen| seen == &name))
            {
                if let Some(target) = entry.get("data").and_then(serde_json::Value::as_str) {
                    accepted_names.push(normalize_dns_name(target));
                }
            }
        }
    }
    let answers = value
        .get("Answer")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                // Type 16 is TXT. An entry with NO `type` is no longer assumed
                // to be one -- that default is what let an untyped forged
                // answer through.
                .filter(|entry| entry.get("type").and_then(serde_json::Value::as_i64) == Some(16))
                .filter(|entry| {
                    entry
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(normalize_dns_name)
                        .is_some_and(|name| accepted_names.iter().any(|seen| seen == &name))
                })
                .filter_map(|entry| entry.get("data").and_then(serde_json::Value::as_str))
                .map(normalize_txt_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    TxtLookup::Answers(answers)
}

/// Strip the presentation-format quoting a DNS TXT record carries. A long TXT
/// record is transmitted as adjacent quoted chunks (`"part1" "part2"`) that
/// concatenate into one string, so quotes and inter-chunk whitespace are
/// removed rather than kept.
fn normalize_txt_value(raw: &str) -> String {
    let unquoted: String = raw
        .split('"')
        .enumerate()
        // Odd segments are inside quotes; even segments are the separators.
        .filter_map(|(index, part)| (index % 2 == 1).then_some(part))
        .collect();
    let unquoted = unquoted.trim();
    // Some resolvers omit the presentation quoting entirely; fall back to the
    // trimmed raw value rather than collapsing to an empty string.
    if unquoted.is_empty() {
        raw.trim().to_string()
    } else {
        unquoted.to_string()
    }
}

/// The resolved verdict of one ownership check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ChallengeOutcome {
    /// The expected TXT value was present. The ONLY outcome that verifies.
    Verified,
    /// The resolver answered, but nothing matched. The binding stays pending.
    NotPublished(String),
    /// The lookup could not be completed. NEVER a verification, and never a
    /// demotion of an existing proof either.
    ResolverUnavailable(String),
}

/// Fold a lookup result against the expected value. Deliberately total and
/// pure: there is exactly one path to [`ChallengeOutcome::Verified`], and it
/// requires an authoritative answer that CONTAINS the expected digest.
pub(super) fn resolve_challenge(expected_value: &str, lookup: TxtLookup) -> ChallengeOutcome {
    match lookup {
        TxtLookup::Unavailable(reason) => ChallengeOutcome::ResolverUnavailable(reason),
        TxtLookup::Answers(answers) => {
            if answers.iter().any(|answer| answer.trim() == expected_value) {
                ChallengeOutcome::Verified
            } else {
                ChallengeOutcome::NotPublished(format!(
                    "expected TXT value not found ({} record(s) observed)",
                    answers.len()
                ))
            }
        }
    }
}

/// The result of the #576 pre-DNS rate-limit gate feeding ownership
/// resolution. Either the per-(tenant, hostname) cooldown refused the attempt
/// -- in which case the resolver was NEVER touched -- or the attempt was
/// admitted and the resolver produced a [`ChallengeOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GatedChallengeCheck {
    /// The cooldown refused this attempt BEFORE any DNS request was constructed
    /// or sent. Carries the bounded retry hint for the typed 429.
    RateLimited { retry_after_secs: i64 },
    /// The attempt was admitted; here is what resolving the challenge produced.
    Resolved(ChallengeOutcome),
}

/// Fold the rate-limit reservation and (only when admitted) the DNS lookup into
/// one outcome. This is the load-bearing short-circuit for #576: on a
/// [`SiteDomainVerificationAttempt::RateLimited`] reservation the resolver's
/// `lookup_txt` is NEVER awaited, so an over-limit `admin.write` credential
/// cannot drive an outbound DNS-over-HTTPS request. The caller passes `None` for
/// the resolver on the refused path (it never builds one), and `Some(resolver)`
/// only after the slot is reserved; an admitted attempt with no resolver folds
/// to `ResolverUnavailable`, never to `Verified`.
pub(super) async fn resolve_challenge_within_rate_limit(
    reservation: SiteDomainVerificationAttempt,
    expected_value: &str,
    record_name: &str,
    resolver: Option<&dyn SiteDomainTxtResolver>,
) -> GatedChallengeCheck {
    match reservation {
        SiteDomainVerificationAttempt::RateLimited { retry_after_secs } => {
            // Refused: the resolver is intentionally left untouched -- no DNS
            // request is constructed and none is sent.
            GatedChallengeCheck::RateLimited { retry_after_secs }
        }
        SiteDomainVerificationAttempt::Allowed => match resolver {
            Some(resolver) => {
                let lookup = resolver.lookup_txt(record_name).await;
                GatedChallengeCheck::Resolved(resolve_challenge(expected_value, lookup))
            }
            None => GatedChallengeCheck::Resolved(ChallengeOutcome::ResolverUnavailable(
                "no DNS resolver was constructed for an admitted verification attempt".to_string(),
            )),
        },
    }
}

/// Which resolver backend the process uses. Selected from the environment so
/// turning verification on does not require a control-plane config-schema
/// change (the `FERROGATE_ASSET_SCANNER` precedent), and so the default stays
/// the offline, fail-closed [`UnboundTxtResolver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SiteDomainResolverBackend {
    Unbound,
    Doh { endpoint: String, timeout_secs: u64 },
    ZoneFile { path: String },
}

impl SiteDomainResolverBackend {
    pub(super) fn from_env() -> Self {
        match std::env::var("FERROGATE_SITE_DOMAIN_RESOLVER")
            .ok()
            .as_deref()
        {
            Some("doh") => SiteDomainResolverBackend::Doh {
                endpoint: std::env::var("FERROGATE_SITE_DOMAIN_RESOLVER_ENDPOINT")
                    .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".to_string()),
                timeout_secs: std::env::var("FERROGATE_SITE_DOMAIN_RESOLVER_TIMEOUT_SECS")
                    .ok()
                    .and_then(|raw| raw.parse::<u64>().ok())
                    .filter(|secs| *secs > 0)
                    .unwrap_or(10),
            },
            // A zone file with no path configured stays UNBOUND rather than
            // silently resolving against a default path.
            Some("zone-file") => match std::env::var("FERROGATE_SITE_DOMAIN_RESOLVER_ZONE_FILE") {
                Ok(path) if !path.trim().is_empty() => SiteDomainResolverBackend::ZoneFile { path },
                _ => SiteDomainResolverBackend::Unbound,
            },
            _ => SiteDomainResolverBackend::Unbound,
        }
    }

    pub(super) fn build_resolver(&self) -> Box<dyn SiteDomainTxtResolver> {
        match self {
            SiteDomainResolverBackend::Unbound => Box::new(UnboundTxtResolver),
            SiteDomainResolverBackend::Doh {
                endpoint,
                timeout_secs,
            } => {
                // #488 review item 1: the module doc says DoH was chosen over a
                // raw UDP resolver because it is "authenticated and
                // integrity-protected by TLS". Nothing enforced the scheme, so
                // FERROGATE_SITE_DOMAIN_RESOLVER_ENDPOINT=http://... silently
                // downgraded the only ownership oracle to an unauthenticated
                // channel -- an on-path attacker answers once and EVERY
                // hostname verifies, while backend_name() still reports "doh"
                // and the audit line still reads "verified via TXT (doh
                // backend)". An operator typo must not be able to do that.
                //
                // Falling back to Unbound rather than panicking: a
                // misconfigured resolver makes ownership UNPROVABLE, which is
                // the safe direction (nothing verifies), and it keeps the
                // gateway serving everything already proven.
                if !endpoint.starts_with("https://") {
                    tracing::error!(
                        endpoint = %endpoint,
                        "site-domain DoH resolver endpoint is not https; refusing to use it \
                         and falling back to the unbound resolver -- no hostname can be \
                         verified until this is corrected (#488)"
                    );
                    return Box::new(UnboundTxtResolver);
                }
                match DohTxtResolver::new(endpoint.clone(), Duration::from_secs(*timeout_secs)) {
                    Some(resolver) => Box::new(resolver),
                    None => {
                        // #488 review item 2.
                        tracing::error!(
                            endpoint = %endpoint,
                            timeout_secs = *timeout_secs,
                            "could not build the site-domain DoH client with the configured \
                             timeout; falling back to the unbound resolver rather than to a \
                             client with NO timeout (#488)"
                        );
                        Box::new(UnboundTxtResolver)
                    }
                }
            }
            SiteDomainResolverBackend::ZoneFile { path } => {
                Box::new(ZoneFileTxtResolver::new(path.clone()))
            }
        }
    }
}

/// Whether pre-#488 bindings are grandfathered at startup.
///
/// MIGRATION DECISION (#488): bindings that already existed when ownership
/// verification landed are GRANDFATHERED by default, recorded EXPLICITLY as a
/// `grandfathered` row rather than silently treated as verified, and logged at
/// WARN with the full hostname list at every startup until they are re-proven.
/// The alternative -- forcing every live binding into `pending_verification` --
/// would take working customer sites offline on upgrade, which is not something
/// a security fix gets to do silently either. The grandfathered set is
/// therefore visible in the store, in `GET /admin/v1/site-domains/{hostname}`,
/// and in the startup log, and an operator who suspects the pre-#488 set
/// contains a land-grab forces the strict posture with
/// `FERROGATE_SITE_DOMAIN_GRANDFATHER=false`, which backfills those bindings as
/// `pending_verification` (they stop serving until proven).
///
/// Grandfathering is only a serving-availability exception. It is NOT an
/// ownership proof and never enrolls a hostname in ACME issuance or renewal;
/// the operator must complete the TXT proof before FerroGate can manage that
/// hostname's certificate.
///
/// Note the narrow blast radius: grandfathering only ever applies to bindings
/// present at the backfill. Everything bound afterwards must prove ownership.
pub(super) fn grandfather_existing_bindings() -> bool {
    !matches!(
        std::env::var("FERROGATE_SITE_DOMAIN_GRANDFATHER")
            .ok()
            .as_deref(),
        Some("false") | Some("0") | Some("no")
    )
}

/// The verification record a startup backfill should write for a pre-#488
/// binding, or `None` when the binding already carries one. Pure so the
/// migration decision is testable without a store.
pub(super) fn backfill_record_for(
    existing: Option<&StoredSiteDomainVerification>,
    tenant_id: &str,
    hostname: &str,
    site: &str,
    token: String,
    now_unix: i64,
    grandfather: bool,
) -> Option<StoredSiteDomainVerification> {
    if existing.is_some() {
        // Never overwrite an existing proof (or an in-flight challenge) -- the
        // backfill is a one-time migration, not a periodic reset.
        return None;
    }
    Some(if grandfather {
        StoredSiteDomainVerification::grandfathered(tenant_id, hostname, site, token, now_unix)
    } else {
        StoredSiteDomainVerification::pending(tenant_id, hostname, site, token, now_unix)
    })
}

/// Wall-clock seconds, saturating at 0 before the epoch.
pub(super) fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

/// What one site-domain mutation must do to the ACME certificate order set.
///
/// Typed, and derived from the STORED proof rather than from a caller-supplied
/// flag, on purpose. The #488 regression this replaces was not a wrong
/// predicate -- it was a correct predicate the call site could pick wrongly:
/// the bind handler held two booleans (`serving` and `live_ownership_proof`)
/// that differ for exactly one state, `grandfathered`, and chose between them
/// by hand at the `refresh_acme_after_domain_change` call. Twice, the choice
/// collapsed back to `serving` and a grandfathered land-grab re-entered the
/// certificate order set. With the decision expressed as a value there is no
/// serving boolean left at the ACME call site to swap in, and
/// [`acme_order_action`] is the single place the policy exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AcmeOrderAction {
    /// The record carries a LIVE DNS ownership proof: the hostname may enter
    /// the certificate order set. This is the ONLY variant that enrolls.
    Enroll,
    /// No live proof, so the hostname stays out of the order set. `serving`
    /// carries WHY it may still answer traffic (the `grandfathered` migration
    /// exception), and `verification_state` names the state for the operator
    /// log -- neither is an input to the enrollment decision.
    Withhold {
        serving: bool,
        verification_state: &'static str,
    },
}

impl AcmeOrderAction {
    /// Whether this action enrolls the hostname. The audit/response wording
    /// reads this rather than re-deriving it, so the line an operator reads
    /// cannot disagree with what was actually done to the order set.
    pub(super) fn enrolls(self) -> bool {
        matches!(self, AcmeOrderAction::Enroll)
    }
}

/// The #488 ACME order-set policy, in one place: a hostname enters a
/// certificate order only on a live `verified` DNS proof.
///
/// `grandfathered` deliberately withholds even though it keeps serving --
/// migration availability is not evidence that FerroGate may request a
/// certificate for the hostname, and an unowned hostname in the order set burns
/// the ACME account's per-account failed-order rate limit for every legitimate
/// domain sharing it.
pub(super) fn acme_order_action(
    record: &StoredSiteDomainVerification,
    now_unix: i64,
) -> AcmeOrderAction {
    if record.has_live_dns_ownership_proof(now_unix) {
        AcmeOrderAction::Enroll
    } else {
        AcmeOrderAction::Withhold {
            serving: record.serves(now_unix),
            verification_state: record.effective_state(now_unix).as_str(),
        }
    }
}

/// Whether a verification record is a live proof eligible for ACME enrollment.
///
/// `grandfathered` deliberately returns false even though it may keep serving:
/// migration availability is not evidence that FerroGate may request a
/// certificate for the hostname.
pub(super) fn eligible_for_acme(record: &StoredSiteDomainVerification, now_unix: i64) -> bool {
    acme_order_action(record, now_unix).enrolls()
}

/// Whether the tenant currently holding a hostname blocks a challenger that has
/// just completed its own DNS-TXT proof.
///
/// Only a LIVE `verified` proof defends a binding. A `grandfathered` incumbent
/// is a pre-#488 land-grab candidate by construction -- it was never asked to
/// prove anything -- so it must not be able to permanently block the tenant that
/// actually owns the hostname and did the work. That is the first-come-first-
/// served land-grab this issue exists to close; defending it with the 409 would
/// keep the squatter and reject the owner.
///
/// This mirrors the storage-level conditional claim in
/// `claim_verified_site_domain` (memory/Postgres/D1) exactly, and exists so the
/// handler's preflight refusal and the atomic write cannot drift apart into two
/// different definitions of "the holder owns this". `None` (no record at all)
/// is not proof either, so it never blocks.
pub(super) fn holder_blocks_verified_takeover(
    holder: Option<&StoredSiteDomainVerification>,
    now_unix: i64,
) -> bool {
    holder.is_some_and(|holder| holder.has_live_dns_ownership_proof(now_unix))
}

/// Whether `tenant_id` is the tenant that CURRENTLY holds the servable
/// `site_domains` row.
///
/// One definition, shared by the re-bind reuse rule and by
/// [`displaced_binding_holder`], so "the caller still holds this binding" and
/// "this other tenant is the one being displaced" cannot drift into two
/// different comparisons.
pub(super) fn holds_binding(binding: Option<&StoredSiteDomain>, tenant_id: &str) -> bool {
    binding.is_some_and(|binding| binding.tenant_id == tenant_id)
}

/// The tenant a completed ownership proof is about to displace, if any.
///
/// `binding` is the PRE-claim read of the `site_domains` row: after
/// `claim_verified_site_domain` the row names the claimant, so the loser is no
/// longer recoverable from it.
///
/// `None` when the hostname was unbound or the claimant already held it. The
/// same-tenant filter is load-bearing, not decoration: without it an ordinary
/// verify (the caller proving a hostname it already holds) would delete the
/// winner's OWN freshly written `verified` row, so the hostname would stop
/// serving the instant it was proved -- a worse failure than the land-grab this
/// cleanup closes.
pub(super) fn displaced_binding_holder<'a>(
    binding: Option<&'a StoredSiteDomain>,
    claimant: &str,
) -> Option<&'a str> {
    binding
        .filter(|binding| binding.tenant_id != claimant)
        .map(|binding| binding.tenant_id.as_str())
}

/// What happened to the displaced tenant's stored proof, once there WAS a
/// displaced tenant.
///
/// Three dispositions rather than a boolean: "there was nothing to drop" and
/// "the drop FAILED" are different facts for an operator, and only the last one
/// can leave a stale serving signal behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DisplacedProofDisposition {
    /// The row existed and is gone.
    Dropped,
    /// There was no verification row for the displaced tenant (nothing to do).
    Absent,
    /// The store refused the delete. The takeover is already durable, so this
    /// can only be reported, never turned into an error response.
    DropFailed,
}

impl DisplacedProofDisposition {
    /// The stable audit/log spelling.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            DisplacedProofDisposition::Dropped => "dropped",
            DisplacedProofDisposition::Absent => "absent",
            DisplacedProofDisposition::DropFailed => "drop_failed",
        }
    }
}

/// The whole outcome of the post-takeover cleanup: WHO was displaced (nobody,
/// in the common same-tenant case) and what happened to their proof. Returned
/// as one value so the audit line and the displaced tenant's own evidence read
/// the same decision the cleanup actually made instead of re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DisplacedProofCleanup {
    /// The claimant already held the binding, or the hostname was unbound: no
    /// other tenant's proof is involved and NOTHING is deleted.
    NoDisplacement,
    Displaced {
        tenant: String,
        disposition: DisplacedProofDisposition,
    },
}

impl DisplacedProofCleanup {
    /// The displaced tenant, or `None` when nobody was displaced.
    pub(super) fn displaced_tenant(&self) -> Option<&str> {
        match self {
            DisplacedProofCleanup::NoDisplacement => None,
            DisplacedProofCleanup::Displaced { tenant, .. } => Some(tenant.as_str()),
        }
    }

    /// The suffix appended to the `site_domain.verify` audit line. Empty when
    /// nothing was displaced, so an ordinary verify's audit record is unchanged.
    pub(super) fn audit_detail(&self) -> String {
        match self {
            DisplacedProofCleanup::NoDisplacement => String::new(),
            DisplacedProofCleanup::Displaced {
                tenant,
                disposition,
            } => format!(
                ", displaced_tenant={tenant}, displaced_proof={}",
                disposition.as_str()
            ),
        }
    }
}

/// Drop the displaced tenant's ownership proof after a verified takeover moved
/// the servable binding away from it (#488).
///
/// WHY: an ownership signal must never outlive the binding it backed. The
/// takeover moves the `site_domains` row, but the loser's own
/// `site_domain_verifications` row used to survive it -- and a `grandfathered`
/// row never expires (`verification_expires_at_unix` is `None`), so the
/// displaced squatter only had to wait for the proven owner to unbind, re-bind,
/// and be served again with nothing proved. The unbind handler already drops the
/// proof together with the binding for exactly this reason; this is the same
/// invariant on the path that moves a binding BETWEEN tenants.
///
/// ORDER: the caller runs this AFTER the claim commits. Until then we do not
/// know the binding moved, and deleting another tenant's proof for a takeover
/// that then 409s would destroy state on a request that changed nothing.
///
/// FAILURE: a failed drop cannot fail the request -- the takeover is already
/// durable, so a 5xx would misreport committed state. It is reported
/// ([`DisplacedProofDisposition::DropFailed`]) instead of hidden. The invariant
/// does NOT depend on this write succeeding: [`reusable_on_rebind`] refuses to
/// carry a `grandfathered` proof forward for a tenant that no longer holds the
/// binding, so an orphaned row cannot resurrect serving even if every delete
/// here fails. This cleanup is hygiene on top of that fail-closed rule, which is
/// also what makes naming the displaced tenant from the PRE-claim read
/// acceptable under concurrency. If the holder changed between that read and the
/// claim, the delete targets the EARLIER holder -- whose row its own unbind
/// already removed, so the disposition is `Absent` -- and the row the actual
/// loser keeps is at worst a non-serving `pending_verification` challenge (a
/// `grandfathered` orphan is refused by [`reusable_on_rebind`], and a holder with
/// a live `verified` proof cannot be displaced at all: the claim CAS refuses that
/// takeover).
pub(super) async fn drop_displaced_ownership_proof(
    state: &crate::state::AppState,
    hostname: &str,
    pre_claim_binding: Option<&StoredSiteDomain>,
    claimant: &str,
) -> DisplacedProofCleanup {
    let Some(displaced) = displaced_binding_holder(pre_claim_binding, claimant) else {
        return DisplacedProofCleanup::NoDisplacement;
    };
    let deleted = state
        .delete_site_domain_verification(displaced, hostname)
        .await;
    if let Err(error) = &deleted {
        tracing::error!(
            hostname = %hostname,
            displaced_tenant = %displaced,
            "took over the site-domain binding after a DNS ownership proof but could not drop \
             the displaced tenant's stale verification row; remove it so the row cannot be \
             read as evidence later (#488): {error}"
        );
    }
    DisplacedProofCleanup::Displaced {
        tenant: displaced.to_string(),
        disposition: displaced_proof_disposition(deleted.map_err(|error| error.to_string())),
    }
}

/// Fold the store's answer to the cleanup delete into a disposition. Pure, so
/// all three arms are assertable without an injectable failing store.
pub(super) fn displaced_proof_disposition(
    deleted: Result<bool, String>,
) -> DisplacedProofDisposition {
    match deleted {
        Ok(true) => DisplacedProofDisposition::Dropped,
        Ok(false) => DisplacedProofDisposition::Absent,
        Err(_) => DisplacedProofDisposition::DropFailed,
    }
}

/// The bound hostnames that currently hold a LIVE ownership proof.
///
/// This is what the ACME domain set is built from at startup (#488): an
/// unproven hostname must never enter the certificate order, both because the
/// order would fail repeatedly against Let's Encrypt's per-account failed-order
/// rate limit and because issuing for a hostname nobody proved is the wrong
/// posture on its own. A failure to read the proofs yields an EMPTY set, not
/// the unfiltered binding list.
pub(super) async fn servable_site_domain_hostnames(
    state: &crate::state::AppState,
    now_unix: i64,
) -> anyhow::Result<Vec<String>> {
    let bindings = state.list_site_domains(None).await?;
    if bindings.is_empty() {
        return Ok(Vec::new());
    }
    let verifications = state.list_site_domain_verifications(None).await?;
    Ok(bindings
        .into_iter()
        .filter(|binding| {
            verifications.iter().any(|record| {
                record.tenant_id == binding.tenant_id
                    && record.hostname == binding.hostname
                    && eligible_for_acme(record, now_unix)
            })
        })
        .map(|binding| binding.hostname)
        .collect())
}

/// What the one-time startup backfill did, for the operator-facing log line.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SiteDomainBackfillReport {
    /// Bindings already carrying a proof or an in-flight challenge.
    pub(super) untouched: usize,
    /// Pre-#488 bindings recorded as `grandfathered` (still serving).
    pub(super) grandfathered: Vec<String>,
    /// Pre-#488 bindings forced to `pending_verification` (no longer serving)
    /// under `FERROGATE_SITE_DOMAIN_GRANDFATHER=false`.
    pub(super) forced_pending: Vec<String>,
}

/// One-time migration pass over every existing binding (#488).
///
/// Runs at startup BEFORE the ACME domain-set merge, unconditionally (the serve
/// gate depends on it, not just TLS). It writes an EXPLICIT verification record
/// for every binding that has none -- see [`grandfather_existing_bindings`] for
/// the decision and how to force the strict posture -- and never touches a
/// binding that already carries one.
pub(super) async fn backfill_site_domain_verifications(
    state: &crate::state::AppState,
    now_unix: i64,
) -> anyhow::Result<SiteDomainBackfillReport> {
    let bindings = state.list_site_domains(None).await?;
    if bindings.is_empty() {
        return Ok(SiteDomainBackfillReport::default());
    }
    let existing = state.list_site_domain_verifications(None).await?;
    let grandfather = grandfather_existing_bindings();
    let mut report = SiteDomainBackfillReport::default();
    for binding in &bindings {
        let current = existing.iter().find(|record| {
            record.tenant_id == binding.tenant_id && record.hostname == binding.hostname
        });
        let Some(record) = backfill_record_for(
            current,
            &binding.tenant_id,
            &binding.hostname,
            &binding.site,
            new_challenge_token()?,
            now_unix,
            grandfather,
        ) else {
            report.untouched += 1;
            continue;
        };
        let label = format!("{}/{}", binding.tenant_id, binding.hostname);
        state.upsert_site_domain_verification(record).await?;
        if grandfather {
            report.grandfathered.push(label);
        } else {
            report.forced_pending.push(label);
        }
    }
    Ok(report)
}

/// The admin-facing view of a verification record: the state machine plus
/// exactly the instructions an operator needs to publish the challenge.
#[derive(Debug, serde::Serialize)]
pub(super) struct AdminSiteDomainVerification {
    pub(super) object: &'static str,
    /// The state as of NOW, with expiry applied -- not the raw stored string.
    pub(super) state: &'static str,
    /// Whether a request arriving on this hostname would actually be served.
    pub(super) serves: bool,
    pub(super) tenant_id: String,
    pub(super) hostname: String,
    pub(super) site: String,
    pub(super) challenge_record_name: String,
    pub(super) challenge_record_type: &'static str,
    /// The exact string to publish. Safe to return: it is a digest, and it is
    /// only ever returned to a caller already authorized for this tenant.
    pub(super) challenge_record_value: String,
    pub(super) issued_at_unix: i64,
    pub(super) token_expires_at_unix: i64,
    pub(super) verified_at_unix: Option<i64>,
    pub(super) verification_expires_at_unix: Option<i64>,
    pub(super) last_checked_at_unix: Option<i64>,
    pub(super) last_failure_reason: Option<String>,
    pub(super) attempt_count: i64,
}

impl AdminSiteDomainVerification {
    pub(super) fn new(record: &StoredSiteDomainVerification, now_unix: i64) -> Self {
        Self {
            object: "site_domain_verification",
            state: record.effective_state(now_unix).as_str(),
            serves: record.serves(now_unix),
            tenant_id: record.tenant_id.clone(),
            hostname: record.hostname.clone(),
            site: record.site.clone(),
            challenge_record_name: challenge_record_name(&record.hostname),
            challenge_record_type: "TXT",
            challenge_record_value: challenge_txt_value(
                &record.tenant_id,
                &record.hostname,
                &record.challenge_token,
            ),
            issued_at_unix: record.issued_at_unix,
            token_expires_at_unix: record.token_expires_at_unix,
            verified_at_unix: record.verified_at_unix,
            verification_expires_at_unix: record.verification_expires_at_unix,
            last_checked_at_unix: record.last_checked_at_unix,
            last_failure_reason: record.last_failure_reason.clone(),
            attempt_count: record.attempt_count,
        }
    }
}

/// Whether an existing record can be carried forward on a re-bind instead of
/// re-issuing a token: a live proof survives a re-bind (ownership is of the
/// HOSTNAME, not of the site it points at) and an unexpired pending challenge
/// keeps its token so an operator who already published the TXT is not sent
/// back to DNS. Anything expired gets a fresh token.
///
/// `binding` is the CURRENT `site_domains` row for the hostname, because
/// `grandfathered` is the one state whose reusability depends on it. That state
/// is not evidence of control -- it is a migration availability exception, and
/// it only ever covered the binding that existed when #488 landed. Once that
/// binding is gone (unbound, or taken over by a tenant that DID prove
/// ownership), an orphaned `grandfathered` row must not resurrect serving on the
/// next bind: that is precisely the land-grab this issue closes, arriving one
/// hop later. So it is reusable only while the record's own tenant still holds
/// the binding.
///
/// This is structurally fail-closed, which is why the post-takeover cleanup in
/// [`drop_displaced_ownership_proof`] is allowed to be best-effort: if the
/// delete fails, or names the wrong loser because the holder changed between the
/// pre-claim read and the claim, the stale row is still not reusable. A
/// legitimate pre-#488 re-bind is unaffected -- it holds its binding by
/// definition -- and `verified` stays reusable regardless, since a live DNS proof
/// IS evidence of control and expires on its own 90-day clock.
///
/// BE PRECISE ABOUT REACHABILITY: from the bind handler the interesting input is
/// `None` (the hostname is unbound and the caller carries an orphaned row),
/// because a caller that does not hold an EXISTING binding is refused with a 409
/// before this is consulted. The rule is still stated over the binding rather
/// than over a "caller holds it" boolean, so it cannot silently become wrong if
/// that preflight changes.
pub(super) fn reusable_on_rebind(
    record: &StoredSiteDomainVerification,
    binding: Option<&StoredSiteDomain>,
    now_unix: i64,
) -> bool {
    match record.effective_state(now_unix) {
        SiteDomainVerificationState::Expired => false,
        SiteDomainVerificationState::Grandfathered => holds_binding(binding, &record.tenant_id),
        SiteDomainVerificationState::PendingVerification
        | SiteDomainVerificationState::Verified => true,
    }
}

#[cfg(test)]
#[path = "site_domain_verification_test.rs"]
mod site_domain_verification_test;
