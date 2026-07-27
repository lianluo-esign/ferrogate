// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `asset_bucket.endpoint` decomposition, moved verbatim out of
//! `ferrogate-cli`'s `gateway/asset_bucket.rs` (#553 stage 3a).
//!
//! It lives here because `Config::validate_asset_bucket_r2` is one of its two
//! callers and validation moved into this crate; leaving it in `ferrogate-cli`
//! would have made `ferrogate-config` depend on `ferrogate-cli`. The runtime
//! SigV4 signer is the other caller and now reads it from here, which is the
//! property #485 bought: one decomposition, not two.

/// The DNS suffix every Cloudflare R2 S3-API host ends with (issue #410).
/// The per-account host is `<account_id>.r2.cloudflarestorage.com`; the
/// jurisdiction hosts insert a `.eu.` / `.fedramp.` label before it.
pub const R2_ENDPOINT_SUFFIX: &str = "r2.cloudflarestorage.com";

/// The region FerroGate requires for an R2 endpoint. R2 ignores geographic
/// regions; its canonical credential scope is `.../auto/s3/aws4_request`, and
/// Cloudflare's S3-compatibility docs additionally accept a *blank* region and
/// `us-east-1` as aliases for `auto`. FerroGate pins the canonical `auto`
/// rather than accepting the aliases: the signer folds whatever region string
/// it is given straight into the credential scope, so pinning one value keeps
/// the signed scope unambiguous and keeps this the only R2-specific config the
/// SigV4 path needs. The load-time guard's error message says exactly what to
/// set.
pub const R2_REGION: &str = "auto";

/// A parsed Cloudflare R2 S3 endpoint (issue #410): the account id and the
/// optional data-residency jurisdiction (`eu` / `fedramp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R2Endpoint {
    pub account_id: String,
    /// `None` for the default global host; `Some("eu")` / `Some("fedramp")`
    /// for the jurisdiction hosts.
    pub jurisdiction: Option<&'static str>,
}

/// `asset_bucket.endpoint` decomposed into the exact pieces the runtime SigV4
/// path uses (issue #485).
///
/// This type exists so the load-time guards and the runtime signer cannot
/// disagree about what an endpoint *means*. Before #485 there were two
/// independent decompositions -- a validation-only `endpoint_host()` that
/// dropped the port and any path suffix, and
/// `AssetBucketClient::scheme_and_host` which dropped neither -- so an
/// endpoint the guard judged to be a clean R2 host could still sign a
/// completely different `host` header. Both now go through
/// [`parse_endpoint`], and the R2 guards are written against
/// [`EndpointParts::signing_host`] (the literal value the signer signs), so a
/// value the guard accepts is by construction the value the signer sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointParts {
    /// `http` only for an explicit `http://` endpoint (local mocks); `https`
    /// otherwise, matching `bedrock.rs::extract_host`'s convention.
    pub scheme: &'static str,
    /// `host[:port]`, ASCII-lowercased. DNS hostnames are case-insensitive, so
    /// normalizing here (rather than in each caller) is what makes the R2
    /// detector case-insensitive *and* guarantees the signer signs the same
    /// spelling the guard inspected.
    pub authority: String,
    /// Any path prefix the endpoint carries (`/storage/v1/s3` for Supabase
    /// Storage), or `""`. Case is preserved -- URL paths are case-sensitive.
    /// A trailing `/` is trimmed, exactly as the signer trims it.
    pub path_prefix: String,
}

impl EndpointParts {
    /// The literal string the runtime puts in the signed `host` header and in
    /// the authority position of every request URL it builds. For a
    /// path-prefixed endpoint this deliberately includes the prefix, because
    /// that is what the signer does today; the R2 guard rejects such an
    /// endpoint precisely because this is not a bare R2 host.
    pub fn signing_host(&self) -> String {
        format!("{}{}", self.authority, self.path_prefix)
    }

    /// The bare DNS host: [`Self::authority`] with any `:port` removed.
    pub fn host_name(&self) -> &str {
        if self.authority.starts_with('[') {
            // IPv6 literal: `[::1]:8080` -> `[::1]`.
            return match self.authority.find(']') {
                Some(end) => &self.authority[..=end],
                None => &self.authority,
            };
        }
        self.authority
            .split(':')
            .next()
            .unwrap_or(self.authority.as_str())
    }
}

/// Decomposes `asset_bucket.endpoint` the way the runtime signer does. THE
/// single source of truth for "what host will we sign?" -- see
/// [`EndpointParts`].
pub fn parse_endpoint(endpoint: &str) -> anyhow::Result<EndpointParts> {
    let raw = endpoint.trim();
    let (scheme, rest) = match raw.strip_prefix("http://") {
        Some(rest) => ("http", rest),
        None => ("https", raw.strip_prefix("https://").unwrap_or(raw)),
    };
    let rest = rest.trim_end_matches('/');
    let (authority, path_prefix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        anyhow::bail!("asset_bucket.endpoint {endpoint} has no host");
    }
    Ok(EndpointParts {
        scheme,
        authority: authority.to_ascii_lowercase(),
        path_prefix: path_prefix.to_string(),
    })
}

/// True when `endpoint`'s host is under the R2 S3 domain (any account /
/// jurisdiction), used to decide whether the R2-specific validation applies.
/// This is a permissive detector: it matches even an endpoint the signer could
/// never use against R2 (a missing account label, a stray port, a path suffix,
/// an upper-case spelling) so `validate_asset_bucket_r2` can reject those with
/// a clear error rather than silently treating them as a generic S3 endpoint.
pub fn endpoint_targets_r2(endpoint: &str) -> bool {
    let Ok(parts) = parse_endpoint(endpoint) else {
        return false;
    };
    let host = parts.host_name();
    host == R2_ENDPOINT_SUFFIX || host.ends_with(&format!(".{R2_ENDPOINT_SUFFIX}"))
}

/// Strictly parses an R2 S3 endpoint of the form
/// `https://<account_id>.r2.cloudflarestorage.com` (optionally with a
/// `.eu.` / `.fedramp.` jurisdiction label). Returns `None` when the host is
/// not R2 *or* when the signer would not sign a bare R2 host for it: a
/// malformed (empty / multi-label) account id, a `:port`, or a path suffix.
/// The account id must be a single DNS label (no dots), matching R2's
/// 32-hex-char account id.
///
/// The port/path rejections are the #485 fix: R2 addresses buckets path-style
/// off the account host, so anything beyond that host is not "ignored" by the
/// runtime -- `AssetBucketClient::scheme_and_host` folds it into the signed
/// `host` header and the request URL, which R2 rejects with an opaque error.
/// `Some(_)` therefore carries a promise: reassembling the returned account id
/// and jurisdiction reproduces [`EndpointParts::signing_host`] exactly (pinned
/// by `r2_validation_and_the_runtime_signer_agree_on_every_endpoint`).
pub fn parse_r2_endpoint(endpoint: &str) -> Option<R2Endpoint> {
    let parts = parse_endpoint(endpoint).ok()?;
    // Anything the signer would append to the host is disqualifying.
    if !parts.path_prefix.is_empty() {
        return None;
    }
    let host = parts.host_name();
    if host.len() != parts.authority.len() {
        return None; // an explicit `:port`
    }
    // `<...>.r2.cloudflarestorage.com` -> `<...>` (with its trailing dot).
    let prefix = host.strip_suffix(R2_ENDPOINT_SUFFIX)?.strip_suffix('.')?; // reject the bare suffix domain (empty account)
    let (account_id, jurisdiction) = if let Some(account) = prefix.strip_suffix(".eu") {
        (account, Some("eu"))
    } else if let Some(account) = prefix.strip_suffix(".fedramp") {
        (account, Some("fedramp"))
    } else {
        (prefix, None)
    };
    // A valid account id is a single, non-empty DNS label.
    if account_id.is_empty() || account_id.contains('.') {
        return None;
    }
    Some(R2Endpoint {
        account_id: account_id.to_string(),
        jurisdiction,
    })
}
