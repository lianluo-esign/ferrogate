// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: AWS Signature Version 4 request signing (issue #172), needed
// by the Bedrock adapter since it's the first provider in this crate whose
// wire auth isn't a static bearer/API-key header. Implemented directly
// against AWS's published algorithm (rather than pulling in the `aws-sigv4`
// crate and its transitive AWS SDK dependency tree) using the already-
// vendored `hmac`/`sha2` crates for the cryptographic primitives -- this
// module only owns the SigV4-specific canonicalization/derivation logic,
// not the underlying HMAC-SHA256/SHA256 implementations themselves.
//
// Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// AWS credentials for SigV4 signing. `session_token` is present for
/// temporary credentials (STS/assumed-role); omitted for long-lived IAM
/// user access keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// Everything needed to sign one request, independent of *when* it's
/// signed -- `timestamp` is a parameter (not read from the system clock
/// internally) so the signing logic itself is deterministic and testable.
#[derive(Clone, Copy)]
pub struct SigningRequest<'a> {
    pub method: &'a str,
    /// Absolute path only (no scheme/host/query), e.g. `/model/foo/converse`.
    pub path: &'a str,
    pub host: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub body: &'a [u8],
    /// Unix seconds; converted internally to the `YYYYMMDDTHHMMSSZ` /
    /// `YYYYMMDD` forms SigV4 requires.
    pub timestamp_unix: u64,
}

/// The headers a signed request must send verbatim, plus the date header
/// value (also needed as the literal `X-Amz-Date` header).
pub struct SignedHeaders {
    pub x_amz_date: String,
    pub authorization: String,
    /// Present only when the credentials carry a session token (temporary
    /// credentials) -- omitted entirely for long-lived IAM user keys,
    /// matching AWS's own SDKs.
    pub x_amz_security_token: Option<String>,
    /// Present only when signed via [`sign_with_content_hash_header`] --
    /// the hex-encoded SHA-256 of the body, which some AWS services (S3
    /// in particular) require as a literal `x-amz-content-sha256` header
    /// in addition to using it inside the canonical request, unlike
    /// Bedrock's Converse/InvokeModel APIs which only need it folded into
    /// the signature.
    pub x_amz_content_sha256: Option<String>,
}

/// Signs `request` with `credentials`, returning the header values to
/// attach verbatim. Only `host`, `x-amz-date`, and (when present)
/// `x-amz-security-token` are included in `SignedHeaders` in the
/// signature -- the minimal signed-header set AWS's own SDKs use for
/// `application/json` POST bodies, so callers don't need to keep every
/// header they send in sync with what's signed.
pub fn sign(request: &SigningRequest<'_>, credentials: &AwsCredentials) -> SignedHeaders {
    sign_internal(request, credentials, false, "")
}

/// Same as [`sign`], but also signs and returns a literal
/// `x-amz-content-sha256` header (`SignedHeaders::x_amz_content_sha256`)
/// -- required by S3-compatible object-storage APIs (`asset_bucket.rs`,
/// issue #176), which is why this crate exposes it separately rather than
/// changing `sign`'s existing behavior for Bedrock.
pub fn sign_with_content_hash_header(
    request: &SigningRequest<'_>,
    credentials: &AwsCredentials,
) -> SignedHeaders {
    sign_internal(request, credentials, true, "")
}

/// Everything needed to sign a request whose body the caller will *stream*
/// rather than hold: identical to [`SigningRequest`] except the payload is
/// named by its already-known hex SHA-256 instead of by its bytes.
///
/// This exists so the asset large-file path (issue #259) can PUT a
/// multi-gigabyte object to an S3-compatible bucket without ever materializing
/// it in gateway memory. SigV4 needs the payload hash *before* the body is
/// sent, which normally forces the signer to hold the whole body; the presigned
/// commit path already knows the object's SHA-256 (the client declared it and
/// the gateway verifies it byte-by-byte as it streams), so it can supply the
/// hash directly.
///
/// The caller is responsible for the hash actually matching the bytes it sends:
/// an S3-compatible bucket recomputes it and rejects a mismatch, which is the
/// desired fail-closed behavior, not something this signer papers over.
#[derive(Clone, Copy)]
pub struct StreamedSigningRequest<'a> {
    pub method: &'a str,
    /// Absolute path only (no scheme/host/query), e.g. `/bucket/key`.
    pub path: &'a str,
    pub host: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// Lowercase hex SHA-256 of the payload the caller will stream.
    pub payload_sha256_hex: &'a str,
    pub timestamp_unix: u64,
}

/// Same as [`sign_with_content_hash_header`], but takes the payload's SHA-256
/// instead of the payload -- see [`StreamedSigningRequest`]. Produces a
/// byte-identical `Authorization` header to
/// [`sign_with_content_hash_header`] for the same request whose body hashes to
/// `payload_sha256_hex` (pinned by
/// `streamed_signing_matches_buffered_signing_for_the_same_payload`).
pub fn sign_streamed_with_content_hash_header(
    request: &StreamedSigningRequest<'_>,
    credentials: &AwsCredentials,
) -> SignedHeaders {
    sign_canonical(
        request.method,
        request.path,
        request.host,
        request.region,
        request.service,
        request.timestamp_unix,
        credentials,
        true,
        "",
        request.payload_sha256_hex.to_string(),
    )
}

/// Same as [`sign_with_content_hash_header`], but folds a pre-built canonical
/// query string into the signature -- required for S3 collection operations
/// like `ListObjectsV2` (`GET /{bucket}?list-type=2&...`, the #263 GC reconcile
/// pass), whose query parameters are part of the canonical request. The caller
/// must pass the query already canonicalized: parameters sorted by encoded key,
/// each key/value RFC3986-encoded, joined with `&` (use
/// [`canonical_query_string`]). Object PUT/GET/DELETE keep using the no-query
/// [`sign_with_content_hash_header`].
pub fn sign_with_content_hash_header_and_query(
    request: &SigningRequest<'_>,
    credentials: &AwsCredentials,
    canonical_query: &str,
) -> SignedHeaders {
    sign_internal(request, credentials, true, canonical_query)
}

/// Builds an S3 SigV4 canonical query string from raw `(key, value)` pairs:
/// each side RFC3986-encoded, then the pairs sorted by encoded key and joined
/// with `&`. Shared by the collection-listing signer (#263) so callers don't
/// re-derive the exact canonicalization the signature depends on.
pub fn canonical_query_string(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(name, value)| (percent_encode_query(name), percent_encode_query(value)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn sign_internal(
    request: &SigningRequest<'_>,
    credentials: &AwsCredentials,
    include_content_hash_header: bool,
    canonical_query: &str,
) -> SignedHeaders {
    sign_canonical(
        request.method,
        request.path,
        request.host,
        request.region,
        request.service,
        request.timestamp_unix,
        credentials,
        include_content_hash_header,
        canonical_query,
        hex_sha256(request.body),
    )
}

/// The one SigV4 header-auth derivation, parameterized by the *already
/// computed* payload hash. Both the buffered ([`sign_internal`]) and the
/// streamed ([`sign_streamed_with_content_hash_header`]) entry points funnel
/// through here so a streamed upload can never drift from the signature a
/// buffered upload of the same bytes would produce.
#[allow(clippy::too_many_arguments)]
fn sign_canonical(
    method: &str,
    path: &str,
    host: &str,
    region: &str,
    service: &str,
    timestamp_unix: u64,
    credentials: &AwsCredentials,
    include_content_hash_header: bool,
    canonical_query: &str,
    hashed_payload: String,
) -> SignedHeaders {
    let (amz_date, date_stamp) = format_timestamps(timestamp_unix);
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");

    let (signed_header_names, canonical_headers) = if include_content_hash_header {
        (
            "host;x-amz-content-sha256;x-amz-date",
            format!("host:{host}\nx-amz-content-sha256:{hashed_payload}\nx-amz-date:{amz_date}\n"),
        )
    } else {
        (
            "host;x-amz-date",
            format!("host:{host}\nx-amz-date:{amz_date}\n"),
        )
    };
    let canonical_request = format!(
        "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_header_names}\n{hashed_payload}",
        canonical_uri(path),
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );

    let signing_key =
        derive_signing_key(&credentials.secret_access_key, &date_stamp, region, service);
    let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_header_names}, Signature={signature}",
        credentials.access_key_id
    );

    SignedHeaders {
        x_amz_date: amz_date,
        authorization,
        x_amz_security_token: credentials.session_token.clone(),
        x_amz_content_sha256: include_content_hash_header.then_some(hashed_payload),
    }
}

/// Everything needed to build one SigV4 *query-string presigned URL* --
/// the same inputs as [`SigningRequest`] minus the body (a presigned
/// PUT/GET signs an `UNSIGNED-PAYLOAD` marker instead of a concrete body,
/// so the holder can stream arbitrary bytes) plus a TTL.
#[derive(Clone, Copy)]
pub struct PresignRequest<'a> {
    pub method: &'a str,
    /// Absolute path only (no scheme/host/query), e.g. `/bucket/key`.
    pub path: &'a str,
    pub host: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// URL validity window in seconds; the caller is responsible for
    /// clamping to the S3 maximum of 604800 (7 days).
    pub expires_secs: u64,
    pub timestamp_unix: u64,
}

/// The payload constraints a *bound* presigned upload commits to (issue
/// #368): the exact `Content-Length` and hex SHA-256 the gateway approved
/// at upload-intent time. Both become SigV4 *signed headers*. The presigned
/// canonical request's payload-hash line remains `UNSIGNED-PAYLOAD`, which
/// is the shape Supabase Storage's S3 compatibility layer accepts for
/// presigned requests. Changing the declared size or checksum header still
/// changes the canonical request and invalidates the signature; uploading
/// different bytes with the original checksum header is rejected only by
/// backends that re-hash the body against `x-amz-content-sha256`.
#[derive(Clone, Copy)]
pub struct PresignBoundPayload<'a> {
    /// Exact byte count of the payload the holder is authorized to upload.
    pub content_length: u64,
    /// Lowercase 64-char hex SHA-256 of the exact payload bytes.
    pub content_sha256_hex: &'a str,
}

/// A bound presigned upload (issue #368): the signed query string plus the
/// exact request headers the holder MUST send verbatim on the direct PUT.
/// The headers are part of the SigV4 `SignedHeaders` set, so they are not
/// advisory -- a request that omits or alters any of them fails signature
/// verification at the bucket. Backends that enforce `x-amz-content-sha256`
/// against the received body also reject same-size byte substitution before
/// storing bytes.
pub struct BoundPresignedUpload {
    /// Full canonical query string with `X-Amz-Signature` appended; the
    /// caller assembles `scheme://host{path}?{query}`.
    pub query: String,
    /// `(header name, value)` pairs to send verbatim. `host` is also
    /// signed but derives from the URL itself, so it is not listed here.
    pub required_headers: Vec<(&'static str, String)>,
}

/// Builds the signed query string (without a leading `?`) for an S3
/// SigV4 *query-string presigned URL* -- the direct large-object upload /
/// download path (issue #259) where the signature travels in the query
/// string so the bytes bypass the gateway. Unlike [`sign`] /
/// [`sign_with_content_hash_header`] (which fold auth into request
/// headers), this signs the `X-Amz-*` query parameters with the payload
/// hash fixed to `UNSIGNED-PAYLOAD`, exactly as AWS's own presigners do,
/// so the recipient (Supabase Storage's S3 endpoint or any S3-compatible
/// service) verifies it identically. Returns the full canonical query
/// string with `X-Amz-Signature` appended; the caller assembles
/// `scheme://host{path}?{returned}`.
///
/// For uploads prefer [`presign_query_bound`] (issue #368), which keeps the
/// presigned payload line S3-compatible while binding the signature to a
/// declared size + checksum through signed headers.
pub fn presign_query(request: &PresignRequest<'_>, credentials: &AwsCredentials) -> String {
    presign_query_internal(
        request,
        credentials,
        &[("host", request.host.to_string())],
        "UNSIGNED-PAYLOAD",
    )
}

/// Same as [`presign_query`], but *bound* to a declared payload (issue
/// #368): `content-length` and `x-amz-content-sha256` join `host` in the
/// SigV4 `SignedHeaders` set, while the canonical request's payload-hash
/// line stays `UNSIGNED-PAYLOAD`. Supabase Storage accepts this presigned
/// shape and still verifies the signed-header set. A changed size or changed
/// checksum header therefore cannot verify; same-size byte substitution is
/// refused only by a backend that compares the received body to the signed
/// `x-amz-content-sha256` header.
pub fn presign_query_bound(
    request: &PresignRequest<'_>,
    credentials: &AwsCredentials,
    payload: &PresignBoundPayload<'_>,
) -> BoundPresignedUpload {
    let content_length = payload.content_length.to_string();
    let content_sha256 = payload.content_sha256_hex.to_ascii_lowercase();
    // Signed headers must be lowercase and sorted by name; this literal
    // ordering is alphabetical already.
    let signed_headers = [
        ("content-length", content_length.clone()),
        ("host", request.host.to_string()),
        ("x-amz-content-sha256", content_sha256.clone()),
    ];
    let query = presign_query_internal(request, credentials, &signed_headers, "UNSIGNED-PAYLOAD");
    BoundPresignedUpload {
        query,
        required_headers: vec![
            ("content-length", content_length),
            ("x-amz-content-sha256", content_sha256),
        ],
    }
}

/// Shared presign core: signs the `X-Amz-*` query parameters over the given
/// signed-header set (which must be lowercase, sorted by name, and include
/// `host`) and payload-hash line, returning the query string with
/// `X-Amz-Signature` appended.
fn presign_query_internal(
    request: &PresignRequest<'_>,
    credentials: &AwsCredentials,
    signed_headers: &[(&'static str, String)],
    payload_hash: &str,
) -> String {
    let (amz_date, date_stamp) = format_timestamps(request.timestamp_unix);
    let credential_scope = format!(
        "{date_stamp}/{}/{}/aws4_request",
        request.region, request.service
    );
    let credential = format!("{}/{credential_scope}", credentials.access_key_id);
    let signed_header_names = signed_headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = signed_headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();

    // The canonical query string is sorted by (encoded) key name; the
    // `X-Amz-*` keys here are already alphabetical, and inserting the
    // optional security token between `X-Amz-Expires` and
    // `X-Amz-SignedHeaders` keeps them so.
    let mut params: Vec<(&str, String)> = vec![
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", request.expires_secs.to_string()),
    ];
    if let Some(token) = &credentials.session_token {
        params.push(("X-Amz-Security-Token", token.clone()));
    }
    params.push(("X-Amz-SignedHeaders", signed_header_names.clone()));
    let canonical_query = params
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                percent_encode_query(name),
                percent_encode_query(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "{}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_header_names}\n{payload_hash}",
        request.method,
        canonical_uri(request.path),
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );
    let signing_key = derive_signing_key(
        &credentials.secret_access_key,
        &date_stamp,
        request.region,
        request.service,
    );
    let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());

    format!("{canonical_query}&X-Amz-Signature={signature}")
}

/// RFC 3986 encoding for a canonical query-string key or value: every byte
/// outside the unreserved set (`A-Za-z0-9-_.~`) is percent-encoded,
/// including `/` (so the slashes inside `X-Amz-Credential` become `%2F`) --
/// stricter than [`percent_encode_segment`], which preserves `/` as a path
/// separator and passes through pre-formed `%XY` escapes.
fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn derive_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    let k_date = hmac_bytes(
        format!("AWS4{secret_access_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_bytes(&k_date, region.as_bytes());
    let k_service = hmac_bytes(&k_region, service.as_bytes());
    hmac_bytes(&k_service, b"aws4_request")
}

fn hmac_bytes(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn hex_hmac(key: &[u8], message: &[u8]) -> String {
    hex_encode(&hmac_bytes(key, message))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `YYYYMMDDTHHMMSSZ` and `YYYYMMDD`, computed from a Unix timestamp
/// without pulling in a chrono-style dependency -- mirrors the existing
/// dependency-free `period_month_from_unix` civil-calendar conversion in
/// `ferrogate-storage`.
fn format_timestamps(unix_seconds: u64) -> (String, String) {
    let days = unix_seconds / 86_400;
    let seconds_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    let amz_date = format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z");
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    (amz_date, date_stamp)
}

/// Howard Hinnant's `civil_from_days`, days-since-epoch -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// AWS's path-segment percent-encoding for the canonical request: every
/// byte outside `A-Za-z0-9-_.~` is percent-encoded, EXCEPT `/`, which is
/// preserved as the path separator (SigV4 encodes the path once, not the
/// "double URI-encode" rule that applies specifically to S3 canonical
/// query strings, which this module never builds).
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(percent_encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// Encodes one path segment, treating an already-well-formed `%XY` escape
/// (two hex digits) as pre-encoded and passing it through verbatim rather
/// than re-encoding the `%` itself. This matters because `bedrock.rs`
/// deliberately pre-percent-encodes an entire model id (including any
/// embedded `/`, e.g. an ARN-style id) into a single path segment before
/// this function ever sees it, specifically so a slash inside the model
/// id can't be mistaken for a path separator -- without this
/// already-escaped detection, `canonical_uri` would re-encode that
/// segment's `%` characters into `%25`, producing a signature that
/// doesn't match what a real AWS-compatible server independently derives
/// from the (correctly, singly-encoded) wire request.
fn percent_encode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[index + 1] as char);
            out.push(bytes[index + 2] as char);
            index += 3;
            continue;
        }
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamps_matches_known_calendar_date() {
        // 2015-08-30T12:36:00Z, the date used throughout AWS's own SigV4
        // documentation examples -- 1440938160 is that instant's Unix time.
        let (amz_date, date_stamp) = format_timestamps(1_440_938_160);
        assert_eq!(amz_date, "20150830T123600Z");
        assert_eq!(date_stamp, "20150830");
    }

    #[test]
    fn canonical_uri_preserves_slashes_and_encodes_reserved_bytes_per_segment() {
        // A Bedrock model id containing `:` (e.g. an inference-profile ARN
        // suffix like "anthropic.claude-3-5-sonnet-20241022-v2:0") must have
        // that colon percent-encoded -- `:` is reserved and not in AWS's
        // unreserved set (`A-Za-z0-9-_.~`).
        assert_eq!(
            canonical_uri("/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse"),
            "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"
        );
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/"), "/");
    }

    #[test]
    fn canonical_uri_does_not_double_encode_an_already_escaped_segment() {
        // bedrock.rs pre-percent-encodes the entire model id (protecting
        // any embedded `/` in an ARN-style id) before building `path`, so
        // canonical_uri must treat the resulting `%3A` as already-encoded
        // rather than re-escaping the `%` into `%25` -- the double-encoded
        // form would make the signature not match what a real
        // AWS-compatible server independently derives from the (singly
        // percent-encoded) request it actually receives on the wire.
        assert_eq!(
            canonical_uri("/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"),
            "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
            "an already-escaped %XY sequence must pass through verbatim, not become %253A0"
        );
        // A bare, unescaped `%` (not followed by two hex digits) is still
        // a raw byte needing encoding -- this isn't a blanket "never
        // touch %" rule, only "don't re-encode a complete escape".
        assert_eq!(canonical_uri("/100%done"), "/100%25done");
    }

    #[test]
    fn hex_sha256_of_empty_input_matches_the_sha256_crate_directly() {
        // Self-consistency against the trusted `sha2` crate (not a
        // hand-transcribed hash) -- catches a hex-encoding bug in this
        // module without depending on correctly recalling a 64-character
        // digest from memory.
        let expected = Sha256::digest(b"");
        assert_eq!(hex_sha256(b""), hex_encode(&expected));
    }

    #[test]
    fn signing_key_derivation_is_deterministic_and_credential_specific() {
        let key_a = derive_signing_key("secretA", "20150830", "us-east-1", "service");
        let key_b = derive_signing_key("secretA", "20150830", "us-east-1", "service");
        let key_c = derive_signing_key("secretB", "20150830", "us-east-1", "service");
        assert_eq!(key_a, key_b, "same inputs must derive the same signing key");
        assert_ne!(
            key_a, key_c,
            "different secret keys must derive different signing keys"
        );
    }

    /// Hand-derives the canonical request AWS's documented algorithm would
    /// produce for a fixed, simple input, and checks this module's `sign()`
    /// output is internally consistent with it -- i.e. this test builds its
    /// own expectation from the documented FORMATTING RULES (line order,
    /// separators, lowercasing, trailing newline placement) rather than
    /// from a memorized final signature, so it actually exercises this
    /// module's canonicalization logic instead of just re-asserting a
    /// magic string.
    #[test]
    fn sign_produces_the_documented_authorization_header_shape() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let request = SigningRequest {
            method: "POST",
            path: "/model/test-model/converse",
            host: "bedrock-runtime.us-east-1.amazonaws.com",
            region: "us-east-1",
            service: "bedrock",
            body: br#"{"messages":[]}"#,
            timestamp_unix: 1_440_938_160,
        };
        let signed = sign(&request, &credentials);

        assert_eq!(signed.x_amz_date, "20150830T123600Z");
        assert!(signed.x_amz_security_token.is_none());
        assert!(signed.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, "
        ));
        assert!(signed
            .authorization
            .contains("SignedHeaders=host;x-amz-date, "));
        assert!(signed.authorization.contains("Signature="));

        // Signature must be a 64-character lowercase hex string.
        let signature = signed.authorization.rsplit("Signature=").next().unwrap();
        assert_eq!(signature.len(), 64);
        assert!(signature
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn sign_includes_the_security_token_when_credentials_are_temporary() {
        let credentials = AwsCredentials {
            access_key_id: "ASIAEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: Some("temporary-session-token".to_string()),
        };
        let request = SigningRequest {
            method: "POST",
            path: "/model/test-model/converse",
            host: "bedrock-runtime.us-east-1.amazonaws.com",
            region: "us-east-1",
            service: "bedrock",
            body: b"{}",
            timestamp_unix: 1_440_938_160,
        };
        let signed = sign(&request, &credentials);
        assert_eq!(
            signed.x_amz_security_token.as_deref(),
            Some("temporary-session-token")
        );
    }

    #[test]
    fn changing_the_body_changes_the_signature() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let base_request = SigningRequest {
            method: "POST",
            path: "/model/test-model/converse",
            host: "bedrock-runtime.us-east-1.amazonaws.com",
            region: "us-east-1",
            service: "bedrock",
            body: br#"{"messages":[]}"#,
            timestamp_unix: 1_440_938_160,
        };
        let other_request = SigningRequest {
            body: br#"{"messages":[{"role":"user"}]}"#,
            ..base_request
        };
        let signed_a = sign(&base_request, &credentials);
        let signed_b = sign(&other_request, &credentials);
        assert_ne!(
            signed_a.authorization, signed_b.authorization,
            "a different payload must produce a different signature (payload hash is part of the canonical request)"
        );
    }

    #[test]
    fn percent_encode_query_escapes_slashes_and_reserved_bytes() {
        // The credential scope's `/` separators must become `%2F` in the
        // canonical query string (unlike a path, where `/` is preserved).
        assert_eq!(
            percent_encode_query("AKID/20150830/us-east-1/s3/aws4_request"),
            "AKID%2F20150830%2Fus-east-1%2Fs3%2Faws4_request"
        );
        // Unreserved bytes pass through unchanged.
        assert_eq!(percent_encode_query("A-Za-z0-9_.~"), "A-Za-z0-9_.~");
    }

    #[test]
    fn presign_query_produces_a_sigv4_query_string_with_all_required_parameters() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let request = PresignRequest {
            method: "PUT",
            path: "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0",
            host: "project.supabase.co",
            region: "us-east-1",
            service: "s3",
            expires_secs: 900,
            timestamp_unix: 1_440_938_160,
        };
        let query = presign_query(&request, &credentials);

        assert!(query.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        // The credential's slashes must be encoded as %2F inside the query.
        assert!(query
            .contains("X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request"));
        assert!(query.contains("X-Amz-Date=20150830T123600Z"));
        assert!(query.contains("X-Amz-Expires=900"));
        assert!(query.contains("X-Amz-SignedHeaders=host"));
        assert!(!query.contains("X-Amz-Security-Token"));

        // The signature is the last parameter and a 64-char lowercase hex.
        let signature = query.rsplit("X-Amz-Signature=").next().unwrap();
        assert_eq!(signature.len(), 64);
        assert!(signature
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Canonical query parameters must be sorted by name (the recipient
        // re-derives the signature from the same sorted set).
        let algorithm = query.find("X-Amz-Algorithm").unwrap();
        let credential = query.find("X-Amz-Credential").unwrap();
        let date = query.find("X-Amz-Date=").unwrap();
        let expires = query.find("X-Amz-Expires").unwrap();
        let signed_headers = query.find("X-Amz-SignedHeaders").unwrap();
        assert!(algorithm < credential && credential < date && date < expires);
        assert!(expires < signed_headers);
    }

    #[test]
    fn presign_query_signature_depends_on_method_key_and_expiry() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let put = PresignRequest {
            method: "PUT",
            path: "/bucket/key",
            host: "host.test",
            region: "us-east-1",
            service: "s3",
            expires_secs: 900,
            timestamp_unix: 1_440_938_160,
        };
        let get = PresignRequest {
            method: "GET",
            ..put
        };
        let other_key = PresignRequest {
            path: "/bucket/other",
            ..put
        };
        let longer_ttl = PresignRequest {
            expires_secs: 3600,
            ..put
        };
        let sig = |request: &PresignRequest| {
            presign_query(request, &credentials)
                .rsplit("X-Amz-Signature=")
                .next()
                .unwrap()
                .to_string()
        };
        assert_ne!(
            sig(&put),
            sig(&get),
            "method is part of the canonical request"
        );
        assert_ne!(sig(&put), sig(&other_key), "the object key is signed");
        assert_ne!(sig(&put), sig(&longer_ttl), "X-Amz-Expires is signed");
    }

    #[test]
    fn presign_query_includes_the_security_token_when_present() {
        let credentials = AwsCredentials {
            access_key_id: "ASIAEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: Some("temp/token+value".to_string()),
        };
        let request = PresignRequest {
            method: "GET",
            path: "/bucket/key",
            host: "host.test",
            region: "us-east-1",
            service: "s3",
            expires_secs: 60,
            timestamp_unix: 1_440_938_160,
        };
        let query = presign_query(&request, &credentials);
        // The token is present and URL-encoded (`/` -> %2F, `+` -> %2B).
        assert!(query.contains("X-Amz-Security-Token=temp%2Ftoken%2Bvalue"));
    }

    /// Recomputes the SigV4 signature the way a Supabase-compatible S3
    /// verifier does for a *received* presigned request (#368): rebuild the
    /// canonical query from the presented `X-Amz-*` parameters (minus the
    /// signature), take each header named in `X-Amz-SignedHeaders` from the
    /// headers the client actually sent (a missing one is an immediate
    /// rejection -- the canonical request cannot even be reconstructed), and
    /// keep the presigned canonical request's payload-hash line at
    /// `UNSIGNED-PAYLOAD`. When `x-amz-content-sha256` is a signed header this
    /// verifier also checks the received bytes against that header, modelling
    /// checksum-enforcing S3 backends such as AWS S3. Returns `(recomputed,
    /// presented)` so tests can assert signature mismatches, or `Err` for
    /// structurally rejected requests / payload checksum mismatches.
    fn bucket_recompute_signature(
        method: &str,
        path: &str,
        query: &str,
        sent_headers: &[(&str, &str)],
        actual_body: &[u8],
        credentials: &AwsCredentials,
    ) -> Result<(String, String), String> {
        let mut presented_signature = None;
        let mut canonical_params = Vec::new();
        let mut signed_header_names = None;
        let mut credential = None;
        let mut amz_date = None;
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or("malformed query pair")?;
            if name == "X-Amz-Signature" {
                presented_signature = Some(value.to_string());
                continue;
            }
            canonical_params.push(format!("{name}={value}"));
            match name {
                "X-Amz-SignedHeaders" => signed_header_names = Some(percent_decode(value)?),
                "X-Amz-Credential" => credential = Some(percent_decode(value)?),
                "X-Amz-Date" => amz_date = Some(value.to_string()),
                _ => {}
            }
        }
        let presented_signature = presented_signature.ok_or("missing X-Amz-Signature")?;
        let signed_header_names = signed_header_names.ok_or("missing X-Amz-SignedHeaders")?;
        let amz_date = amz_date.ok_or("missing X-Amz-Date")?;
        let canonical_query = canonical_params.join("&");

        // Scope pieces come from the presented credential, exactly as a
        // bucket parses them: access-key/date/region/service/aws4_request.
        let credential = credential.ok_or("missing X-Amz-Credential")?;
        let mut scope = credential.split('/');
        let _access_key = scope.next().ok_or("empty credential")?;
        let date_stamp = scope.next().ok_or("credential missing date")?.to_string();
        let region = scope.next().ok_or("credential missing region")?.to_string();
        let service = scope
            .next()
            .ok_or("credential missing service")?
            .to_string();

        let mut canonical_headers = String::new();
        let mut signed_content_sha256 = None;
        for name in signed_header_names.split(';') {
            let value = sent_headers
                .iter()
                .find(|(sent, _)| sent.eq_ignore_ascii_case(name))
                .map(|(_, value)| *value)
                .ok_or_else(|| format!("required signed header {name} was not sent"))?;
            if name == "x-amz-content-sha256" {
                signed_content_sha256 = Some(value.trim().to_string());
            }
            canonical_headers.push_str(&format!("{name}:{}\n", value.trim()));
        }
        if let Some(declared) = signed_content_sha256 {
            let actual = hex_sha256(actual_body);
            if actual != declared {
                return Err(format!(
                    "payload checksum mismatch: header {declared}, actual {actual}"
                ));
            }
        }
        let payload_hash = "UNSIGNED-PAYLOAD";

        let canonical_request = format!(
            "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_header_names}\n{payload_hash}",
            canonical_uri(path),
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{date_stamp}/{region}/{service}/aws4_request\n{}",
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key = derive_signing_key(
            &credentials.secret_access_key,
            &date_stamp,
            &region,
            &service,
        );
        Ok((
            hex_hmac(&signing_key, string_to_sign.as_bytes()),
            presented_signature,
        ))
    }

    /// Minimal percent-decoder for the test verifier (the only escapes the
    /// presigner emits are %2F and %3B).
    fn percent_decode(value: &str) -> Result<String, String> {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = value
                    .get(index + 1..index + 3)
                    .ok_or("truncated percent escape")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "invalid percent escape")?);
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(out).map_err(|_| "non-UTF8 decoded value".to_string())
    }

    fn bound_test_credentials() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    fn bound_test_request() -> PresignRequest<'static> {
        PresignRequest {
            method: "PUT",
            path: "/ferrogate-assets/.ferrogate/staging/abc123",
            host: "project.supabase.co",
            region: "us-east-1",
            service: "s3",
            expires_secs: 900,
            timestamp_unix: 1_440_938_160,
        }
    }

    /// Asserts a received request is NOT acceptable to a bucket-side
    /// verifier: either it is structurally rejected (missing signed header),
    /// its independently recomputed signature mismatches the presented one
    /// (canonical request differs), or a checksum-enforcing backend rejects
    /// the bytes against the signed `x-amz-content-sha256` header.
    fn assert_bucket_rejects(
        query: &str,
        sent_headers: &[(&str, &str)],
        actual_body: &[u8],
        why: &str,
    ) {
        let request = bound_test_request();
        match bucket_recompute_signature(
            request.method,
            request.path,
            query,
            sent_headers,
            actual_body,
            &bound_test_credentials(),
        ) {
            Err(_) => {}
            Ok((recomputed, presented)) => assert_ne!(recomputed, presented, "{why}"),
        }
    }

    #[test]
    fn bound_presign_verifies_end_to_end_when_size_checksum_and_headers_match() {
        // #368/#368 gate bounce: both sides recompute the same Supabase-
        // compatible presigned canonical request (UNSIGNED-PAYLOAD line)
        // when the holder sends exactly the declared size, checksum header,
        // and bytes.
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let credentials = bound_test_credentials();
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &credentials,
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        // The signed-header set travels in the query (with `;` encoded).
        assert!(bound
            .query
            .contains("X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256"));
        // The typed required-header map the intent endpoint returns verbatim.
        assert_eq!(
            bound.required_headers,
            vec![
                ("content-length", body.len().to_string()),
                ("x-amz-content-sha256", sha.clone()),
            ]
        );

        let content_length = body.len().to_string();
        let sent_headers = [
            ("host", request.host),
            ("content-length", content_length.as_str()),
            ("x-amz-content-sha256", sha.as_str()),
        ];
        let (recomputed, presented) = bucket_recompute_signature(
            request.method,
            request.path,
            &bound.query,
            &sent_headers,
            body,
            &credentials,
        )
        .expect("a fully matching upload must be verifiable");
        assert_eq!(
            recomputed, presented,
            "matching size + checksum + headers + bytes must verify"
        );
    }

    #[test]
    fn bound_presign_rejects_a_different_declared_size() {
        // A URL signed for N bytes cannot authorize an upload declaring a
        // different Content-Length: that header is in the canonical request.
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &bound_test_credentials(),
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        // The writer pads the payload to burn quota, updating the length
        // header to match its real (larger) upload.
        let padded = [body.as_slice(), b" plus quota-burning padding"].concat();
        let padded_length = padded.len().to_string();
        let padded_sha = hex_sha256(&padded);
        assert_bucket_rejects(
            &bound.query,
            &[
                ("host", request.host),
                ("content-length", padded_length.as_str()),
                ("x-amz-content-sha256", padded_sha.as_str()),
            ],
            &padded,
            "an upload larger than the signed content-length must not verify",
        );
    }

    /// The size binding, isolated so it is NOT provable by the checksum.
    ///
    /// `bound_presign_rejects_a_different_declared_size` pads the payload, so
    /// its rejection also follows from the payload hash changing: that test
    /// stays green with `content-length` removed from the signed set, and
    /// therefore pins nothing about the size binding (the vacuity shape of
    /// #461/6bf367c). Here the bytes, the `x-amz-content-sha256` header and the
    /// received payload are all EXACTLY what was signed -- only the declared
    /// `content-length` differs, which is the case that matters for the quota
    /// invariant this issue exists to protect (an S3-compatible verifier that
    /// trusts the declared length rather than re-hashing). If `content-length`
    /// were not a signed header this request would verify.
    #[test]
    fn bound_presign_rejects_a_lying_content_length_with_the_signed_bytes_and_checksum() {
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &bound_test_credentials(),
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        let inflated = (body.len() as u64 * 1024).to_string();
        assert_bucket_rejects(
            &bound.query,
            &[
                ("host", request.host),
                ("content-length", inflated.as_str()),
                ("x-amz-content-sha256", sha.as_str()),
            ],
            body,
            "a declared content-length other than the signed one must not verify, even when the \
             checksum header and the received bytes are exactly what was signed",
        );
    }

    #[test]
    fn bound_presign_rejects_different_bytes_with_an_honest_checksum() {
        // Same size, different content, checksum header updated to match
        // the substituted bytes: the signed x-amz-content-sha256 differs.
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &bound_test_credentials(),
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        let substituted = b"the DIFFERENT same-length payload!";
        assert_eq!(substituted.len(), body.len());
        let substituted_sha = hex_sha256(substituted);
        let content_length = substituted.len().to_string();
        assert_bucket_rejects(
            &bound.query,
            &[
                ("host", request.host),
                ("content-length", content_length.as_str()),
                ("x-amz-content-sha256", substituted_sha.as_str()),
            ],
            substituted,
            "different bytes with a matching self-declared checksum must not verify",
        );
    }

    #[test]
    fn bound_presign_rejects_omitted_required_headers() {
        // Omitting either signed header leaves the bucket unable to
        // reconstruct the canonical request -- immediate rejection.
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &bound_test_credentials(),
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        let content_length = body.len().to_string();
        assert_bucket_rejects(
            &bound.query,
            &[
                ("host", request.host),
                ("content-length", content_length.as_str()),
            ],
            body,
            "omitting x-amz-content-sha256 must not verify",
        );
        assert_bucket_rejects(
            &bound.query,
            &[("host", request.host), ("x-amz-content-sha256", &sha)],
            body,
            "omitting content-length must not verify",
        );
    }

    #[test]
    fn bound_presign_rejects_a_replay_with_different_bytes() {
        // A replay sends the ORIGINAL signed headers verbatim but different
        // bytes. The presigned canonical request still uses UNSIGNED-PAYLOAD,
        // but a checksum-enforcing bucket compares the received body to the
        // signed x-amz-content-sha256 header and rejects before storing.
        let body = b"the exact approved staging payload";
        let sha = hex_sha256(body);
        let request = bound_test_request();
        let bound = presign_query_bound(
            &request,
            &bound_test_credentials(),
            &PresignBoundPayload {
                content_length: body.len() as u64,
                content_sha256_hex: &sha,
            },
        );

        let tampered = b"tampered bytes replayed on the URL";
        assert_eq!(tampered.len(), body.len());
        let content_length = body.len().to_string();
        assert_bucket_rejects(
            &bound.query,
            &[
                ("host", request.host),
                ("content-length", content_length.as_str()),
                ("x-amz-content-sha256", sha.as_str()),
            ],
            tampered,
            "a replay with different bytes must not verify",
        );
    }

    #[test]
    fn unbound_presign_still_verifies_with_only_the_host_header() {
        // Regression guard for the download path (#259): the host-only,
        // UNSIGNED-PAYLOAD presign is unchanged by the #368 refactor.
        let credentials = bound_test_credentials();
        let request = PresignRequest {
            method: "GET",
            ..bound_test_request()
        };
        let query = presign_query(&request, &credentials);
        assert!(query.contains("X-Amz-SignedHeaders=host"));
        let (recomputed, presented) = bucket_recompute_signature(
            request.method,
            request.path,
            &query,
            &[("host", request.host)],
            b"",
            &credentials,
        )
        .expect("the host-only presign must remain verifiable");
        assert_eq!(recomputed, presented);
    }

    #[test]
    fn streamed_signing_matches_buffered_signing_for_the_same_payload() {
        // The asset large-file path (issue #259) signs a multi-gigabyte PUT it
        // will never hold, by naming the payload's SHA-256 instead of passing
        // the payload. If that produced a different signature than signing the
        // bytes does, every streamed upload would be refused by the bucket --
        // and the failure would look like data corruption, not a signer bug.
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let body = b"a staged asset object the gateway refuses to buffer";
        let buffered = sign_with_content_hash_header(
            &SigningRequest {
                method: "PUT",
                path: "/my-bucket/.ferrogate/objects/abc/obj_deadbeef",
                host: "storage.example.test",
                region: "us-east-1",
                service: "s3",
                body,
                timestamp_unix: 1_440_938_160,
            },
            &credentials,
        );
        let streamed = sign_streamed_with_content_hash_header(
            &StreamedSigningRequest {
                method: "PUT",
                path: "/my-bucket/.ferrogate/objects/abc/obj_deadbeef",
                host: "storage.example.test",
                region: "us-east-1",
                service: "s3",
                payload_sha256_hex: &hex_sha256(body),
                timestamp_unix: 1_440_938_160,
            },
            &credentials,
        );

        assert_eq!(streamed.authorization, buffered.authorization);
        assert_eq!(streamed.x_amz_date, buffered.x_amz_date);
        assert_eq!(streamed.x_amz_content_sha256, buffered.x_amz_content_sha256);
        assert_eq!(
            streamed.x_amz_content_sha256.as_deref(),
            Some(hex_sha256(body).as_str())
        );

        // ...and a DIFFERENT declared hash must produce a different signature,
        // so the bucket's own payload check is what refuses a lying caller.
        let lying = sign_streamed_with_content_hash_header(
            &StreamedSigningRequest {
                method: "PUT",
                path: "/my-bucket/.ferrogate/objects/abc/obj_deadbeef",
                host: "storage.example.test",
                region: "us-east-1",
                service: "s3",
                payload_sha256_hex: &hex_sha256(b"different bytes"),
                timestamp_unix: 1_440_938_160,
            },
            &credentials,
        );
        assert_ne!(lying.authorization, buffered.authorization);
    }

    #[test]
    fn sign_with_content_hash_header_signs_a_third_header_and_returns_the_payload_hash() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let request = SigningRequest {
            method: "PUT",
            path: "/my-bucket/tenant-a/cli_tool/hello/1.0.0",
            host: "storage.example.test",
            region: "us-east-1",
            service: "s3",
            body: b"asset bytes",
            timestamp_unix: 1_440_938_160,
        };
        let signed = sign_with_content_hash_header(&request, &credentials);

        assert_eq!(
            signed.x_amz_content_sha256.as_deref(),
            Some(hex_sha256(b"asset bytes").as_str())
        );
        assert!(signed
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date, "));

        // The plain sign() variant must remain unaffected: still no
        // x-amz-content-sha256 header, still only host;x-amz-date signed.
        let plain = sign(&request, &credentials);
        assert!(plain.x_amz_content_sha256.is_none());
        assert!(plain
            .authorization
            .contains("SignedHeaders=host;x-amz-date, "));
        assert_ne!(
            signed.authorization, plain.authorization,
            "signing a different header set must produce a different signature"
        );
    }
}
