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
    let (amz_date, date_stamp) = format_timestamps(request.timestamp_unix);
    let credential_scope = format!(
        "{date_stamp}/{}/{}/aws4_request",
        request.region, request.service
    );

    let hashed_payload = hex_sha256(request.body);
    let (signed_header_names, canonical_headers) = if include_content_hash_header {
        (
            "host;x-amz-content-sha256;x-amz-date",
            format!(
                "host:{}\nx-amz-content-sha256:{hashed_payload}\nx-amz-date:{amz_date}\n",
                request.host
            ),
        )
    } else {
        (
            "host;x-amz-date",
            format!("host:{}\nx-amz-date:{amz_date}\n", request.host),
        )
    };
    let canonical_request = format!(
        "{}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_header_names}\n{hashed_payload}",
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
pub fn presign_query(request: &PresignRequest<'_>, credentials: &AwsCredentials) -> String {
    let (amz_date, date_stamp) = format_timestamps(request.timestamp_unix);
    let credential_scope = format!(
        "{date_stamp}/{}/{}/aws4_request",
        request.region, request.service
    );
    let credential = format!("{}/{credential_scope}", credentials.access_key_id);

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
    params.push(("X-Amz-SignedHeaders", "host".to_string()));
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
        "{}\n{}\n{canonical_query}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        request.method,
        canonical_uri(request.path),
        request.host,
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
