// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Gate-owned live probe for #368 acceptance box 3 -- "the
// implementation is verified against Supabase Storage S3 compatibility with
// bounded small functional objects before claiming support".
//
// The claim under test is narrow and entirely about the SIGNATURE, so this
// probe is written to answer it even where the credentials cannot write:
// Supabase's S3 layer returns `SignatureDoesNotMatch` when the presigned
// request does not verify, and a *different* error (`AccessDenied`, or a 2xx)
// once it does. So the assertion is "the honest, contract-following bound PUT
// is not refused as a signature mismatch", with the unbound `presign_query`
// form as the control that proves the credentials and endpoint are sound.
//
// Everything is env-gated and SKIPS cleanly with an explicit message when the
// credentials are absent -- there is no live Supabase Storage S3 credential in
// the dev sandbox by default. Objects are tiny (< 64 bytes) and any object the
// probe manages to create is deleted and its absence re-verified. No load,
// stress or throughput traffic is generated: at most four small requests.

use ferrogate_providers::{
    presign_sigv4_query, presign_sigv4_query_bound, AwsCredentials, PresignBoundPayload,
    PresignRequest,
};
use ferrogate_storage::sha256_hex;

/// Env contract:
///   * `FERROGATE_SUPABASE_S3_ENDPOINT`   e.g. `https://<ref>.storage.supabase.co/storage/v1/s3`
///   * `FERROGATE_SUPABASE_S3_BUCKET`     an existing bucket to probe
///   * `FERROGATE_SUPABASE_S3_REGION`     the project region (e.g. `ap-northeast-1`)
///   * `FERROGATE_SUPABASE_S3_ACCESS_KEY_ID` / `..._SECRET_ACCESS_KEY`
///     either the dashboard S3 access-key pair, or the session-token form
///     (`access key id` = project ref, `secret` = anon key) together with
///   * `FERROGATE_SUPABASE_S3_SESSION_TOKEN` (optional) a valid Supabase JWT.
struct LiveSupabaseS3 {
    endpoint: String,
    bucket: String,
    region: String,
    credentials: AwsCredentials,
}

fn live_env() -> Option<LiveSupabaseS3> {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    Some(LiveSupabaseS3 {
        endpoint: var("FERROGATE_SUPABASE_S3_ENDPOINT")?,
        bucket: var("FERROGATE_SUPABASE_S3_BUCKET")?,
        region: var("FERROGATE_SUPABASE_S3_REGION").unwrap_or_else(|| "us-east-1".to_string()),
        credentials: AwsCredentials {
            access_key_id: var("FERROGATE_SUPABASE_S3_ACCESS_KEY_ID")?,
            secret_access_key: var("FERROGATE_SUPABASE_S3_SECRET_ACCESS_KEY")?,
            session_token: var("FERROGATE_SUPABASE_S3_SESSION_TOKEN"),
        },
    })
}

/// Splits `https://host/prefix` into `("https://host", "/prefix")` so the
/// signer receives the absolute path Supabase actually routes on.
fn split_endpoint(endpoint: &str) -> (String, String, String) {
    let trimmed = endpoint.trim_end_matches('/');
    let (scheme, rest) = trimmed
        .split_once("://")
        .expect("endpoint must carry a scheme");
    let (host, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    (
        scheme.to_string(),
        host.to_string(),
        if prefix.is_empty() {
            String::new()
        } else {
            format!("/{prefix}")
        },
    )
}

fn error_code(body: &str) -> String {
    body.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_string())
        .unwrap_or_else(|| "<no S3 error code>".to_string())
}

#[tokio::test]
async fn supabase_storage_s3_accepts_the_bound_presigned_put_this_gateway_issues() {
    let Some(env) = live_env() else {
        eprintln!(
            "skipping supabase_storage_s3_accepts_the_bound_presigned_put_this_gateway_issues: \
             set FERROGATE_SUPABASE_S3_ENDPOINT, FERROGATE_SUPABASE_S3_BUCKET, \
             FERROGATE_SUPABASE_S3_REGION, FERROGATE_SUPABASE_S3_ACCESS_KEY_ID and \
             FERROGATE_SUPABASE_S3_SECRET_ACCESS_KEY (plus an optional \
             FERROGATE_SUPABASE_S3_SESSION_TOKEN) to run the #368 live Supabase parity proof"
        );
        return;
    };

    let (scheme, host, prefix) = split_endpoint(&env.endpoint);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let key = format!(".ferrogate-368-gate-probe/{stamp}");
    let path = format!("{prefix}/{}/{key}", env.bucket);
    let body = format!("ferrogate 368 probe {stamp}\n").into_bytes();
    assert!(body.len() < 64, "the live probe must stay a tiny object");
    let sha = sha256_hex(&body);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let request = PresignRequest {
        method: "PUT",
        path: &path,
        host: &host,
        region: &env.region,
        service: "s3",
        expires_secs: 300,
        timestamp_unix: now,
    };
    // Same provider install the gateway binary does at startup (`main.rs`).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::new();

    // Control: the pre-#368 unbound presign. If THIS is refused the credentials
    // or endpoint are wrong and the bound result below would prove nothing.
    let control_url = format!(
        "{scheme}://{host}{path}?{}",
        presign_sigv4_query(&request, &env.credentials)
    );
    let control = http
        .put(&control_url)
        .body(body.clone())
        .send()
        .await
        .expect("control PUT must reach Supabase Storage");
    let control_status = control.status();
    let control_body = control.text().await.unwrap_or_default();
    let control_code = error_code(&control_body);
    assert_ne!(
        control_code, "SignatureDoesNotMatch",
        "the unbound control presign must verify against Supabase Storage \
         (HTTP {control_status}); the credentials/endpoint/region are wrong: {control_body}"
    );

    // The subject: the exact bound form the #368 upload-intent endpoint issues.
    let bound = presign_sigv4_query_bound(
        &request,
        &env.credentials,
        &PresignBoundPayload {
            content_length: body.len() as u64,
            content_sha256_hex: &sha,
        },
    );
    let mut bound_request = http
        .put(format!("{scheme}://{host}{path}?{}", bound.query))
        .body(body.clone());
    // A real uploader sends every required header verbatim; `content-length` is
    // emitted by the HTTP client from the body it is given.
    for (name, value) in bound
        .required_headers
        .iter()
        .filter(|(name, _)| *name != "content-length")
    {
        bound_request = bound_request.header(*name, value);
    }
    let bound_response = bound_request
        .send()
        .await
        .expect("bound PUT must reach Supabase Storage");
    let bound_status = bound_response.status();
    let bound_body = bound_response.text().await.unwrap_or_default();
    let bound_code = error_code(&bound_body);

    // Cleanup before asserting: delete anything the probe managed to create and
    // verify it is gone, so a failing assertion never leaves an object behind.
    let cleanup = PresignRequest {
        method: "DELETE",
        ..request
    };
    let _ = http
        .delete(format!(
            "{scheme}://{host}{path}?{}",
            presign_sigv4_query(&cleanup, &env.credentials)
        ))
        .send()
        .await;
    let head = PresignRequest {
        method: "GET",
        ..request
    };
    let after = http
        .get(format!(
            "{scheme}://{host}{path}?{}",
            presign_sigv4_query(&head, &env.credentials)
        ))
        .send()
        .await
        .expect("post-cleanup GET must reach Supabase Storage");
    assert!(
        !after.status().is_success(),
        "the probe object must be gone after cleanup (HTTP {})",
        after.status()
    );

    assert_ne!(
        bound_code, "SignatureDoesNotMatch",
        "#368 acceptance box 3: the size+checksum-bound presigned PUT this gateway hands to \
         clients must verify against Supabase Storage's S3 compatibility layer, but the honest, \
         contract-following upload was refused as a signature mismatch (HTTP {bound_status}) \
         while the unbound control was accepted ({control_code}). Supabase computes the \
         presigned canonical request with the payload-hash line pinned to UNSIGNED-PAYLOAD, so \
         a concrete SHA-256 on that line can never verify there: {bound_body}"
    );
}
