use super::*;

const ACTION_A: &str = "fgact_11111111111111111111111111111111";
const ACTION_B: &str = "fgact_22222222222222222222222222222222";
const ISSUED_AT: u64 = 1_800_000_000;

fn request(action_id: &str, token: &str) -> RequestHeader {
    let mut request = RequestHeader::build("POST", b"/admin/v1/config/reload", None).unwrap();
    request.insert_header(ACTION_ID_HEADER, action_id).unwrap();
    request.insert_header(TIME_TOKEN_HEADER, token).unwrap();
    request
}

fn refusal(action_id: &str, token: &str, received_at: u64) -> ClientActionTimeError {
    let signer = Arc::new(ServerTimeTokenSigner::fixture());
    let mut module = ClientActionTimeModule::new(signer);
    module.inspect_request_at(&request(action_id, token).headers, received_at);
    module.request_error().expect("request must be refused")
}

#[test]
fn response_hook_issues_an_action_bound_verifiable_token() {
    let signer = Arc::new(ServerTimeTokenSigner::fixture());
    let mut module = ClientActionTimeModule::new(Arc::clone(&signer));
    // An effect request (anything but the safe GET /healthz challenge) is
    // admitted only when it echoes a live token; that valid echo is what
    // authorises the response hook to mint the next one. Sending no token here
    // is the refusal case, not the happy path.
    let echoed = signer.issue(ACTION_A, ISSUED_AT);
    let mut first = RequestHeader::build("POST", b"/admin/v1/config/reload", None).unwrap();
    first.insert_header(ACTION_ID_HEADER, ACTION_A).unwrap();
    first.insert_header(TIME_TOKEN_HEADER, echoed).unwrap();
    module.inspect_request_at(&first.headers, ISSUED_AT + 1);
    assert!(module.request_error().is_none());

    let mut response = ResponseHeader::build(StatusCode::OK, None).unwrap();
    module
        .issue_response_at(&mut response, ISSUED_AT + 1)
        .unwrap();
    let token = response
        .headers
        .get(TIME_TOKEN_HEADER)
        .unwrap()
        .to_str()
        .unwrap();
    signer
        .validate(token, ACTION_A, ISSUED_AT + 2)
        .expect("the response hook minted a valid token for this action");
}

#[tokio::test]
async fn a_healthz_get_with_no_token_bootstraps_a_mintable_token() {
    // The only request the gateway admits WITHOUT a token: the safe GET
    // /healthz challenge that hands out the very first one. This drives the real
    // `request_header_filter`, so the `method == GET && path.ends_with(/healthz)`
    // allowance is what is under test rather than a hand-passed flag.
    let signer = Arc::new(ServerTimeTokenSigner::fixture());
    let mut module = ClientActionTimeModule::new(Arc::clone(&signer));
    let mut challenge = RequestHeader::build("GET", b"/healthz", None).unwrap();
    challenge.insert_header(ACTION_ID_HEADER, ACTION_A).unwrap();
    module.request_header_filter(&mut challenge).await.unwrap();
    assert!(
        module.request_error().is_none(),
        "a tokenless GET /healthz is the bootstrap the client cannot get a first token without: {:?}",
        module.request_error()
    );

    let mut response = ResponseHeader::build(StatusCode::OK, None).unwrap();
    module
        .response_header_filter(&mut response, true)
        .await
        .unwrap();
    // Captured AFTER the mint so it is at or after the token's server issue
    // instant; the 30s TTL swallows the sub-millisecond gap either way.
    let received_at = server_unix_seconds().unwrap();
    let token = response
        .headers
        .get(TIME_TOKEN_HEADER)
        .expect("the challenge response mints the first token")
        .to_str()
        .unwrap();
    signer
        .validate(token, ACTION_A, received_at)
        .expect("the bootstrap token validates for this action at the mint instant");
}

#[tokio::test]
async fn a_tokenless_effect_get_is_refused_despite_being_a_get() {
    // Same tokenless shape as the bootstrap, but on an effect path: the
    // missing-token allowance is health-ONLY, so dropping the path clause of the
    // `request_header_filter` guard would let this through and red this test.
    let signer = Arc::new(ServerTimeTokenSigner::fixture());
    let mut module = ClientActionTimeModule::new(signer);
    let mut request = RequestHeader::build("GET", b"/admin/v1/status", None).unwrap();
    request.insert_header(ACTION_ID_HEADER, ACTION_A).unwrap();
    module.request_header_filter(&mut request).await.unwrap();
    let error = module
        .request_error()
        .expect("a tokenless effect GET must be refused");
    assert!(error.to_string().contains("is required"));
}

#[tokio::test]
async fn a_tokenless_non_get_healthz_call_is_refused() {
    // Health PATH but not a GET: the allowance is GET-only, so dropping the
    // method clause of the `request_header_filter` guard would admit this
    // tokenless POST /healthz and red this test.
    let signer = Arc::new(ServerTimeTokenSigner::fixture());
    let mut module = ClientActionTimeModule::new(signer);
    let mut request = RequestHeader::build("POST", b"/healthz", None).unwrap();
    request.insert_header(ACTION_ID_HEADER, ACTION_A).unwrap();
    module.request_header_filter(&mut request).await.unwrap();
    let error = module
        .request_error()
        .expect("a tokenless non-GET health call must be refused");
    assert!(error.to_string().contains("is required"));
}

#[test]
fn request_hook_rejects_a_token_moved_to_another_action() {
    let signer = ServerTimeTokenSigner::fixture();
    let token = signer.issue(ACTION_A, ISSUED_AT);
    let error = refusal(ACTION_B, &token, ISSUED_AT + 1);
    assert!(error.to_string().contains("different action id"));
}

#[test]
fn request_hook_rejects_an_expired_token_using_server_receive_time() {
    let signer = ServerTimeTokenSigner::fixture();
    let token = signer.issue(ACTION_A, ISSUED_AT);
    let error = refusal(ACTION_A, &token, ISSUED_AT + TOKEN_TTL_SECONDS + 1);
    assert!(error.to_string().contains("server-authoritative TTL"));
}

#[test]
fn request_hook_rejects_a_token_with_a_bad_signature() {
    let signer = ServerTimeTokenSigner::fixture();
    let mut token = signer.issue(ACTION_A, ISSUED_AT);
    let signature_start = token.rfind(";sig=").unwrap() + ";sig=".len();
    let replacement = if token.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    token.replace_range(signature_start..signature_start + 1, replacement);
    let error = refusal(ACTION_A, &token, ISSUED_AT + 1);
    assert!(error.to_string().contains("signature is invalid"));
}
