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
    let mut first = RequestHeader::build("GET", b"/admin/v1/status", None).unwrap();
    first.insert_header(ACTION_ID_HEADER, ACTION_A).unwrap();
    module.inspect_request_at(&first.headers, ISSUED_AT);
    assert!(module.request_error().is_none());

    let mut response = ResponseHeader::build(StatusCode::OK, None).unwrap();
    module.issue_response_at(&mut response, ISSUED_AT).unwrap();
    let token = response
        .headers
        .get(TIME_TOKEN_HEADER)
        .unwrap()
        .to_str()
        .unwrap();
    signer
        .validate(token, ACTION_A, ISSUED_AT + 1)
        .expect("the response hook minted a valid token for this action");
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
