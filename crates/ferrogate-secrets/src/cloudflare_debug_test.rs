// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Token4AI Cloud, FerroGate AI Gateway, private Cloudflare secret request Debug tests.

use super::CfSecretCreate;

#[test]
fn cf_secret_create_debug_redacts_plaintext_and_keeps_diagnostics() {
    const SECRET_PREFIX: &str = "cf-secret-create-debug-leak-canary";
    const SECRET: &str = "cf-secret-create-debug-leak-canary-sensitive-tail";

    let request = CfSecretCreate {
        name: "openai-api-key",
        value: SECRET,
        scopes: ["workers"],
        comment: Some("rotation canary"),
    };
    let rendered = format!("{request:?}");
    let value_len = format!("value_len: {}", SECRET.len());

    assert!(
        !rendered.contains(SECRET),
        "CfSecretCreate Debug leaked the complete plaintext: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET_PREFIX),
        "CfSecretCreate Debug leaked the plaintext prefix: {rendered}"
    );
    assert!(
        rendered.contains(r#"value: "<redacted>""#),
        "CfSecretCreate Debug must identify the redacted field: {rendered}"
    );
    assert!(
        rendered.contains("CfSecretCreate")
            && rendered.contains(r#"name: "openai-api-key""#)
            && rendered.contains(value_len.as_str())
            && rendered.contains(r#"scopes: ["workers"]"#)
            && rendered.contains(r#"comment: Some("rotation canary")"#),
        "CfSecretCreate Debug must retain its non-secret diagnostics: {rendered}"
    );
}
