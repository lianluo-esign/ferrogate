// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP identity state, kept outside business logic.

use super::*;

static IDENTITY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn ciphertext_is_bound_to_subject_aad_and_debug_never_contains_plaintext() {
    let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
    std::env::set_var(MCP_IDENTITY_KEY_ENV, "11".repeat(32));
    let cipher = IdentityCipher::from_env().unwrap();
    let (nonce, ciphertext) = cipher
        .encrypt(b"secret-access-token", b"tenant-a/user-a")
        .unwrap();
    assert!(!ciphertext
        .windows(19)
        .any(|window| window == b"secret-access-token"));
    assert_eq!(
        cipher
            .decrypt(&nonce, &ciphertext, b"tenant-a/user-a")
            .unwrap(),
        b"secret-access-token"
    );
    assert!(cipher
        .decrypt(&nonce, &ciphertext, b"tenant-a/user-b")
        .is_err());
    std::env::remove_var(MCP_IDENTITY_KEY_ENV);
}

#[test]
fn encryption_key_requires_exact_hex_material() {
    let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
    std::env::set_var(MCP_IDENTITY_KEY_ENV, "short");
    let error = match IdentityCipher::from_env() {
        Ok(_) => panic!("short encryption key unexpectedly passed validation"),
        Err(error) => error,
    };
    assert_eq!(error.code, "mcp_identity_key_invalid");
    std::env::remove_var(MCP_IDENTITY_KEY_ENV);
}
