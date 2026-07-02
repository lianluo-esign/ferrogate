// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for scoped HS256 function-token minting (#118).

use super::*;

fn minter() -> FunctionTokenMinter {
    FunctionTokenMinter::new("ferrogate", "super-secret-project-jwt-key").unwrap()
}

#[test]
fn mint_then_verify_roundtrips_with_scoped_claims() {
    let token = minter()
        .mint("org_a", "charge-credits", "rest", 1_000, 60)
        .unwrap();
    // Standard three-segment JWT.
    assert_eq!(token.split('.').count(), 3);

    let claims = minter().verify(&token, 1_030).unwrap();
    assert_eq!(claims.iss, "ferrogate");
    assert_eq!(claims.aud, "charge-credits");
    assert_eq!(claims.tenant, "org_a");
    assert_eq!(claims.capability, "rest");
    assert_eq!(claims.iat, 1_000);
    assert_eq!(claims.exp, 1_060);
}

#[test]
fn ttl_is_clamped_to_max() {
    let token = minter().mint("org_a", "fn", "rest", 1_000, 10_000).unwrap();
    let claims = minter().verify(&token, 1_001).unwrap();
    assert_eq!(claims.exp, 1_000 + MAX_FUNCTION_TOKEN_TTL_SECS);
}

#[test]
fn verify_rejects_expired_token() {
    let token = minter().mint("org_a", "fn", "rest", 1_000, 30).unwrap();
    // exp = 1_030; at exactly exp and beyond it must be expired.
    assert_eq!(
        minter().verify(&token, 1_030),
        Err(FunctionTokenError::Expired)
    );
    assert_eq!(
        minter().verify(&token, 5_000),
        Err(FunctionTokenError::Expired)
    );
    // Just before expiry it is still valid.
    assert!(minter().verify(&token, 1_029).is_ok());
}

#[test]
fn verify_rejects_wrong_secret_and_tampering() {
    let token = minter().mint("org_a", "fn", "rest", 1_000, 60).unwrap();

    let other = FunctionTokenMinter::new("ferrogate", "different-secret").unwrap();
    assert_eq!(
        other.verify(&token, 1_001),
        Err(FunctionTokenError::BadSignature)
    );

    // Tamper with the claims segment: signature must no longer match.
    let mut segments: Vec<&str> = token.split('.').collect();
    let forged_claims = B64URL.encode(
        r#"{"iss":"ferrogate","aud":"fn","tenant":"org_evil","capability":"rest","iat":1000,"exp":9999999999}"#,
    );
    segments[1] = &forged_claims;
    let forged = segments.join(".");
    assert_eq!(
        minter().verify(&forged, 1_001),
        Err(FunctionTokenError::BadSignature)
    );
}

#[test]
fn verify_rejects_malformed_tokens() {
    let m = minter();
    assert_eq!(
        m.verify("only-one-part", 1),
        Err(FunctionTokenError::MalformedToken)
    );
    assert_eq!(m.verify("a.b", 1), Err(FunctionTokenError::MalformedToken));
    assert_eq!(
        m.verify("a.b.c.d", 1),
        Err(FunctionTokenError::MalformedToken)
    );
    assert_eq!(
        m.verify("!!.??.$$", 1),
        Err(FunctionTokenError::MalformedToken)
    );
}

#[test]
fn construction_and_mint_fail_closed_on_empty_fields() {
    assert_eq!(
        FunctionTokenMinter::new("ferrogate", "  ").err(),
        Some(FunctionTokenError::EmptySigningSecret)
    );
    assert_eq!(
        FunctionTokenMinter::new("  ", "secret").err(),
        Some(FunctionTokenError::EmptyField("iss"))
    );

    let m = minter();
    assert_eq!(
        m.mint("", "fn", "rest", 1, 60),
        Err(FunctionTokenError::EmptyField("tenant"))
    );
    assert_eq!(
        m.mint("org_a", "  ", "rest", 1, 60),
        Err(FunctionTokenError::EmptyField("aud"))
    );
    assert_eq!(
        m.mint("org_a", "fn", "", 1, 60),
        Err(FunctionTokenError::EmptyField("capability"))
    );
    assert_eq!(
        m.mint("org_a", "fn", "rest", 1, 0),
        Err(FunctionTokenError::ZeroTtl)
    );
}

#[test]
fn minter_debug_redacts_secret() {
    let rendered = format!("{:?}", minter());
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-project-jwt-key"));
}
