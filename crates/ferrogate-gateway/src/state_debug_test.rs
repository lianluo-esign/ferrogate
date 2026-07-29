// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Debug redaction guard for AppState provider secret cache (#492).

use super::AppState;
use ferrogate_config::{Config, Provider};

const PROVIDER_SECRET_ENV: &str = "FG_TEST_APP_STATE_DEBUG_PROVIDER_SECRET";
const PROVIDER_SECRET: &str = "sk-live-appstate-debug-canary-sensitive-tail";

fn provider_with_secret_ref() -> Provider {
    Provider {
        region: None,
        aws_access_key_id: None,
        aws_secret_access_key_env: None,
        aws_session_token_env: None,
        gcp_project_id: None,
        gcp_access_token_env: None,
        name: "openai".into(),
        kind: "openai".into(),
        base_url: "http://127.0.0.1:10001/v1".into(),
        api_key_env: None,
        secret_ref: Some(format!("env://{PROVIDER_SECRET_ENV}")),
        openrouter_http_referer: None,
        openrouter_x_title: None,
        cloudflare_ai_gateway: None,
        enabled: true,
    }
}

#[test]
fn app_state_debug_redacts_resolved_provider_secrets() {
    std::env::set_var(PROVIDER_SECRET_ENV, PROVIDER_SECRET);
    let state = AppState::new(Config {
        providers: vec![provider_with_secret_ref()],
        ..Config::default()
    });
    std::env::remove_var(PROVIDER_SECRET_ENV);

    let rendered = format!("{state:?}");
    assert!(
        !rendered.contains(PROVIDER_SECRET),
        "resolved provider secret leaked into AppState Debug: {rendered}"
    );
    for prefix_len in [4usize, 8, 16] {
        let prefix = &PROVIDER_SECRET[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "resolved provider secret prefix leaked into AppState Debug: {rendered}"
        );
    }
    assert!(rendered.contains("AppState"), "{rendered}");
    assert!(rendered.contains("providers: 1"), "{rendered}");
    assert!(
        rendered.contains("resolved_provider_secrets: \"<redacted>\""),
        "{rendered}"
    );
}
