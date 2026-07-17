// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for quota and policy state, kept outside business logic.

use super::*;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn match_guardrail_for_test<'a>(
    state: &AppState,
    stage: crate::config::GuardrailStage,
    tenant: &'a ferrogate_core::TenantContext,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    body: &'a str,
) -> Option<GuardrailMatch> {
    match_guardrail_for_test_with_streaming(state, stage, tenant, model, provider, body, false)
}

fn match_guardrail_for_test_with_streaming<'a>(
    state: &AppState,
    stage: crate::config::GuardrailStage,
    tenant: &'a ferrogate_core::TenantContext,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    body: &'a str,
    streaming: bool,
) -> Option<GuardrailMatch> {
    let detector_stage = match stage {
        crate::config::GuardrailStage::Request => DetectorStage::Request,
        crate::config::GuardrailStage::Response => DetectorStage::Response,
    };
    let envelope = match stage {
        crate::config::GuardrailStage::Request => {
            ferrogate_guardrails::GuardrailEnvelope::from_text(
                ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
                detector_stage,
                ferrogate_guardrails::ContentSource::User,
                "messages[0].content",
                body,
            )
        }
        crate::config::GuardrailStage::Response => {
            let response = serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": body}}]
            });
            ferrogate_guardrails::normalize_response(
                ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
                &serde_json::to_vec(&response).expect("response fixture"),
                false,
            )
        }
    };
    tokio::runtime::Runtime::new()
        .expect("test runtime")
        .block_on(state.match_guardrail(
            stage,
            GuardrailEvaluationContext {
                request_id: "test-request",
                trace_id: Some("test-trace"),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                actor_api_key_id: None,
                tenant,
                service_account_id: None,
                gateway_config_id: None,
                model,
                provider,
                streaming,
                envelope: &envelope,
                managed_action: None,
            },
        ))
}

fn test_provider() -> Provider {
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
        secret_ref: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        enabled: true,
    }
}

fn test_model() -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-test".into(),
        routing_strategy: RoutingStrategy::default(),
        fallbacks: Vec::new(),
        visible_organization_ids: Vec::new(),
        visible_project_ids: Vec::new(),
        capabilities: Vec::new(),
        context_window: None,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
        cache_enabled: None,
    }
}

fn durable_guardrail_revision(
    policy_id: &str,
    revision: u32,
    keyword: &str,
    scope: PolicyScopeSelector,
) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision,
        name: format!("{policy_id} revision {revision}"),
        description: None,
        enforced: true,
        scope,
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "durable_guardrail_blocked",
            "blocked by durable guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "durable_guardrail_unavailable",
            "durable guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: u64::from(revision),
        created_by: "test-admin".to_string(),
    }
}

#[test]
fn guardrail_evidence_records_sanitized_overall_and_per_check_decisions() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    shared
        .create_guardrail_policy_revision(durable_guardrail_revision(
            "evidence-policy",
            1,
            "raw-secret-must-not-persist",
            PolicyScopeSelector::default(),
        ))
        .unwrap();
    shared
        .activate_guardrail_policy_revision("evidence-policy", 1, "test-admin", 10, false)
        .unwrap();
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("tenant-evidence".to_string()),
        api_key_id: Some("key-evidence".to_string()),
        ..ferrogate_core::TenantContext::default()
    };
    let state = shared.current();
    assert!(match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &tenant,
        Some("fast-chat"),
        Some("openai"),
        "raw-secret-must-not-persist",
    )
    .is_some());

    let evaluations = state.repositories.list_guardrail_evaluations(None).unwrap();
    let checks = state
        .repositories
        .list_guardrail_check_evaluations(None)
        .unwrap();
    assert_eq!(evaluations.len(), 1);
    assert_eq!(evaluations[0].verdict, "fail");
    assert_eq!(evaluations[0].action, "block");
    assert_eq!(evaluations[0].enforcement_status, "enforced");
    assert_eq!(evaluations[0].finding_category_counts["contains"], 1);
    assert!(evaluations[0].input_fingerprint.starts_with("hmac-sha256:"));
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].verdict, "fail");
    assert_eq!(checks[0].detector_id, "ferrogate.local");
    assert_eq!(checks[0].detector_version, "deterministic/1");
    let encoded = serde_json::to_string(&(evaluations, checks)).unwrap();
    assert!(!encoded.contains("raw-secret-must-not-persist"));
    assert!(!encoded.contains("matched_text"));
}

#[test]
fn immutable_policy_activation_and_rollback_change_the_live_evaluator() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let first = durable_guardrail_revision(
        "durable-policy",
        1,
        "secret-v1",
        PolicyScopeSelector::default(),
    );
    shared
        .create_guardrail_policy_revision(first.clone())
        .expect("create first revision");
    assert!(shared
        .create_guardrail_policy_revision(first)
        .unwrap_err()
        .to_string()
        .contains("already exists"));
    shared
        .activate_guardrail_policy_revision("durable-policy", 1, "test-admin", 10, false)
        .expect("activate first revision");
    assert!(match_guardrail_for_test(
        &shared.current(),
        GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret-v1"
    )
    .is_some());

    let second = durable_guardrail_revision(
        "durable-policy",
        2,
        "secret-v2",
        PolicyScopeSelector::default(),
    );
    shared
        .create_guardrail_policy_revision(second)
        .expect("create second revision");
    shared
        .activate_guardrail_policy_revision("durable-policy", 2, "test-admin", 20, false)
        .expect("activate second revision");
    assert!(match_guardrail_for_test(
        &shared.current(),
        GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret-v1"
    )
    .is_none());
    assert!(match_guardrail_for_test(
        &shared.current(),
        GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret-v2"
    )
    .is_some());

    shared
        .activate_guardrail_policy_revision("durable-policy", 1, "test-admin", 30, true)
        .expect("roll back first revision");
    assert!(match_guardrail_for_test(
        &shared.current(),
        GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret-v1"
    )
    .is_some());
    let views = shared
        .current()
        .guardrail_policy_revision_views(Some("durable-policy"))
        .unwrap();
    assert_eq!(views[0].status, PolicyRevisionStatus::Active);
    assert_eq!(views[1].status, PolicyRevisionStatus::Archived);
}

#[test]
fn structured_policy_activation_compiles_json_schema_into_live_runtime() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let mut revision = durable_guardrail_revision(
        "structured-policy",
        1,
        "unused-legacy-keyword",
        PolicyScopeSelector::default(),
    );
    revision.checks[0].sources = vec![ferrogate_guardrails::ContentSource::Metadata];
    revision.checks[0].detector = serde_json::from_value(serde_json::json!({
        "kind": "local",
        "json": {
            "schema": {
                "type": "object",
                "required": ["safe"],
                "properties": {"safe": {"type": "boolean"}}
            },
            "required_keys": ["/safe"],
            "forbidden_keys": ["/credential"]
        }
    }))
    .unwrap();
    shared
        .create_guardrail_policy_revision(revision)
        .expect("create structured revision");
    shared
        .activate_guardrail_policy_revision("structured-policy", 1, "test-admin", 10, false)
        .expect("compile and activate structured revision");
    assert_eq!(
        shared
            .current()
            .guardrail_policy_binding("structured-policy")
            .unwrap()
            .unwrap()
            .active_revision,
        Some(1)
    );
}

#[test]
fn lower_scope_allow_action_cannot_remove_organization_enforcement() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let organization = durable_guardrail_revision(
        "organization-policy",
        1,
        "secret",
        PolicyScopeSelector {
            organization_ids: vec!["org-a".to_string()],
            ..PolicyScopeSelector::default()
        },
    );
    let mut key = durable_guardrail_revision(
        "key-policy",
        1,
        "secret",
        PolicyScopeSelector {
            api_key_ids: vec!["key-a".to_string()],
            ..PolicyScopeSelector::default()
        },
    );
    key.on_fail = vec![PolicyAction::allow()];
    for policy in [organization, key] {
        let policy_id = policy.policy_id.clone();
        shared.create_guardrail_policy_revision(policy).unwrap();
        shared
            .activate_guardrail_policy_revision(&policy_id, 1, "test-admin", 1, false)
            .unwrap();
    }
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("org-a".to_string()),
        api_key_id: Some("key-a".to_string()),
        ..Default::default()
    };
    let matched = match_guardrail_for_test(
        &shared.current(),
        GuardrailStage::Request,
        &tenant,
        None,
        None,
        "contains secret",
    )
    .expect("organization policy must still block");
    assert_eq!(matched.rule_id, "organization-policy");
    assert_eq!(matched.policy_revision, 1);
}

#[test]
fn sequential_and_parallel_execution_use_the_same_aggregation_semantics() {
    for execution in [PolicyExecution::Sequential, PolicyExecution::Parallel] {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        let mut policy = durable_guardrail_revision(
            "execution-policy",
            1,
            "secret",
            PolicyScopeSelector::default(),
        );
        policy.execution = execution;
        policy.checks.push(CheckBinding {
            id: "non-match".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            detector: DetectorDefinition::local(vec!["not-present".to_string()], Vec::new(), None),
            fallback_detector: None,
        });
        shared.create_guardrail_policy_revision(policy).unwrap();
        shared
            .activate_guardrail_policy_revision("execution-policy", 1, "test-admin", 1, false)
            .unwrap();
        assert!(match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret"
        )
        .is_some());
    }
}

#[test]
fn streaming_modes_reject_before_dispatch_or_force_shadow_evaluation() {
    let reject_state = SharedAppState::with_source_path(Config::default(), None);
    let mut reject = durable_guardrail_revision(
        "reject-streaming",
        1,
        "secret",
        PolicyScopeSelector::default(),
    );
    reject.streaming = PolicyStreamingMode::RejectStreaming;
    reject.checks[0].stage = DetectorStage::Response;
    reject_state
        .create_guardrail_policy_revision(reject)
        .unwrap();
    reject_state
        .activate_guardrail_policy_revision("reject-streaming", 1, "test-admin", 1, false)
        .unwrap();
    let rejected = match_guardrail_for_test_with_streaming(
        &reject_state.current(),
        GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "safe",
        true,
    )
    .expect("reject_streaming must block before provider dispatch");
    assert_eq!(rejected.code, "guardrail_streaming_unsupported");
    let rejected_checks = reject_state
        .current()
        .repositories
        .list_guardrail_check_evaluations(None)
        .unwrap();
    assert_eq!(rejected_checks.len(), 1);
    assert_eq!(rejected_checks[0].verdict, "skipped");
    assert_eq!(
        rejected_checks[0].error_kind.as_deref(),
        Some("streaming_unsupported")
    );

    let shadow_state = SharedAppState::with_source_path(Config::default(), None);
    let mut shadow = durable_guardrail_revision(
        "streaming-shadow",
        1,
        "secret",
        PolicyScopeSelector::default(),
    );
    shadow.streaming = PolicyStreamingMode::ShadowAfterComplete;
    shadow.checks[0].stage = DetectorStage::Response;
    shadow_state
        .create_guardrail_policy_revision(shadow)
        .unwrap();
    shadow_state
        .activate_guardrail_policy_revision("streaming-shadow", 1, "test-admin", 1, false)
        .unwrap();
    assert!(match_guardrail_for_test_with_streaming(
        &shadow_state.current(),
        GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret",
        true,
    )
    .is_none());
    assert!(shadow_state.current().audit_events().iter().any(|event| {
        event.action == "guardrail.policy_evaluate"
            && event.target == "streaming-shadow@1"
            && event.outcome == "not_enforced"
    }));
    assert_eq!(
        shadow_state
            .current()
            .streaming_guardrail_plan(PolicySelectionContext {
                organization_id: None,
                project_id: None,
                workspace_id: None,
                api_key_id: None,
                service_account_id: None,
                gateway_config_id: None,
                model: None,
                provider: None,
                managed_action: None,
            }),
        StreamingGuardrailPlan::ShadowAfterComplete
    );
    assert!(match_guardrail_for_test(
        &shadow_state.current(),
        GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "contains secret",
    )
    .is_some());
}

#[test]
fn streaming_buffer_limits_use_configured_error_action_and_sanitized_evidence() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let mut policy =
        durable_guardrail_revision("buffer-errors", 1, "secret", PolicyScopeSelector::default());
    policy.checks[0].stage = DetectorStage::Response;
    shared.create_guardrail_policy_revision(policy).unwrap();
    shared
        .activate_guardrail_policy_revision("buffer-errors", 1, "test-admin", 1, false)
        .unwrap();

    let state = shared.current();
    let tenant = ferrogate_core::TenantContext::default();
    let envelope = ferrogate_guardrails::GuardrailEnvelope::from_text(
        ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
        DetectorStage::Response,
        ferrogate_guardrails::ContentSource::Assistant,
        "test.response",
        "sensitive-stream-body",
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for error_code in [
        "guardrail_stream_buffer_limit_exceeded",
        "guardrail_stream_buffer_timeout",
    ] {
        let matched = runtime
            .block_on(state.guardrail_streaming_buffer_failure(
                GuardrailEvaluationContext {
                    request_id: error_code,
                    trace_id: None,
                    agent_run_id: None,
                    workflow_id: None,
                    workflow_version: None,
                    workflow_node_id: None,
                    actor_api_key_id: None,
                    tenant: &tenant,
                    service_account_id: None,
                    gateway_config_id: None,
                    model: Some("fast-chat"),
                    provider: Some("openai"),
                    streaming: true,
                    envelope: &envelope,
                    managed_action: None,
                },
                error_code,
            ))
            .expect("buffer failure must follow the configured block action");
        assert_eq!(matched.code, "durable_guardrail_unavailable");
    }

    let events = state
        .audit_events()
        .into_iter()
        .filter(|event| event.target == "buffer-errors@1")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| {
        event.action == "guardrail.policy_evaluate"
            && event.outcome == "error"
            && !event.message.contains("sensitive-stream-body")
    }));
    assert!(events.iter().any(|event| {
        event
            .message
            .contains("guardrail_stream_buffer_limit_exceeded")
    }));
    assert!(events
        .iter()
        .any(|event| { event.message.contains("guardrail_stream_buffer_timeout") }));
}

#[test]
fn normalized_segments_inspect_every_chat_role_and_report_utf8_byte_ranges() {
    let envelope = ferrogate_guardrails::normalize_request(
        ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
        &serde_json::json!({
            "messages": [
                {"role": "system", "content": "前缀秘密"},
                {"role": "developer", "content": "developer-secret"},
                {"role": "user", "content": "user-secret"},
                {"role": "assistant", "tool_calls": [{"function": {"arguments": "{\"token\":\"argument-secret\"}"}}]},
                {"role": "tool", "content": "result-secret"}
            ],
            "tools": [{"type": "function", "function": {"name": "schema-secret"}}],
            "metadata": {"case": "metadata-secret"}
        }),
    );
    for (keyword, expected_source) in [
        ("秘密", ferrogate_guardrails::ContentSource::System),
        (
            "developer-secret",
            ferrogate_guardrails::ContentSource::Developer,
        ),
        ("user-secret", ferrogate_guardrails::ContentSource::User),
        (
            "argument-secret",
            ferrogate_guardrails::ContentSource::ToolArguments,
        ),
        (
            "result-secret",
            ferrogate_guardrails::ContentSource::ToolResult,
        ),
        (
            "schema-secret",
            ferrogate_guardrails::ContentSource::ToolSchema,
        ),
        (
            "metadata-secret",
            ferrogate_guardrails::ContentSource::Metadata,
        ),
    ] {
        let detector = DeterministicDetector::new(DeterministicDetectorConfig {
            id: "normalized".to_string(),
            supported_sources: vec![expected_source],
            keywords: vec![keyword.to_string()],
            regex: Vec::new(),
            max_input_bytes: None,
            json: None,
            request: None,
            secret_patterns: Vec::new(),
            fingerprint_key: None,
        })
        .unwrap();
        let text = envelope.flattened_text();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(detector.evaluate(
                &DetectorInput {
                    protocol: envelope.protocol,
                    stage: envelope.stage,
                    tenant: DetectorTenant {
                        organization_id: None,
                        team_id: None,
                        project_id: None,
                        user_id: None,
                        api_key_id: None,
                    },
                    model: None,
                    provider: None,
                    text: &text,
                    segments: &envelope.segments,
                },
                Instant::now() + Duration::from_secs(1),
            ))
            .unwrap();
        let evaluation = external_guardrail_evaluation("normalized", result, &envelope);
        assert_eq!(evaluation.outcome, CheckOutcome::Fail, "{keyword}");
        let segment = envelope
            .segments
            .iter()
            .find(|segment| Some(&segment.segment_id) == evaluation.segment_id.as_ref())
            .expect("matched segment must exist");
        assert_eq!(segment.source, expected_source, "{keyword}");
        let start = segment.text.find(keyword).unwrap();
        assert_eq!(evaluation.byte_start, Some(start), "{keyword}");
        assert_eq!(
            evaluation.byte_end,
            Some(start + keyword.len()),
            "{keyword}"
        );
    }

    let excluded_detector = DeterministicDetector::new(DeterministicDetectorConfig {
        id: "normalized".to_string(),
        supported_sources: vec![ferrogate_guardrails::ContentSource::User],
        keywords: vec!["developer-secret".to_string()],
        regex: Vec::new(),
        max_input_bytes: None,
        json: None,
        request: None,
        secret_patterns: Vec::new(),
        fingerprint_key: None,
    })
    .unwrap();
    let text = envelope.flattened_text();
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(excluded_detector.evaluate(
            &DetectorInput {
                protocol: envelope.protocol,
                stage: envelope.stage,
                tenant: DetectorTenant {
                    organization_id: None,
                    team_id: None,
                    project_id: None,
                    user_id: None,
                    api_key_id: None,
                },
                model: None,
                provider: None,
                text: &text,
                segments: &envelope.segments,
            },
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
    let excluded = external_guardrail_evaluation("normalized", result, &envelope);
    assert_eq!(excluded.outcome, CheckOutcome::Pass);
}

#[test]
fn matches_request_guardrail_by_tenant_model_provider_and_keyword() {
    let config = Config {
        providers: vec![Provider {
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
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        guardrails: vec![crate::config::GuardrailRule {
            id: "block-secret".into(),
            name: "Block secret".into(),
            enabled: true,
            stage: crate::config::GuardrailStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec!["org_demo".into()],
            project_ids: vec!["project_demo".into()],
            api_key_ids: vec!["key_demo".into()],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: crate::config::GuardrailEffect::Deny,
            code: "guardrail_blocked".into(),
            message: "blocked by guardrail".into(),
        }],
        ..Config::default()
    };
    let state = AppState::new(config);
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("org_demo".into()),
        project_id: Some("project_demo".into()),
        api_key_id: Some("key_demo".into()),
        ..Default::default()
    };

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &tenant,
        Some("fast-chat"),
        Some("openai"),
        "contains secret",
    )
    .expect("guardrail should match");

    assert_eq!(matched.rule_id, "block-secret");
    assert_eq!(matched.rule_name, "Block secret");
    assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
    assert_eq!(matched.code, "guardrail_blocked");
    assert_eq!(matched.message, "blocked by guardrail");
}

#[test]
fn ignores_disabled_guardrails() {
    let config = Config {
        providers: vec![Provider {
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
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        guardrails: vec![crate::config::GuardrailRule {
            id: "block-secret".into(),
            name: "Block secret".into(),
            enabled: false,
            stage: crate::config::GuardrailStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            models: vec![],
            providers: vec![],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: crate::config::GuardrailEffect::Deny,
            code: "guardrail_blocked".into(),
            message: "blocked by guardrail".into(),
        }],
        ..Config::default()
    };
    let state = AppState::new(config);

    assert!(match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "contains secret"
    )
    .is_none());
}

#[test]
fn matches_response_guardrail_with_redact_effect() {
    let config = Config {
        providers: vec![Provider {
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
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        guardrails: vec![crate::config::GuardrailRule {
            id: "redact-secret".into(),
            name: "Redact secret".into(),
            enabled: true,
            stage: crate::config::GuardrailStage::Response,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec!["secret".into()],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: crate::config::GuardrailEffect::Redact,
            code: "guardrail_redacted".into(),
            message: "redacted by guardrail".into(),
        }],
        ..Config::default()
    };
    let state = AppState::new(config);

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "provider returned secret",
    )
    .expect("response guardrail should match");

    assert_eq!(matched.rule_id, "redact-secret");
    assert_eq!(matched.effect, crate::config::GuardrailEffect::Redact);
    state.record_guardrail_match(&matched);
    let snapshot = state.prometheus_metrics_snapshot();
    assert_eq!(snapshot.guardrail_match_total, 1);
    assert_eq!(snapshot.guardrail_denial_total, 0);
    assert_eq!(snapshot.guardrail_redaction_total, 1);
}

#[test]
fn later_block_marks_an_earlier_redaction_as_not_enforced() {
    let base = crate::config::GuardrailRule {
        id: "redact-secret".into(),
        name: "Redact secret".into(),
        enabled: true,
        stage: crate::config::GuardrailStage::Response,
        sources: ferrogate_guardrails::all_content_sources(),
        organization_ids: vec![],
        project_ids: vec![],
        api_key_ids: vec![],
        models: vec!["fast-chat".into()],
        providers: vec!["openai".into()],
        keywords: vec!["secret".into()],
        regex: vec![],
        max_input_bytes: None,
        provider: GuardrailProviderKind::None,
        provider_endpoint: None,
        provider_timeout_ms: 2_000,
        provider_runtime: Default::default(),
        effect: crate::config::GuardrailEffect::Redact,
        code: "guardrail_redacted".into(),
        message: "redacted by guardrail".into(),
    };
    let mut block = base.clone();
    block.id = "block-secret".into();
    block.name = "Block secret".into();
    block.effect = crate::config::GuardrailEffect::Deny;
    block.code = "guardrail_blocked".into();
    let state = AppState::new(Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![base, block],
        ..Config::default()
    });

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "provider returned secret",
    )
    .expect("the blocking policy must win");
    assert_eq!(matched.rule_id, "block-secret");

    let evaluations = state.repositories.list_guardrail_evaluations(None).unwrap();
    let redaction = evaluations
        .iter()
        .find(|evaluation| evaluation.policy_id == "redact-secret")
        .unwrap();
    let block = evaluations
        .iter()
        .find(|evaluation| evaluation.policy_id == "block-secret")
        .unwrap();
    assert_eq!(redaction.action, "redact");
    assert_eq!(redaction.enforcement_status, "not_enforced");
    assert!(!redaction.transformed);
    assert_eq!(block.action, "block");
    assert_eq!(block.enforcement_status, "enforced");
    assert!(!block.transformed);
}

/// Spawns a one-shot plain-HTTP mock guardrail provider on `127.0.0.1`
/// that reads a single `Content-Length`-bounded request, records its
/// JSON body, and replies with `response_body`.
fn spawn_guardrail_provider_mock(
    response_body: impl Into<String>,
) -> (String, Arc<Mutex<Option<serde_json::Value>>>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(None));
    let server_captured = Arc::clone(&captured);
    let response_body = response_body.into();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "connection closed before request was complete");
            raw.extend_from_slice(&buffer[..read]);
            if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let content_length: usize = String::from_utf8_lossy(&raw[..header_end])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while raw.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "connection closed before body was complete");
            raw.extend_from_slice(&buffer[..read]);
        }
        let body = &raw[header_end..header_end + content_length];
        *server_captured.lock().unwrap() = Some(serde_json::from_slice(body).unwrap());

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    (endpoint, captured)
}

fn custom_http_guardrail_rule(provider_endpoint: String) -> crate::config::GuardrailRule {
    crate::config::GuardrailRule {
        id: "pii-detector".into(),
        name: "External PII detector".into(),
        enabled: true,
        stage: crate::config::GuardrailStage::Request,
        sources: ferrogate_guardrails::all_content_sources(),
        organization_ids: vec![],
        project_ids: vec![],
        api_key_ids: vec![],
        models: vec![],
        providers: vec![],
        keywords: vec![],
        regex: vec![],
        max_input_bytes: None,
        provider: GuardrailProviderKind::CustomHttp,
        provider_endpoint: Some(provider_endpoint),
        provider_timeout_ms: 2_000,
        provider_runtime: crate::config::GuardrailProviderRuntimeConfig {
            provider_allow_private_network: true,
            ..Default::default()
        },
        effect: crate::config::GuardrailEffect::Deny,
        code: "guardrail_pii_detected".into(),
        message: "blocked by external PII detector".into(),
    }
}

#[test]
fn matches_guardrail_via_custom_http_provider_and_sends_request_context() {
    let (endpoint, captured) = spawn_guardrail_provider_mock(
        r#"{"match":true,"matched_text":"john@example.com","category":"pii"}"#,
    );
    let config = Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![custom_http_guardrail_rule(endpoint)],
        ..Config::default()
    };
    let state = AppState::new(config);
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("org_demo".into()),
        project_id: Some("project_demo".into()),
        ..Default::default()
    };

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &tenant,
        Some("fast-chat"),
        Some("openai"),
        "my email is john@example.com",
    )
    .expect("custom_http provider should report a match");

    assert_eq!(matched.rule_id, "pii-detector");
    assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
    assert_eq!(
        matched.redact_text("my email is john@example.com"),
        "[REDACTED]"
    );

    let request = captured.lock().unwrap().take().expect("request captured");
    assert_eq!(request["stage"], "request");
    assert_eq!(request["model"], "fast-chat");
    assert_eq!(request["provider"], "openai");
    assert_eq!(request["text"], "my email is john@example.com");
    assert_eq!(request["tenant"]["organization_id"], "org_demo");
    assert_eq!(request["tenant"]["project_id"], "project_demo");
}

#[test]
fn custom_http_provider_no_match_returns_none() {
    let (endpoint, _captured) = spawn_guardrail_provider_mock(r#"{"match":false}"#);
    let config = Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![custom_http_guardrail_rule(endpoint)],
        ..Config::default()
    };
    let state = AppState::new(config);

    assert!(match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "nothing suspicious here",
    )
    .is_none());
}

#[test]
fn custom_http_provider_failure_fails_closed_regardless_of_configured_effect() {
    // Bind then immediately drop the listener: the port is valid but
    // nothing is listening, so the connection is refused.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
    drop(listener);

    let mut rule = custom_http_guardrail_rule(endpoint);
    rule.effect = crate::config::GuardrailEffect::Redact;
    let config = Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![rule],
        ..Config::default()
    };
    let state = AppState::new(config);

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "hello",
    )
    .expect("unreachable provider must fail closed with a match");

    assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
    assert_eq!(matched.code, "guardrail_provider_unavailable");
    assert!(matched.message.contains("External PII detector"));
    assert_eq!(
        state
            .prometheus_metrics_snapshot()
            .guardrail_detector_error_total,
        1
    );
    let audit = state.audit_events();
    let detector_error = audit
        .iter()
        .find(|event| event.action == "guardrail.detector_error")
        .expect("detector error audit");
    assert_eq!(detector_error.request_id, "test-request");
    assert_eq!(detector_error.target, "pii-detector@1/static-check");
    assert_eq!(detector_error.outcome, "blocked");
    assert!(audit.iter().any(|event| {
        event.action == "guardrail.policy_evaluate"
            && event.target == "pii-detector@1"
            && event.outcome == "error"
    }));
    let evidence = state
        .repositories
        .list_guardrail_check_evaluations(None)
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].verdict, "error");
    assert_eq!(evidence[0].action, "block");
    assert_eq!(evidence[0].enforcement_status, "enforced");
    assert_eq!(evidence[0].error_kind.as_deref(), Some("unavailable"));
}

#[test]
fn custom_http_provider_record_mode_audits_and_allows_on_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
    drop(listener);

    let mut rule = custom_http_guardrail_rule(endpoint);
    rule.provider_runtime.provider_on_error = GuardrailProviderErrorMode::Record;
    let state = AppState::new(Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![rule],
        ..Config::default()
    });

    assert!(match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "hello",
    )
    .is_none());
    assert_eq!(
        state
            .prometheus_metrics_snapshot()
            .guardrail_detector_error_total,
        1
    );
    let audit = state.audit_events();
    let detector_error = audit
        .iter()
        .find(|event| event.action == "guardrail.detector_error")
        .expect("detector error audit");
    assert_eq!(detector_error.outcome, "recorded");
    assert!(audit.iter().any(|event| {
        event.action == "guardrail.policy_evaluate"
            && event.target == "pii-detector@1"
            && event.outcome == "error"
    }));
    let evaluation = state.repositories.list_guardrail_evaluations(None).unwrap();
    assert_eq!(evaluation[0].verdict, "error");
    assert_eq!(evaluation[0].action, "record");
    assert_eq!(evaluation[0].enforcement_status, "enforced");
}

#[test]
fn custom_http_provider_fallback_mode_runs_local_detector_on_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
    drop(listener);

    let mut rule = custom_http_guardrail_rule(endpoint);
    rule.keywords = vec!["secret".into()];
    rule.provider_runtime.provider_on_error = GuardrailProviderErrorMode::FallbackDetector;
    let state = AppState::new(Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![rule],
        ..Config::default()
    });

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "contains secret",
    )
    .expect("local fallback detector should match");
    assert_eq!(matched.code, "guardrail_pii_detected");
    assert_eq!(state.audit_events()[0].outcome, "fallback");
}

#[test]
fn custom_http_provider_applies_typed_redaction_patches() {
    let content = "email john@example.com";
    let fingerprint = ferrogate_guardrails::content_fingerprint(content);
    let (endpoint, _) = spawn_guardrail_provider_mock(
        serde_json::json!({
            "verdict": "fail",
            "findings": [{
                "category": "pii",
                "severity": "high",
                "segment_id": "chat:0",
                "byte_start": 6,
                "byte_end": 22
            }],
            "patches": [{
                "segment_id": "chat:0",
                "expected_fingerprint": fingerprint,
                "protocol_location": "choices[0].message.content",
                "byte_start": 6,
                "byte_end": 22,
                "replacement": "[EMAIL]"
            }],
            "detector_version": "test-1"
        })
        .to_string(),
    );
    let mut rule = custom_http_guardrail_rule(endpoint);
    rule.stage = crate::config::GuardrailStage::Response;
    rule.effect = crate::config::GuardrailEffect::Redact;
    let state = AppState::new(Config {
        providers: vec![test_provider()],
        models: vec![test_model()],
        guardrails: vec![rule],
        ..Config::default()
    });

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        content,
    )
    .expect("typed patch detector should match");
    let response = serde_json::json!({
        "model": "must-not-change",
        "choices": [{"message": {"role": "assistant", "content": content}}]
    })
    .to_string();
    let redacted: serde_json::Value =
        serde_json::from_str(&matched.redact_text(&response)).unwrap();
    assert_eq!(
        redacted["choices"][0]["message"]["content"],
        "email [EMAIL]"
    );
    assert_eq!(redacted["model"], "must-not-change");
}

#[test]
fn matches_regex_and_redacts_with_compiled_pattern() {
    let config = Config {
        providers: vec![Provider {
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
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        guardrails: vec![crate::config::GuardrailRule {
            id: "redact-token".into(),
            name: "Redact token".into(),
            enabled: true,
            stage: crate::config::GuardrailStage::Response,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            models: vec!["fast-chat".into()],
            providers: vec!["openai".into()],
            keywords: vec![],
            regex: vec![r"token-[0-9]+".into()],
            max_input_bytes: None,
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: crate::config::GuardrailEffect::Redact,
            code: "guardrail_redacted".into(),
            message: "redacted by guardrail".into(),
        }],
        ..Config::default()
    };
    let state = AppState::new(config);

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Response,
        &ferrogate_core::TenantContext::default(),
        Some("fast-chat"),
        Some("openai"),
        "provider returned token-123 and token-456",
    )
    .expect("regex guardrail should match");

    assert_eq!(matched.rule_id, "redact-token");
    let response = serde_json::json!({
        "model": "must-not-change",
        "choices": [{"message": {
            "role": "assistant",
            "content": "provider returned token-123 and token-456"
        }}]
    })
    .to_string();
    let redacted: serde_json::Value =
        serde_json::from_str(&matched.redact_text(&response)).unwrap();
    assert_eq!(
        redacted["choices"][0]["message"]["content"],
        "provider returned [REDACTED] and [REDACTED]"
    );
    assert_eq!(redacted["model"], "must-not-change");
}

#[test]
fn matches_request_max_input_bytes() {
    let config = Config {
        guardrails: vec![crate::config::GuardrailRule {
            id: "max-input".into(),
            name: "Max input".into(),
            enabled: true,
            stage: crate::config::GuardrailStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            models: vec![],
            providers: vec![],
            keywords: vec![],
            regex: vec![],
            max_input_bytes: Some(8),
            provider: GuardrailProviderKind::None,
            provider_endpoint: None,
            provider_timeout_ms: 2_000,
            provider_runtime: Default::default(),
            effect: crate::config::GuardrailEffect::Deny,
            code: "guardrail_input_too_large".into(),
            message: "input is too large".into(),
        }],
        ..Config::default()
    };
    let state = AppState::new(config);

    let matched = match_guardrail_for_test(
        &state,
        crate::config::GuardrailStage::Request,
        &ferrogate_core::TenantContext::default(),
        None,
        None,
        "012345678",
    )
    .expect("length guardrail should match");

    assert_eq!(matched.rule_id, "max-input");
    assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
}

#[test]
fn usage_report_filter_parses_scope_period_and_group_by_from_query() {
    let filter = UsageReportFilter::from_query(Some(
            "scope_type=workspace&scope_id=ws-1&from_month=2026-01&to_month=2026-03&group_by=period_month",
        ));
    assert_eq!(filter.scope_type, Some(QuotaScopeKind::Workspace));
    assert_eq!(filter.scope_id.as_deref(), Some("ws-1"));
    assert_eq!(filter.from_month.as_deref(), Some("2026-01"));
    assert_eq!(filter.to_month.as_deref(), Some("2026-03"));
    assert_eq!(filter.group_by, Some(UsageReportGroupBy::PeriodMonth));

    // `period_month` is a convenience alias that pins both bounds to the
    // same exact month.
    let exact = UsageReportFilter::from_query(Some("period_month=2026-05"));
    assert_eq!(exact.from_month.as_deref(), Some("2026-05"));
    assert_eq!(exact.to_month.as_deref(), Some("2026-05"));

    assert_eq!(
        UsageReportFilter::from_query(None),
        UsageReportFilter::default()
    );

    // group_by=metadata.<key> (issue #171) extracts the key verbatim;
    // an empty key (just "metadata.") or an unrecognized value parses
    // to no group_by rather than panicking.
    let metadata_filter = UsageReportFilter::from_query(Some("group_by=metadata.customer_id"));
    assert_eq!(
        metadata_filter.group_by,
        Some(UsageReportGroupBy::Metadata("customer_id".to_string()))
    );
    assert_eq!(
        UsageReportFilter::from_query(Some("group_by=metadata.")).group_by,
        None
    );
    assert_eq!(
        UsageReportFilter::from_query(Some("group_by=nonsense")).group_by,
        None
    );
}

#[test]
fn usage_report_filters_by_scope_and_aggregates_with_group_by() {
    let config = Config {
        providers: vec![Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:10002/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: Some(1.0),
            output_price_per_1m: Some(2.0),
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };
    let state = AppState::new(config);

    let request_for = |api_key_id: &str| RequestContext {
        request_id: format!("fg-{api_key_id}"),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        route: Some("openai.chat.completions".into()),
        upstream: Some("openai".into()),
        tenant: ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org-shared".into()),
            team_id: None,
            project_id: None,
            user_id: None,
            api_key_id: Some(api_key_id.into()),
        },
    };

    for api_key_id in ["key-a", "key-b"] {
        block_on(state.record_billing_event(
            BillingEventDraft {
                request: &request_for(api_key_id),
                logical_model: "fast-chat",
                provider: "openai",
                provider_model: "gpt-4o-mini",
                status_code: 200,
                latency_ms: Some(10),
                metadata: None,
            },
            &ProviderUsage {
                prompt_tokens: Some(1000),
                completion_tokens: Some(1000),
                total_tokens: Some(2000),
            },
        ))
        .unwrap();
    }

    // Scoped to a single key: exactly one row, matching that key's own spend.
    let key_a_rows = block_on(state.usage_report(&UsageReportFilter {
        scope_type: Some(QuotaScopeKind::Key),
        scope_id: Some("key-a".into()),
        ..UsageReportFilter::default()
    }))
    .unwrap();
    assert_eq!(key_a_rows.len(), 1);
    assert_eq!(key_a_rows[0].scope_id.as_deref(), Some("key-a"));
    assert!((key_a_rows[0].cost_usd - 0.003).abs() < 1e-9);
    assert_eq!(key_a_rows[0].request_count, 1);

    // Both keys roll up into a single tenant-scope row.
    let tenant_rows = block_on(state.usage_report(&UsageReportFilter {
        scope_type: Some(QuotaScopeKind::Tenant),
        scope_id: Some("org-shared".into()),
        ..UsageReportFilter::default()
    }))
    .unwrap();
    assert_eq!(tenant_rows.len(), 1);
    assert!((tenant_rows[0].cost_usd - 0.006).abs() < 1e-9);
    assert_eq!(tenant_rows[0].request_count, 2);

    // A future-only window excludes every real (current-month) row.
    let out_of_range = block_on(state.usage_report(&UsageReportFilter {
        scope_type: Some(QuotaScopeKind::Key),
        from_month: Some("9999-12".into()),
        ..UsageReportFilter::default()
    }))
    .unwrap();
    assert!(out_of_range.is_empty());

    // group_by=period_month sums both key-scope rows (same real month)
    // into a single row, dropping the per-scope identity.
    let grouped = block_on(state.usage_report(&UsageReportFilter {
        scope_type: Some(QuotaScopeKind::Key),
        group_by: Some(UsageReportGroupBy::PeriodMonth),
        ..UsageReportFilter::default()
    }))
    .unwrap();
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].scope_type, None);
    assert_eq!(grouped[0].scope_id, None);
    assert!((grouped[0].cost_usd - 0.006).abs() < 1e-9);
    assert_eq!(grouped[0].request_count, 2);
}

/// #200 Slice 3a: a managed-action-scoped guardrail policy is selected and
/// evaluated ONLY when the evaluation context carries a matching
/// `ManagedActionContext` (class + target). This exercises the
/// `managed_action: context.managed_action` threading in `match_guardrail`'s
/// policy selection: model-content contexts (`None`) and mismatched classes
/// must not select the policy (mutual exclusivity, fail-closed selection).
#[test]
fn managed_action_context_selects_managed_action_scoped_policy() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let scope = PolicyScopeSelector {
        managed_action: Some(ferrogate_guardrails::ManagedActionSelector {
            classes: vec![ferrogate_guardrails::ManagedActionClass::Mcp],
            targets: vec!["github/create_issue".to_string()],
        }),
        ..PolicyScopeSelector::default()
    };
    let policy = durable_guardrail_revision("managed-guard", 1, "danger", scope);
    shared.create_guardrail_policy_revision(policy).unwrap();
    shared
        .activate_guardrail_policy_revision("managed-guard", 1, "test-admin", 1, false)
        .unwrap();

    let state = shared.current();
    let tenant = ferrogate_core::TenantContext::default();
    let envelope = ferrogate_guardrails::GuardrailEnvelope::managed_action(
        DetectorStage::Request,
        "mcp:github/create_issue/arguments",
        "please danger the repo",
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let eval = |managed: Option<ferrogate_guardrails::ManagedActionContext<'_>>| {
        runtime.block_on(state.match_guardrail(
            crate::config::GuardrailStage::Request,
            GuardrailEvaluationContext {
                request_id: "managed-req",
                trace_id: None,
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                actor_api_key_id: None,
                tenant: &tenant,
                service_account_id: None,
                gateway_config_id: None,
                model: None,
                provider: None,
                streaming: false,
                envelope: &envelope,
                managed_action: managed,
            },
        ))
    };

    // Positive: matching class + target selects the policy; the keyword fires.
    let matched = eval(Some(ferrogate_guardrails::ManagedActionContext {
        class: ferrogate_guardrails::ManagedActionClass::Mcp,
        target: Some("github/create_issue"),
    }))
    .expect("managed-action policy must be selected for a matching context");
    assert_eq!(matched.code, "durable_guardrail_blocked");

    // Negative A: model-content context (None) must NOT select a managed-action
    // policy — the two target dimensions are mutually exclusive.
    assert!(
        eval(None).is_none(),
        "managed-action policy must not apply to model-content evaluation"
    );

    // Negative B: a mismatched action class must NOT select the policy.
    assert!(
        eval(Some(ferrogate_guardrails::ManagedActionContext {
            class: ferrogate_guardrails::ManagedActionClass::Tool,
            target: Some("github/create_issue"),
        }))
        .is_none(),
        "managed-action policy must not apply to a different action class"
    );
}
