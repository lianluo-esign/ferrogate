// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Immutable Guardrail policy revision and deterministic composition domain.

use crate::{
    all_content_sources, validate_custom_http_endpoint, ContentSource, DetectorError,
    DetectorErrorKind, DetectorStage, JsonConstraints, RequestConstraints, SecretPattern,
    MAX_DETECTOR_TIMEOUT,
};
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    Enforce,
    Shadow,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyExecution {
    #[default]
    Sequential,
    Parallel,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStreamingMode {
    #[default]
    BufferAndEnforce,
    ShadowAfterComplete,
    RejectStreaming,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRevisionStatus {
    #[default]
    Draft,
    Active,
    Archived,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyAggregation {
    All,
    Any,
    Threshold { minimum: u32 },
}

impl Default for PolicyAggregation {
    fn default() -> Self {
        Self::All
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopeSelector {
    #[serde(default)]
    pub tenant_ids: Vec<String>,
    #[serde(default)]
    pub organization_ids: Vec<String>,
    #[serde(default)]
    pub project_ids: Vec<String>,
    #[serde(default)]
    pub workspace_ids: Vec<String>,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    #[serde(default)]
    pub service_account_ids: Vec<String>,
    #[serde(default)]
    pub gateway_config_ids: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct PolicySelectionContext<'a> {
    pub organization_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub api_key_id: Option<&'a str>,
    pub service_account_id: Option<&'a str>,
    pub gateway_config_id: Option<&'a str>,
    pub model: Option<&'a str>,
    pub provider: Option<&'a str>,
}

impl PolicyScopeSelector {
    pub fn matches(&self, context: PolicySelectionContext<'_>) -> bool {
        let organization_matches = if self.tenant_ids.is_empty() && self.organization_ids.is_empty()
        {
            true
        } else {
            context.organization_id.is_some_and(|actual| {
                self.tenant_ids.iter().any(|allowed| allowed == actual)
                    || self
                        .organization_ids
                        .iter()
                        .any(|allowed| allowed == actual)
            })
        };
        organization_matches
            && matches_optional(&self.project_ids, context.project_id)
            && matches_optional(&self.workspace_ids, context.workspace_id)
            && matches_optional(&self.api_key_ids, context.api_key_id)
            && matches_optional(&self.service_account_ids, context.service_account_id)
            && matches_optional(&self.gateway_config_ids, context.gateway_config_id)
            && matches_optional(&self.models, context.model)
            && matches_optional(&self.providers, context.provider)
    }

    pub fn administrative_rank(&self) -> u8 {
        if !self.gateway_config_ids.is_empty() {
            5
        } else if !self.api_key_ids.is_empty() || !self.service_account_ids.is_empty() {
            4
        } else if !self.workspace_ids.is_empty() {
            3
        } else if !self.project_ids.is_empty() {
            2
        } else if !self.tenant_ids.is_empty() || !self.organization_ids.is_empty() {
            1
        } else {
            0
        }
    }

    fn validate(&self) -> Result<(), DetectorError> {
        for (field, values) in [
            ("tenant_ids", &self.tenant_ids),
            ("organization_ids", &self.organization_ids),
            ("project_ids", &self.project_ids),
            ("workspace_ids", &self.workspace_ids),
            ("api_key_ids", &self.api_key_ids),
            ("service_account_ids", &self.service_account_ids),
            ("gateway_config_ids", &self.gateway_config_ids),
            ("models", &self.models),
            ("providers", &self.providers),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                return Err(invalid_policy(format!(
                    "guardrail policy scope {field} cannot contain an empty value"
                )));
            }
        }
        Ok(())
    }
}

fn matches_optional(allowed: &[String], actual: Option<&str>) -> bool {
    allowed.is_empty()
        || actual.is_some_and(|actual| allowed.iter().any(|allowed| allowed == actual))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorDefinition {
    Local {
        #[serde(default)]
        keywords: Vec<String>,
        #[serde(default)]
        regex: Vec<String>,
        #[serde(default)]
        max_input_bytes: Option<usize>,
        #[serde(default)]
        json: Option<JsonConstraints>,
        #[serde(default)]
        request: Option<Box<RequestConstraints>>,
        #[serde(default)]
        secret_patterns: Vec<SecretPattern>,
        /// Resolves once during activation/reload. Required when secret
        /// patterns are enabled so evidence is keyed and non-reversible.
        #[serde(default)]
        fingerprint_secret_ref: Option<String>,
    },
    CustomHttp {
        endpoint: String,
        #[serde(default = "default_detector_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_detector_max_concurrency")]
        max_concurrency: usize,
        #[serde(default = "default_detector_circuit_failure_threshold")]
        circuit_failure_threshold: u32,
        #[serde(default = "default_detector_circuit_cooldown_ms")]
        circuit_cooldown_ms: u64,
        #[serde(default)]
        max_retries: u8,
        #[serde(default = "default_detector_max_payload_bytes")]
        max_payload_bytes: usize,
        #[serde(default = "default_detector_max_response_bytes")]
        max_response_bytes: usize,
        #[serde(default)]
        allow_private_network: bool,
        #[serde(default)]
        secret_ref: Option<String>,
    },
}

impl DetectorDefinition {
    pub fn local(
        keywords: Vec<String>,
        regex: Vec<String>,
        max_input_bytes: Option<usize>,
    ) -> Self {
        Self::Local {
            keywords,
            regex,
            max_input_bytes,
            json: None,
            request: None,
            secret_patterns: Vec::new(),
            fingerprint_secret_ref: None,
        }
    }

    pub fn validate(&self) -> Result<(), DetectorError> {
        match self {
            Self::Local {
                keywords,
                regex,
                max_input_bytes,
                json,
                request,
                secret_patterns,
                fingerprint_secret_ref,
            } => {
                if keywords.is_empty()
                    && regex.is_empty()
                    && max_input_bytes.is_none()
                    && json.as_ref().is_none_or(JsonConstraints::is_empty)
                    && request.as_deref().is_none_or(RequestConstraints::is_empty)
                    && secret_patterns.is_empty()
                {
                    return Err(invalid_policy(
                        "local guardrail detector requires at least one deterministic constraint",
                    ));
                }
                if keywords.iter().any(|keyword| keyword.is_empty()) {
                    return Err(invalid_policy(
                        "local guardrail detector keywords cannot be empty",
                    ));
                }
                for pattern in regex {
                    Regex::new(pattern).map_err(|_| {
                        invalid_policy("local guardrail detector contains an invalid regex")
                    })?;
                }
                if *max_input_bytes == Some(0) {
                    return Err(invalid_policy(
                        "local guardrail detector max_input_bytes must be greater than zero",
                    ));
                }
                if let Some(json) = json {
                    json.validate("json")?;
                }
                if let Some(request) = request.as_deref() {
                    request.validate()?;
                }
                if secret_patterns.iter().collect::<HashSet<_>>().len() != secret_patterns.len() {
                    return Err(invalid_policy(
                        "local guardrail secret_patterns must be unique",
                    ));
                }
                if !secret_patterns.is_empty()
                    && fingerprint_secret_ref.as_deref().is_none_or(str::is_empty)
                {
                    return Err(invalid_policy(
                        "local secret detection requires fingerprint_secret_ref",
                    ));
                }
                if fingerprint_secret_ref.as_deref().is_some_and(str::is_empty) {
                    return Err(invalid_policy(
                        "local fingerprint_secret_ref cannot be empty",
                    ));
                }
            }
            Self::CustomHttp {
                endpoint,
                timeout_ms,
                max_concurrency,
                circuit_failure_threshold,
                circuit_cooldown_ms,
                max_retries,
                max_payload_bytes,
                max_response_bytes,
                secret_ref,
                allow_private_network,
            } => {
                let endpoint = Url::parse(endpoint)
                    .map_err(|_| invalid_policy("custom_http detector endpoint is invalid"))?;
                validate_custom_http_endpoint(&endpoint, *allow_private_network)?;
                if *timeout_ms == 0
                    || *timeout_ms > MAX_DETECTOR_TIMEOUT.as_millis() as u64
                    || *max_concurrency == 0
                    || *circuit_failure_threshold == 0
                    || *circuit_cooldown_ms == 0
                    || *max_payload_bytes == 0
                    || *max_response_bytes == 0
                    || *max_retries > 1
                {
                    return Err(invalid_policy(
                        "custom_http detector limits are invalid or exceed the runtime ceiling",
                    ));
                }
                if secret_ref.as_deref().is_some_and(str::is_empty) {
                    return Err(invalid_policy(
                        "custom_http detector secret_ref cannot be empty",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckBinding {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub stage: DetectorStage,
    #[serde(default = "all_content_sources")]
    pub sources: Vec<ContentSource>,
    pub detector: DetectorDefinition,
    #[serde(default)]
    pub fallback_detector: Option<DetectorDefinition>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Allow,
    Block,
    Redact,
    Record,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyAction {
    pub kind: ActionKind,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl PolicyAction {
    pub fn allow() -> Self {
        Self {
            kind: ActionKind::Allow,
            code: None,
            message: None,
        }
    }

    pub fn record() -> Self {
        Self {
            kind: ActionKind::Record,
            code: None,
            message: None,
        }
    }

    pub fn block(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: ActionKind::Block,
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }

    pub fn redact(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: ActionKind::Redact,
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }

    fn validate(&self) -> Result<(), DetectorError> {
        if matches!(self.kind, ActionKind::Block | ActionKind::Redact)
            && (self.code.as_deref().is_none_or(str::is_empty)
                || self.message.as_deref().is_none_or(str::is_empty))
        {
            return Err(invalid_policy(
                "block and redact actions require non-empty code and message",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub revision: u32,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enforced: bool,
    #[serde(default)]
    pub scope: PolicyScopeSelector,
    pub checks: Vec<CheckBinding>,
    #[serde(default)]
    pub aggregation: PolicyAggregation,
    #[serde(default)]
    pub execution: PolicyExecution,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub streaming: PolicyStreamingMode,
    pub on_pass: Vec<PolicyAction>,
    pub on_fail: Vec<PolicyAction>,
    pub on_error: Vec<PolicyAction>,
    #[serde(default = "default_policy_deadline_ms")]
    pub deadline_ms: u64,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub created_by: String,
}

impl PolicyRevision {
    pub fn immutable_id(&self) -> String {
        format!("{}@{}", self.policy_id, self.revision)
    }

    pub fn validate(&self) -> Result<(), DetectorError> {
        if self.policy_id.trim().is_empty()
            || self.name.trim().is_empty()
            || self.created_by.trim().is_empty()
            || self.revision == 0
        {
            return Err(invalid_policy(
                "guardrail policy id, name, revision, and created_by are required",
            ));
        }
        if self.deadline_ms == 0 || self.deadline_ms > MAX_DETECTOR_TIMEOUT.as_millis() as u64 {
            return Err(invalid_policy(
                "guardrail policy deadline must be between 1 and 30000 milliseconds",
            ));
        }
        self.scope.validate()?;
        if self.checks.is_empty() {
            return Err(invalid_policy(
                "guardrail policy requires at least one check",
            ));
        }
        let mut check_ids = HashSet::new();
        let mut enabled_checks = 0_u32;
        for check in &self.checks {
            if check.id.trim().is_empty() || !check_ids.insert(check.id.as_str()) {
                return Err(invalid_policy(
                    "guardrail policy check ids must be non-empty and unique",
                ));
            }
            let unique_sources = check.sources.iter().collect::<HashSet<_>>();
            if check.sources.is_empty() || unique_sources.len() != check.sources.len() {
                return Err(invalid_policy(
                    "guardrail policy check sources must be non-empty and unique",
                ));
            }
            check.detector.validate()?;
            if let Some(fallback) = &check.fallback_detector {
                if !matches!(fallback, DetectorDefinition::Local { .. }) {
                    return Err(invalid_policy(
                        "guardrail policy fallback_detector must be local",
                    ));
                }
                fallback.validate()?;
            }
            if check.enabled {
                enabled_checks = enabled_checks.saturating_add(1);
            }
        }
        if enabled_checks == 0 {
            return Err(invalid_policy(
                "guardrail policy requires at least one enabled check",
            ));
        }
        if let PolicyAggregation::Threshold { minimum } = self.aggregation {
            if minimum == 0 || minimum > enabled_checks {
                return Err(invalid_policy(
                    "guardrail policy threshold must be between one and the enabled check count",
                ));
            }
        }
        for (name, actions) in [
            ("on_pass", &self.on_pass),
            ("on_fail", &self.on_fail),
            ("on_error", &self.on_error),
        ] {
            if actions.is_empty() {
                return Err(invalid_policy(format!(
                    "guardrail policy {name} actions cannot be empty"
                )));
            }
            for action in actions {
                action.validate()?;
            }
        }
        Ok(())
    }

    pub fn selected_check_ids(&self, stage: DetectorStage) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|check| check.enabled && check.stage == stage)
            .map(|check| check.id.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRevisionView {
    #[serde(flatten)]
    pub revision: PolicyRevision,
    pub status: PolicyRevisionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    Pass,
    Fail,
    Error,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateOutcome {
    Pass,
    Fail,
    Error,
}

pub fn aggregate_check_outcomes(
    aggregation: &PolicyAggregation,
    outcomes: &[CheckOutcome],
) -> AggregateOutcome {
    let enabled = outcomes
        .iter()
        .copied()
        .filter(|outcome| *outcome != CheckOutcome::Disabled)
        .collect::<Vec<_>>();
    if enabled.is_empty() {
        return AggregateOutcome::Error;
    }
    let passes = enabled
        .iter()
        .filter(|outcome| **outcome == CheckOutcome::Pass)
        .count();
    let failures = enabled
        .iter()
        .filter(|outcome| **outcome == CheckOutcome::Fail)
        .count();
    let errors = enabled
        .iter()
        .filter(|outcome| **outcome == CheckOutcome::Error)
        .count();
    match aggregation {
        PolicyAggregation::All => {
            if failures > 0 {
                AggregateOutcome::Fail
            } else if errors > 0 {
                AggregateOutcome::Error
            } else {
                AggregateOutcome::Pass
            }
        }
        PolicyAggregation::Any => {
            if passes > 0 {
                AggregateOutcome::Pass
            } else if errors > 0 {
                AggregateOutcome::Error
            } else {
                AggregateOutcome::Fail
            }
        }
        PolicyAggregation::Threshold { minimum } => {
            let minimum = *minimum as usize;
            if failures >= minimum {
                AggregateOutcome::Fail
            } else if failures.saturating_add(errors) >= minimum {
                AggregateOutcome::Error
            } else {
                AggregateOutcome::Pass
            }
        }
    }
}

pub fn select_policy_revisions<'a>(
    policies: &'a [PolicyRevision],
    context: PolicySelectionContext<'_>,
) -> Vec<&'a PolicyRevision> {
    let mut selected = policies
        .iter()
        .filter(|policy| policy.scope.matches(context))
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.scope
            .administrative_rank()
            .cmp(&right.scope.administrative_rank())
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.revision.cmp(&right.revision))
    });
    selected
}

fn invalid_policy(message: impl Into<String>) -> DetectorError {
    DetectorError::new(DetectorErrorKind::InvalidConfiguration, message)
}

const fn default_true() -> bool {
    true
}

const fn default_policy_deadline_ms() -> u64 {
    2_000
}

const fn default_detector_timeout_ms() -> u64 {
    2_000
}

const fn default_detector_max_concurrency() -> usize {
    16
}

const fn default_detector_circuit_failure_threshold() -> u32 {
    3
}

const fn default_detector_circuit_cooldown_ms() -> u64 {
    30_000
}

const fn default_detector_max_payload_bytes() -> usize {
    1024 * 1024
}

const fn default_detector_max_response_bytes() -> usize {
    256 * 1024
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod policy_test;
