// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Policy decision boundaries.

use ferrogate_core::{RequestContext, TenantContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { code: String, message: String },
}

pub trait PolicyEngine {
    fn evaluate(
        &self,
        request: &RequestContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> PolicyDecision;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BasicPolicyEngine {
    rules: Vec<PolicyRule>,
}

impl BasicPolicyEngine {
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }
}

impl PolicyEngine for BasicPolicyEngine {
    fn evaluate(
        &self,
        request: &RequestContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> PolicyDecision {
        self.rules
            .iter()
            .find_map(|rule| rule.evaluate(&request.tenant, model, provider))
            .unwrap_or(PolicyDecision::Allow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub subject: PolicySubject,
    pub models: Vec<String>,
    pub providers: Vec<String>,
    pub code: String,
    pub message: String,
}

impl PolicyRule {
    pub fn deny(
        subject: PolicySubject,
        models: Vec<String>,
        providers: Vec<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            subject,
            models,
            providers,
            code: code.into(),
            message: message.into(),
        }
    }

    fn evaluate(
        &self,
        tenant: &TenantContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> Option<PolicyDecision> {
        if !self.subject.matches(tenant) {
            return None;
        }
        if !matches_optional_list(&self.models, model) {
            return None;
        }
        if !matches_optional_list(&self.providers, provider) {
            return None;
        }

        Some(PolicyDecision::Deny {
            code: self.code.clone(),
            message: self.message.clone(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySubject {
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
}

impl PolicySubject {
    fn matches(&self, tenant: &TenantContext) -> bool {
        matches_optional_value(&self.organization_id, tenant.organization_id.as_deref())
            && matches_optional_value(&self.project_id, tenant.project_id.as_deref())
            && matches_optional_value(&self.api_key_id, tenant.api_key_id.as_deref())
    }
}

fn matches_optional_value(expected: &Option<String>, actual: Option<&str>) -> bool {
    expected
        .as_deref()
        .is_none_or(|expected| Some(expected) == actual)
}

fn matches_optional_list(expected: &[String], actual: Option<&str>) -> bool {
    expected.is_empty() || actual.is_some_and(|actual| expected.iter().any(|item| item == actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows() {
        let engine = BasicPolicyEngine::default();
        let request = request("org", "project", "key");

        assert_eq!(
            engine.evaluate(&request, Some("fast-chat"), Some("openai")),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn deny_rule_matches_tenant_model_and_provider() {
        let engine = BasicPolicyEngine::new(vec![PolicyRule::deny(
            PolicySubject {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
            },
            vec!["fast-chat".into()],
            vec!["openai".into()],
            "policy_denied",
            "blocked by policy",
        )]);
        let request = request("org", "project", "key");

        assert_eq!(
            engine.evaluate(&request, Some("fast-chat"), Some("openai")),
            PolicyDecision::Deny {
                code: "policy_denied".into(),
                message: "blocked by policy".into()
            }
        );
        assert_eq!(
            engine.evaluate(&request, Some("smart-chat"), Some("openai")),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn deny_rule_ignores_non_matching_tenant() {
        let engine = BasicPolicyEngine::new(vec![PolicyRule::deny(
            PolicySubject {
                organization_id: Some("other".into()),
                project_id: None,
                api_key_id: None,
            },
            vec![],
            vec!["openai".into()],
            "policy_denied",
            "blocked by policy",
        )]);
        let request = request("org", "project", "key");

        assert_eq!(
            engine.evaluate(&request, Some("fast-chat"), Some("openai")),
            PolicyDecision::Allow
        );
    }

    fn request(organization_id: &str, project_id: &str, api_key_id: &str) -> RequestContext {
        RequestContext {
            request_id: "fg-test".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: TenantContext {
                organization_id: Some(organization_id.into()),
                team_id: None,
                project_id: Some(project_id.into()),
                user_id: None,
                api_key_id: Some(api_key_id.into()),
            },
        }
    }
}
