//! Virtual API key and tenant resolution boundaries.

use ferrogate_core::TenantContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: String,
    pub organization_id: String,
    pub team_id: Option<String>,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub display_name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub id: String,
    pub organization_id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBinding {
    pub id: String,
    pub role_id: String,
    pub tenant: TenantContext,
    pub subject: PolicySubject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySubject {
    User { user_id: String },
    ServiceAccount { service_account_id: String },
    ApiKey { api_key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub tenant: TenantContext,
    pub scopes: Vec<String>,
}

pub trait ApiKeyAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_binding_preserves_tenant_and_subject_identity() {
        let binding = PolicyBinding {
            id: "binding_admin".into(),
            role_id: "role_admin".into(),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                team_id: Some("team".into()),
                project_id: Some("project".into()),
                user_id: Some("user".into()),
                api_key_id: Some("key".into()),
            },
            subject: PolicySubject::ApiKey {
                api_key_id: "key".into(),
            },
        };

        assert_eq!(binding.tenant.organization_id.as_deref(), Some("org"));
        assert_eq!(
            binding.subject,
            PolicySubject::ApiKey {
                api_key_id: "key".into()
            }
        );
    }

    #[test]
    fn role_groups_permissions() {
        let role = Role {
            id: "role_chat".into(),
            name: "Chat caller".into(),
            permissions: vec![Permission {
                action: "chat.completions".into(),
                resource: "model:fast-chat".into(),
            }],
        };

        assert_eq!(role.permissions[0].action, "chat.completions");
    }
}
