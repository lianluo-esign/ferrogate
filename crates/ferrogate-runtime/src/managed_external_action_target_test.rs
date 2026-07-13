use super::*;
use crate::{
    CapabilityPolicy, CapabilityTargetGrant, CapabilityTargetSelector, ClassOnlyPolicyMode,
    SimpleCapabilityAuthorizer,
};

#[test]
fn malformed_secret_reference_is_denied_without_echoing_caller_value() {
    let raw_value = "TOKEN=resolved-secret-value";
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::Secret,
            selector_id: "provider-secret".into(),
            selector: CapabilityTargetSelector::Secret {
                reference_namespace: "vault".into(),
                reference_name: "provider-key".into(),
                destination_adapter: "native-harness".into(),
                destination_action: "provider.call".into(),
            },
        }],
        class_only_policy_mode: ClassOnlyPolicyMode::Deny,
        revision: "secret-policy-1".into(),
        ..CapabilityPolicy::default()
    });
    let (evidence, event) = authorize_managed_external_action(
        &authorizer,
        ManagedExternalActionRequest {
            session: FrameworkAdapterSession {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                tenant_id: "tenant-1".into(),
                workspace_id: "workspace-1".into(),
                worker_id: "worker-1".into(),
                isolation_backend: "firecracker".into(),
                adapter_name: "native-harness".into(),
                adapter_version: "test".into(),
                framework: SupportedFramework::NativeHarness,
                mode: FrameworkAdapterMode::Managed,
            },
            action: ManagedExternalAction::Secret(ManagedSecretAction {
                secret_id: raw_value.into(),
                purpose: "provider.call".into(),
            }),
            high_risk: false,
        },
    )
    .unwrap();

    assert_eq!(evidence.decision, CapabilityAuthorizationDecision::Denied);
    assert!(!evidence.target.contains(raw_value));
    assert!(!event.canonical_json().to_string().contains(raw_value));
    assert!(event.metadata["secret_ref_fingerprint"].starts_with("sha256:"));
}

#[test]
fn filesystem_execute_operation_survives_the_worker_wire_contract() {
    let request: ExternalActionAuthorizationRequest = serde_json::from_value(serde_json::json!({
        "session": {
            "session_id": "session-1",
            "run_id": "run-1",
            "tenant_id": "tenant-1",
            "workspace_id": "workspace-1",
            "worker_id": "worker-1",
            "isolation_backend": "firecracker",
            "adapter_name": "native-harness",
            "adapter_version": "test",
            "framework": "native_harness",
            "mode": "managed"
        },
        "action": {
            "kind": "filesystem",
            "path": "bin/tool",
            "access": "execute",
            "workspace_relative": true
        }
    }))
    .unwrap();

    let managed = request.into_managed_request().unwrap();
    assert!(matches!(
        managed.action,
        ManagedExternalAction::Filesystem(ManagedFilesystemAction {
            access: ManagedFilesystemAccess::Execute,
            ..
        })
    ));
}
