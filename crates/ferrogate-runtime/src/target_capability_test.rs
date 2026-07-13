use std::{collections::BTreeMap, fs};

use super::*;

#[test]
fn mcp_selector_denies_sibling_tool_and_argument_shape_bypass() {
    let selector = CapabilityTargetSelector::Mcp {
        server: "crm".into(),
        tool: "lookup".into(),
        risk: McpRisk::Read,
        argument_schema: object_shape([("id", JsonShape::String)]),
        allow_extra_arguments: false,
    };
    let allowed = canonical_mcp_target("crm", "lookup", r#"{"id":"42"}"#, false).unwrap();
    let sibling = canonical_mcp_target("crm", "delete", r#"{"id":"42"}"#, false).unwrap();
    let bypass =
        canonical_mcp_target("crm", "lookup", r#"{"id":"42","admin":true}"#, false).unwrap();
    assert!(allowed.matches(&selector).unwrap());
    assert!(!sibling.matches(&selector).unwrap());
    assert!(!bypass.matches(&selector).unwrap());
    let other_value = canonical_mcp_target("crm", "lookup", r#"{"id":"43"}"#, false).unwrap();
    assert_ne!(allowed.fingerprint(), other_value.fingerprint());
    let nested_a = canonical_mcp_target(
        "crm",
        "lookup",
        r#"{"filter":{"active":true,"team":"red"},"id":"42"}"#,
        false,
    )
    .unwrap();
    let nested_b = canonical_mcp_target(
        "crm",
        "lookup",
        r#"{"id":"42","filter":{"team":"red","active":true}}"#,
        false,
    )
    .unwrap();
    assert_eq!(nested_a.fingerprint(), nested_b.fingerprint());

    let array_selector = CapabilityTargetSelector::Mcp {
        server: "crm".into(),
        tool: "batch_lookup".into(),
        risk: McpRisk::Read,
        argument_schema: object_shape([(
            "items",
            JsonShape::Array {
                items: Box::new(object_shape([("id", JsonShape::String)])),
            },
        )]),
        allow_extra_arguments: false,
    };
    let array_allowed = canonical_mcp_target(
        "crm",
        "batch_lookup",
        r#"{"items":[{"id":"42"},{"id":"43"}]}"#,
        false,
    )
    .unwrap();
    let array_bypass = canonical_mcp_target(
        "crm",
        "batch_lookup",
        r#"{"items":[{"id":"42","admin":true}]}"#,
        false,
    )
    .unwrap();
    assert!(array_allowed.matches(&array_selector).unwrap());
    assert!(!array_bypass.matches(&array_selector).unwrap());
    assert!(canonical_mcp_target(
        "crm",
        "batch_lookup",
        r#"{"items":[{"id":"42"},"ambiguous"]}"#,
        false,
    )
    .is_err());
}

#[test]
fn mcp_argument_shape_preserves_field_boundaries_without_flattening_collisions() {
    let dotted_field =
        canonical_mcp_target("crm", "lookup", r#"{"profile.name":"alice"}"#, false).unwrap();
    let nested_field =
        canonical_mcp_target("crm", "lookup", r#"{"profile":{"name":"alice"}}"#, false).unwrap();
    assert_ne!(dotted_field, nested_field);
    assert_ne!(dotted_field.fingerprint(), nested_field.fingerprint());

    let nested_selector = CapabilityTargetSelector::Mcp {
        server: "crm".into(),
        tool: "lookup".into(),
        risk: McpRisk::Read,
        argument_schema: object_shape([("profile", object_shape([("name", JsonShape::String)]))]),
        allow_extra_arguments: false,
    };
    assert!(nested_field.matches(&nested_selector).unwrap());
    assert!(!dotted_field.matches(&nested_selector).unwrap());
}

fn object_shape<const N: usize>(fields: [(&str, JsonShape); N]) -> JsonShape {
    JsonShape::Object {
        fields: fields
            .into_iter()
            .map(|(name, shape)| (name.to_string(), shape))
            .collect(),
    }
}

#[test]
fn filesystem_rejects_traversal_and_symlink_escape() {
    assert!(canonical_filesystem_target("../secret", TargetOperation::Read, true).is_err());
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), "secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
    let target = canonical_filesystem_target("escape/secret", TargetOperation::Read, true).unwrap();
    let selector = CapabilityTargetSelector::Filesystem {
        workspace_root: root.path().display().to_string(),
        path_glob: "**".into(),
        operations: vec![TargetOperation::Read],
    };
    #[cfg(unix)]
    assert!(target.matches(&selector).is_err());

    let allowed_path = root.path().join("allowed.txt");
    fs::write(&allowed_path, "allowed").unwrap();
    let allowed = canonical_filesystem_target("allowed.txt", TargetOperation::Read, true).unwrap();
    let bound = allowed.bind(&selector).unwrap().unwrap();
    let evidence: serde_json::Value = serde_json::from_str(&bound.canonical_target).unwrap();
    assert_eq!(
        evidence["workspace_root"],
        root.path().canonicalize().unwrap().display().to_string()
    );
    assert_eq!(
        evidence["resolved_path"],
        allowed_path.canonicalize().unwrap().display().to_string()
    );
    #[cfg(unix)]
    {
        assert!(evidence["root_device"].as_u64().is_some());
        assert!(evidence["root_inode"].as_u64().is_some());
        assert!(evidence["target_device"].as_u64().is_some());
        assert!(evidence["target_inode"].as_u64().is_some());
    }
}

#[test]
fn filesystem_write_binds_existing_parent_and_absent_leaf() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("output");
    fs::create_dir(&parent).unwrap();
    fs::write(parent.join("sibling.txt"), "keep").unwrap();
    let selector = CapabilityTargetSelector::Filesystem {
        workspace_root: root.path().display().to_string(),
        path_glob: "output/*.txt".into(),
        operations: vec![TargetOperation::Write],
    };
    let target =
        canonical_filesystem_target("output/new.txt", TargetOperation::Write, true).unwrap();

    let bound = target.bind(&selector).unwrap().unwrap();
    let evidence: serde_json::Value = serde_json::from_str(&bound.canonical_target).unwrap();

    assert_eq!(evidence["operation"], "write");
    assert_eq!(
        evidence["resolved_parent"],
        parent.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(evidence["leaf_name"], "new.txt");
    assert_eq!(evidence["target_must_not_exist"], true);
    assert!(evidence.get("target_inode").is_none());
    assert!(evidence["parent_inode"].as_u64().is_some());
    assert_eq!(
        fs::read_to_string(parent.join("sibling.txt")).unwrap(),
        "keep"
    );
    assert!(!parent.join("new.txt").exists());

    fs::write(parent.join("new.txt"), "existing").unwrap();
    assert!(target
        .bind(&selector)
        .unwrap_err()
        .contains("already exists"));
}

#[test]
fn network_rejects_alternate_host_redirect_and_dns_rebinding() {
    assert!(canonical_network_url("http://2130706433/admin", Some("GET"), &[], &[]).is_err());
    assert!(canonical_network_url("http://0177.0.0.1/admin", Some("GET"), &[], &[]).is_err());
    assert!(canonical_network_url("http://0x7f000001/admin", Some("GET"), &[], &[]).is_err());
    let selector = CapabilityTargetSelector::Network {
        scheme: "https".into(),
        host: "api.example.com".into(),
        port: 443,
        method: Some("GET".into()),
        path_glob: "/v1/**".into(),
        allowed_ips: vec!["203.0.113.10".parse().unwrap()],
        allow_redirects: false,
    };
    let rebound = canonical_network_url(
        "https://API.EXAMPLE.COM.:443/v1/data",
        Some("get"),
        &["127.0.0.1".into()],
        &[],
    )
    .unwrap();
    assert!(rebound.matches(&selector).is_err());
    let redirect = canonical_network_url(
        "https://api.example.com/v1/data",
        Some("GET"),
        &["203.0.113.10".into()],
        &["https://evil.example/v1/data".into()],
    );
    assert!(redirect.is_err());

    let unpinned_selector = CapabilityTargetSelector::Network {
        scheme: "https".into(),
        host: "api.example.com".into(),
        port: 443,
        method: Some("GET".into()),
        path_glob: "/v1/**".into(),
        allowed_ips: Vec::new(),
        allow_redirects: false,
    };
    assert!(unpinned_selector.validate().is_err());
}

#[test]
fn cli_exact_argv_rule_denies_argument_injection() {
    let cwd = tempfile::tempdir().unwrap();
    let cwd = cwd.path().display().to_string();
    let selector = CapabilityTargetSelector::Cli {
        executable: "/usr/bin/git".into(),
        argv: vec!["status".into()],
        environment: BTreeMap::new(),
        cwd_glob: cwd.clone(),
        max_timeout_millis: 1_000,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 1024,
    };
    let allowed =
        canonical_cli_target("/usr/bin/git", &["status".into()], &cwd, 1_000, 1024, 1024).unwrap();
    let bypass = canonical_cli_target(
        "/usr/bin/git",
        &["status".into(), "--porcelain=v2;cat /etc/passwd".into()],
        &cwd,
        1_000,
        1024,
        1024,
    )
    .unwrap();
    assert!(allowed.matches(&selector).unwrap());
    assert!(!bypass.matches(&selector).unwrap());
}

#[test]
fn secret_target_never_accepts_resolved_values_or_wrong_destination() {
    assert!(canonical_secret_target("TOKEN=plaintext", "codex", "provider.call").is_err());
    let target = canonical_secret_target("vault/provider-key", "codex", "provider.call").unwrap();
    let selector = CapabilityTargetSelector::Secret {
        reference_namespace: "vault".into(),
        reference_name: "provider-key".into(),
        destination_adapter: "codex".into(),
        destination_action: "provider.call".into(),
    };
    let wrong = CapabilityTargetSelector::Secret {
        reference_namespace: "vault".into(),
        reference_name: "provider-key".into(),
        destination_adapter: "codex".into(),
        destination_action: "shell.env".into(),
    };
    assert!(target.matches(&selector).unwrap());
    assert!(!target.matches(&wrong).unwrap());
    assert!(!target.canonical_json().contains("plaintext"));
    assert!(!target.canonical_json().contains("provider-key"));
    for value in ["vault/sk-live", "vault/ghp_token", "vault/AKIA1234"] {
        assert!(canonical_secret_target(value, "codex", "provider.call").is_err());
    }
}
