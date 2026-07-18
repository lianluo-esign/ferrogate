use std::{
    collections::BTreeSet,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityTargetGrant, CapabilityTargetSelector,
    ClassOnlyPolicyMode, JsonShape, McpRisk, TargetOperation,
};

use super::*;

#[test]
fn authorized_network_execution_fails_closed_without_pinned_ip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
            allow_direct_network_egress: true,
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));

    let error = execute_governed_network_egress_action(
        &gate,
        session(),
        ManagedNetworkEgressAction {
            host: "127.0.0.1".into(),
            port: endpoint.port(),
            protocol: "tcp".into(),
            resolved_ips: Vec::new(),
        },
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("authorization-pinned IP"));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}

#[test]
fn authorized_rest_execution_consumes_the_same_pinned_ip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));

    let error = execute_governed_rest_action(
        &gate,
        session(),
        ManagedRestAction {
            method: "GET".into(),
            url: format!("http://{endpoint}/pinned"),
            headers_policy: "deny_credentials".into(),
            body_policy: "empty".into(),
            timeout_millis: 100,
            retry_limit: 0,
            resolved_ips: vec!["127.0.0.2".into()],
            redirect_chain: Vec::new(),
        },
        false,
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("differs from the authorized pinned IP"));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}

#[test]
fn typed_filesystem_grant_executes_through_gateway_transport_and_bound_root() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("allowed.txt"), "authorized content").unwrap();
    let socket_dir = tempfile::tempdir().unwrap();
    let socket = socket_dir.path().join("target-capability.sock");
    let server_socket = socket.clone();
    let root = workspace.path().display().to_string();
    let server = thread::spawn(move || {
        serve_gateway_authorizer_unix(
            &server_socket,
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
                CapabilityPolicy {
                    target_grants: vec![CapabilityTargetGrant {
                        action: CapabilityAction::Filesystem,
                        selector_id: "workspace-read".into(),
                        selector: CapabilityTargetSelector::Filesystem {
                            workspace_root: root,
                            path_glob: "allowed.txt".into(),
                            operations: vec![TargetOperation::Read],
                        },
                    }],
                    revision: "filesystem-bound-1".into(),
                    ..CapabilityPolicy::default()
                },
            )),
            1,
        )
        .unwrap()
    });
    wait_for_authorizer_socket(&socket).unwrap();

    let events = execute_governed_filesystem_action(
        &UnixGatewayExternalActionAuthorizer::new_authenticated(&socket, std::process::id()),
        session(),
        ManagedFilesystemAction {
            path: "allowed.txt".into(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap();

    server.join().unwrap();
    assert_eq!(events[0].metadata["selector"], "workspace-read");
    assert_eq!(events[0].metadata["policy_revision"], "filesystem-bound-1");
    assert_eq!(events[1].metadata["executed_after_authorization"], "true");
    assert_eq!(events[1].metadata["content_excerpt"], "authorized content");
}

#[cfg(target_os = "linux")]
#[test]
fn typed_filesystem_read_rejects_hardlink_escape() {
    // A hard link at an in-workspace path can alias a sensitive inode that also
    // has a name OUTSIDE the workspace. Empirically, before the fail-closed
    // `st_nlink > 1` guard, this exact setup made `execute_governed_filesystem_action`
    // return content_excerpt = "TOP SECRET OUTSIDE WORKSPACE": the authorization
    // layer bound the outside inode, openat2(RESOLVE_BENEATH | NO_SYMLINKS) opened
    // the in-root directory entry (a hard link is not a symlink), and the dev/ino
    // re-check matched the aliased inode. It must now fail closed.
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "TOP SECRET OUTSIDE WORKSPACE").unwrap();
    std::fs::hard_link(&secret, workspace.path().join("allowed_link.txt")).unwrap();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            target_grants: vec![CapabilityTargetGrant {
                action: CapabilityAction::Filesystem,
                selector_id: "workspace-read".into(),
                selector: CapabilityTargetSelector::Filesystem {
                    workspace_root: workspace.path().display().to_string(),
                    path_glob: "allowed*.txt".into(),
                    operations: vec![TargetOperation::Read],
                },
            }],
            ..CapabilityPolicy::default()
        },
    ));

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        ManagedFilesystemAction {
            path: "allowed_link.txt".into(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("hard-linked"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn typed_filesystem_execution_rejects_symlink_swap_after_authorization() {
    struct SwapAfterAuthorization<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        target: std::path::PathBuf,
        outside: std::path::PathBuf,
    }

    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for SwapAfterAuthorization<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            std::fs::remove_file(&self.target).unwrap();
            std::os::unix::fs::symlink(&self.outside, &self.target).unwrap();
            Ok(decision)
        }
    }

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "outside secret").unwrap();
    let target = workspace.path().join("allowed.txt");
    std::fs::write(&target, "authorized content").unwrap();
    let gate = SwapAfterAuthorization {
        inner: RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                target_grants: vec![CapabilityTargetGrant {
                    action: CapabilityAction::Filesystem,
                    selector_id: "workspace-read".into(),
                    selector: CapabilityTargetSelector::Filesystem {
                        workspace_root: workspace.path().display().to_string(),
                        path_glob: "allowed.txt".into(),
                        operations: vec![TargetOperation::Read],
                    },
                }],
                ..CapabilityPolicy::default()
            },
        )),
        target,
        outside: outside.path().to_path_buf(),
    };

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        ManagedFilesystemAction {
            path: "allowed.txt".into(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("open beneath authorized root failed"));
}

#[cfg(target_os = "linux")]
#[test]
fn typed_filesystem_create_is_exclusive_and_preserves_siblings() {
    let workspace = tempfile::tempdir().unwrap();
    let output = workspace.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("sibling.txt"), "keep").unwrap();
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            target_grants: vec![CapabilityTargetGrant {
                action: CapabilityAction::Filesystem,
                selector_id: "workspace-create".into(),
                selector: CapabilityTargetSelector::Filesystem {
                    workspace_root: workspace.path().display().to_string(),
                    path_glob: "output/*.txt".into(),
                    operations: vec![TargetOperation::Write],
                },
            }],
            ..CapabilityPolicy::default()
        },
    ));
    let action = ManagedFilesystemAction {
        path: "output/new.txt".into(),
        access: ManagedFilesystemAccess::Write,
        workspace_relative: true,
    };

    let events = execute_governed_filesystem_action(
        &gate,
        session(),
        action.clone(),
        workspace.path(),
        false,
    )
    .unwrap();

    assert_eq!(events[1].metadata["filesystem_access"], "write");
    assert_eq!(std::fs::read(output.join("new.txt")).unwrap(), b"");
    assert_eq!(
        std::fs::read_to_string(output.join("sibling.txt")).unwrap(),
        "keep"
    );
    let error =
        execute_governed_filesystem_action(&gate, session(), action, workspace.path(), false)
            .unwrap_err();
    assert!(error.to_string().contains("already exists"));
}

#[cfg(target_os = "linux")]
#[test]
fn typed_filesystem_create_rejects_leaf_symlink_inserted_after_authorization() {
    struct InsertSymlink<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        target: std::path::PathBuf,
        outside: std::path::PathBuf,
    }
    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for InsertSymlink<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            std::os::unix::fs::symlink(&self.outside, &self.target).unwrap();
            Ok(decision)
        }
    }
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let gate = InsertSymlink {
        inner: filesystem_create_gate(workspace.path()),
        target: workspace.path().join("new.txt"),
        outside: outside.path().join("escaped.txt"),
    };

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        filesystem_write_action("new.txt"),
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("create-only target open failed"));
    assert!(!outside.path().join("escaped.txt").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn typed_filesystem_create_rejects_parent_swap_after_authorization() {
    struct SwapParent<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        parent: std::path::PathBuf,
        outside: std::path::PathBuf,
    }
    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for SwapParent<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            std::fs::rename(&self.parent, self.parent.with_extension("authorized-old")).unwrap();
            std::os::unix::fs::symlink(&self.outside, &self.parent).unwrap();
            Ok(decision)
        }
    }
    let workspace = tempfile::tempdir().unwrap();
    let parent = workspace.path().join("output");
    std::fs::create_dir(&parent).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let gate = SwapParent {
        inner: filesystem_create_gate(workspace.path()),
        parent,
        outside: outside.path().to_path_buf(),
    };

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        filesystem_write_action("output/new.txt"),
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("parent open beneath authorized root failed"));
    assert!(!outside.path().join("new.txt").exists());
}

fn filesystem_create_gate(
    workspace: &std::path::Path,
) -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::Filesystem,
            selector_id: "workspace-create".into(),
            selector: CapabilityTargetSelector::Filesystem {
                workspace_root: workspace.display().to_string(),
                path_glob: "**".into(),
                operations: vec![TargetOperation::Write],
            },
        }],
        ..CapabilityPolicy::default()
    }))
}

fn filesystem_write_action(path: &str) -> ManagedFilesystemAction {
    ManagedFilesystemAction {
        path: path.into(),
        access: ManagedFilesystemAccess::Write,
        workspace_relative: true,
    }
}

#[test]
fn governed_rest_transport_does_not_follow_redirects() {
    let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
    redirect_target.set_nonblocking(true).unwrap();
    let redirect_endpoint = redirect_target.local_addr().unwrap();
    let source = TcpListener::bind("127.0.0.1:0").unwrap();
    let source_endpoint = source.local_addr().unwrap();
    let source_server = thread::spawn(move || {
        let (mut stream, _) = source.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: http://{redirect_endpoint}/escaped\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));

    let error = execute_governed_rest_action(
        &gate,
        session(),
        ManagedRestAction {
            method: "GET".into(),
            url: format!("http://{source_endpoint}/start"),
            headers_policy: "deny_credentials".into(),
            body_policy: "empty".into(),
            timeout_millis: 500,
            retry_limit: 0,
            resolved_ips: vec!["127.0.0.1".into()],
            redirect_chain: Vec::new(),
        },
        false,
    )
    .unwrap_err();

    source_server.join().unwrap();
    assert!(error.to_string().contains("returned status 302"));
    assert!(
        matches!(redirect_target.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock)
    );
}

#[test]
fn worker_rejects_an_allowed_decision_replayed_for_different_mcp_arguments() {
    #[derive(Clone)]
    struct ReplayedDecision(ExternalActionGateDecision);

    impl GatewayExternalActionAuthorizer for ReplayedDecision {
        fn authorize_external_action(
            &self,
            _request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            Ok(self.0.clone())
        }
    }

    let approved_action = ManagedMcpToolAction {
        server_name: "local-smoke".into(),
        tool_name: "echo".into(),
        arguments_policy: "exact_arguments".into(),
        arguments: serde_json::json!({"message": "approved"}),
    };
    let policy = CapabilityPolicy {
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::McpTool,
            selector_id: "local-echo".into(),
            selector: CapabilityTargetSelector::Mcp {
                server: "local-smoke".into(),
                tool: "echo".into(),
                risk: McpRisk::Read,
                argument_schema: JsonShape::Object {
                    fields: std::collections::BTreeMap::from([(
                        "message".into(),
                        JsonShape::String,
                    )]),
                },
                allow_extra_arguments: false,
            },
        }],
        revision: "mcp-replay-test".into(),
        ..CapabilityPolicy::default()
    };
    let (_, event) = authorize_managed_external_action(
        &SimpleCapabilityAuthorizer::new(policy),
        ManagedExternalActionRequest {
            session: session(),
            action: ManagedExternalAction::McpTool(approved_action),
            high_risk: false,
        },
    )
    .unwrap();
    let replay = ReplayedDecision(ExternalActionGateDecision {
        decision: CapabilityAuthorizationDecision::Allowed,
        event,
    });

    let error = execute_governed_mcp_tool_action(
        &replay,
        session(),
        ManagedMcpToolAction {
            server_name: "local-smoke".into(),
            tool_name: "echo".into(),
            arguments_policy: "exact_arguments".into(),
            arguments: serde_json::json!({"message": "changed-after-approval"}),
        },
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("action fingerprint mismatch"));
}

#[test]
fn governed_cli_execution_uses_the_fingerprinted_empty_environment() {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_cli_action(
        &gate,
        session(),
        ManagedCliAction {
            command: "/usr/bin/env".into(),
            args: Vec::new(),
            working_dir: "/tmp".into(),
            env_policy: "empty".into(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            artifact_capture: false,
        },
        false,
    )
    .unwrap();

    assert!(events[0].metadata["canonical_target"].contains("environment"));
    assert_eq!(events[1].metadata["stdout_excerpt"], "");
}

#[test]
fn governed_cli_rejects_executable_swap_after_authorization() {
    struct SwapAfterAuthorization<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        executable: PathBuf,
        replacement: PathBuf,
    }

    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for SwapAfterAuthorization<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            std::fs::rename(&self.replacement, &self.executable).unwrap();
            Ok(decision)
        }
    }

    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("allowed-command");
    let replacement = workspace.path().join("replacement-command");
    write_executable(&executable, "authorized");
    write_executable(&replacement, "swapped");
    let gate = SwapAfterAuthorization {
        inner: RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                target_grants: vec![CapabilityTargetGrant {
                    action: CapabilityAction::Cli,
                    selector_id: "bound-cli".into(),
                    selector: CapabilityTargetSelector::Cli {
                        executable: executable.display().to_string(),
                        argv: Vec::new(),
                        environment: Default::default(),
                        cwd_glob: workspace.path().display().to_string(),
                        max_timeout_millis: 1_000,
                        max_stdout_bytes: 1_024,
                        max_stderr_bytes: 1_024,
                    },
                }],
                ..CapabilityPolicy::default()
            },
        )),
        executable: executable.clone(),
        replacement,
    };

    let error = execute_governed_cli_action(
        &gate,
        session(),
        ManagedCliAction {
            command: executable.display().to_string(),
            args: Vec::new(),
            working_dir: workspace.path().display().to_string(),
            env_policy: "empty".into(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            artifact_capture: false,
        },
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("action fingerprint mismatch"));
}

#[test]
fn governed_cli_rejects_in_place_executable_mutation_after_authorization() {
    struct MutateAfterAuthorization<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        executable: PathBuf,
    }

    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for MutateAfterAuthorization<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            let inode_before = std::fs::metadata(&self.executable).unwrap().ino();
            write_executable(&self.executable, "tampered");
            assert_eq!(
                std::fs::metadata(&self.executable).unwrap().ino(),
                inode_before
            );
            Ok(decision)
        }
    }

    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("allowed-command");
    let marker = workspace.path().join("tampered-marker");
    write_executable(&executable, "authorized");
    let gate = MutateAfterAuthorization {
        inner: RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                target_grants: vec![CapabilityTargetGrant {
                    action: CapabilityAction::Cli,
                    selector_id: "immutable-cli".into(),
                    selector: CapabilityTargetSelector::Cli {
                        executable: executable.display().to_string(),
                        argv: Vec::new(),
                        environment: Default::default(),
                        cwd_glob: workspace.path().display().to_string(),
                        max_timeout_millis: 1_000,
                        max_stdout_bytes: 1_024,
                        max_stderr_bytes: 1_024,
                    },
                }],
                ..CapabilityPolicy::default()
            },
        )),
        executable: executable.clone(),
    };

    let error = execute_governed_cli_action(
        &gate,
        session(),
        ManagedCliAction {
            command: executable.display().to_string(),
            args: Vec::new(),
            working_dir: workspace.path().display().to_string(),
            env_policy: "empty".into(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            artifact_capture: false,
        },
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("action fingerprint mismatch"));
    assert!(!marker.exists());
}

#[test]
fn cli_snapshot_rejects_in_place_mutation_between_authorization_and_copy() {
    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("allowed-command");
    write_executable(&executable, "authorized");
    let action = ManagedCliAction {
        command: executable.display().to_string(),
        args: Vec::new(),
        working_dir: workspace.path().display().to_string(),
        env_policy: "empty".into(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    };
    let decision = cli_target_decision(workspace.path(), &action);
    let inode_before = std::fs::metadata(&executable).unwrap().ino();
    write_executable(&executable, "tampered");
    assert_eq!(std::fs::metadata(&executable).unwrap().ino(), inode_before);

    let error = match open_authorized_cli_objects(&decision) {
        Ok(_) => panic!("mutated executable must not produce an immutable snapshot"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("content fingerprint"));
}

#[test]
fn sealed_cli_snapshot_executes_authorized_bytes_after_source_mutation() {
    let workspace = tempfile::tempdir().unwrap();
    // Keep the utility's real basename: argv[0] is preserved through the
    // sealed exec, and multi-call coreutils (uutils) dispatch on it.
    let executable = workspace.path().join("echo");
    copy_elf("/bin/echo", &executable);
    let action = ManagedCliAction {
        command: executable.display().to_string(),
        args: vec!["authorized".into()],
        working_dir: workspace.path().display().to_string(),
        env_policy: "empty".into(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    };
    let decision = cli_target_decision(workspace.path(), &action);
    let snapshot = open_authorized_cli_objects(&decision).unwrap();
    copy_elf("/bin/false", &executable);

    let output = snapshot.command(&action).env_clear().output().unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "authorized\n");
}

#[test]
fn sealed_cli_exec_preserves_original_program_name_as_argv0() {
    let workspace = tempfile::tempdir().unwrap();
    // /bin/sh ($0 in -c mode reflects argv[0]) copied under a custom name:
    // the child must observe the authorized path, not /proc/self/fd/N.
    let executable = workspace.path().join("argv0-probe");
    copy_elf("/bin/sh", &executable);
    let action = ManagedCliAction {
        command: executable.display().to_string(),
        args: vec!["-c".into(), "printf %s \"$0\"".into()],
        working_dir: workspace.path().display().to_string(),
        env_policy: "empty".into(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    };
    let decision = cli_target_decision(workspace.path(), &action);
    let snapshot = open_authorized_cli_objects(&decision).unwrap();

    let output = snapshot.command(&action).env_clear().output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        executable.display().to_string()
    );
}

#[test]
fn cli_rejects_cwd_swap_between_authorization_and_binding() {
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().join("cwd");
    let moved = root.path().join("cwd-authorized");
    std::fs::create_dir(&cwd).unwrap();
    let executable = root.path().join("allowed-command");
    write_executable(&executable, "authorized");
    let action = ManagedCliAction {
        command: executable.display().to_string(),
        args: Vec::new(),
        working_dir: cwd.display().to_string(),
        env_policy: "empty".into(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    };
    let decision = cli_target_decision(&cwd, &action);
    std::fs::rename(&cwd, &moved).unwrap();
    std::fs::create_dir(&cwd).unwrap();

    let error = match open_authorized_cli_objects(&decision) {
        Ok(_) => panic!("replacement cwd must not bind"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("cwd identity changed"));
}

#[test]
fn bound_cli_cwd_fd_survives_path_replacement_after_binding() {
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().join("cwd");
    let moved = root.path().join("cwd-authorized");
    std::fs::create_dir(&cwd).unwrap();
    // Keep the utility's real basename: argv[0] is preserved through the
    // sealed exec, and multi-call coreutils (uutils) dispatch on it.
    let executable = root.path().join("touch");
    copy_elf("/usr/bin/touch", &executable);
    let action = ManagedCliAction {
        command: executable.display().to_string(),
        args: vec!["cwd-marker".into()],
        working_dir: cwd.display().to_string(),
        env_policy: "empty".into(),
        timeout_millis: 1_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        artifact_capture: false,
    };
    let decision = cli_target_decision(&cwd, &action);
    let snapshot = open_authorized_cli_objects(&decision).unwrap();
    std::fs::rename(&cwd, &moved).unwrap();
    std::fs::create_dir(&cwd).unwrap();

    let output = snapshot.command(&action).env_clear().output().unwrap();

    assert!(output.status.success());
    assert!(moved.join("cwd-marker").exists());
    assert!(!cwd.join("cwd-marker").exists());
}

fn cli_target_decision(workspace: &Path, action: &ManagedCliAction) -> ExternalActionGateDecision {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            target_grants: vec![CapabilityTargetGrant {
                action: CapabilityAction::Cli,
                selector_id: "immutable-cli".into(),
                selector: CapabilityTargetSelector::Cli {
                    executable: action.command.clone(),
                    argv: action.args.clone(),
                    environment: Default::default(),
                    cwd_glob: workspace.display().to_string(),
                    max_timeout_millis: action.timeout_millis,
                    max_stdout_bytes: action.stdout_limit_bytes,
                    max_stderr_bytes: action.stderr_limit_bytes,
                },
            }],
            ..CapabilityPolicy::default()
        },
    ));
    gate.authorize_external_action(ManagedExternalActionRequest {
        session: session(),
        action: ManagedExternalAction::Cli(action.clone()),
        high_risk: false,
    })
    .unwrap()
}

#[test]
fn typed_filesystem_execute_runs_the_bound_workspace_inode() {
    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("tool");
    copy_elf("/bin/true", &executable);
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            target_grants: vec![CapabilityTargetGrant {
                action: CapabilityAction::Filesystem,
                selector_id: "workspace-execute".into(),
                selector: CapabilityTargetSelector::Filesystem {
                    workspace_root: workspace.path().display().to_string(),
                    path_glob: "tool".into(),
                    operations: vec![TargetOperation::Execute],
                },
            }],
            ..CapabilityPolicy::default()
        },
    ));

    let events = execute_governed_filesystem_action(
        &gate,
        session(),
        ManagedFilesystemAction {
            path: "tool".into(),
            access: ManagedFilesystemAccess::Execute,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap();

    assert_eq!(events[1].metadata["content_excerpt"], "");
    assert_eq!(events[1].metadata["filesystem_access"], "execute");
}

#[test]
fn typed_filesystem_execute_rejects_in_place_mutation_after_authorization() {
    struct MutateAfterAuthorization<A> {
        inner: RuntimeGatewayExternalActionAuthorizer<A>,
        executable: PathBuf,
    }

    impl<A: CapabilityAuthorizer> GatewayExternalActionAuthorizer for MutateAfterAuthorization<A> {
        fn authorize_external_action(
            &self,
            request: ManagedExternalActionRequest,
        ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
            let decision = self.inner.authorize_external_action(request)?;
            let inode_before = std::fs::metadata(&self.executable).unwrap().ino();
            copy_elf("/bin/false", &self.executable);
            assert_eq!(
                std::fs::metadata(&self.executable).unwrap().ino(),
                inode_before
            );
            Ok(decision)
        }
    }

    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("tool");
    let marker = workspace.path().join("tampered-filesystem-marker");
    copy_elf("/bin/true", &executable);
    let gate = MutateAfterAuthorization {
        inner: RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                target_grants: vec![CapabilityTargetGrant {
                    action: CapabilityAction::Filesystem,
                    selector_id: "workspace-execute".into(),
                    selector: CapabilityTargetSelector::Filesystem {
                        workspace_root: workspace.path().display().to_string(),
                        path_glob: "tool".into(),
                        operations: vec![TargetOperation::Execute],
                    },
                }],
                ..CapabilityPolicy::default()
            },
        )),
        executable,
    };

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        ManagedFilesystemAction {
            path: "tool".into(),
            access: ManagedFilesystemAccess::Execute,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("content fingerprint"));
    assert!(!marker.exists());
}

#[test]
fn unix_authorizer_rejects_a_same_uid_server_with_the_wrong_pid() {
    let socket_dir = tempfile::tempdir().unwrap();
    let socket = socket_dir.path().join("fake-authorizer.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let fake = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut ignored = String::new();
        stream.read_to_string(&mut ignored).unwrap();
    });
    let client = UnixGatewayExternalActionAuthorizer::new_authenticated(
        &socket,
        std::process::id().saturating_add(1),
    );

    let decision = client
        .authorize_external_action(ManagedExternalActionRequest {
            session: session(),
            action: ManagedExternalAction::McpTool(ManagedMcpToolAction {
                server_name: "local-smoke".into(),
                tool_name: "echo".into(),
                arguments_policy: "exact_arguments".into(),
                arguments: serde_json::json!({"message": "must-not-run"}),
            }),
            high_risk: false,
        })
        .unwrap();

    assert_eq!(decision.decision, CapabilityAuthorizationDecision::Denied);
    assert!(decision
        .event
        .message
        .as_deref()
        .unwrap()
        .contains("peer PID"));
    fake.join().unwrap();
}

#[test]
fn worker_rejects_target_action_when_it_cannot_recompute_a_canonical_target() {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        },
    ));
    let error = execute_governed_cli_action(
        &gate,
        session(),
        ManagedCliAction {
            command: "ferrogate-command-that-must-not-spawn".into(),
            args: Vec::new(),
            working_dir: "/tmp".into(),
            env_policy: "empty".into(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            artifact_capture: false,
        },
        false,
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("cannot derive a canonical execution target"));
}

#[test]
fn cli_rejects_shebang_executable_before_interpreter_resolution() {
    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("script");
    let marker = workspace.path().join("script-ran");
    std::fs::write(
        &executable,
        format!("#!/bin/sh\n/usr/bin/touch {}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let action = cli_action(
        &executable,
        workspace.path(),
        Vec::new(),
        1_000,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("shebang scripts are denied"));
    assert!(!marker.exists());
}

#[test]
fn filesystem_execute_rejects_shebang_executable_before_interpreter_resolution() {
    let workspace = tempfile::tempdir().unwrap();
    let executable = workspace.path().join("script");
    let marker = workspace.path().join("filesystem-script-ran");
    std::fs::write(
        &executable,
        format!("#!/bin/sh\n/usr/bin/touch {}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let gate = filesystem_execute_gate(workspace.path(), "script");

    let error = execute_governed_filesystem_action(
        &gate,
        session(),
        ManagedFilesystemAction {
            path: "script".into(),
            access: ManagedFilesystemAccess::Execute,
            workspace_relative: true,
        },
        workspace.path(),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("shebang scripts are denied"));
    assert!(!marker.exists());
}

#[test]
fn concurrent_cli_child_cannot_enumerate_another_action_snapshot() {
    let workspace = tempfile::tempdir().unwrap();
    let held_executable = workspace.path().join("held-command");
    copy_elf("/bin/true", &held_executable);
    let held_action = cli_action(
        &held_executable,
        workspace.path(),
        Vec::new(),
        1_000,
        1_024,
        1_024,
    );
    let held_decision = cli_target_decision(workspace.path(), &held_action);
    let _held_snapshot = open_authorized_cli_objects(&held_decision).unwrap();
    let probe = r#"for fd in /proc/self/fd/*; do link=$(readlink "$fd" 2>/dev/null || :); case "$link" in *ferrogate-cli-executable*) printf '%s\n' "$link";; esac; done"#;
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), probe.into()],
        1_000,
        4_096,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let execution = run_authorized_cli_action(&action, &decision).unwrap();

    assert_eq!(execution.stdout_excerpt, "");
}

#[test]
fn cli_stdout_overflow_kills_the_process_group_without_waiting_for_timeout() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("overflow-descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; while :; do printf 1234567890; done",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        64,
        64,
    );
    let decision = cli_target_decision(workspace.path(), &action);
    let started = Instant::now();

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("stdout exceeded 64 bytes"));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn cli_stderr_overflow_kills_the_process_group_without_waiting_for_timeout() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("stderr-overflow-descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; while :; do printf 1234567890 >&2; done",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        64,
        64,
    );
    let decision = cli_target_decision(workspace.path(), &action);
    let started = Instant::now();

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("stderr exceeded 64 bytes"));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn stopped_bounded_reader_drains_buffered_chunks_and_still_enforces_limit() {
    let captured = b"buffered-output".repeat(1_024);
    assert!(captured.len() > 8 * 1024);
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    writer.write_all(&captured).unwrap();
    writer.shutdown(std::net::Shutdown::Write).unwrap();
    configure_nonblocking_pipe(&reader).unwrap();
    let stop = Arc::new(AtomicBool::new(true));

    let under_limit = spawn_bounded_pipe_reader(
        reader,
        u64::try_from(captured.len()).unwrap(),
        Arc::clone(&stop),
    )
    .join()
    .unwrap()
    .unwrap();

    let BoundedPipeRead::Complete(actual) = under_limit else {
        panic!("buffered under-limit output must be captured completely");
    };
    assert_eq!(actual, captured);

    let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    writer.write_all(&captured).unwrap();
    writer.shutdown(std::net::Shutdown::Write).unwrap();
    configure_nonblocking_pipe(&reader).unwrap();
    let over_limit = spawn_bounded_pipe_reader(reader, 8 * 1024, stop)
        .join()
        .unwrap()
        .unwrap();
    assert!(matches!(over_limit, BoundedPipeRead::Exceeded));
}

#[test]
fn fast_exit_cli_captures_exact_multi_chunk_stdout_and_stderr() {
    let workspace = tempfile::tempdir().unwrap();
    let stdout = "stdout-fast-exit".repeat(1_024);
    let stderr = "stderr-fast-exit".repeat(1_024);
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec![
            "-c".into(),
            "printf '%s' \"$1\"; printf '%s' \"$2\" >&2".into(),
            "ferrogate-fast-exit".into(),
            stdout.clone(),
            stderr.clone(),
        ],
        2_000,
        u64::try_from(stdout.len()).unwrap(),
        u64::try_from(stderr.len()).unwrap(),
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let execution = run_authorized_cli_action(&action, &decision).unwrap();

    assert_eq!(execution.stdout_excerpt, stdout);
    assert_eq!(execution.stderr_excerpt, stderr);
}

#[test]
fn fast_exit_cli_stdout_over_cap_is_rejected_after_leader_exit() {
    let workspace = tempfile::tempdir().unwrap();
    let output = "stdout-over-cap".repeat(1_024);
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec![
            "-c".into(),
            "printf '%s' \"$1\"".into(),
            "ferrogate-fast-exit".into(),
            output,
        ],
        2_000,
        8 * 1024,
        8 * 1024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("stdout exceeded"));
}

#[test]
fn fast_exit_cli_stderr_over_cap_is_rejected_after_leader_exit() {
    let workspace = tempfile::tempdir().unwrap();
    let output = "stderr-over-cap".repeat(1_024);
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec![
            "-c".into(),
            "printf '%s' \"$1\" >&2".into(),
            "ferrogate-fast-exit".into(),
            output,
        ],
        2_000,
        8 * 1024,
        8 * 1024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("stderr exceeded"));
}

#[test]
fn cli_reaps_forked_descendant_when_leader_exits() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; exit 0",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(run_authorized_cli_action(&action, &decision))
            .unwrap()
    });

    let result = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            kill_pid_from_file(&pid_file);
            let _ = rx.recv_timeout(Duration::from_secs(1));
            panic!("CLI execution waited on a forked descendant: {error}");
        }
    };

    result.unwrap();
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn cli_output_collection_does_not_wait_on_descendant_that_changes_session() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("new-session-descendant.pid");
    let shell = format!(
        "setsid /bin/sh -c 'sleep 30' & child=$!; printf '%s' \"$child\" > {}; exit 0",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(run_authorized_cli_action(&action, &decision))
            .unwrap()
    });

    let result = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            kill_pid_from_file(&pid_file);
            let _ = rx.recv_timeout(Duration::from_secs(1));
            panic!("CLI output collection waited on a new-session descendant: {error}");
        }
    };

    result.unwrap();
    kill_pid_from_file(&pid_file);
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn cli_timeout_kills_and_reaps_forked_descendant_group() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("timeout-descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; wait",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        100,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let error = expect_cli_error(run_authorized_cli_action(&action, &decision));

    assert!(error.to_string().contains("timed out after 100ms"));
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn cli_cancellation_kills_and_reaps_forked_descendant_group() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("cancel-descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; wait",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let cancellation = run_authorized_cli_action_until_cancelled(&action, &decision).unwrap();

    assert_eq!(cancellation.cancellation_reason, "operator_cancelled");
    assert_pid_file_process_exited(&pid_file);
}

#[test]
fn cli_cancellation_cleans_descendant_when_leader_exits_before_cancel_check() {
    let workspace = tempfile::tempdir().unwrap();
    let pid_file = workspace.path().join("early-exit-descendant.pid");
    let shell = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; exit 0",
        pid_file.display()
    );
    let action = cli_action(
        Path::new("/bin/sh"),
        workspace.path(),
        vec!["-c".into(), shell],
        2_000,
        1_024,
        1_024,
    );
    let decision = cli_target_decision(workspace.path(), &action);

    let error = match run_authorized_cli_action_until_cancelled(&action, &decision) {
        Ok(_) => panic!("leader unexpectedly remained active until cancellation"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("completed before cancellation"));
    assert_pid_file_process_exited(&pid_file);
}

fn cli_action(
    executable: &Path,
    cwd: &Path,
    args: Vec<String>,
    timeout_millis: u64,
    stdout_limit_bytes: u64,
    stderr_limit_bytes: u64,
) -> ManagedCliAction {
    ManagedCliAction {
        command: executable.display().to_string(),
        args,
        working_dir: cwd.display().to_string(),
        env_policy: "empty".into(),
        timeout_millis,
        stdout_limit_bytes,
        stderr_limit_bytes,
        artifact_capture: false,
    }
}

fn filesystem_execute_gate(
    workspace: &Path,
    path_glob: &str,
) -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::Filesystem,
            selector_id: "workspace-execute".into(),
            selector: CapabilityTargetSelector::Filesystem {
                workspace_root: workspace.display().to_string(),
                path_glob: path_glob.into(),
                operations: vec![TargetOperation::Execute],
            },
        }],
        ..CapabilityPolicy::default()
    }))
}

fn kill_pid_from_file(path: &Path) {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(pid) = raw.parse::<i32>() else {
        return;
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return;
    };
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
}

fn assert_pid_file_process_exited(path: &Path) {
    let raw = std::fs::read_to_string(path).unwrap();
    let pid = rustix::process::Pid::from_raw(raw.parse::<i32>().unwrap()).unwrap();
    for _ in 0..100 {
        if rustix::process::test_kill_process(pid).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    panic!("descendant process {pid} remained alive");
}

fn expect_cli_error(
    result: Result<GovernedCliExecution, FrameworkAdapterError>,
) -> FrameworkAdapterError {
    match result {
        Ok(_) => panic!("managed CLI execution unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn write_executable(path: &Path, output: &str) {
    let source = if output == "authorized" {
        "/bin/true"
    } else {
        "/bin/false"
    };
    copy_elf(source, path);
}

fn copy_elf(source: &str, destination: &Path) {
    std::fs::copy(source, destination).unwrap();
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "session-target".into(),
        run_id: "run-target".into(),
        tenant_id: "tenant-target".into(),
        workspace_id: "workspace-target".into(),
        worker_id: "worker-target".into(),
        isolation_backend: "firecracker".into(),
        adapter_name: "native-harness".into(),
        adapter_version: "test".into(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::Managed,
    }
}
