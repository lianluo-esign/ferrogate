// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Canonical target-level capability selectors for managed agent actions.

use std::{collections::BTreeMap, net::IpAddr, path::Component};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassOnlyPolicyMode {
    #[default]
    Deny,
    LegacyClassWide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOperation {
    Read,
    Write,
    Delete,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpRisk {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JsonShape {
    Null,
    Boolean,
    Number,
    String,
    Array {
        items: Box<JsonShape>,
    },
    Object {
        #[serde(default)]
        fields: BTreeMap<String, JsonShape>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilityTargetSelector {
    Mcp {
        server: String,
        tool: String,
        risk: McpRisk,
        argument_schema: JsonShape,
        #[serde(default)]
        allow_extra_arguments: bool,
    },
    Filesystem {
        workspace_root: String,
        path_glob: String,
        operations: Vec<TargetOperation>,
    },
    Network {
        scheme: String,
        host: String,
        port: u16,
        #[serde(default)]
        method: Option<String>,
        #[serde(default = "default_path_glob")]
        path_glob: String,
        #[serde(default)]
        allowed_ips: Vec<IpAddr>,
        #[serde(default)]
        allow_redirects: bool,
    },
    Secret {
        reference_namespace: String,
        reference_name: String,
        destination_adapter: String,
        destination_action: String,
    },
    Cli {
        executable: String,
        argv: Vec<String>,
        #[serde(default)]
        environment: BTreeMap<String, String>,
        cwd_glob: String,
        max_timeout_millis: u64,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
    },
}

impl CapabilityTargetSelector {
    pub fn supports_action(&self, action: crate::CapabilityAction) -> bool {
        matches!(
            (self, action),
            (Self::Mcp { .. }, crate::CapabilityAction::McpTool)
                | (Self::Filesystem { .. }, crate::CapabilityAction::Filesystem)
                | (Self::Network { .. }, crate::CapabilityAction::Rest)
                | (Self::Network { .. }, crate::CapabilityAction::NetworkEgress)
                | (Self::Secret { .. }, crate::CapabilityAction::Secret)
                | (Self::Cli { .. }, crate::CapabilityAction::Cli)
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Mcp {
                server,
                tool,
                argument_schema,
                ..
            } => {
                canonical_identifier("MCP server", server)?;
                canonical_identifier("MCP tool", tool)?;
                if !matches!(argument_schema, JsonShape::Object { .. }) {
                    return Err("MCP argument schema root must be an object".to_string());
                }
                validate_json_shape(argument_schema)?;
                Ok(())
            }
            Self::Filesystem {
                workspace_root,
                path_glob,
                operations,
            } => {
                let root = std::fs::canonicalize(workspace_root)
                    .map_err(|error| format!("workspace root cannot be resolved: {error}"))?;
                if !root.is_dir() {
                    return Err("workspace root must be a directory".to_string());
                }
                if path_glob.trim().is_empty() {
                    return Err("filesystem path_glob must not be empty".to_string());
                }
                if operations.is_empty() {
                    return Err("filesystem selector requires at least one operation".to_string());
                }
                Ok(())
            }
            Self::Network {
                scheme,
                host,
                port,
                method,
                path_glob,
                allowed_ips,
                allow_redirects,
                ..
            } => {
                let scheme = scheme.trim().to_ascii_lowercase();
                if !matches!(scheme.as_str(), "http" | "https" | "tcp" | "tls") {
                    return Err(
                        "network selector scheme must be http, https, tcp, or tls".to_string()
                    );
                }
                if *port == 0 {
                    return Err("network selector port must be greater than zero".to_string());
                }
                if method
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty())
                {
                    return Err("network selector method must not be empty".to_string());
                }
                if path_glob.trim().is_empty() {
                    return Err("network selector path_glob must not be empty".to_string());
                }
                let host = normalize_host(host)?;
                if host.parse::<IpAddr>().is_err() && allowed_ips.is_empty() {
                    return Err(
                        "hostname target selector requires a non-empty operator allowed_ips allowlist"
                            .to_string(),
                    );
                }
                if *allow_redirects {
                    return Err(
                        "redirect authorization is unsupported until execution-derived hops are enforced"
                            .to_string(),
                    );
                }
                Ok(())
            }
            Self::Secret {
                reference_namespace,
                reference_name,
                destination_adapter,
                destination_action,
                ..
            } => {
                canonical_secret_reference(reference_namespace, reference_name)?;
                canonical_identifier("secret destination adapter", destination_adapter)?;
                canonical_identifier("secret destination action", destination_action)?;
                Ok(())
            }
            Self::Cli {
                executable,
                argv,
                environment,
                cwd_glob,
                max_timeout_millis,
                max_stdout_bytes,
                max_stderr_bytes,
            } => {
                canonical_cli_executable(executable)?;
                if argv.iter().any(|argument| argument.contains('\0')) {
                    return Err("CLI argv contains a NUL byte".to_string());
                }
                if !environment.is_empty() {
                    return Err(
                        "CLI custom environment is unsupported; managed execution is empty-env"
                            .to_string(),
                    );
                }
                if cwd_glob.trim().is_empty() {
                    return Err("CLI cwd_glob must not be empty".to_string());
                }
                if *max_timeout_millis == 0 || *max_stdout_bytes == 0 || *max_stderr_bytes == 0 {
                    return Err("CLI resource bounds must be greater than zero".to_string());
                }
                Ok(())
            }
        }
    }
}

fn default_path_glob() -> String {
    "/**".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalCapabilityTarget {
    Mcp {
        server: String,
        tool: String,
        arguments_fingerprint: String,
        argument_shape: JsonShape,
    },
    Filesystem {
        path: String,
        operation: TargetOperation,
    },
    Network {
        scheme: String,
        host: String,
        port: u16,
        method: Option<String>,
        path: String,
        resolved_ips: Vec<IpAddr>,
        redirects: Vec<String>,
    },
    Secret {
        reference_namespace: String,
        reference_fingerprint: String,
        destination_adapter: String,
        destination_action: String,
    },
    Cli {
        executable: String,
        executable_device: u64,
        executable_inode: u64,
        executable_content_fingerprint: String,
        argv: Vec<String>,
        environment: BTreeMap<String, String>,
        cwd: String,
        cwd_device: u64,
        cwd_inode: u64,
        timeout_millis: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundCapabilityTarget {
    pub canonical_target: String,
    pub action_fingerprint: String,
    pub approval_required: bool,
}

impl CanonicalCapabilityTarget {
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("canonical target serialization is infallible")
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        format!("sha256:{digest:x}")
    }

    pub fn matches(&self, selector: &CapabilityTargetSelector) -> Result<bool, String> {
        match (self, selector) {
            (
                Self::Mcp {
                    server,
                    tool,
                    argument_shape,
                    ..
                },
                CapabilityTargetSelector::Mcp {
                    server: allowed_server,
                    tool: allowed_tool,
                    risk: _,
                    argument_schema,
                    allow_extra_arguments,
                },
            ) => Ok(server == allowed_server
                && tool == allowed_tool
                && json_shape_matches(argument_shape, argument_schema, *allow_extra_arguments)),
            (
                Self::Filesystem { path, operation },
                CapabilityTargetSelector::Filesystem {
                    workspace_root,
                    path_glob,
                    operations,
                },
            ) => {
                let root = std::fs::canonicalize(workspace_root)
                    .map_err(|error| format!("workspace root cannot be resolved: {error}"))?;
                let requested = root.join(path);
                let resolved = match std::fs::canonicalize(&requested) {
                    Ok(resolved) => resolved,
                    Err(_) if *operation == TargetOperation::Write => {
                        let parent = requested.parent().ok_or_else(|| {
                            "filesystem write target has no resolvable parent".to_string()
                        })?;
                        let resolved_parent = std::fs::canonicalize(parent).map_err(|error| {
                            format!("filesystem write parent cannot be resolved: {error}")
                        })?;
                        resolved_parent.join(
                            requested.file_name().ok_or_else(|| {
                                "filesystem write target has no filename".to_string()
                            })?,
                        )
                    }
                    Err(error) => {
                        return Err(format!(
                            "filesystem target cannot be resolved without ambiguity: {error}"
                        ))
                    }
                };
                if !resolved.starts_with(&root) {
                    return Err("filesystem target resolves outside workspace root".to_string());
                }
                // Reads/executes resolve to an existing inode; a hard link to that
                // inode from outside the root would otherwise slip past the
                // starts_with confinement (see `reject_hardlinked_read_target`).
                // Writes are create-only (the leaf must not yet exist), so there is
                // no inode to alias.
                if *operation != TargetOperation::Write {
                    reject_hardlinked_read_target(&resolved)?;
                }
                Ok(operations.contains(operation) && glob_matches(path_glob, path))
            }
            (
                Self::Network {
                    scheme,
                    host,
                    port,
                    method,
                    path,
                    resolved_ips,
                    redirects,
                },
                CapabilityTargetSelector::Network {
                    scheme: allowed_scheme,
                    host: allowed_host,
                    port: allowed_port,
                    method: allowed_method,
                    path_glob,
                    allowed_ips,
                    allow_redirects,
                },
            ) => {
                let literal_host = host.parse::<IpAddr>().ok();
                let normalized_allowed_host = normalize_host(allowed_host)?;
                if normalized_allowed_host.parse::<IpAddr>().is_err() && allowed_ips.is_empty() {
                    return Err(
                        "hostname target selector requires a non-empty operator allowed_ips allowlist"
                            .to_string(),
                    );
                }
                if literal_host.is_none() && resolved_ips.is_empty() {
                    return Err("hostname target requires pinned resolved_ips evidence".to_string());
                }
                if literal_host
                    .is_some_and(|literal| resolved_ips.iter().any(|resolved| *resolved != literal))
                {
                    return Err("literal host conflicts with resolved_ips evidence".to_string());
                }
                if !allowed_ips.is_empty()
                    && (resolved_ips.is_empty()
                        || resolved_ips.iter().any(|ip| !allowed_ips.contains(ip)))
                {
                    return Err("resolved IP is outside the selector allowlist".to_string());
                }
                if *allow_redirects || !redirects.is_empty() {
                    return Err(
                        "redirects must be derived and checked by the execution transport; caller-declared chains are rejected"
                            .to_string(),
                    );
                }
                Ok(scheme == &allowed_scheme.to_ascii_lowercase()
                    && host == &normalized_allowed_host
                    && port == allowed_port
                    && method
                        == &allowed_method
                            .as_ref()
                            .map(|value| value.to_ascii_uppercase())
                    && glob_matches(path_glob, path))
            }
            (
                Self::Secret {
                    reference_namespace,
                    reference_fingerprint,
                    destination_adapter,
                    destination_action,
                },
                CapabilityTargetSelector::Secret {
                    reference_namespace: allowed_namespace,
                    reference_name: allowed_name,
                    destination_adapter: allowed_adapter,
                    destination_action: allowed_action,
                },
            ) => Ok(reference_namespace == allowed_namespace
                && reference_fingerprint
                    == &opaque_reference_fingerprint(&canonical_secret_reference(
                        allowed_namespace,
                        allowed_name,
                    )?)
                && destination_adapter == allowed_adapter
                && destination_action == allowed_action),
            (
                Self::Cli {
                    executable,
                    executable_device: _,
                    executable_inode: _,
                    executable_content_fingerprint: _,
                    argv,
                    environment,
                    cwd,
                    cwd_device: _,
                    cwd_inode: _,
                    timeout_millis,
                    stdout_bytes,
                    stderr_bytes,
                },
                CapabilityTargetSelector::Cli {
                    executable: allowed_executable,
                    argv: allowed_argv,
                    environment: allowed_environment,
                    cwd_glob,
                    max_timeout_millis,
                    max_stdout_bytes,
                    max_stderr_bytes,
                },
            ) => Ok(executable == &canonical_cli_executable(allowed_executable)?
                && argv == allowed_argv
                && environment == allowed_environment
                && glob_matches(cwd_glob, cwd)
                && timeout_millis <= max_timeout_millis
                && stdout_bytes <= max_stdout_bytes
                && stderr_bytes <= max_stderr_bytes),
            _ => Ok(false),
        }
    }

    pub fn bind(
        &self,
        selector: &CapabilityTargetSelector,
    ) -> Result<Option<BoundCapabilityTarget>, String> {
        if !self.matches(selector)? {
            return Ok(None);
        }
        let canonical_target =
            match (self, selector) {
                (
                    Self::Filesystem { path, operation },
                    CapabilityTargetSelector::Filesystem { workspace_root, .. },
                ) => {
                    let root = std::fs::canonicalize(workspace_root)
                        .map_err(|error| format!("workspace root cannot be resolved: {error}"))?;
                    if *operation == TargetOperation::Write {
                        let requested = root.join(path);
                        let parent = requested.parent().ok_or_else(|| {
                            "filesystem write target has no resolvable parent".to_string()
                        })?;
                        let parent = std::fs::canonicalize(parent).map_err(|error| {
                            format!("filesystem write parent cannot be resolved: {error}")
                        })?;
                        if !parent.starts_with(&root) {
                            return Err("filesystem write parent resolves outside workspace root"
                                .to_string());
                        }
                        let leaf = requested
                            .file_name()
                            .ok_or_else(|| "filesystem write target has no filename".to_string())?;
                        let leaf_name = leaf.to_str().ok_or_else(|| {
                            "filesystem write target filename is not UTF-8".to_string()
                        })?;
                        let target = parent.join(leaf);
                        match std::fs::symlink_metadata(&target) {
                            Ok(_) => return Err(
                                "filesystem write target already exists; writes are create-only"
                                    .to_string(),
                            ),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(format!(
                                    "filesystem write target existence cannot be checked: {error}"
                                ))
                            }
                        }
                        let (root_device, root_inode, parent_device, parent_inode) =
                            filesystem_object_identities(&root, &parent)?;
                        return serde_json::to_string(&serde_json::json!({
                            "kind": "filesystem",
                            "workspace_root": root,
                            "resolved_parent": parent,
                            "leaf_name": leaf_name,
                            "operation": operation,
                            "root_device": root_device,
                            "root_inode": root_inode,
                            "parent_device": parent_device,
                            "parent_inode": parent_inode,
                            "target_must_not_exist": true,
                        }))
                        .map(|canonical_target| {
                            let action_fingerprint =
                                opaque_reference_fingerprint(&canonical_target);
                            Some(BoundCapabilityTarget {
                                canonical_target,
                                action_fingerprint,
                                approval_required: false,
                            })
                        })
                        .map_err(|error| {
                            format!("bound filesystem target serialization failed: {error}")
                        });
                    }
                    let target = std::fs::canonicalize(root.join(path)).map_err(|error| {
                        format!("filesystem target cannot be resolved without ambiguity: {error}")
                    })?;
                    if !target.starts_with(&root) {
                        return Err("filesystem target resolves outside workspace root".to_string());
                    }
                    // A hard link beneath the root can alias an inode named from
                    // outside the root; the dev/ino pin below would faithfully bind
                    // that outside inode. Fail closed on any multiply-linked
                    // read/execute target before recording its identity.
                    reject_hardlinked_read_target(&target)?;
                    let (root_device, root_inode, target_device, target_inode) =
                        filesystem_object_identities(&root, &target)?;
                    let target_content_fingerprint = (*operation == TargetOperation::Execute)
                        .then(|| file_content_fingerprint(&target, "filesystem executable"))
                        .transpose()?;
                    serde_json::to_string(&serde_json::json!({
                        "kind": "filesystem",
                        "workspace_root": root,
                        "resolved_path": target,
                        "operation": operation,
                        "root_device": root_device,
                        "root_inode": root_inode,
                        "target_device": target_device,
                        "target_inode": target_inode,
                        "target_content_fingerprint": target_content_fingerprint,
                    }))
                    .expect("bound filesystem target serialization is infallible")
                }
                _ => self.canonical_json(),
            };
        let action_fingerprint = opaque_reference_fingerprint(&canonical_target);
        let approval_required = matches!(
            selector,
            CapabilityTargetSelector::Mcp {
                risk: McpRisk::Write,
                ..
            }
        );
        Ok(Some(BoundCapabilityTarget {
            canonical_target,
            action_fingerprint,
            approval_required,
        }))
    }
}

#[cfg(unix)]
fn filesystem_object_identities(
    root: &std::path::Path,
    target: &std::path::Path,
) -> Result<(u64, u64, u64, u64), String> {
    use std::os::unix::fs::MetadataExt;

    let root_metadata = std::fs::metadata(root)
        .map_err(|error| format!("workspace root identity cannot be read: {error}"))?;
    let target_metadata = std::fs::metadata(target)
        .map_err(|error| format!("filesystem target identity cannot be read: {error}"))?;
    Ok((
        root_metadata.dev(),
        root_metadata.ino(),
        target_metadata.dev(),
        target_metadata.ino(),
    ))
}

#[cfg(not(unix))]
fn filesystem_object_identities(
    _root: &std::path::Path,
    _target: &std::path::Path,
) -> Result<(u64, u64, u64, u64), String> {
    Err("filesystem object identity binding is unsupported on this platform".to_string())
}

/// Fail closed on a read/execute target whose inode is reachable from more than
/// one directory entry (a hard link).
///
/// `canonicalize` + `starts_with(root)` and the execution-layer
/// `openat2(RESOLVE_BENEATH | NO_SYMLINKS)` both accept a hard link that lives
/// beneath the workspace root, because the directory entry genuinely *is*
/// beneath the root and a hard link is not a symlink. But a hard link is only an
/// additional name for an inode: the same inode can simultaneously be named by a
/// path *outside* the root (e.g. `/etc/shadow` hard-linked to
/// `<root>/allowed.txt`), so reading the in-workspace name discloses the outside
/// content and the dev/ino pin still matches. There is no feasible way to
/// enumerate every alias of an inode without scanning the whole filesystem, so
/// we reject any multiply-linked read/execute target outright.
///
/// Tradeoff: a legitimately hard-linked file that lives *entirely* inside the
/// workspace is also refused for managed read/execute. That is the fail-closed
/// price of not being able to prove the absence of an out-of-root alias; managed
/// read/execute targets must therefore be single-link (`st_nlink == 1`) files.
#[cfg(unix)]
fn reject_hardlinked_read_target(target: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(target)
        .map_err(|error| format!("filesystem target identity cannot be read: {error}"))?;
    if metadata.nlink() > 1 {
        return Err(
            "filesystem target is hard-linked (st_nlink > 1); its inode may alias content outside the workspace root"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hardlinked_read_target(_target: &std::path::Path) -> Result<(), String> {
    Err("filesystem hard-link containment is unsupported on this platform".to_string())
}

pub fn opaque_reference_fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{digest:x}")
}

pub fn canonical_mcp_target(
    server: &str,
    tool: &str,
    arguments_json: &str,
    _caller_high_risk: bool,
) -> Result<CanonicalCapabilityTarget, String> {
    let server = canonical_identifier("MCP server", server)?;
    let tool = canonical_identifier("MCP tool", tool)?;
    let value: serde_json::Value = serde_json::from_str(arguments_json)
        .map_err(|error| format!("MCP arguments must be JSON: {error}"))?;
    value
        .as_object()
        .ok_or_else(|| "MCP arguments must be a JSON object".to_string())?;
    let argument_shape = json_shape(&value)?;
    let normalized_arguments = canonical_json_value(&value);
    Ok(CanonicalCapabilityTarget::Mcp {
        server,
        tool,
        arguments_fingerprint: opaque_reference_fingerprint(&normalized_arguments),
        argument_shape,
    })
}

fn canonical_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("JSON string serialization is infallible")
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(left, _)| *left);
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key)
                            .expect("JSON object key serialization is infallible"),
                        canonical_json_value(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub fn canonical_filesystem_target(
    path: &str,
    operation: TargetOperation,
    workspace_relative: bool,
) -> Result<CanonicalCapabilityTarget, String> {
    if !workspace_relative {
        return Err("filesystem target must be workspace-relative".to_string());
    }
    let normalized = normalize_relative_path(path)?;
    Ok(CanonicalCapabilityTarget::Filesystem {
        path: normalized,
        operation,
    })
}

pub fn bind_filesystem_target(
    path: &str,
    operation: TargetOperation,
    workspace_root: &str,
) -> Result<BoundCapabilityTarget, String> {
    canonical_filesystem_target(path, operation, true)?
        .bind(&CapabilityTargetSelector::Filesystem {
            workspace_root: workspace_root.to_string(),
            path_glob: "**".to_string(),
            operations: vec![operation],
        })?
        .ok_or_else(|| "filesystem target does not bind to its execution root".to_string())
}

pub fn canonical_network_url(
    url: &str,
    method: Option<&str>,
    resolved_ips: &[String],
    redirects: &[String],
) -> Result<CanonicalCapabilityTarget, String> {
    if !redirects.is_empty() {
        return Err("caller-declared redirect chains are not trusted".to_string());
    }
    if contains_ambiguous_percent_encoding(url) {
        return Err("URL contains ambiguous encoded path separators or traversal".to_string());
    }
    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| "network target requires an absolute URL".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("network target scheme must be http or https".to_string());
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.contains('@') || authority.is_empty() {
        return Err("network target authority is ambiguous".to_string());
    }
    let (host, port) = parse_authority(authority, &scheme)?;
    let suffix = &remainder[authority_end..];
    if suffix.contains('#') {
        return Err("network target fragments are not authorized".to_string());
    }
    let path = match suffix.split_once('?') {
        Some((path, query)) => format!("{}?{}", normalize_url_path(path)?, query),
        None => normalize_url_path(suffix)?,
    };
    let mut ips = resolved_ips
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid resolved IP {value}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ips.sort();
    ips.dedup();
    Ok(CanonicalCapabilityTarget::Network {
        scheme,
        host,
        port,
        method: method.map(|value| value.trim().to_ascii_uppercase()),
        path,
        resolved_ips: ips,
        redirects: redirects.to_vec(),
    })
}

pub fn canonical_network_host(
    protocol: &str,
    host: &str,
    port: u16,
    resolved_ips: &[String],
) -> Result<CanonicalCapabilityTarget, String> {
    let scheme = protocol.trim().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "tcp" | "tls" | "http" | "https") {
        return Err("network egress protocol must be tcp, tls, http, or https".to_string());
    }
    let host = normalize_host(host)?;
    let mut ips = resolved_ips
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid resolved IP {value}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ips.sort();
    ips.dedup();
    Ok(CanonicalCapabilityTarget::Network {
        scheme,
        host,
        port,
        method: None,
        path: "/".to_string(),
        resolved_ips: ips,
        redirects: Vec::new(),
    })
}

fn json_shape(value: &serde_json::Value) -> Result<JsonShape, String> {
    match value {
        serde_json::Value::Null => Ok(JsonShape::Null),
        serde_json::Value::Bool(_) => Ok(JsonShape::Boolean),
        serde_json::Value::Number(_) => Ok(JsonShape::Number),
        serde_json::Value::String(_) => Ok(JsonShape::String),
        serde_json::Value::Object(object) => Ok(JsonShape::Object {
            fields: object
                .iter()
                .map(|(key, value)| Ok((key.clone(), json_shape(value)?)))
                .collect::<Result<_, String>>()?,
        }),
        serde_json::Value::Array(values) => {
            let Some(first) = values.first() else {
                return Err("MCP argument arrays must not be empty or schema-ambiguous".to_string());
            };
            let items = json_shape(first)?;
            for value in &values[1..] {
                if json_shape(value)? != items {
                    return Err(
                        "MCP argument arrays must have one unambiguous item shape".to_string()
                    );
                }
            }
            Ok(JsonShape::Array {
                items: Box::new(items),
            })
        }
    }
}

fn validate_json_shape(shape: &JsonShape) -> Result<(), String> {
    match shape {
        JsonShape::Array { items } => validate_json_shape(items),
        JsonShape::Object { fields } => {
            if fields.keys().any(|field| field.is_empty()) {
                return Err("MCP argument object field names must not be empty".to_string());
            }
            for nested in fields.values() {
                validate_json_shape(nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn json_shape_matches(actual: &JsonShape, allowed: &JsonShape, allow_extra: bool) -> bool {
    match (actual, allowed) {
        (JsonShape::Null, JsonShape::Null)
        | (JsonShape::Boolean, JsonShape::Boolean)
        | (JsonShape::Number, JsonShape::Number)
        | (JsonShape::String, JsonShape::String) => true,
        (JsonShape::Array { items }, JsonShape::Array { items: allowed }) => {
            json_shape_matches(items, allowed, allow_extra)
        }
        (
            JsonShape::Object { fields },
            JsonShape::Object {
                fields: allowed_fields,
            },
        ) => {
            allowed_fields.iter().all(|(name, allowed)| {
                fields
                    .get(name)
                    .is_some_and(|actual| json_shape_matches(actual, allowed, allow_extra))
            }) && (allow_extra || fields.len() == allowed_fields.len())
        }
        _ => false,
    }
}

pub fn canonical_secret_target(
    secret_ref: &str,
    destination_adapter: &str,
    destination_action: &str,
) -> Result<CanonicalCapabilityTarget, String> {
    let (reference_namespace, reference_name) = secret_ref
        .split_once('/')
        .ok_or_else(|| "secret target must use an explicit namespace/name reference".to_string())?;
    let reference = canonical_secret_reference(reference_namespace, reference_name)?;
    Ok(CanonicalCapabilityTarget::Secret {
        reference_namespace: reference_namespace.to_string(),
        reference_fingerprint: opaque_reference_fingerprint(&reference),
        destination_adapter: canonical_identifier(
            "secret destination adapter",
            destination_adapter,
        )?,
        destination_action: canonical_identifier("secret destination action", destination_action)?,
    })
}

fn canonical_secret_reference(namespace: &str, name: &str) -> Result<String, String> {
    let namespace = canonical_identifier("secret reference namespace", namespace)?;
    let name = canonical_identifier("secret reference name", name)?;
    let upper = name.to_ascii_uppercase();
    if name.starts_with("sk-")
        || name.starts_with("ghp_")
        || upper.starts_with("AKIA")
        || name.contains('=')
    {
        return Err("secret target resembles resolved credential material".to_string());
    }
    Ok(format!("{namespace}/{name}"))
}

pub fn canonical_cli_target(
    executable: &str,
    argv: &[String],
    cwd: &str,
    timeout_millis: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> Result<CanonicalCapabilityTarget, String> {
    let executable = canonical_cli_executable(executable)?;
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err("CLI argv contains a NUL byte".to_string());
    }
    let cwd = std::fs::canonicalize(cwd)
        .map_err(|error| format!("CLI cwd cannot be resolved: {error}"))?;
    if !cwd.is_dir() {
        return Err("CLI cwd must resolve to a directory".to_string());
    }
    let (executable_device, executable_inode, cwd_device, cwd_inode) =
        filesystem_object_identities(std::path::Path::new(&executable), &cwd)?;
    let executable_content_fingerprint =
        file_content_fingerprint(std::path::Path::new(&executable), "CLI executable")?;
    Ok(CanonicalCapabilityTarget::Cli {
        executable,
        executable_device,
        executable_inode,
        executable_content_fingerprint,
        argv: argv.to_vec(),
        environment: BTreeMap::new(),
        cwd: cwd.display().to_string(),
        cwd_device,
        cwd_inode,
        timeout_millis,
        stdout_bytes,
        stderr_bytes,
    })
}

fn file_content_fingerprint(executable: &std::path::Path, label: &str) -> Result<String, String> {
    use std::io::Read;

    const MAX_CLI_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

    let mut file = std::fs::File::open(executable)
        .map_err(|error| format!("{label} content cannot be opened: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{label} metadata cannot be read: {error}"))?;
    if metadata.len() > MAX_CLI_EXECUTABLE_BYTES {
        return Err(format!(
            "{label} exceeds the {MAX_CLI_EXECUTABLE_BYTES}-byte immutable snapshot limit"
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("{label} content cannot be read: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn canonical_cli_executable(executable: &str) -> Result<String, String> {
    if !executable.starts_with('/') || executable.contains("/../") {
        return Err("CLI executable must be an absolute normalized path".to_string());
    }
    let executable = std::fs::canonicalize(executable)
        .map_err(|error| format!("CLI executable cannot be resolved: {error}"))?;
    if !executable.is_file() {
        return Err("CLI executable must resolve to a file".to_string());
    }
    Ok(executable.display().to_string())
}

fn canonical_identifier(label: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.contains(['/', '\\', ':'])
    {
        return Err(format!("{label} is not a canonical identifier"));
    }
    Ok(value.to_string())
}

fn normalize_relative_path(path: &str) -> Result<String, String> {
    if path.contains('\\') || path.starts_with('/') {
        return Err("path must use workspace-relative POSIX notation".to_string());
    }
    let mut parts = Vec::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("path traversal is not authorized".to_string())
            }
        }
    }
    if parts.is_empty() {
        return Err("path must identify a workspace target".to_string());
    }
    Ok(parts.join("/"))
}

fn normalize_host(host: &str) -> Result<String, String> {
    let value = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || !value.is_ascii()
        || value.contains('%')
        || value.chars().any(char::is_whitespace)
    {
        return Err("host notation is ambiguous".to_string());
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(value.parse::<IpAddr>().unwrap().to_string());
    }
    if value.starts_with("0x")
        || value
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
    {
        return Err("alternate numeric host notation is not authorized".to_string());
    }
    Ok(value)
}

fn parse_authority(authority: &str, scheme: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 authority".to_string())?;
        let port = if port.is_empty() {
            default_port(scheme)
        } else {
            port.strip_prefix(':')
                .ok_or_else(|| "invalid IPv6 port".to_string())?
                .parse::<u16>()
                .map_err(|_| "invalid network port".to_string())?
        };
        return Ok((normalize_host(host)?, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|_| "invalid network port".to_string())?,
        ),
        _ => (authority, default_port(scheme)),
    };
    Ok((normalize_host(host)?, port))
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

fn normalize_url_path(path: &str) -> Result<String, String> {
    let path = if path.is_empty() { "/" } else { path };
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("URL path traversal is not authorized".to_string()),
            value => parts.push(value),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

fn contains_ambiguous_percent_encoding(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|encoded| lower.contains(encoded))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[u8], value: &[u8]) -> bool {
        if pattern.is_empty() {
            return value.is_empty();
        }
        if pattern.starts_with(b"**") {
            return matches(&pattern[2..], value)
                || (!value.is_empty() && matches(pattern, &value[1..]));
        }
        if pattern[0] == b'*' {
            return matches(&pattern[1..], value)
                || (!value.is_empty() && value[0] != b'/' && matches(pattern, &value[1..]));
        }
        !value.is_empty() && pattern[0] == value[0] && matches(&pattern[1..], &value[1..])
    }
    matches(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
#[path = "target_capability_test.rs"]
mod tests;
